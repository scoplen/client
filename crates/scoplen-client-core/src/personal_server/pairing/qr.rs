// SPDX-License-Identifier: Apache-2.0
//! Bounded, local-only QR rendering and PNG recognition for the transient pairing boundary.

use std::{
    fs::File,
    io::{BufReader, Read as _},
    path::Path,
};

use qrcode::{EcLevel, QrCode};
use scoplen_crypto::PairingQrPayload;
use serde::Serialize;
use specta::Type;
use zeroize::{Zeroize as _, Zeroizing};

use super::PairingError;

const MAX_FILE_BYTES: u64 = 8 * 1_024 * 1_024;
const MAX_PIXELS: u64 = 4_194_304;
const MAX_DIMENSION: u32 = 4_096;
const MAX_ALLOCATION: usize = 32 * 1_024 * 1_024;

/// Secret-bearing module matrix, returned only with the one-time password display.
#[derive(Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct PairingQrDisplay {
    /// Number of modules on each side, excluding the four-module quiet zone.
    pub size: u16,
    /// Row-major monochrome modules: zero is white and one is black.
    pub modules: Vec<u8>,
}

impl Drop for PairingQrDisplay {
    fn drop(&mut self) {
        self.modules.zeroize();
    }
}

impl std::fmt::Debug for PairingQrDisplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairingQrDisplay([REDACTED])")
    }
}

pub(super) fn display(payload: &PairingQrPayload) -> Result<PairingQrDisplay, PairingError> {
    let encoded = payload.encode();
    let code = QrCode::with_error_correction_level(encoded.as_bytes(), EcLevel::M)
        .or_else(|_| QrCode::with_error_correction_level(encoded.as_bytes(), EcLevel::L))
        .map_err(|_| PairingError::QrUnavailable)?;
    let size = u16::try_from(code.width()).map_err(|_| PairingError::QrUnavailable)?;
    let mut colors = code.into_colors();
    let modules = colors.iter().map(|color| u8::from(*color == qrcode::Color::Dark)).collect();
    colors.fill(qrcode::Color::Light);
    Ok(PairingQrDisplay { size, modules })
}

pub(super) fn read_png(path: &Path) -> Result<PairingQrPayload, PairingError> {
    let file = File::open(path).map_err(|_| PairingError::QrImage)?;
    if !file.metadata().map_err(|_| PairingError::QrImage)?.is_file() {
        return Err(PairingError::QrImage);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes).map_err(|_| PairingError::QrImage)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(PairingError::QrImage);
    }
    decode_png(&bytes)
}

fn decode_png(bytes: &[u8]) -> Result<PairingQrPayload, PairingError> {
    let mut decoder = png::Decoder::new_with_limits(
        BufReader::new(std::io::Cursor::new(bytes)),
        png::Limits { bytes: MAX_ALLOCATION },
    );
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder.read_info().map_err(|_| PairingError::QrImage)?;
    let info = reader.info();
    let (width, height) = (info.width, info.height);
    if width == 0
        || height == 0
        || width > MAX_DIMENSION
        || height > MAX_DIMENSION
        || u64::from(width) * u64::from(height) > MAX_PIXELS
        || info.animation_control.is_some()
    {
        return Err(PairingError::QrImage);
    }
    let size = reader
        .output_buffer_size()
        .filter(|size| *size <= MAX_ALLOCATION)
        .ok_or(PairingError::QrImage)?;
    let mut decoded = Zeroizing::new(vec![0; size]);
    let output = reader.next_frame(&mut decoded).map_err(|_| PairingError::QrImage)?;
    reader.finish().map_err(|_| PairingError::QrImage)?;
    let channels = output.color_type.samples();
    let width = width as usize;
    let height = height as usize;
    let mut image = rqrr::PreparedImage::prepare_from_greyscale(width, height, |x, y| {
        let pixel = &decoded[(y * width + x) * channels..][..channels];
        let (luma, alpha) = match output.color_type {
            png::ColorType::Grayscale => (u32::from(pixel[0]), 255),
            png::ColorType::GrayscaleAlpha => (u32::from(pixel[0]), u32::from(pixel[1])),
            png::ColorType::Rgb | png::ColorType::Rgba => (
                (u32::from(pixel[0]) * 77 + u32::from(pixel[1]) * 150 + u32::from(pixel[2]) * 29)
                    / 256,
                if channels == 4 { u32::from(pixel[3]) } else { 255 },
            ),
            png::ColorType::Indexed => (255, 255),
        };
        ((luma * alpha + 255 * (255 - alpha)) / 255) as u8
    });
    let grids = image.detect_grids();
    if grids.len() != 1 {
        return Err(PairingError::QrImage);
    }
    let mut text = Zeroizing::new(Vec::new());
    grids[0].decode_to(&mut *text).map_err(|_| PairingError::QrImage)?;
    let text = std::str::from_utf8(&text).map_err(|_| PairingError::QrImage)?;
    PairingQrPayload::decode(text).map_err(|_| PairingError::QrImage)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use scoplen_crypto::{DeviceKemKeyPair, P256SigningKey, PairingCode};

    fn payload(origin: &str) -> PairingQrPayload {
        PairingQrPayload::new(
            origin,
            "03000000-0000-7000-8000-000000000000".parse().unwrap(),
            DeviceKemKeyPair::from_private_bytes(&[7; 32]).unwrap().public_key(),
            &P256SigningKey::from_bytes(&[2; 32]).unwrap().public_key_sec1(),
            PairingCode::from_ascii(b"01234567").unwrap(),
        )
        .unwrap()
    }

    pub(crate) fn png_bytes(
        display: &PairingQrDisplay,
        color: png::ColorType,
        copies: u32,
    ) -> Vec<u8> {
        let side = (u32::from(display.size) + 8) * 4;
        let width = side * copies;
        let channels = color.samples();
        let mut pixels = Zeroizing::new(vec![255; (width * side) as usize * channels]);
        for y in 0..side {
            for x in 0..width {
                let (mx, my) = ((x % side) / 4, y / 4);
                let black = mx >= 4
                    && my >= 4
                    && mx < u32::from(display.size) + 4
                    && my < u32::from(display.size) + 4
                    && display.modules[((my - 4) * u32::from(display.size) + mx - 4) as usize] == 1;
                let pixel = &mut pixels[(y * width + x) as usize * channels..][..channels];
                if black {
                    pixel.fill(0);
                }
                if matches!(color, png::ColorType::Rgba | png::ColorType::GrayscaleAlpha) {
                    pixel[channels - 1] = if black { 255 } else { 0 };
                }
            }
        }
        encode_png(width, side, color, &pixels, false)
    }

    fn encode_png(
        width: u32,
        height: u32,
        color: png::ColorType,
        pixels: &[u8],
        animated: bool,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut bytes, width, height);
            encoder.set_color(color);
            encoder.set_depth(png::BitDepth::Eight);
            if animated {
                encoder.set_animated(1, 0).unwrap();
            }
            let mut writer = encoder.write_header().unwrap();
            writer.write_image_data(pixels).unwrap();
            writer.finish().unwrap();
        }
        bytes
    }

    pub(crate) fn write_png(display: &PairingQrDisplay, path: &Path) {
        std::fs::write(path, Zeroizing::new(png_bytes(display, png::ColorType::Rgb, 1))).unwrap();
    }

    pub(crate) fn write_payload(payload: &PairingQrPayload, path: &Path) {
        write_png(&display(payload).unwrap(), path);
    }

    #[test]
    fn real_qr_round_trips_static_png_color_formats_and_alpha_over_white() {
        let payload = payload("https://ssh.example.test");
        let display = display(&payload).unwrap();
        for color in [
            png::ColorType::Grayscale,
            png::ColorType::GrayscaleAlpha,
            png::ColorType::Rgb,
            png::ColorType::Rgba,
        ] {
            let bytes = Zeroizing::new(png_bytes(&display, color, 1));
            let decoded = decode_png(&bytes).unwrap();
            assert!(decoded.encode().as_bytes() == payload.encode().as_bytes());
        }
    }

    #[test]
    fn rejects_missing_multiple_legacy_and_noncanonical_qr() {
        assert!(matches!(
            decode_png(&encode_png(64, 64, png::ColorType::Grayscale, &[255; 4096], false)),
            Err(PairingError::QrImage)
        ));
        let display = display(&payload("https://ssh.example.test")).unwrap();
        assert!(matches!(
            decode_png(&png_bytes(&display, png::ColorType::Rgb, 2)),
            Err(PairingError::QrImage)
        ));
        for text in [
            "splpair1:legacy".to_owned(),
            format!(
                "{} ",
                std::str::from_utf8(payload("https://ssh.example.test").encode().as_bytes())
                    .unwrap()
            ),
        ] {
            let code = QrCode::new(text.as_bytes()).unwrap();
            let display = PairingQrDisplay {
                size: code.width() as u16,
                modules: code
                    .into_colors()
                    .iter()
                    .map(|c| u8::from(*c == qrcode::Color::Dark))
                    .collect(),
            };
            assert!(matches!(
                decode_png(&png_bytes(&display, png::ColorType::Rgb, 1)),
                Err(PairingError::QrImage)
            ));
        }
    }

    #[test]
    fn rejects_corrupt_truncated_animated_and_oversized_png() {
        let display = display(&payload("https://ssh.example.test")).unwrap();
        let bytes = png_bytes(&display, png::ColorType::Rgb, 1);
        assert!(matches!(decode_png(b"not a PNG"), Err(PairingError::QrImage)));
        assert!(matches!(decode_png(&bytes[..bytes.len() - 12]), Err(PairingError::QrImage)));
        let mut corrupt = bytes.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(matches!(decode_png(&corrupt), Err(PairingError::QrImage)));
        for (width, height) in [(4097, 1), (2049, 2049)] {
            let bytes = encode_png(
                width,
                height,
                png::ColorType::Grayscale,
                &vec![255; (width * height) as usize],
                false,
            );
            assert!(matches!(decode_png(&bytes), Err(PairingError::QrImage)));
        }
        assert!(matches!(
            decode_png(&encode_png(1, 1, png::ColorType::Grayscale, &[255], true)),
            Err(PairingError::QrImage)
        ));
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().set_len(MAX_FILE_BYTES + 1).unwrap();
        assert!(matches!(read_png(file.path()), Err(PairingError::QrImage)));
    }

    #[test]
    fn maximum_canonical_origin_fits_standard_qr() {
        let hostname = ["a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(61)].join(".");
        assert_eq!(hostname.len(), 253);
        let origin = format!("https://{hostname}:65535");
        assert_eq!(origin.len(), 267);
        let payload = payload(&origin);
        assert_eq!(payload.encode().as_bytes().len(), 476);
        let display = display(&payload).unwrap();
        assert!(display.size <= 177);
        assert_eq!(display.modules.len(), usize::from(display.size).pow(2));
        assert_eq!(format!("{display:?}"), "PairingQrDisplay([REDACTED])");
    }
}
