// SPDX-License-Identifier: Apache-2.0

//! Windows: the key is wrapped by an RSA key held in the TPM through the
//! Microsoft Platform Crypto Provider where a TPM is available, and by DPAPI
//! for the current user otherwise. The wrapped bytes are kept in a file next
//! to the store, prefixed by the method that wrapped them.

use std::path::{Path, PathBuf};
use uuid::Uuid;

use windows::Win32::Foundation::{HLOCAL, LocalFree, NTE_BAD_KEYSET};
use windows::Win32::Security::Cryptography::{
    BCRYPT_OAEP_PADDING_INFO, BCRYPT_RSA_ALGORITHM, BCRYPT_SHA256_ALGORITHM, CERT_KEY_SPEC,
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_FLAGS, NCRYPT_HANDLE, NCRYPT_KEY_HANDLE,
    NCRYPT_PAD_OAEP_FLAG, NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG, NCryptCreatePersistedKey,
    NCryptDecrypt, NCryptDeleteKey, NCryptEncrypt, NCryptFinalizeKey, NCryptFreeObject,
    NCryptOpenKey, NCryptOpenStorageProvider,
};
use windows::core::{HSTRING, PCWSTR, w};
use zeroize::Zeroizing;

use super::{Keystore, KeystoreError};

const NAME: &str = "Windows keystore";
const FILE: &str = "local-key.protected";
const METHOD_DPAPI: u8 = 1;
const METHOD_TPM: u8 = 2;
/// Mixed into DPAPI so that another application's protected blob for the
/// same user cannot be substituted.
const DPAPI_ENTROPY: &[u8] = b"spl-local-db-key-dpapi-v1";

pub(super) struct WindowsKeystore {
    file: PathBuf,
    tpm_key_name: HSTRING,
}

impl WindowsKeystore {
    pub(super) fn for_data_dir(data_dir: &Path) -> WindowsKeystore {
        // One TPM key per store location; the name is derived from the path so
        // that development and release installs do not share a key.
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in data_dir.as_os_str().as_encoded_bytes() {
            hash = (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3);
        }
        WindowsKeystore {
            file: data_dir.join(FILE),
            tpm_key_name: HSTRING::from(format!("Scoplen local database key {hash:016x}")),
        }
    }

    pub(super) fn for_credential(data_dir: &Path, credential: Uuid) -> WindowsKeystore {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in data_dir.as_os_str().as_encoded_bytes() {
            hash = (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3);
        }
        for byte in credential.as_bytes() {
            hash = (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3);
        }
        WindowsKeystore {
            file: data_dir.join(format!("device-credential-{hash:016x}.protected")),
            tpm_key_name: HSTRING::from(format!("Scoplen device credential {hash:016x}")),
        }
    }

    fn file_error(operation: &'static str) -> impl FnOnce(std::io::Error) -> KeystoreError {
        move |source| KeystoreError::File { operation, source }
    }

    fn delete_with_native(
        &self,
        delete_native: impl FnOnce(&HSTRING) -> Result<(), windows::core::Error>,
    ) -> Result<(), KeystoreError> {
        // A DPAPI blob or a missing file does not rule out a key left by an
        // earlier TPM wrapping attempt. Keep the blob until native cleanup succeeds.
        delete_native(&self.tpm_key_name).map_err(|e| platform("delete", e))?;
        match std::fs::remove_file(&self.file) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Self::file_error("removed")(e)),
        }
    }
}

impl Keystore for WindowsKeystore {
    fn name(&self) -> &'static str {
        NAME
    }

    fn load(&self) -> Result<Option<Zeroizing<Vec<u8>>>, KeystoreError> {
        let bytes = match std::fs::read(&self.file) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Self::file_error("read")(e)),
        };
        match bytes.split_first() {
            Some((&METHOD_DPAPI, wrapped)) => dpapi_unprotect(wrapped).map(Some),
            Some((&METHOD_TPM, wrapped)) => tpm_unwrap(&self.tpm_key_name, wrapped).map(Some),
            _ => Err(KeystoreError::Unrecoverable { keystore: NAME }),
        }
    }

    fn store(&self, secret: &[u8]) -> Result<(), KeystoreError> {
        let mut file = match tpm_wrap(&self.tpm_key_name, secret) {
            Ok(wrapped) => [&[METHOD_TPM][..], &wrapped].concat(),
            // No TPM, or the provider refused: DPAPI still binds the key to
            // this user on this machine.
            Err(_) => [&[METHOD_DPAPI][..], &dpapi_protect(secret)?].concat(),
        };
        let partial = self.file.with_extension("protected.partial");
        std::fs::write(&partial, &file).map_err(Self::file_error("written"))?;
        std::fs::rename(&partial, &self.file).map_err(Self::file_error("written"))?;
        file.iter_mut().for_each(|b| *b = 0);
        Ok(())
    }

    fn delete(&self) -> Result<(), KeystoreError> {
        self.delete_with_native(tpm_delete)
    }
}

fn platform(operation: &'static str, error: windows::core::Error) -> KeystoreError {
    KeystoreError::Platform { keystore: NAME, operation, detail: error.message() }
}

fn blob(bytes: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB { cbData: bytes.len() as u32, pbData: bytes.as_ptr().cast_mut() }
}

/// Copies and frees a blob allocated by DPAPI.
fn take_blob(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
    // SAFETY: on success DPAPI returns `cbData` readable bytes at `pbData`,
    // allocated with LocalAlloc; they are copied before being freed once.
    unsafe {
        let bytes = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        std::ptr::write_bytes(out.pbData, 0, out.cbData as usize);
        LocalFree(Some(HLOCAL(out.pbData.cast())));
        bytes
    }
}

fn dpapi_protect(secret: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    let input = blob(secret);
    let entropy = blob(DPAPI_ENTROPY);
    let mut out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: the input and entropy blobs point to live slices for the
    // duration of the call, and `out` is a valid place for the result.
    unsafe {
        CryptProtectData(
            &input,
            w!("Scoplen local database key"),
            Some(&entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    }
    .map_err(|e| platform("protect", e))?;
    Ok(take_blob(out))
}

fn dpapi_unprotect(wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
    let input = blob(wrapped);
    let entropy = blob(DPAPI_ENTROPY);
    let mut out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: as in `dpapi_protect`.
    unsafe {
        CryptUnprotectData(
            &input,
            None,
            Some(&entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    }
    .map_err(|_| KeystoreError::Unrecoverable { keystore: NAME })?;
    Ok(Zeroizing::new(take_blob(out)))
}

/// An NCrypt handle freed when dropped.
struct Handle(NCRYPT_HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: the handle came from NCrypt and is freed exactly once.
            let _ = unsafe { NCryptFreeObject(self.0) };
        }
    }
}

fn open_provider() -> Result<Handle, windows::core::Error> {
    let mut provider = NCRYPT_PROV_HANDLE::default();
    // SAFETY: `provider` is a valid place for the returned handle.
    unsafe { NCryptOpenStorageProvider(&mut provider, MS_PLATFORM_CRYPTO_PROVIDER, 0) }?;
    Ok(Handle(NCRYPT_HANDLE(provider.0)))
}

fn open_key(
    provider: &Handle,
    name: &HSTRING,
    create: bool,
) -> Result<Handle, windows::core::Error> {
    let provider = NCRYPT_PROV_HANDLE(provider.0.0);
    let mut key = NCRYPT_KEY_HANDLE::default();
    // SAFETY: `provider` is open, `name` outlives the call, and `key` is a
    // valid place for the returned handle.
    let opened = unsafe {
        NCryptOpenKey(provider, &mut key, PCWSTR(name.as_ptr()), CERT_KEY_SPEC(0), NCRYPT_FLAGS(0))
    };
    if opened.is_ok() || !create {
        opened?;
        return Ok(Handle(NCRYPT_HANDLE(key.0)));
    }
    // SAFETY: as above; the new key is finalized before use.
    unsafe {
        NCryptCreatePersistedKey(
            provider,
            &mut key,
            BCRYPT_RSA_ALGORITHM,
            PCWSTR(name.as_ptr()),
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        )?;
        let handle = Handle(NCRYPT_HANDLE(key.0));
        NCryptFinalizeKey(key, NCRYPT_FLAGS(0))?;
        Ok(handle)
    }
}

fn oaep() -> BCRYPT_OAEP_PADDING_INFO {
    BCRYPT_OAEP_PADDING_INFO {
        pszAlgId: BCRYPT_SHA256_ALGORITHM,
        pbLabel: std::ptr::null_mut(),
        cbLabel: 0,
    }
}

/// The shape shared by `NCryptEncrypt` and `NCryptDecrypt`.
type NcryptOperation = unsafe fn(
    NCRYPT_KEY_HANDLE,
    Option<&[u8]>,
    Option<*const core::ffi::c_void>,
    Option<&mut [u8]>,
    *mut u32,
    NCRYPT_FLAGS,
) -> windows::core::Result<()>;

/// Runs an NCrypt encrypt or decrypt: first to size the output, then for real.
fn ncrypt(
    operation: NcryptOperation,
    key: &Handle,
    input: &[u8],
) -> Result<Vec<u8>, windows::core::Error> {
    let key = NCRYPT_KEY_HANDLE(key.0.0);
    let padding = oaep();
    let padding_ptr = Some(std::ptr::from_ref(&padding).cast());
    let mut size = 0u32;
    // SAFETY: `key` is open, `input` and `padding` outlive both calls, and the
    // output buffer has the size NCrypt reported.
    unsafe {
        operation(key, Some(input), padding_ptr, None, &mut size, NCRYPT_PAD_OAEP_FLAG)?;
        let mut output = vec![0u8; size as usize];
        operation(
            key,
            Some(input),
            padding_ptr,
            Some(&mut output),
            &mut size,
            NCRYPT_PAD_OAEP_FLAG,
        )?;
        output.truncate(size as usize);
        Ok(output)
    }
}

fn tpm_wrap(name: &HSTRING, secret: &[u8]) -> Result<Vec<u8>, windows::core::Error> {
    let provider = open_provider()?;
    let key = open_key(&provider, name, true)?;
    ncrypt(NCryptEncrypt, &key, secret)
}

fn tpm_unwrap(name: &HSTRING, wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
    let unrecoverable = |_| KeystoreError::Unrecoverable { keystore: NAME };
    let provider = open_provider().map_err(unrecoverable)?;
    let key = open_key(&provider, name, false).map_err(unrecoverable)?;
    ncrypt(NCryptDecrypt, &key, wrapped).map(Zeroizing::new).map_err(unrecoverable)
}

fn tpm_delete(name: &HSTRING) -> Result<(), windows::core::Error> {
    let provider = open_provider()?;
    let mut raw = NCRYPT_KEY_HANDLE::default();
    // SAFETY: `provider` is open, `name` outlives the call, and `raw` is a
    // valid place for the returned handle. Without MACHINE_KEY this opens
    // only this current user's exact named key; SILENT prevents provider UI.
    let opened = unsafe {
        NCryptOpenKey(
            NCRYPT_PROV_HANDLE(provider.0.0),
            &mut raw,
            PCWSTR(name.as_ptr()),
            CERT_KEY_SPEC(0),
            NCRYPT_SILENT_FLAG,
        )
    };
    match opened {
        Err(e) if e.code() == NTE_BAD_KEYSET => return Ok(()),
        Err(e) => return Err(e),
        Ok(()) => {}
    }
    let key = Handle(NCRYPT_HANDLE(raw.0));
    // SAFETY: the key handle is open. NCryptDeleteKey frees it on success, so
    // the guard is then forgotten; on failure the guard frees it.
    unsafe { NCryptDeleteKey(raw, 0) }?;
    std::mem::forget(key);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::windows::fs::OpenOptionsExt;

    use super::*;
    use windows::Win32::Foundation::{
        NTE_BAD_FLAGS, NTE_FAIL, NTE_NOT_SUPPORTED, NTE_PERM, NTE_SILENT_CONTEXT,
    };
    use windows::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

    fn dpapi_slot() -> (tempfile::TempDir, WindowsKeystore, Vec<u8>) {
        let directory = tempfile::Builder::new()
            .prefix("scoplen-keystore-")
            .disable_cleanup(true)
            .tempdir()
            .unwrap();
        let data = directory.path().canonicalize().unwrap();
        let keystore = WindowsKeystore::for_data_dir(&data);
        let wrapped = dpapi_protect(b"owned DPAPI test secret").unwrap();
        let protected = [&[METHOD_DPAPI][..], &wrapped].concat();
        std::fs::write(&keystore.file, &protected).unwrap();
        (directory, keystore, protected)
    }

    #[test]
    fn native_errors_preserve_the_dpapi_blob_and_its_readability() {
        let (directory, keystore, protected) = dpapi_slot();
        // BAD_KEYSET from a native step other than exact OpenKey is still an error.
        for code in [
            NTE_BAD_FLAGS,
            NTE_NOT_SUPPORTED,
            NTE_PERM,
            NTE_SILENT_CONTEXT,
            NTE_FAIL,
            NTE_BAD_KEYSET,
        ] {
            let result =
                keystore.delete_with_native(|_| Err(windows::core::Error::from_hresult(code)));
            match result {
                Err(KeystoreError::Platform { operation: "delete", detail, .. }) => {
                    assert_eq!(detail, windows::core::Error::from_hresult(code).message());
                }
                _ => panic!("native deletion failures must be returned"),
            }
            assert_eq!(std::fs::read(&keystore.file).unwrap(), protected);
            assert_eq!(keystore.load().unwrap().unwrap().as_slice(), b"owned DPAPI test secret");
        }
        keystore.delete().unwrap();
        directory.close().unwrap();
    }

    #[test]
    fn a_missing_blob_does_not_hide_native_errors() {
        let directory = tempfile::Builder::new()
            .prefix("scoplen-keystore-")
            .disable_cleanup(true)
            .tempdir()
            .unwrap();
        let data = directory.path().canonicalize().unwrap();
        let keystore = WindowsKeystore::for_data_dir(&data);
        let result = keystore
            .delete_with_native(|_| Err(windows::core::Error::from_hresult(NTE_NOT_SUPPORTED)));
        assert!(matches!(result, Err(KeystoreError::Platform { operation: "delete", .. })));
        assert!(!keystore.file.exists());
        keystore.delete().unwrap();
        directory.close().unwrap();
    }

    #[test]
    fn the_public_keystore_deletes_a_real_dpapi_blob_and_an_absent_slot() {
        let (directory, slot, _) = dpapi_slot();
        let data = directory.path().canonicalize().unwrap();
        let keystore = super::super::local_key_store(&data).unwrap();
        assert_eq!(keystore.load().unwrap().unwrap().as_slice(), b"owned DPAPI test secret");
        let provider = open_provider().unwrap();
        assert!(
            matches!(open_key(&provider, &slot.tpm_key_name, false), Err(e) if e.code() == NTE_BAD_KEYSET)
        );
        keystore.delete().unwrap();
        assert!(!slot.file.exists());
        assert!(keystore.load().unwrap().is_none());
        keystore.delete().unwrap();
        assert!(
            matches!(open_key(&provider, &slot.tpm_key_name, false), Err(e) if e.code() == NTE_BAD_KEYSET)
        );
        directory.close().unwrap();
    }

    #[test]
    fn the_public_keystore_retries_file_removal_after_native_absence() {
        let (directory, slot, protected) = dpapi_slot();
        let data = directory.path().canonicalize().unwrap();
        let keystore = super::super::local_key_store(&data).unwrap();
        let retained = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)
            .open(&slot.file)
            .unwrap();
        assert!(matches!(keystore.delete(), Err(KeystoreError::File { operation: "removed", .. })));
        assert_eq!(std::fs::read(&slot.file).unwrap(), protected);
        assert_eq!(keystore.load().unwrap().unwrap().as_slice(), b"owned DPAPI test secret");
        drop(retained);
        keystore.delete().unwrap();
        assert!(!slot.file.exists());
        assert!(keystore.load().unwrap().is_none());
        keystore.delete().unwrap();
        directory.close().unwrap();
    }
}
