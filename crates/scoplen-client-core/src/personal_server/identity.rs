// SPDX-License-Identifier: Apache-2.0
//! Device-local SQLCipher serialization of retained secret keys.

use scoplen_crypto::SecretVec;

use super::PersonalServerError;

pub(super) struct Secrets<'a>(&'a [u8]);

impl<'a> Secrets<'a> {
    pub fn parse(material: &'a SecretVec) -> Result<Self, PersonalServerError> {
        if !matches!((material.as_bytes().first(), material.len()), (Some(1), 225) | (Some(2), 193))
        {
            return Err(PersonalServerError::Identity);
        }
        Ok(Self(material.as_bytes()))
    }

    pub fn signing(&self) -> &[u8] {
        &self.0[1..33]
    }
    pub fn device_kem(&self) -> &[u8] {
        &self.0[33..65]
    }
    pub fn ark(&self) -> &[u8] {
        &self.0[65..97]
    }
    pub fn account_signing(&self) -> &[u8] {
        &self.0[97..129]
    }
    pub fn account_kem(&self) -> &[u8] {
        &self.0[129..161]
    }
    pub fn vault(&self) -> &[u8] {
        &self.0[161..193]
    }
    pub fn recovery(&self) -> Option<&[u8]> {
        self.0.get(193..225)
    }
}
