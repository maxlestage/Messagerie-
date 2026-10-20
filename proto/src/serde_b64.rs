//! Les octets des états sérialisés (JSON) sont écrits en base64 standard.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serializer};
use zeroize::Zeroizing;

/// `[u8; N]` ou `Vec<u8>` ↔ chaîne base64.
pub(crate) fn serialize<S: Serializer, T: AsRef<[u8]>>(v: &T, s: S) -> Result<S::Ok, S::Error> {
    let text = Zeroizing::new(STANDARD.encode(v.as_ref()));
    s.serialize_str(&text)
}

pub(crate) fn deserialize<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: TryFrom<Vec<u8>>,
{
    let text = Zeroizing::new(String::deserialize(d)?);
    let bytes = STANDARD
        .decode(text.as_bytes())
        .map_err(|_| D::Error::custom("base64 invalide"))?;
    T::try_from(bytes).map_err(|_| D::Error::custom("longueur invalide"))
}

/// `Option<[u8; N]>` ↔ chaîne base64 ou `null`.
pub(crate) mod opt {
    use super::*;

    pub(crate) fn serialize<S: Serializer, T: AsRef<[u8]>>(
        v: &Option<T>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match v {
            Some(v) => super::serialize(v, s),
            None => s.serialize_none(),
        }
    }

    pub(crate) fn deserialize<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
    where
        D: Deserializer<'de>,
        T: TryFrom<Vec<u8>>,
    {
        let text: Option<String> = Option::deserialize(d)?;
        match text {
            None => Ok(None),
            Some(text) => {
                let text = Zeroizing::new(text);
                let bytes = STANDARD
                    .decode(text.as_bytes())
                    .map_err(|_| D::Error::custom("base64 invalide"))?;
                T::try_from(bytes)
                    .map(Some)
                    .map_err(|_| D::Error::custom("longueur invalide"))
            }
        }
    }
}
