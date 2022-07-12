use ciborium::value::Value;
use serde::{Deserialize, Deserializer};

use super::key_mapped::{Keymappable, KeymappedStruct};

impl<'de, T: Keymappable<u8> + Deserialize<'de>> Deserialize<'de> for KeymappedStruct<T, u8> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // TODO: currently, deserializing is a bit hacky, first deserializing to an int keyed CBOR mapped,
        // which is then transformed to a string keyed one (via the Keymappable trait), only to be deserialized
        // again to the final value.
        let mut value = Value::deserialize(deserializer)?;
        if !value.is_map() {
            return Err(serde::de::Error::custom(format!("Expected top level CBOR value to be a map while deserializing keymapped, got {:?} instead", value)));
        }

        let map_entries = value.as_map_mut().unwrap();

        for (key, _value) in map_entries {
            let int_key = i128::from(key.as_integer().ok_or_else(|| {
                serde::de::Error::custom(format!(
                    "Expected top level map key to be integer, got {:?} instead",
                    key
                ))
            })?);
            let u8_key = u8::try_from(int_key).map_err(|_| {
                serde::de::Error::custom(format!(
                    "Encountered integer key {} that does not fit in a u8",
                    int_key
                ))
            })?;
            let string_key = T::inverse_map_field(&u8_key).ok_or_else(|| {
                serde::de::Error::custom(format!(
                    "The integer key {} cannot be mapped to a field",
                    u8_key
                ))
            })?;
            *key = Value::Text(string_key);
        }

        let t: T = value
            .deserialized()
            .map_err(|e| serde::de::Error::custom(format!("{}", e)))?;
        Ok(KeymappedStruct::from(t))
    }
}
