use std::{collections::HashMap, hash::Hash, marker::PhantomData};

use once_cell::sync::Lazy;
use serde::{
    ser::{SerializeMap, SerializeStruct},
    Deserialize, Serialize, Serializer,
};

/// A serializer that serializes structs as maps,
/// and also maps the fields to a different
struct KeyMappedSerializer<S: Serializer, F> {
    base_serializer: S,
    key_mapper: F,
}

struct KeyMappedStructSerializer<S: Serializer, F> {
    key_mapper: F,
    base_map_serializer: S::SerializeMap,
}

impl<S: Serializer, U: Serialize, F: Fn(&str) -> U> SerializeStruct
    for KeyMappedStructSerializer<S, F>
{
    type Ok = S::Ok;

    type Error = S::Error;

    fn serialize_field<T: ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error>
    where
        T: Serialize,
    {
        let new_key = (self.key_mapper)(key);
        self.base_map_serializer.serialize_entry(&new_key, value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.base_map_serializer.end()
    }
}

impl<S: Serializer, U: Serialize, F: Clone + Fn(&str) -> U> Serializer
    for KeyMappedSerializer<S, F>
{
    type Ok = S::Ok;

    type Error = S::Error;

    type SerializeSeq = S::SerializeSeq;

    type SerializeTuple = S::SerializeTuple;

    type SerializeTupleStruct = S::SerializeTupleStruct;

    type SerializeTupleVariant = S::SerializeTupleVariant;

    type SerializeMap = S::SerializeMap;

    type SerializeStruct = KeyMappedStructSerializer<S, F>;

    type SerializeStructVariant = S::SerializeStructVariant;

    fn serialize_bool(self, v: bool) -> Result<Self::Ok, Self::Error> {
        self.base_serializer.serialize_bool(v)
    }

    fn serialize_i8(self, v: i8) -> Result<Self::Ok, Self::Error> {
        self.base_serializer.serialize_i8(v)
    }

    fn serialize_i16(self, v: i16) -> Result<Self::Ok, Self::Error> {
        self.base_serializer.serialize_i16(v)
    }

    fn serialize_i32(self, v: i32) -> Result<Self::Ok, Self::Error> {
        self.base_serializer.serialize_i32(v)
    }

    fn serialize_i64(self, v: i64) -> Result<Self::Ok, Self::Error> {
        self.base_serializer.serialize_i64(v)
    }

    fn serialize_u8(self, v: u8) -> Result<Self::Ok, Self::Error> {
        self.base_serializer.serialize_u8(v)
    }

    fn serialize_u16(self, v: u16) -> Result<Self::Ok, Self::Error> {
        self.base_serializer.serialize_u16(v)
    }

    fn serialize_u32(self, v: u32) -> Result<Self::Ok, Self::Error> {
        self.base_serializer.serialize_u32(v)
    }

    fn serialize_u64(self, v: u64) -> Result<Self::Ok, Self::Error> {
        self.base_serializer.serialize_u64(v)
    }

    fn serialize_f32(self, v: f32) -> Result<Self::Ok, Self::Error> {
        self.base_serializer.serialize_f32(v)
    }

    fn serialize_f64(self, v: f64) -> Result<Self::Ok, Self::Error> {
        self.base_serializer.serialize_f64(v)
    }

    fn serialize_char(self, v: char) -> Result<Self::Ok, Self::Error> {
        self.base_serializer.serialize_char(v)
    }

    fn serialize_str(self, v: &str) -> Result<Self::Ok, Self::Error> {
        self.base_serializer.serialize_str(v)
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok, Self::Error> {
        self.base_serializer.serialize_bytes(v)
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        self.base_serializer.serialize_none()
    }

    fn serialize_some<T: ?Sized>(self, value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize,
    {
        self.base_serializer.serialize_some(value)
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        self.base_serializer.serialize_unit()
    }

    fn serialize_unit_struct(self, name: &'static str) -> Result<Self::Ok, Self::Error> {
        self.base_serializer.serialize_unit_struct(name)
    }

    fn serialize_unit_variant(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        self.base_serializer
            .serialize_unit_variant(name, variant_index, variant)
    }

    fn serialize_newtype_struct<T: ?Sized>(
        self,
        name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize,
    {
        self.base_serializer.serialize_newtype_struct(name, value)
    }

    fn serialize_newtype_variant<T: ?Sized>(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize,
    {
        self.base_serializer
            .serialize_newtype_variant(name, variant_index, variant, value)
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        self.base_serializer.serialize_seq(len)
    }

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        self.base_serializer.serialize_tuple(len)
    }

    fn serialize_tuple_struct(
        self,
        name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        self.base_serializer.serialize_tuple_struct(name, len)
    }

    fn serialize_tuple_variant(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        self.base_serializer
            .serialize_tuple_variant(name, variant_index, variant, len)
    }

    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        self.base_serializer.serialize_map(len)
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        let key_mapper = self.key_mapper.clone();
        let base_map_serializer = self.serialize_map(Some(len))?;

        Ok(KeyMappedStructSerializer {
            base_map_serializer,
            key_mapper,
        })
    }

    fn serialize_struct_variant(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        self.base_serializer
            .serialize_struct_variant(name, variant_index, variant, len)
    }
}

/// Allows a struct type to have its fields
/// converted to a different serializable value of type U during (de)serialization,
/// as defined via the trait's methods.
pub trait Keymappable<U> {
    fn map_field(field: &str) -> U;
    fn inverse_map_field(val: &U) -> String;
}

/// Newtype wrapper for structs to be (de)serialized as maps,
/// where the keys are mapped to a different type U.
pub struct KeymappedStruct<T, U>(pub T, PhantomData<U>);

impl<T, U> From<T> for KeymappedStruct<T, U> {
    fn from(t: T) -> Self {
        KeymappedStruct(t, PhantomData)
    }
}

impl<U: Serialize, T: Keymappable<U> + Serialize> Serialize for KeymappedStruct<T, U> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mapped_serializer = KeyMappedSerializer {
            base_serializer: serializer,
            key_mapper: T::map_field,
        };

        self.0.serialize(mapped_serializer)
    }
}

/// A helper trait for implementing [Keymappable] by defining a vector of (field_identifier, new_key)
/// tuples.
pub trait DictKeymappable<U>
where
    U: Serialize + Eq + Hash + Clone,
{
    fn field_mappings() -> Vec<(&'static str, U)>;
    fn field_map() -> Lazy<HashMap<&'static str, U>> {
        Lazy::new(|| {
            HashMap::from_iter(Self::field_mappings())
        })
    }
    fn inverse_field_map() -> Lazy<HashMap<U, &'static str>> {
        Lazy::new(|| {
            let mut m = HashMap::new();
            for (field, u) in Self::field_map().iter() {
                m.insert(u.clone(), *field);
            }
            m
        })
    }
}

impl<U: Serialize + Eq + Hash + Clone, T: DictKeymappable<U>> Keymappable<U> for T {
    fn map_field(field: &str) -> U {
        T::field_map()
            .get(field)
            .cloned()
            .expect(&format!("Field {} isn't mapped", field))
    }

    fn inverse_map_field(val: &U) -> String {
        T::inverse_field_map()
            .get(val)
            .map(|s| (*s).to_owned())
            .expect("Inverse mapping failed")
    }
}

mod tests {
    use serde::Deserialize;

    use super::*;

    #[test]
    fn test_packed_struct() {
        #[derive(Serialize)]
        struct Foo {
            x: u8,
            y: u8,
            bar: Bar,
        }
        #[derive(Serialize)]
        struct Bar {
            z: u8,
            b: KeymappedStruct<Baz, u8>,
        }
        #[derive(Serialize)]
        struct Baz {
            x: String,
        }

        impl DictKeymappable<u8> for Foo {
            fn field_mappings() -> Vec<(&'static str, u8)>{
                vec![("x", 137), ("y", 138), ("bar", 139)]
            }
        }

        impl DictKeymappable<u8> for Baz {
            fn field_mappings() -> Vec<(&'static str, u8)>{
                vec![("x", 9)]
            }
        }

        let mut bytes = vec![];
        let value = Foo {
            x: 5,
            y: 10,
            bar: Bar {
                z: 20,
                b: Baz {
                    x: "hey".to_owned(),
                }
                .into(),
            },
        };
        let packed = KeymappedStruct::from(value);
        ciborium::ser::into_writer(&packed, &mut bytes).unwrap();
        assert_eq!(
            hex::encode(&bytes).to_uppercase(),
            "A3188905188A0A188BA2617A146162A10963686579"
        );
    }
}
