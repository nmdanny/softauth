use std::{marker::PhantomData, collections::HashMap};
use std::hash::Hash;
use once_cell::sync::Lazy;
use serde::Serialize;



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

impl<T: Clone, U> Clone for KeymappedStruct<T, U> {
    fn clone(&self) -> Self {
        Self(self.0.clone(), PhantomData)
    }
}

impl<T, U> From<T> for KeymappedStruct<T, U> {
    fn from(t: T) -> Self {
        KeymappedStruct(t, PhantomData)
    }
}

/// A helper trait for implementing [Keymappable] by defining a vector of (field_identifier, new_key)
/// tuples.
pub trait VecKeymappable<U>
where
    U: Serialize + Eq + Hash + Clone,
{
    fn field_mappings() -> Vec<(&'static str, U)>;
    fn field_map() -> Lazy<HashMap<&'static str, U>> {
        Lazy::new(|| HashMap::from_iter(Self::field_mappings()))
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

impl<U: Serialize + Eq + Hash + Clone, T: VecKeymappable<U>> Keymappable<U> for T {
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
    fn test_keymapped() {
        #[derive(Serialize, Deserialize)]
        struct Foo {
            x: u8,
            y: u8,
            bar: Bar,
        }
        #[derive(Serialize, Deserialize)]
        struct Bar {
            z: u8,
            b: KeymappedStruct<Baz, u8>,
        }
        #[derive(Serialize, Deserialize)]
        struct Baz {
            x: String,
        }

        impl VecKeymappable<u8> for Foo {
            fn field_mappings() -> Vec<(&'static str, u8)> {
                vec![("x", 137), ("y", 138), ("bar", 139)]
            }
        }

        impl VecKeymappable<u8> for Baz {
            fn field_mappings() -> Vec<(&'static str, u8)> {
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

        let res: KeymappedStruct<Foo, _> = ciborium::de::from_reader(&*bytes).unwrap();
        let res = res.0;
        assert_eq!(res.x, 5);
        assert_eq!(res.y, 10);
        assert_eq!(res.bar.z, 20);
        assert_eq!(res.bar.b.0.x, "hey".to_owned());
    }
}