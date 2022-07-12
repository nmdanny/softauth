use std::cmp::Ordering;

use ciborium::value::Value;

fn cmp_values(val1: &Value, val2: &Value) -> Ordering {
    if let (Some(t1), Some(t2)) = (val1.as_text(), val2.as_text()) {
        return t1.len().cmp(&t2.len()).then_with(|| t1.cmp(t2));
    }
    if let (Some(t1), Some(t2)) = (val1.as_integer(), val2.as_integer()) {
        return t1.cmp(&t2);
    }
    // TODO: more robust comparison for serialization
    panic!(
        "Encountered map with non integer/text keys or non equal key types: {:?}, {:?}",
        val1, val2
    );
}

/// Given a CBOR value, modifies it such that any map within it is ordered according to
/// the CTAP2 canonical CBOR encoding scheme.
pub fn make_ordered(value: &mut Value) {
    match value {
        Value::Tag(_t, v) => make_ordered(v),
        Value::Array(vals) => {
            for v in vals {
                make_ordered(v);
            }
        }
        Value::Map(m) => {
            for (k, v) in m.iter_mut() {
                make_ordered(k);
                make_ordered(v);
            }
            m.sort_by(|(k1, _v1), (k2, _v2)| cmp_values(k1, k2))
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::cbor;
    #[test]
    fn test_make_ordered_int() {
        let mut inp = cbor!({
            5 => 5,
            3 => 3,
            4 => { 9 => 9, 8 => 8}
        })
        .unwrap();
        let expected = cbor!({
            3 => 3,
            4 => { 8 => 8, 9 => 9},
            5 => 5
        })
        .unwrap();

        make_ordered(&mut inp);
        assert_eq!(inp, expected);
    }

    #[test]
    fn test_make_ordered_text() {
        let mut inp = cbor!({
            "z" => 5,
            "zb" => 3,
            "azz" => { "bbb" => 9, "b" => 8, "ab" => 7}
        })
        .unwrap();
        let expected = cbor!({
            "z" => 5,
            "zb" => 3,
            "azz" => { "b" => 8, "ab" => 7, "bbb" => 9},
        })
        .unwrap();

        make_ordered(&mut inp);
        assert_eq!(inp, expected);
    }
}
