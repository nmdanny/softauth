use std::collections::HashSet;

use ciborium::value::Value;
use coset::{
    iana::{self, EnumI64},
    Algorithm, CoseKey, CoseKeyBuilder, KeyType, Label,
};
use once_cell::sync::Lazy;
use ring::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{COSEAlgorithmIdentifier, CryptoKeyPair, CryptoSystem};

#[derive(Debug, Serialize, Deserialize)]
pub enum RingKeyPair {
    P256(RingP256KeyPair),
    Ed25519(RingEd25519KeyPair),
}

impl CryptoKeyPair for RingKeyPair {
    fn to_public_cose_key(&self) -> CoseKey {
        match self {
            RingKeyPair::P256(p256) => p256.to_public_cose_key(),
            RingKeyPair::Ed25519(ed25519) => ed25519.to_public_cose_key(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RingP256KeyPair {
    private: Vec<u8>,
}

impl CryptoKeyPair for RingP256KeyPair {
    fn to_public_cose_key(&self) -> CoseKey {
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, self.private.as_ref())
            .unwrap();
        // according to ring docs, the public key
        // is represented via "Octet-String-to-Elliptic-Curve-Point Conversion"
        // in an uncompressed form, as specified in https://www.secg.org/sec1-v2.pdf
        // Which is: 0x04 || x || y
        let octet_string = key.public_key().as_ref();
        assert_eq!(octet_string.len(), 1 + 32 + 32);
        assert_eq!(
            octet_string[0], 0x04,
            "Public key must be in uncompressed form"
        );
        let (x, y) = octet_string[1..].split_at(32);
        CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x.to_owned(), y.to_owned())
            .algorithm(iana::Algorithm::ES256)
            .build()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RingEd25519KeyPair {
    private: Vec<u8>,
}

impl CryptoKeyPair for RingEd25519KeyPair {
    fn to_public_cose_key(&self) -> CoseKey {
        let key = Ed25519KeyPair::from_pkcs8(self.private.as_ref()).unwrap();
        let x = key.public_key().as_ref();
        assert_eq!(x.len(), 32);
        CoseKey {
            kty: KeyType::Assigned(iana::KeyType::OKP),
            alg: Some(Algorithm::Assigned(iana::Algorithm::EdDSA)),
            params: vec![
                (
                    Label::Int(iana::Ec2KeyParameter::Crv as i64),
                    Value::from(iana::EllipticCurve::Ed25519 as u64),
                ),
                (
                    Label::Int(iana::Ec2KeyParameter::X as i64),
                    Value::Bytes(x.to_owned()),
                ),
            ],
            ..Default::default()
        }
    }
}

struct RingCryptoSystem;

#[derive(Debug, Error)]
pub enum RingError {
    #[error("COSE Identifier {0} is unsupported")]
    UnsupportedAlgorithm(i32),

    #[error("Unspecified ring error")]
    RingUnspecified(ring::error::Unspecified),
}

const RING_SIGN_ALGS: &[iana::Algorithm] = &[
    iana::Algorithm::ES256, // NIST P-256 scheme
    iana::Algorithm::EdDSA, // Ed25519 scheme
];

static COSET_ALGO_IDENTIFIERS: Lazy<HashSet<COSEAlgorithmIdentifier>> = Lazy::new(|| {
    RING_SIGN_ALGS
        .iter()
        .map(|alg| COSEAlgorithmIdentifier(alg.to_i64().try_into().unwrap()))
        .collect()
});

impl CryptoSystem for RingCryptoSystem {
    type Error = RingError;
    type KeyPair = RingKeyPair;

    fn supported_algs(&self) -> Result<&HashSet<COSEAlgorithmIdentifier>, Self::Error> {
        Ok(&COSET_ALGO_IDENTIFIERS)
    }

    fn generate_credential_keypair(
        &self,
        alg: COSEAlgorithmIdentifier,
    ) -> Result<Self::KeyPair, Self::Error> {
        //  The COSE_Key-encoded credential public key MUST contain the "alg" parameter and MUST NOT contain any other OPTIONAL parameters
        if !self.supported_algs()?.contains(&alg) {
            return Err(RingError::UnsupportedAlgorithm(alg.0));
        }
        let alg = iana::Algorithm::from_i64(alg.0 as i64).unwrap();
        let rng = SystemRandom::new();

        match alg {
            iana::Algorithm::ES256 => {
                let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
                    .map_err(RingError::RingUnspecified)?;
                return Ok(RingKeyPair::P256(RingP256KeyPair {
                    private: doc.as_ref().to_owned(),
                }));
            }
            iana::Algorithm::EdDSA => {
                let doc =
                    Ed25519KeyPair::generate_pkcs8(&rng).map_err(RingError::RingUnspecified)?;
                return Ok(RingKeyPair::Ed25519(RingEd25519KeyPair {
                    private: doc.as_ref().to_owned(),
                }));
            }
            _ => unreachable!(),
        }
    }

    fn sign_data(&self, keypair: &Self::KeyPair, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        match keypair {
            RingKeyPair::P256(p256) => {
                let key = EcdsaKeyPair::from_pkcs8(
                    &ECDSA_P256_SHA256_ASN1_SIGNING,
                    p256.private.as_ref(),
                )
                .unwrap();
                let rng = SystemRandom::new();
                let signature = key.sign(&rng, data).map_err(RingError::RingUnspecified)?;
                Ok(signature.as_ref().to_owned())
            }
            RingKeyPair::Ed25519(ed25519) => {
                let key = Ed25519KeyPair::from_pkcs8(ed25519.private.as_ref()).unwrap();
                let signature = key.sign(data);
                Ok(signature.as_ref().to_owned())
            }
        }
    }
}
