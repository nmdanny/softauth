use serde::{Serialize, Deserialize};


/// Identifies a cryptographic algorithm.
/// 
/// [See more](https://w3c.github.io/webauthn/#typedefdef-cosealgorithmidentifier)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct COSEAlgorithmIdentifier(i32);



/// A COSE key object
/// [See more in WebAuthn spec](https://www.w3.org/TR/webauthn/#sctn-attested-credential-data)
/// [See more in COSE spec](https://datatracker.ietf.org/doc/html/rfc8152#section-7)
#[derive(Debug, Serialize, Deserialize)]
pub struct CoseKey {
    //  The COSE_Key-encoded credential public key MUST contain the "alg" parameter and MUST NOT contain any other OPTIONAL parameters
    alg: COSEAlgorithmIdentifier,
    
}
