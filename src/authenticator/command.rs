use num_enum::{IntoPrimitive, TryFromPrimitive};
use thiserror::Error;

/// A CTAP command byte
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
pub enum CTAPCommand {
    MakeCredential = 0x01,
    GetAssertion = 0x02,
    GetNextAssertion = 0x08,
    GetInfo = 0x04,
    GetClientPin = 0x06,
    Reset = 0x07,
    BioEnrollment = 0x09,
    Selection = 0x0B,
    LargeBlobs = 0x0C,
    Config = 0x0D,
}

/// Status codes sent as part of a CTAP response
/// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#error-responses
#[repr(u8)]
#[derive(Error, Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
pub enum StatusCode {
    #[error("Indicates successful response.")]
    Ctap1ErrSuccess = 0x00,

    #[error("The command is not a valid CTAP command.")]
    Ctap1ErrInvalidCommand = 0x01,

    #[error("The command included an invalid parameter.")]
    Ctap1ErrInvalidParameter = 0x02,

    #[error("Invalid message or item length.")]
    Ctap1ErrInvalidLength = 0x03,

    #[error("Invalid message sequencing.")]
    Ctap1ErrInvalidSeq = 0x04,

    #[error("Message timed out.")]
    Ctap1ErrTimeout = 0x05,

    #[error("Channel busy. Client SHOULD retry the request after a short delay. Note that the client MAY abort the transaction if the command is no longer relevant.")]
    Ctap1ErrChannelBusy = 0x06,

    #[error("Command requires channel lock.")]
    Ctap1ErrLockRequired = 0x0A,

    #[error("Command not allowed on this cid.")]
    Ctap1ErrInvalidChannel = 0x0B,

    #[error("Invalid/unexpected CBOR error.")]
    Ctap2ErrCborUnexpectedType = 0x11,

    #[error("Error when parsing CBOR.")]
    Ctap2ErrInvalidCbor = 0x12,

    #[error("Missing non-optional parameter.")]
    Ctap2ErrMissingParameter = 0x14,

    #[error("Limit for number of items exceeded.")]
    Ctap2ErrLimitExceeded = 0x15,

    #[error("Fingerprint data base is full, e.g., during enrollment.")]
    Ctap2ErrFpDatabaseFull = 0x17,

    #[error("Large blob storage is full. (See § 6.10.3 Large, per-credential blobs.)")]
    Ctap2ErrLargeBlobStorageFull = 0x18,

    #[error("Valid credential found in the exclude list.")]
    Ctap2ErrCredentialExcluded = 0x19,

    #[error("Processing (Lengthy operation is in progress).")]
    Ctap2ErrProcessing = 0x21,

    #[error("Credential not valid for the authenticator.")]
    Ctap2ErrInvalidCredential = 0x22,

    #[error("Authentication is waiting for user interaction.")]
    Ctap2ErrUserActionPending = 0x23,

    #[error("Processing, lengthy operation is in progress.")]
    Ctap2ErrOperationPending = 0x24,

    #[error("No request is pending.")]
    Ctap2ErrNoOperations = 0x25,

    #[error("Authenticator does not support requested algorithm.")]
    Ctap2ErrUnsupportedAlgorithm = 0x26,

    #[error("Not authorized for requested operation.")]
    Ctap2ErrOperationDenied = 0x27,

    #[error("Internal key storage is full.")]
    Ctap2ErrKeyStoreFull = 0x28,

    #[error("Unsupported option.")]
    Ctap2ErrUnsupportedOption = 0x2B,

    #[error("Not a valid option for current operation.")]
    Ctap2ErrInvalidOption = 0x2C,

    #[error("Pending keep alive was cancelled.")]
    Ctap2ErrKeepaliveCancel = 0x2D,

    #[error("No valid credentials provided.")]
    Ctap2ErrNoCredentials = 0x2E,

    #[error("A user action timeout occurred.")]
    Ctap2ErrUserActionTimeout = 0x2F,

    #[error("Continuation command, such as, authenticatorGetNextAssertion not allowed.")]
    Ctap2ErrNotAllowed = 0x30,

    #[error("PIN Invalid.")]
    Ctap2ErrPinInvalid = 0x31,

    #[error("PIN Blocked.")]
    Ctap2ErrPinBlocked = 0x32,

    #[error("PIN authentication,pinUvAuthParam, verification failed.")]
    Ctap2ErrPinAuthInvalid = 0x33,

    #[error("PIN authentication using pinUvAuthToken blocked. Requires power cycle to reset.")]
    Ctap2ErrPinAuthBlocked = 0x34,

    #[error("No PIN has been set.")]
    Ctap2ErrPinNotSet = 0x35,

    #[error("A pinUvAuthToken is required for the selected operation. See also the pinUvAuthToken option ID.")]
    Ctap2ErrPuatRequired = 0x36,

    #[error("PIN policy violation. Currently only enforces minimum length.")]
    Ctap2ErrPinPolicyViolation = 0x37,

    #[error("for Future Use 	Reserved for Future Use")]
    Reserved = 0x38,

    #[error("Authenticator cannot handle this request due to memory constraints.")]
    Ctap2ErrRequestTooLarge = 0x39,

    #[error("The current operation has timed out.")]
    Ctap2ErrActionTimeout = 0x3A,

    #[error("User presence is required for the requested operation.")]
    Ctap2ErrUpRequired = 0x3B,

    #[error("built-in user verification is disabled.")]
    Ctap2ErrUvBlocked = 0x3C,

    #[error("A checksum did not match.")]
    Ctap2ErrIntegrityFailure = 0x3D,

    #[error("The requested subcommand is either invalid or not implemented.")]
    Ctap2ErrInvalidSubcommand = 0x3E,

    #[error("built-in user verification unsuccessful. The platform SHOULD retry.")]
    Ctap2ErrUvInvalid = 0x3F,

    #[error("The permissions parameter contains an unauthorized permission.")]
    Ctap2ErrUnauthorizedPermission = 0x40,

    #[error("Other unspecified error.")]
    Ctap1ErrOther = 0x7F,

    #[error("CTAP 2 spec last error.")]
    Ctap2ErrSpecLast = 0xDF,

    #[error("Extension specific error.")]
    Ctap2ErrExtensionFirst = 0xE0,

    #[error("Extension specific error.")]
    Ctap2ErrExtensionLast = 0xEF,

    #[error("Vendor specific error.")]
    Ctap2ErrVendorFirst = 0xF0,

    #[error("Vendor specific error.")]
    Ctap2ErrVendorLast = 0xFF,
}
