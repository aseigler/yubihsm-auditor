//! Human-readable names and categories for HSM command and response codes.

use yubihsm::{command, response};

/// Sentinel the device writes when a key slot is not applicable to an entry.
pub const NO_KEY: u16 = 0xffff;

/// Stable snake_case name for a command code, e.g. `sign_ecdsa`.
pub fn command_name(code: command::Code) -> String {
    to_snake_case(&format!("{code:?}"))
}

/// Coarse grouping used for reporting and dashboards.
pub fn command_category(code: command::Code) -> &'static str {
    use command::Code::*;
    match code {
        Echo => "diagnostic",
        CreateSession | AuthenticateSession | SessionMessage | CloseSession => "session",
        DeviceInfo | GetStorageInfo | Bsl | ResetDevice | Command9 | BlinkDevice => "device",
        PutOpaqueObject
        | GetOpaqueObject
        | PutAuthenticationKey
        | PutAsymmetricKey
        | GenerateAsymmetricKey
        | PutWrapKey
        | PutHmacKey
        | GenerateHmacKey
        | GenerateWrapKey
        | DeleteObject
        | ListObjects
        | GetObjectInfo
        | GetPublicKey
        | PutTemplate
        | GetTemplate
        | ChangeAuthenticationKey
        | PutOtpAead => "key_management",
        SignPkcs1
        | SignPss
        | SignEcdsa
        | SignEddsa
        | SignHmac
        | SignSshCertificate
        | SignAttestationCertificate => "sign",
        DecryptPkcs1 | DecryptOaep | DecryptOtp => "decrypt",
        DeriveEcdh => "derive",
        ExportWrapped | ImportWrapped | WrapData | UnwrapData => "wrap",
        VerifyHmac => "verify",
        CreateOtpAead | RandomizeOtpAead | RewrapOtpAead | GenerateOtpAead => "otp",
        GetLogEntries | SetLogIndex | SetOption | GetOption => "audit",
        GetPseudoRandom => "random",
        Error => "error",
        HsmInitialization => "boot",
        Unknown => "other",
    }
}

/// True when the entry represents a key being *used* (as opposed to managed).
pub fn is_key_usage(code: command::Code) -> bool {
    matches!(
        command_category(code),
        "sign" | "decrypt" | "derive" | "wrap" | "verify" | "otp"
    )
}

/// True for commands that create, modify, or destroy objects.
pub fn is_key_management(code: command::Code) -> bool {
    use command::Code::*;
    matches!(
        code,
        PutOpaqueObject
            | PutAuthenticationKey
            | PutAsymmetricKey
            | GenerateAsymmetricKey
            | PutWrapKey
            | PutHmacKey
            | GenerateHmacKey
            | GenerateWrapKey
            | DeleteObject
            | PutTemplate
            | ChangeAuthenticationKey
            | PutOtpAead
            | ImportWrapped
    )
}

/// Result of an audited operation, split into fields that are easy to filter on.
pub struct ResultInfo {
    /// `success` or `error`.
    pub status: &'static str,
    /// snake_case name, e.g. `success` or `device_insufficient_permissions`.
    pub name: String,
    /// Wire code as a signed value (successes are >= 0, errors negative).
    pub code: i16,
}

pub fn result_info(code: response::Code) -> ResultInfo {
    // The wire byte is the signed status code biased by 0x80: successes carry
    // the command code (0..=0x7f), errors are negative.
    let signed = code.to_u8() as i16 - 0x80;
    match code {
        response::Code::Success(_) => ResultInfo {
            status: "success",
            name: "success".to_owned(),
            code: signed,
        },
        other => ResultInfo {
            status: "error",
            name: to_snake_case(&format!("{other:?}")),
            code: signed,
        },
    }
}

/// `SignEcdsa` -> `sign_ecdsa`, `DecryptOaep` -> `decrypt_oaep`.
fn to_snake_case(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 4);
    for (i, ch) in name.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if i != 0 {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_snake_case() {
        assert_eq!(command_name(command::Code::SignEcdsa), "sign_ecdsa");
        assert_eq!(command_name(command::Code::Echo), "echo");
        assert_eq!(
            command_name(command::Code::HsmInitialization),
            "hsm_initialization"
        );
    }

    #[test]
    fn result_success_and_error() {
        let ok = result_info(response::Code::Success(command::Code::SignEcdsa));
        assert_eq!(ok.status, "success");
        assert_eq!(ok.name, "success");

        let err = result_info(response::Code::DeviceInsufficientPermissions);
        assert_eq!(err.status, "error");
        assert_eq!(err.name, "device_insufficient_permissions");
        assert!(err.code < 0);
    }

    #[test]
    fn key_usage_classification() {
        assert!(is_key_usage(command::Code::SignEcdsa));
        assert!(is_key_usage(command::Code::ExportWrapped));
        assert!(!is_key_usage(command::Code::GetLogEntries));
        assert!(is_key_management(command::Code::DeleteObject));
        assert!(!is_key_management(command::Code::SignEcdsa));
    }
}
