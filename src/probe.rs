//! Unauthenticated `GetDeviceInfo` straight over the connector.
//!
//! `Client` funnels every command through `send_command`, which opens with
//! `self.session()?`, so any `Client` call is a session command and therefore an
//! audited one. `GetDeviceInfo` needs no session: the device answers it in the
//! clear and records nothing. Asking the connector directly keeps the device's
//! 62-entry log buffer for real traffic, and — because `log_store_used` comes
//! back with it — lets a poll decide whether opening a session is worth it at
//! all.
//!
//! The cost is that nothing here is authenticated. A session response is R-MAC'd
//! under the SCP03 session keys, so it is provably from the device holding the
//! auth key and provably fresh; this one is plaintext HTTP that anything on the
//! path can forge or replay. Callers must treat these values as a hint, never as
//! evidence — see `Config::force_full_poll_every`.
//!
//! `Connector::send_message` is public but takes `connector::Message`, which the
//! crate exports only as `pub(crate)`. The type is therefore unnameable here and
//! we have to reach it through the public `From<Vec<u8>>`/`Into<Vec<u8>>` impls
//! and type inference. That works, but it is plainly not a path the crate meant
//! to offer; see README ("Self-generated log entries").

use crate::config::Device;
use anyhow::{Context, Result, bail};
use std::sync::atomic::{AtomicU64, Ordering};
use yubihsm::{Uuid, connector::Connector};

/// `GetDeviceInfo` command code.
const CMD_DEVICE_INFO: u8 = 0x06;
/// Response codes are the command code with the high bit set.
const RSP_DEVICE_INFO: u8 = CMD_DEVICE_INFO | 0x80;
/// The device's generic error response.
const RSP_ERROR: u8 = 0x7f | 0x80;
/// major(1) minor(1) build(1) serial(4) log_capacity(1) log_used(1).
const MIN_BODY_LEN: usize = 9;

/// The subset of `device::Info` this tool needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceInfo {
    pub major_version: u8,
    pub minor_version: u8,
    pub build_version: u8,
    pub serial_number: u32,
    pub log_store_capacity: u8,
    pub log_store_used: u8,
}

impl DeviceInfo {
    /// Zero-padded to 10 digits, matching `device::serial::Number`'s `Display`
    /// so events read the same whichever source produced them.
    pub fn serial(&self) -> String {
        format!("{:010}", self.serial_number)
    }

    pub fn version(&self) -> String {
        format!(
            "{}.{}.{}",
            self.major_version, self.minor_version, self.build_version
        )
    }
}

/// Ask the connector for device info without opening a session.
pub fn fetch(device: &Device) -> Result<DeviceInfo> {
    let connector = Connector::http(&device.http_config());
    fetch_with(&connector, &device.name)
}

/// As [`fetch`], but reusing an existing connector.
pub fn fetch_with(connector: &Connector, device_name: &str) -> Result<DeviceInfo> {
    let request = vec![CMD_DEVICE_INFO, 0x00, 0x00];
    let response: Vec<u8> = connector
        // `.into()`/`.from()` on the unnameable `connector::Message`.
        .send_message(next_uuid(), request.into())
        .with_context(|| format!("{device_name}: unauthenticated get device info"))?
        .into();
    parse(&response).with_context(|| format!("{device_name}: parsing device info response"))
}

/// UUIDs only tag requests in the connector's own logs, so a counter is enough
/// and saves a dependency on a random source.
fn next_uuid() -> Uuid {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    Uuid::from_u128(COUNTER.fetch_add(1, Ordering::Relaxed) as u128)
}

/// Decode a `GetDeviceInfo` response frame: code(1) length(2) body.
fn parse(frame: &[u8]) -> Result<DeviceInfo> {
    if frame.len() < 3 {
        bail!("response too short: {} bytes", frame.len());
    }
    let length = u16::from_be_bytes([frame[1], frame[2]]) as usize;
    let body = frame
        .get(3..3 + length)
        .with_context(|| format!("truncated response: header says {length} bytes"))?;

    match frame[0] {
        RSP_DEVICE_INFO => {}
        RSP_ERROR => {
            let kind = body
                .first()
                .map(|tag| format!("{:?}", yubihsm::device::ErrorKind::from_u8(*tag)))
                .unwrap_or_else(|| "no error code".to_owned());
            bail!("device returned an error: {kind}");
        }
        other => bail!("unexpected response code 0x{other:02x}"),
    }

    if body.len() < MIN_BODY_LEN {
        bail!(
            "device info body too short: {} bytes (need {})",
            body.len(),
            MIN_BODY_LEN
        );
    }

    Ok(DeviceInfo {
        major_version: body[0],
        minor_version: body[1],
        build_version: body[2],
        serial_number: u32::from_be_bytes([body[3], body[4], body[5], body[6]]),
        log_store_capacity: body[7],
        log_store_used: body[8],
        // The remainder is the supported-algorithm list, which this tool has no
        // use for.
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(code: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![code];
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn parses_a_device_info_response() {
        // 2.4.0, serial 0000001234, 62-entry log with 5 used, then algorithms.
        let mut body = vec![2, 4, 0];
        body.extend_from_slice(&1234u32.to_be_bytes());
        body.extend_from_slice(&[62, 5]);
        body.extend_from_slice(&[0x01, 0x02, 0x03]);

        let info = parse(&frame(RSP_DEVICE_INFO, &body)).unwrap();
        assert_eq!(info.serial_number, 1234);
        assert_eq!(info.serial(), "0000001234");
        assert_eq!(info.version(), "2.4.0");
        assert_eq!(info.log_store_capacity, 62);
        assert_eq!(info.log_store_used, 5);
    }

    #[test]
    fn rejects_malformed_frames() {
        assert!(parse(&[]).is_err());
        assert!(
            parse(&frame(RSP_DEVICE_INFO, &[2, 4, 0])).is_err(),
            "short body"
        );
        assert!(parse(&frame(0x99, &[0; 9])).is_err(), "wrong code");
        // Header claims more than the frame carries.
        assert!(parse(&[RSP_DEVICE_INFO, 0x00, 0x20, 0x01]).is_err());
    }

    #[test]
    fn reports_a_device_error() {
        let error = parse(&frame(RSP_ERROR, &[0x06])).unwrap_err().to_string();
        assert!(error.contains("device returned an error"), "{error}");
    }

    #[test]
    fn uuids_do_not_repeat() {
        assert_ne!(next_uuid(), next_uuid());
    }
}
