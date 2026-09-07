//! Per-device cursor state, persisted so restarts neither duplicate nor skip
//! entries and so the hash chain can be checked across polls.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct DeviceState {
    /// Device serial, recorded the first time we see it.
    pub serial: Option<String>,

    /// `item` of the last entry we emitted.
    pub last_item: Option<u16>,

    /// Hex digest of the last entry we emitted (hash chain anchor).
    pub last_digest: Option<String>,

    /// Tick of the last entry we emitted, used to detect device reboots.
    pub last_tick: Option<u32>,

    /// Monotonic count of entries emitted for this device. Gives a total
    /// ordering that survives `item` wrapping at 65535.
    pub sequence: u64,

    /// Incremented whenever a reboot is detected (tick regression).
    pub boot_session: u64,

    /// `log_store_used` as observed *after* the last poll acknowledged entries.
    ///
    /// The baseline for the fast path: entries are only freed by `set-log-index`
    /// or a reset, so between polls this figure only rises. Any change at all
    /// means connect. Recorded post-ack because the poll's own
    /// `get-log-entries`/`set-log-index` entries land after the read.
    pub last_log_store_used: Option<u8>,

    /// Consecutive polls that took the fast path, to bound the blind window.
    pub polls_skipped: u32,

    /// RFC 3339 timestamp of the last successful poll.
    pub updated_at: Option<String>,
}

impl DeviceState {
    pub fn path(state_dir: &Path, device_name: &str) -> PathBuf {
        state_dir.join(format!("{}.json", sanitize(device_name)))
    }

    pub fn load(state_dir: &Path, device_name: &str) -> Result<Self> {
        let path = Self::path(state_dir, device_name);
        match fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text)
                .with_context(|| format!("parsing state file {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading state file {}", path.display())),
        }
    }

    /// Write atomically: full write + fsync to a temp file, then rename.
    pub fn save(&self, state_dir: &Path, device_name: &str) -> Result<()> {
        fs::create_dir_all(state_dir)
            .with_context(|| format!("creating state dir {}", state_dir.display()))?;
        let path = Self::path(state_dir, device_name);
        let tmp = path.with_extension("json.tmp");

        let json = serde_json::to_vec_pretty(self)?;
        {
            let mut file =
                fs::File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
            file.write_all(&json)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
        }
        // Windows rename fails if the destination exists.
        if path.exists() {
            fs::remove_file(&path).ok();
        }
        fs::rename(&tmp, &path)
            .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
        Ok(())
    }
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_names() {
        assert_eq!(sanitize("hsm/../etc:1"), "hsm_.._etc_1");
    }

    #[test]
    fn round_trips() {
        let dir = std::env::temp_dir().join(format!("yubihsm-auditor-test-{}", std::process::id()));
        let state = DeviceState {
            serial: Some("0000001234".into()),
            last_item: Some(42),
            last_digest: Some("00112233445566778899aabbccddeeff".into()),
            last_tick: Some(99),
            sequence: 7,
            boot_session: 1,
            last_log_store_used: Some(3),
            polls_skipped: 2,
            updated_at: Some("2026-01-01T00:00:00Z".into()),
        };
        state.save(&dir, "dev 1").unwrap();
        let loaded = DeviceState::load(&dir, "dev 1").unwrap();
        assert_eq!(loaded.last_item, Some(42));
        assert_eq!(loaded.sequence, 7);
        assert_eq!(loaded.last_log_store_used, Some(3));
        assert_eq!(loaded.polls_skipped, 2);
        // Saving twice must succeed (rename over existing file).
        state.save(&dir, "dev 1").unwrap();
        fs::remove_dir_all(&dir).ok();
    }
}
