//! Trust-on-first-use host key verification for SSH/SFTP connections.
//!
//! The application stores its own known_hosts file under the same config
//! directory as sessions.json. First use learns a key; later connections must
//! present the same key for the same host:port.

use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use ssh_key::known_hosts::{Entry, HostPatterns, Marker};
use ssh_key::{HashAlg, PublicKey};
use thiserror::Error;

use crate::config::ConfigStore;

#[derive(Debug, Clone)]
pub struct HostKeyVerifier {
    host: String,
    port: u16,
}

impl HostKeyVerifier {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    pub fn check(&self, key: &PublicKey) -> Result<HostKeyStatus, HostKeyError> {
        verify_or_learn_at(&known_hosts_path()?, &self.host, self.port, key)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyStatus {
    Trusted,
    Learned,
}

#[derive(Debug, Error)]
pub enum HostKeyError {
    #[error("host key changed for {host_pattern}; line {line}; expected {expected}; got {actual}")]
    KeyChanged {
        host_pattern: String,
        line: usize,
        expected: String,
        actual: String,
    },
    #[error("host key for {host_pattern} is revoked at line {line}")]
    Revoked { host_pattern: String, line: usize },
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    SshKey(#[from] ssh_key::Error),
}

impl HostKeyError {
    pub fn into_russh_error(self) -> russh::Error {
        match self {
            HostKeyError::KeyChanged { line, .. } | HostKeyError::Revoked { line, .. } => {
                russh::Error::KeyChanged { line }
            }
            HostKeyError::Io(err) => russh::Error::IO(err),
            HostKeyError::SshKey(err) => russh::Error::SshKey(err),
        }
    }
}

fn known_hosts_path() -> Result<PathBuf, io::Error> {
    ConfigStore::config_dir()
        .map(|dir| dir.join("known_hosts"))
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
}

fn verify_or_learn_at(
    path: &Path,
    host: &str,
    port: u16,
    key: &PublicKey,
) -> Result<HostKeyStatus, HostKeyError> {
    let host_pattern = host_pattern(host, port);
    let actual = fingerprint(key);
    let raw = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(err) if err.kind() == io::ErrorKind::NotFound => String::new(),
        Err(err) => return Err(err.into()),
    };

    for (idx, line) in raw.lines().enumerate() {
        let trimmed = strip_comment(line).trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry = match trimmed.parse::<Entry>() {
            Ok(entry) => entry,
            Err(err) => {
                tracing::warn!(
                    "ignoring invalid known_hosts line {} in {}: {err}",
                    idx + 1,
                    path.display()
                );
                continue;
            }
        };
        if !matches_host(entry.host_patterns(), &host_pattern) {
            continue;
        }
        if matches!(entry.marker(), Some(Marker::Revoked)) {
            return Err(HostKeyError::Revoked {
                host_pattern,
                line: idx + 1,
            });
        }
        if entry.public_key() == key {
            return Ok(HostKeyStatus::Trusted);
        }
        return Err(HostKeyError::KeyChanged {
            host_pattern,
            line: idx + 1,
            expected: fingerprint(entry.public_key()),
            actual,
        });
    }

    append_known_host(path, &raw, &host_pattern, key)?;
    Ok(HostKeyStatus::Learned)
}

fn append_known_host(
    path: &Path,
    existing: &str,
    host_pattern: &str,
    key: &PublicKey,
) -> Result<(), HostKeyError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let existed = path.exists();
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    if !existed {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
    } else if !existing.is_empty() && !existing.ends_with('\n') {
        writeln!(file)?;
    }
    writeln!(file, "{} {}", host_pattern, key.to_openssh()?)?;
    Ok(())
}

fn host_pattern(host: &str, port: u16) -> String {
    format!("[{}]:{}", host.trim(), port)
}

fn strip_comment(line: &str) -> &str {
    line.split_once('#').map(|(left, _)| left).unwrap_or(line)
}

fn matches_host(patterns: &HostPatterns, host_pattern: &str) -> bool {
    match patterns {
        HostPatterns::Patterns(patterns) => patterns.iter().any(|p| p == host_pattern),
        HostPatterns::HashedName { .. } => false,
    }
}

fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key(comment: &str) -> PublicKey {
        let raw = format!(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB9dG4kjRhQTtWTVzd2t27+t0DEHBPW7iOD23TUiYLio {comment}"
        );
        raw.parse().unwrap()
    }

    fn other_key() -> PublicKey {
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti other"
            .parse()
            .unwrap()
    }

    fn temp_known_hosts() -> PathBuf {
        std::env::temp_dir().join(format!("meatshell-known-hosts-{}", uuid::Uuid::new_v4()))
    }

    #[test]
    fn learns_then_trusts_same_key() {
        let path = temp_known_hosts();
        let key = sample_key("server");

        assert_eq!(
            verify_or_learn_at(&path, "example.com", 22, &key).unwrap(),
            HostKeyStatus::Learned
        );
        assert_eq!(
            verify_or_learn_at(&path, "example.com", 22, &key).unwrap(),
            HostKeyStatus::Trusted
        );
    }

    #[test]
    fn rejects_changed_key() {
        let path = temp_known_hosts();
        let key = sample_key("server");
        verify_or_learn_at(&path, "example.com", 22, &key).unwrap();

        let err = verify_or_learn_at(&path, "example.com", 22, &other_key()).unwrap_err();
        assert!(matches!(err, HostKeyError::KeyChanged { line: 1, .. }));
    }
}
