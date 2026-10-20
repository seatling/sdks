use crate::lock::FileLock;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static TMP_FILE_SEQ: AtomicU64 = AtomicU64::new(0);

fn sanitize_path_component(input: &str) -> String {
    let sanitized: String = input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
        .collect();
    let trimmed = sanitized.trim_matches('.');
    if trimmed.is_empty() {
        "default".to_string()
    } else {
        trimmed.to_string()
    }
}

pub struct StorageManager {
    dir_path: PathBuf,
}

impl StorageManager {
    pub fn new(workspace_id: &str, product_id: &str, custom_dir: Option<&str>) -> Self {
        let dir_path = if let Some(custom) = custom_dir {
            PathBuf::from(custom)
        } else {
            let safe_ws = sanitize_path_component(workspace_id);
            let safe_prod = sanitize_path_component(product_id);
            Self::default_dir(&safe_ws, &safe_prod)
        };

        let _ = fs::create_dir_all(&dir_path);
        Self { dir_path }
    }

    pub fn get_dir(&self) -> &Path {
        &self.dir_path
    }

    pub fn acquire_lock(&self, timeout: Duration) -> std::io::Result<FileLock> {
        FileLock::acquire(&self.dir_path, timeout)
    }

    pub fn keystore_path(&self) -> PathBuf {
        self.dir_path.join("keystore.bin")
    }

    pub fn lease_path(&self) -> PathBuf {
        self.dir_path.join("lease.seatling")
    }

    pub fn ack_path(&self) -> PathBuf {
        self.dir_path.join("heartbeat.seatling")
    }

    pub fn read_keystore(&self) -> Option<String> {
        fs::read_to_string(self.keystore_path()).ok()
    }

    pub fn write_keystore(&self, content: &str) -> Result<(), std::io::Error> {
        self.atomic_write(&self.keystore_path(), content)
    }

    pub fn read_lease(&self) -> Option<String> {
        fs::read_to_string(self.lease_path()).ok()
    }

    pub fn write_lease(&self, content: &str) -> Result<(), std::io::Error> {
        self.atomic_write(&self.lease_path(), content)
    }

    pub fn delete_lease(&self) {
        let _ = fs::remove_file(self.lease_path());
        let _ = fs::remove_file(self.ack_path());
    }

    pub fn read_ack(&self) -> Option<String> {
        fs::read_to_string(self.ack_path()).ok()
    }

    pub fn write_ack(&self, content: &str) -> Result<(), std::io::Error> {
        self.atomic_write(&self.ack_path(), content)
    }

    fn atomic_write(&self, target: &Path, content: &str) -> Result<(), std::io::Error> {
        let _ = fs::create_dir_all(&self.dir_path);
        let seq = TMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp_name = format!(
            "{}.tmp.{}.{}",
            target.file_name().unwrap_or_default().to_string_lossy(),
            std::process::id(),
            seq
        );
        let tmp_path = self.dir_path.join(tmp_name);

        fs::write(&tmp_path, content)?;

        if fs::rename(&tmp_path, target).is_err() {
            // Fallback for Windows if target file is locked during atomic rename
            if let Err(e) = fs::copy(&tmp_path, target) {
                let _ = fs::remove_file(&tmp_path);
                return Err(e);
            }
            let _ = fs::remove_file(&tmp_path);
        }
        Ok(())
    }

    fn default_dir(workspace_id: &str, product_id: &str) -> PathBuf {
        #[cfg(target_os = "windows")]
        {
            if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
                PathBuf::from(local_app_data)
                    .join("Seatling")
                    .join(workspace_id)
                    .join(product_id)
            } else if let Ok(user_profile) = std::env::var("USERPROFILE") {
                PathBuf::from(user_profile)
                    .join("AppData")
                    .join("Local")
                    .join("Seatling")
                    .join(workspace_id)
                    .join(product_id)
            } else {
                PathBuf::from(".seatling")
                    .join(workspace_id)
                    .join(product_id)
            }
        }

        #[cfg(target_os = "macos")]
        {
            if let Ok(home) = std::env::var("HOME") {
                PathBuf::from(home)
                    .join("Library")
                    .join("Application Support")
                    .join("Seatling")
                    .join(workspace_id)
                    .join(product_id)
            } else {
                PathBuf::from(".seatling")
                    .join(workspace_id)
                    .join(product_id)
            }
        }

        #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
        {
            if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
                PathBuf::from(xdg)
                    .join("seatling")
                    .join(workspace_id)
                    .join(product_id)
            } else if let Ok(home) = std::env::var("HOME") {
                PathBuf::from(home)
                    .join(".local")
                    .join("share")
                    .join("seatling")
                    .join(workspace_id)
                    .join(product_id)
            } else {
                PathBuf::from(".seatling")
                    .join(workspace_id)
                    .join(product_id)
            }
        }
    }
}
