use crate::lock::FileLock;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static TMP_FILE_SEQ: AtomicU64 = AtomicU64::new(0);
const MAX_STORAGE_FILE_BYTES: usize = 64 * 1024;

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

fn ensure_secure_dir(path: &Path) -> std::io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

fn read_bounded_string(path: &Path, max_bytes: usize) -> Option<String> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() || meta.len() > max_bytes as u64 {
        return None;
    }
    let file = fs::File::open(path).ok()?;
    let mut buf = Vec::with_capacity((meta.len() as usize).min(max_bytes));
    file.take((max_bytes as u64) + 1)
        .read_to_end(&mut buf)
        .ok()?;
    if buf.len() > max_bytes {
        return None;
    }
    String::from_utf8(buf).ok()
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

        let _ = ensure_secure_dir(&dir_path);
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

    pub fn secret_anchor_path(&self) -> PathBuf {
        self.dir_path.join(".keystore.secret")
    }

    pub fn lease_path(&self) -> PathBuf {
        self.dir_path.join("lease.seatling")
    }

    pub fn ack_path(&self) -> PathBuf {
        self.dir_path.join("heartbeat.seatling")
    }

    pub fn read_keystore(&self) -> Option<String> {
        read_bounded_string(&self.keystore_path(), MAX_STORAGE_FILE_BYTES)
    }

    pub fn write_keystore(&self, content: &str) -> Result<(), std::io::Error> {
        self.atomic_write(&self.keystore_path(), content.as_bytes())
    }

    pub fn read_secret_anchor(&self) -> Option<[u8; 32]> {
        let path = self.secret_anchor_path();
        let meta = fs::symlink_metadata(&path).ok()?;
        if !meta.file_type().is_file() || meta.len() != 32 {
            return None;
        }
        let mut file = fs::File::open(&path).ok()?;
        let mut out = [0u8; 32];
        file.read_exact(&mut out).ok()?;
        Some(out)
    }

    pub fn write_secret_anchor(&self, secret: &[u8; 32]) -> Result<(), std::io::Error> {
        self.atomic_write(&self.secret_anchor_path(), secret)
    }

    pub fn read_lease(&self) -> Option<String> {
        read_bounded_string(&self.lease_path(), MAX_STORAGE_FILE_BYTES)
    }

    pub fn write_lease(&self, content: &str) -> Result<(), std::io::Error> {
        self.atomic_write(&self.lease_path(), content.as_bytes())
    }

    pub fn delete_lease(&self) {
        let _ = fs::remove_file(self.lease_path());
        let _ = fs::remove_file(self.ack_path());
    }

    pub fn delete_ack(&self) {
        let _ = fs::remove_file(self.ack_path());
    }

    pub fn read_ack(&self) -> Option<String> {
        read_bounded_string(&self.ack_path(), MAX_STORAGE_FILE_BYTES)
    }

    pub fn write_ack(&self, content: &str) -> Result<(), std::io::Error> {
        self.atomic_write(&self.ack_path(), content.as_bytes())
    }

    fn atomic_write(&self, target: &Path, content: &[u8]) -> Result<(), std::io::Error> {
        let _ = ensure_secure_dir(&self.dir_path);
        let seq = TMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut rnd = [0u8; 8];
        rand::fill(&mut rnd);
        let tmp_name = format!(
            "{}.tmp.{}.{}.{}",
            target.file_name().unwrap_or_default().to_string_lossy(),
            std::process::id(),
            seq,
            hex::encode(rnd)
        );
        let tmp_path = self.dir_path.join(tmp_name);

        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }

        {
            let mut file = opts.open(&tmp_path)?;
            if let Err(e) = file.write_all(content).and_then(|_| file.sync_all()) {
                let _ = fs::remove_file(&tmp_path);
                return Err(e);
            }
        }

        if fs::rename(&tmp_path, target).is_err() {
            // Fallback for Windows if target file is locked during atomic rename
            if let Ok(meta) = fs::symlink_metadata(target) {
                if !meta.file_type().is_file() {
                    let _ = fs::remove_file(&tmp_path);
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Refusing to overwrite non-regular file",
                    ));
                }
            }
            if let Err(e) = fs::copy(&tmp_path, target) {
                let _ = fs::remove_file(&tmp_path);
                return Err(e);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(target, fs::Permissions::from_mode(0o600));
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
