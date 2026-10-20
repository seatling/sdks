pub mod linux;
pub mod macos;
pub mod windows;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealingAnchors {
    pub hardware: Vec<(&'static str, String)>,
    pub user_scope: Option<String>,
}

impl SealingAnchors {
    pub fn is_hardware_rooted(&self) -> bool {
        !self.hardware.is_empty()
    }
}

#[derive(Clone, Debug)]
pub struct PlatformIdentifiers {
    pub cpu: Option<String>,
    pub mobo: Option<String>,
    pub disk: Option<String>,
    pub os_uuid: Option<String>,
    pub anchors: SealingAnchors,
}

pub fn normalize(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let upper = trimmed.to_ascii_uppercase();
    let lower = trimmed.to_ascii_lowercase();

    // Known placeholder or dummy OEM values
    const REJECTS: &[&str] = &[
        "NONE",
        "0",
        "DEFAULT STRING",
        "TO BE FILLED BY O.E.M.",
        "TO BE FILLED BY OEM",
        "SYSTEM SERIAL NUMBER",
        "NOT SPECIFIED",
        "NOT APPLICABLE",
        "UNKNOWN",
        "BASEBOARD SERIAL NUMBER",
        "CHASSIS SERIAL NUMBER",
        "03000200-0400-0500-0006-000700080009",
    ];

    for &rej in REJECTS {
        if upper == rej {
            return None;
        }
    }

    // Check for all-zeros, all-Fs, or repeated single char
    let hex_only = lower.replace('-', "");
    if !hex_only.is_empty() && hex_only.chars().all(|c| c == '0' || c == 'f') {
        return None;
    }

    Some(upper)
}

pub fn collect() -> PlatformIdentifiers {
    #[cfg(target_os = "windows")]
    {
        windows::collect_windows()
    }
    #[cfg(target_os = "macos")]
    {
        macos::collect_macos()
    }
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        linux::collect_linux()
    }
}
