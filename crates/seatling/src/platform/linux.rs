use super::{normalize, PlatformIdentifiers, SealingAnchors};

pub fn collect_linux() -> PlatformIdentifiers {
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        use std::fs;

        // 1. CPU
        let mut cpu = None;
        if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
            for line in cpuinfo.lines() {
                if line.starts_with("model name")
                    || line.starts_with("Hardware")
                    || line.starts_with("Processor")
                {
                    if let Some(colon) = line.find(':') {
                        let val = &line[colon + 1..];
                        if let Some(norm) = normalize(val) {
                            cpu = Some(format!("{}:{}", std::env::consts::ARCH, norm));
                            break;
                        }
                    }
                }
            }
        }
        if cpu.is_none() {
            cpu = normalize(std::env::consts::ARCH);
        }

        // 2. OS UUID: /etc/machine-id or /var/lib/dbus/machine-id
        let os_uuid = fs::read_to_string("/etc/machine-id")
            .or_else(|_| fs::read_to_string("/var/lib/dbus/machine-id"))
            .ok()
            .and_then(|s| normalize(&s));

        // 3. Motherboard: DMI UUID or serial
        let dmi_uuid = fs::read_to_string("/sys/class/dmi/id/product_uuid")
            .ok()
            .and_then(|s| normalize(&s));
        let dmi_serial = fs::read_to_string("/sys/class/dmi/id/board_serial")
            .ok()
            .and_then(|s| normalize(&s));

        let mobo = dmi_uuid.clone().or_else(|| dmi_serial.clone()).or_else(|| {
            let vendor = fs::read_to_string("/sys/class/dmi/id/board_vendor")
                .ok()
                .and_then(|s| normalize(&s));
            let name = fs::read_to_string("/sys/class/dmi/id/board_name")
                .ok()
                .and_then(|s| normalize(&s));
            match (vendor, name) {
                (Some(v), Some(n)) => Some(format!("{}:{}", v, n)),
                (Some(v), None) => Some(v),
                (None, Some(n)) => Some(n),
                (None, None) => None,
            }
        });

        // 4. Disk: root-FS UUID or dev:ino fallback
        let mut disk = None;
        if let Ok(mountinfo) = fs::read_to_string("/proc/self/mountinfo") {
            for line in mountinfo.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 && parts[4] == "/" {
                    // Try to resolve root device to UUID
                    if let Ok(entries) = fs::read_dir("/dev/disk/by-uuid") {
                        for entry in entries.flatten() {
                            if let Ok(target) = fs::read_link(entry.path()) {
                                let target_str = target.to_string_lossy();
                                if parts.iter().any(|p| {
                                    p.ends_with(target_str.as_ref()) || target_str.ends_with(p)
                                }) {
                                    if let Some(uuid_str) = entry.file_name().to_str() {
                                        disk = normalize(uuid_str);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    break;
                }
            }
        }
        if disk.is_none() {
            if let Ok(m) = fs::metadata("/") {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    disk = Some(format!("dev:{}:ino:{}", m.dev(), m.ino()));
                }
            }
        }

        // Sealing Anchors
        let mut hardware_anchors = Vec::new();
        if let Some(ref uuid) = dmi_uuid {
            hardware_anchors.push(("dmi_uuid", uuid.clone()));
        } else if let Some(ref sn) = dmi_serial {
            hardware_anchors.push(("dmi_serial", sn.clone()));
        }
        if let Some(ref mid) = os_uuid {
            hardware_anchors.push(("machine_id", mid.clone()));
        }

        let uid = unsafe { libc::getuid() };

        PlatformIdentifiers {
            cpu,
            mobo,
            disk,
            os_uuid,
            anchors: SealingAnchors {
                hardware: hardware_anchors,
                user_scope: Some(uid.to_string()),
            },
        }
    }
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    {
        PlatformIdentifiers {
            cpu: normalize(std::env::consts::ARCH),
            mobo: None,
            disk: None,
            os_uuid: None,
            anchors: SealingAnchors {
                hardware: Vec::new(),
                user_scope: None,
            },
        }
    }
}
