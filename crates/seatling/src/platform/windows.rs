use super::normalize;
#[cfg(target_os = "windows")]
use super::{PlatformIdentifiers, SealingAnchors};

#[derive(Default, Debug)]
pub struct SmbiosInfo {
    pub system_uuid: Option<String>,
    pub board_manufacturer: Option<String>,
    pub board_product: Option<String>,
    pub board_serial: Option<String>,
}

pub fn parse_smbios(data: &[u8]) -> SmbiosInfo {
    let mut info = SmbiosInfo::default();
    if data.len() < 8 {
        return info;
    }

    let mut offset = 0;
    while offset + 4 <= data.len() {
        let entry_type = data[offset];
        let length = data[offset + 1] as usize;
        if length < 4 || offset + length > data.len() {
            break;
        }

        let formatted_area = &data[offset..offset + length];
        let mut str_offset = offset + length;
        let mut strings = Vec::new();

        while str_offset < data.len() {
            if data[str_offset] == 0 {
                str_offset += 1;
                break;
            }
            let mut end = str_offset;
            while end < data.len() && data[end] != 0 {
                end += 1;
            }
            if let Ok(s) = std::str::from_utf8(&data[str_offset..end]) {
                strings.push(s.to_string());
            }
            str_offset = end + 1;
        }

        let get_str = |idx: u8| -> Option<String> {
            if idx == 0 || (idx as usize) > strings.len() {
                None
            } else {
                normalize(&strings[(idx - 1) as usize])
            }
        };

        if entry_type == 1 && formatted_area.len() >= 0x18 {
            // Type 1 UUID is at 0x08 (16 bytes)
            let raw_uuid = &formatted_area[0x08..0x18];
            // Format UUID: SMBIOS 2.6+ specifies mixed-endian representation
            // time_low (4 bytes LE), time_mid (2 bytes LE), time_hi_and_version (2 bytes LE), rest 8 bytes BE
            let d1 = u32::from_le_bytes(raw_uuid[0..4].try_into().unwrap_or_default());
            let d2 = u16::from_le_bytes(raw_uuid[4..6].try_into().unwrap_or_default());
            let d3 = u16::from_le_bytes(raw_uuid[6..8].try_into().unwrap_or_default());
            let formatted_uuid = format!(
                "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                d1,
                d2,
                d3,
                raw_uuid[8],
                raw_uuid[9],
                raw_uuid[10],
                raw_uuid[11],
                raw_uuid[12],
                raw_uuid[13],
                raw_uuid[14],
                raw_uuid[15]
            );
            if let Some(norm) = normalize(&formatted_uuid) {
                info.system_uuid = Some(norm);
            }
        } else if entry_type == 2 && formatted_area.len() >= 8 {
            // Type 2 BaseBoard: Manufacturer at 0x04, Product at 0x05, SerialNumber at 0x07
            info.board_manufacturer = get_str(formatted_area[0x04]);
            info.board_product = get_str(formatted_area[0x05]);
            info.board_serial = get_str(formatted_area[0x07]);
        }

        if entry_type == 127 {
            break;
        }

        offset = str_offset;
    }

    info
}

#[cfg(target_os = "windows")]
fn query_reg_string(subkey_str: &str, val_name_str: &str) -> Option<String> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY,
    };

    unsafe {
        let subkey: Vec<u16> = subkey_str
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let val_name: Vec<u16> = val_name_str
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut hkey = std::mem::zeroed();

        if RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &mut hkey,
        ) == 0
        {
            let mut buf = [0u16; 256];
            let mut size = (buf.len() * std::mem::size_of::<u16>()) as u32;
            let status = RegQueryValueExW(
                hkey,
                val_name.as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                buf.as_mut_ptr() as *mut u8,
                &mut size,
            );
            RegCloseKey(hkey);

            if status == 0 && size >= 2 {
                let u16_len = (size as usize / 2).min(buf.len());
                let slice = &buf[..u16_len];
                let actual_len = slice.iter().position(|&c| c == 0).unwrap_or(u16_len);
                let s = OsString::from_wide(&slice[..actual_len])
                    .to_string_lossy()
                    .trim()
                    .to_string();
                if !s.is_empty() {
                    return normalize(&s);
                }
            }
        }
    }
    None
}

#[cfg(target_os = "windows")]
pub fn get_smbios_raw() -> Option<Vec<u8>> {
    use windows_sys::Win32::System::SystemInformation::GetSystemFirmwareTable;

    // 'RSMB' provider = 0x52534D42
    let provider = u32::from_be_bytes(*b"RSMB");
    unsafe {
        let size = GetSystemFirmwareTable(provider, 0, std::ptr::null_mut(), 0);
        if size == 0 {
            return None;
        }
        let mut buffer = vec![0u8; size as usize];
        let read = GetSystemFirmwareTable(provider, 0, buffer.as_mut_ptr() as *mut _, size);
        if read == size {
            Some(buffer)
        } else {
            None
        }
    }
}

#[cfg(target_os = "windows")]
pub fn collect_windows() -> PlatformIdentifiers {
    use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationW;

    let smbios = get_smbios_raw()
        .map(|buf| parse_smbios(&buf))
        .unwrap_or_default();

    // 1. CPU: ProcessorNameString + Identifier + arch
    let cpu_name = query_reg_string(
        "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
        "ProcessorNameString",
    );
    let cpu_id = query_reg_string(
        "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
        "Identifier",
    );
    let cpu = match (cpu_name, cpu_id) {
        (Some(name), Some(id)) => Some(format!("{}:{}:{}", std::env::consts::ARCH, name, id)),
        (Some(name), None) => Some(format!("{}:{}", std::env::consts::ARCH, name)),
        (None, Some(id)) => Some(format!("{}:{}", std::env::consts::ARCH, id)),
        (None, None) => normalize(std::env::consts::ARCH),
    };

    // 2. OS UUID: MachineGuid
    let os_uuid = query_reg_string("SOFTWARE\\Microsoft\\Cryptography", "MachineGuid");

    // 3. Motherboard: Serial preferred; fallback to UUID; fallback to Manufacturer:Product
    let mobo = smbios
        .board_serial
        .clone()
        .or_else(|| smbios.system_uuid.clone())
        .or_else(
            || match (&smbios.board_manufacturer, &smbios.board_product) {
                (Some(mfg), Some(prod)) => Some(format!("{}:{}", mfg, prod)),
                (Some(mfg), None) => Some(mfg.clone()),
                (None, Some(prod)) => Some(prod.clone()),
                (None, None) => {
                    let mfg = query_reg_string(
                        "HARDWARE\\DESCRIPTION\\System\\BIOS",
                        "BaseBoardManufacturer",
                    );
                    let prod =
                        query_reg_string("HARDWARE\\DESCRIPTION\\System\\BIOS", "BaseBoardProduct");
                    match (mfg, prod) {
                        (Some(m), Some(p)) => Some(format!("{}:{}", m, p)),
                        (Some(m), None) => Some(m),
                        (None, Some(p)) => Some(p),
                        (None, None) => None,
                    }
                }
            },
        );

    // 4. Primary disk serial via authoritative Windows system directory drive root
    let mut root_path: Vec<u16> = "C:\\\0".encode_utf16().collect();
    unsafe {
        let mut sys_dir = [0u16; 260];
        let len = windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW(
            sys_dir.as_mut_ptr(),
            sys_dir.len() as u32,
        );
        if len >= 3 && sys_dir[1] == b':' as u16 && sys_dir[2] == b'\\' as u16 {
            root_path = vec![sys_dir[0], b':' as u16, b'\\' as u16, 0u16];
        } else if let Ok(sys_drive) = std::env::var("SystemDrive") {
            let root_path_str = format!("{}\\\0", sys_drive.trim_end_matches('\\'));
            root_path = root_path_str.encode_utf16().collect();
        }
    }
    let mut disk = None;
    unsafe {
        let mut serial = 0u32;
        if GetVolumeInformationW(
            root_path.as_ptr(),
            std::ptr::null_mut(),
            0,
            &mut serial,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
        ) != 0
            && serial != 0
        {
            disk = Some(format!("{:X}", serial));
        }
    }

    // Sealing Anchors (Hardware subset only)
    let mut hardware_anchors = Vec::new();
    if let Some(ref guid) = os_uuid {
        hardware_anchors.push(("machine_guid", guid.clone()));
    }
    if let Some(ref uuid) = smbios.system_uuid {
        hardware_anchors.push(("smbios_uuid", uuid.clone()));
    }

    PlatformIdentifiers {
        cpu,
        mobo,
        disk,
        os_uuid,
        anchors: SealingAnchors {
            hardware: hardware_anchors,
            user_scope: None,
        },
    }
}
