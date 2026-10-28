use super::{normalize, PlatformIdentifiers, SealingAnchors};

#[cfg(target_os = "macos")]
mod iokit {
    use core_foundation::base::{CFTypeRef, TCFType};
    use core_foundation::string::{CFString, CFStringRef};
    use std::ffi::c_void;

    #[allow(non_camel_case_types)]
    type io_service_t = u32;
    #[allow(non_camel_case_types)]
    type io_object_t = u32;
    #[allow(non_camel_case_types)]
    type mach_port_t = u32;

    #[link(name = "IOKit", kind = "framework")]
    extern "C" {
        fn IOServiceMatching(name: *const std::os::raw::c_char) -> *mut c_void;
        fn IOServiceGetMatchingService(
            main_port: mach_port_t,
            matching: *mut c_void,
        ) -> io_service_t;
        fn IORegistryEntryCreateCFProperty(
            entry: io_service_t,
            key: CFStringRef,
            allocator: *const c_void,
            options: u32,
        ) -> CFTypeRef;
        fn IOObjectRelease(object: io_object_t) -> i32;
    }

    pub fn get_iokit_property(property_name: &str) -> Option<String> {
        unsafe {
            let matching = IOServiceMatching(c"IOPlatformExpertDevice".as_ptr() as *const _);
            if matching.is_null() {
                return None;
            }

            let service = IOServiceGetMatchingService(0, matching);
            if service == 0 {
                return None;
            }

            let cf_prop_name = CFString::new(property_name);
            let prop_ref = IORegistryEntryCreateCFProperty(
                service,
                cf_prop_name.as_concrete_TypeRef(),
                std::ptr::null(),
                0,
            );
            IOObjectRelease(service);

            if prop_ref.is_null() {
                return None;
            }

            let cf_str = CFString::wrap_under_create_rule(prop_ref as CFStringRef);
            let s = cf_str.to_string();
            Some(s)
        }
    }
}

pub fn collect_macos() -> PlatformIdentifiers {
    #[cfg(target_os = "macos")]
    {
        let platform_uuid = iokit::get_iokit_property("IOPlatformUUID").and_then(|s| normalize(&s));
        let platform_serial =
            iokit::get_iokit_property("IOPlatformSerialNumber").and_then(|s| normalize(&s));

        // CPU Brand String via sysctl
        let mut cpu = None;
        let mut size = 0usize;
        unsafe {
            let name = b"machdep.cpu.brand_string\0";
            if libc::sysctlbyname(
                name.as_ptr() as *const _,
                std::ptr::null_mut(),
                &mut size,
                std::ptr::null_mut(),
                0,
            ) == 0
                && size > 0
            {
                let mut buf = vec![0u8; size];
                if libc::sysctlbyname(
                    name.as_ptr() as *const _,
                    buf.as_mut_ptr() as *mut _,
                    &mut size,
                    std::ptr::null_mut(),
                    0,
                ) == 0
                {
                    if let Ok(brand) = std::str::from_utf8(&buf) {
                        cpu = normalize(brand).map(|b| format!("{}:{}", std::env::consts::ARCH, b));
                    }
                }
            }
        }
        if cpu.is_none() {
            cpu = normalize(std::env::consts::ARCH);
        }

        // Disk volume identification using statfs (zero-prompt, no child subprocesses)
        let mut disk = None;
        unsafe {
            let mut stat: libc::statfs = std::mem::zeroed();
            let root_path = b"/\0";
            if libc::statfs(root_path.as_ptr() as *const _, &mut stat) == 0 {
                let fsid_str = format!("{:08x}:{:08x}", stat.f_fsid.val[0], stat.f_fsid.val[1]);
                disk = normalize(&fsid_str);
            }
        }

        let mut hardware_anchors = Vec::new();
        if let Some(ref uuid) = platform_uuid {
            hardware_anchors.push(("platform_uuid", uuid.clone()));
        }
        if let Some(ref sn) = platform_serial {
            hardware_anchors.push(("platform_serial", sn.clone()));
        }

        PlatformIdentifiers {
            cpu,
            mobo: platform_serial.clone(),
            disk,
            os_uuid: platform_uuid.clone(),
            anchors: SealingAnchors {
                hardware: hardware_anchors,
                user_scope: None,
            },
        }
    }
    #[cfg(not(target_os = "macos"))]
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
