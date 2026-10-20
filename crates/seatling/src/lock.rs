use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;
use std::thread::sleep;
use std::time::{Duration, Instant};

pub struct FileLock {
    #[allow(dead_code)]
    file: File,
}

impl FileLock {
    pub fn acquire(dir: &Path, timeout: Duration) -> io::Result<Self> {
        let lock_path = dir.join(".seatling.lock");
        let start = Instant::now();

        loop {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&lock_path)?;

            #[cfg(target_os = "windows")]
            {
                use std::os::windows::io::AsRawHandle;
                use windows_sys::Win32::Storage::FileSystem::{
                    LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
                };
                use windows_sys::Win32::System::IO::OVERLAPPED;

                let handle = file.as_raw_handle();
                let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
                let res = unsafe {
                    LockFileEx(
                        handle as _,
                        LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                        0,
                        1,
                        0,
                        &mut overlapped,
                    )
                };

                if res != 0 {
                    return Ok(Self { file });
                }
            }

            #[cfg(unix)]
            {
                use std::os::unix::io::AsRawFd;
                let fd = file.as_raw_fd();
                let res = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
                if res == 0 {
                    return Ok(Self { file });
                }
            }

            #[cfg(not(any(target_os = "windows", unix)))]
            {
                return Ok(Self { file });
            }

            if start.elapsed() >= timeout {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Failed to acquire cross-process lock before timeout",
                ));
            }

            sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Storage::FileSystem::UnlockFileEx;
            use windows_sys::Win32::System::IO::OVERLAPPED;

            let handle = self.file.as_raw_handle();
            let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
            unsafe {
                UnlockFileEx(handle as _, 0, 1, 0, &mut overlapped);
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = self.file.as_raw_fd();
            unsafe {
                libc::flock(fd, libc::LOCK_UN);
            }
        }
    }
}
