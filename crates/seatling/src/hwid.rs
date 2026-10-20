use crate::platform::{self, PlatformIdentifiers, SealingAnchors};
use crate::types::HWIDComponents;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

static CACHED_PLATFORM: OnceLock<PlatformIdentifiers> = OnceLock::new();
static CACHED_COMPONENTS: OnceLock<HWIDComponents> = OnceLock::new();

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub struct HWIDCollector;

impl HWIDCollector {
    pub fn platform() -> &'static PlatformIdentifiers {
        CACHED_PLATFORM.get_or_init(platform::collect)
    }

    pub fn sealing_anchors() -> &'static SealingAnchors {
        &Self::platform().anchors
    }

    pub fn get_components() -> HWIDComponents {
        CACHED_COMPONENTS
            .get_or_init(|| {
                let p = Self::platform();

                let raw_cpu = p.cpu.as_deref().unwrap_or("seatling:unavailable:cpu");
                let raw_mobo = p.mobo.as_deref().unwrap_or("seatling:unavailable:mobo");
                let raw_disk = p.disk.as_deref().unwrap_or("seatling:unavailable:disk");
                let raw_os = p
                    .os_uuid
                    .as_deref()
                    .unwrap_or("seatling:unavailable:os_uuid");

                HWIDComponents {
                    cpu: sha256_hex(raw_cpu.as_bytes()),
                    mobo: sha256_hex(raw_mobo.as_bytes()),
                    disk: sha256_hex(raw_disk.as_bytes()),
                    os_uuid: sha256_hex(raw_os.as_bytes()),
                }
            })
            .clone()
    }

    pub fn get_hwid() -> String {
        let c = Self::get_components();
        let composite = format!("{}:{}:{}:{}", c.cpu, c.mobo, c.disk, c.os_uuid);
        sha256_hex(composite.as_bytes())
    }

    pub const WEIGHT_MOBO: u32 = 35;
    pub const WEIGHT_CPU: u32 = 25;
    pub const WEIGHT_DISK: u32 = 20;
    pub const WEIGHT_OS_UUID: u32 = 20;
    pub const QUORUM_PASSING_SCORE: u32 = 70;

    pub fn weighted_score(a: &HWIDComponents, b: &HWIDComponents) -> u32 {
        let mut score = 0;
        if a.mobo == b.mobo {
            score += Self::WEIGHT_MOBO;
        }
        if a.cpu == b.cpu {
            score += Self::WEIGHT_CPU;
        }
        if a.disk == b.disk {
            score += Self::WEIGHT_DISK;
        }
        if a.os_uuid == b.os_uuid {
            score += Self::WEIGHT_OS_UUID;
        }
        score
    }

    pub fn fuzzy_match_quorum(a: &HWIDComponents, b: &HWIDComponents) -> bool {
        Self::weighted_score(a, b) >= Self::QUORUM_PASSING_SCORE
    }
}
