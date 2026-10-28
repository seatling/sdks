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

    pub fn is_unavailable_component(val: &str) -> bool {
        val == "1e075079a4055273ca35d46bb12cc436151c890100a0669d2aaebcfc47743d52" // cpu
            || val == "816766468a35607ae8dbb46091db857022066fa21df996452243763f350c37cb" // mobo
            || val == "eb154aa1b3c95944ae68f711e7c9966133d1b72a6bca2321591fcf3b85fae9c0" // disk
            || val == "da04f58ba9b0a7cbe5f23bdfbc71a8eaae13735c02931d86f78a2eefeb9fa5f8"
        // os_uuid
    }

    pub fn weighted_score(a: &HWIDComponents, b: &HWIDComponents) -> u32 {
        let mut score = 0;
        if a.mobo == b.mobo && !Self::is_unavailable_component(&a.mobo) {
            score += Self::WEIGHT_MOBO;
        }
        if a.cpu == b.cpu && !Self::is_unavailable_component(&a.cpu) {
            score += Self::WEIGHT_CPU;
        }
        if a.disk == b.disk && !Self::is_unavailable_component(&a.disk) {
            score += Self::WEIGHT_DISK;
        }
        if a.os_uuid == b.os_uuid && !Self::is_unavailable_component(&a.os_uuid) {
            score += Self::WEIGHT_OS_UUID;
        }
        score
    }

    pub fn fuzzy_match_quorum(a: &HWIDComponents, b: &HWIDComponents) -> bool {
        Self::weighted_score(a, b) >= Self::QUORUM_PASSING_SCORE
    }
}
