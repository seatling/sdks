pub mod cache;
pub mod client;
pub mod error;
pub mod ffi;
pub mod hwid;
pub mod jwt;
pub mod keystore;
pub mod lock;
pub mod platform;
pub mod storage;
pub mod types;
pub mod verifier;

pub use client::SeatlingClient;
pub use error::SeatlingError;
pub use hwid::HWIDCollector;
pub use keystore::HardwareSealedKeystore;
pub use storage::StorageManager;
pub use types::*;
pub use verifier::TokenVerifier;

pub type Seatling = SeatlingClient;
pub type SeatlingStatus = types::StatusCode;
