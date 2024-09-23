use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
/// CCA configuration struct
pub struct CCAConfig {
    // /// Path to SEV firmware
    // pub firmware_path: String,
    // /// Path to kernel hash
    // pub kernel_hash_path: String,
    // /// Path to initrd hash
    // pub initrd_hash_path: Option<String>,
    // /// Path to guest launch blob
    // pub session_path: Option<String>,
    // /// Path to guest DH public key
    // pub dh_cert: Option<String>,
    // /// Guest policy
    // pub policy: u32,
    /// CCA
    pub virtcca: bool,
    pub measurement_algo: Option<String>,
    pub personalization_value: Option<String>,
}
