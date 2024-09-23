
use std::{
    fmt::Display,
    sync::Arc,
    fs::{File, OpenOptions},
};
use crate::logger::info;
use anyhow::anyhow;
use hex;
use libc::__u64;

// pub use kvm_bindings::{
//     kvm_vm_enable_cap,
//     kvm_cap_arm_tmm_config_item, kvm_cap_arm_rme_init_ipa_args,
//     kvm_cap_arm_tmm_populate_region_args,
    
//     KVM_CAP_ARM_TMM, KVM_CAP_ARM_TMM_CREATE_RD, KVM_CAP_ARM_TMM_CONFIG_CVM,
//     KVM_CAP_ARM_TMM_CFG_RPV, KVM_CAP_ARM_TMM_RPV_SIZE, KVM_CAP_ARM_TMM_CFG_HASH_ALGO,
//     KVM_CAP_ARM_TMM_CFG_SVE, KVM_CAP_ARM_TMM_CFG_DBG, KVM_CAP_ARM_TMM_CFG_PMU, 
//     KVM_CAP_ARM_TMM_POPULATE_CVM, KVM_ARM_TMM_POPULATE_FLAGS_MEASURE,
//     KVM_CAP_ARM_TMM_MEASUREMENT_ALGO_SHA256, KVM_CAP_ARM_TMM_MEASUREMENT_ALGO_SHA512,
//     KVM_CAP_ARM_TMM_ACTIVATE_CVM, KVM_CAP_ARM_TMM_POPULATE_CVM,
//     KVM_CAP_ARM_TMM_INIT_IPA_CVM, KVM_ARM_TMM_POPULATE_FLAGS_MEASURE,
//     KVM_ARM_VCPU_TEC,
// };

pub use kvm_bindings::{
    kvm_enable_cap,
    kvm_cap_arm_rme_config_item, kvm_cap_arm_rme_init_ipa_args,
    kvm_cap_arm_rme_populate_realm_args, KVM_ARM_RME_POPULATE_FLAGS_MEASURE, KVM_ARM_VCPU_REC,
    KVM_CAP_ARM_RME, KVM_CAP_ARM_RME_ACTIVATE_REALM, KVM_CAP_ARM_RME_CFG_HASH_ALGO,
    KVM_CAP_ARM_RME_CFG_RPV, KVM_CAP_ARM_RME_CONFIG_REALM, KVM_CAP_ARM_RME_CREATE_RD,
    KVM_CAP_ARM_RME_INIT_IPA_REALM, KVM_CAP_ARM_RME_MEASUREMENT_ALGO_SHA256,
    KVM_CAP_ARM_RME_MEASUREMENT_ALGO_SHA512, KVM_CAP_ARM_RME_POPULATE_REALM,
    KVM_CAP_ARM_RME_RPV_SIZE,
};

use kvm_ioctls::{NoDatamatch, VcpuFd, VmFd};
use thiserror::Error;
use utils::time::TimestampUs;
use vm_memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

pub enum State {
    /// The guest is uninitialized
    UnInit,
    /// The CCA platform has been initialized
    Init,
    /// The guest is currently beign launched and plaintext data and VMCB save areas are being imported
    LaunchUpdate,
    /// The guest is currently being launched and ciphertext data are being imported
    LaunchSecret,
    /// The guest is fully launched or migrated in, and not being migrated out to another machine
    Running,
    /// The guest is currently being migrated out to another machine
    SendUpdate,
    /// The guest is currently being migrated from another machine
    RecieveUpdate,
    /// The guest has been sent to another machine
    Sent,
}

struct MemoryRegion {
    start: GuestAddress,
    len: u64,
}

#[derive(Debug)]
/// Struct to hold CCA info
pub struct CCA {
    fd: File,
    vm_fd: Arc<VmFd>,
    // handle: u32,
    // policy: u32,
    // state: State,
    // measure: [u8; 48],
    // timestamp: TimestampUs,
    // /// CCA active
    // pub cca: bool,
    // /// position of the Cbit
    // pub cbitpos: u32,
    // /// Regions to pre-encrypt
    // measured_regions: Vec<MemoryRegion>,
    // /// Regions that should be marked shared in the RMP
    // shared_regions: Vec<MemoryRegion>,
    // /// Regions that should be marked private in the RMP
    // ram_regions: Vec<MemoryRegion>,
}

#[derive(Debug, Error)]
/// CCA platform errors
pub enum CCAError {
    ConfigRealm,
    CreateRealm,
    PopulateRealm,
    ActivateRealm,
    ConfigRealmRPV,
    ConfigRealmHashAlgo,
    InvalidErrorCode,
    Errno(i32),
}

impl Display for CCAError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<u32> for CCAError {
    fn from(code: u32) -> Self {
        match code {
            0x01 => Self::ConfigRealm,
            0x02 => Self::CreateRealm,
            0x03 => Self::PopulateRealm,
            0x04 => Self::ActivateRealm,
            0x05 => Self::ConfigRealmRPV,
            0x06 => Self::ConfigRealmHashAlgo,
            _ => Self::InvalidErrorCode,
        }
    }
}

/// Configuration of a confidential VM on Arm
//#[derive(Debug)]
// pub struct ArmRmeConfig {
//     pub measurement_algo: Option<String>,
//     pub personalization_value: Option<String>,
// }
#[derive(Debug)]
pub struct ArmRmeConfig<'a> {
    pub measurement_algo: Option<&'a str>,
    pub personalization_value: Option<&'a str>,
}

/// Wrapper over KVM VM ioctls.
// pub struct KvmCvm {
//     fd: Arc<VmFd>,
//     arm_rme_enabled: bool,
// }

/// CCA result return type
pub type CCAResult<T> = std::result::Result<T, CCAError>;


impl CCA {

    ///Initialize CCA
    pub fn new(vm_fd: Arc<VmFd>) -> Self {
        //Open /dev/kvm
    
        info!("Initializing new CCA guest context");
    
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .unwrap();
    
        CCA {
            fd: fd,
            vm_fd: vm_fd,
        }
    }

    // Configure the Realm
    pub fn arm_rme_realm_configure(&self, realm_config: &ArmRmeConfig) -> CCAResult<()> {
        info!("arm_rme_realm_configure");
        // if let Some(rpv) = realm_config.personalization_value {
        //     info!("Configure RPV");
        //     info!("rpv: {:?}", rpv);
        //     let rpv_bytes = 
        //         hex::decode(rpv).map_err(|_| CCAError::ConfigRealmRPV)?;
        //     info!("rpv_bytes: {:?}", rpv_bytes);
            
        //     if rpv_bytes.len() > KVM_CAP_ARM_RME_RPV_SIZE as usize {
        //         return Err(CCAError::ConfigRealmRPV);
        //     }

        //     let mut cfg = kvm_cap_arm_rme_config_item {
        //         cfg: KVM_CAP_ARM_RME_CFG_RPV,
        //         ..Default::default()
        //     };

        //     //Fill the first few bytes. The RPV is zero-padded on the right
        //     for (i, b) in rpv_bytes.into_iter().enumerate() {
        //         // SAFETY: accessing a union field in a valid structure
        //         unsafe {
        //             cfg.__bindgen_anon_1.__bindgen_anon_1.rpv[i] = b;
        //         }
        //     }

        //     let cap = kvm_enable_cap {
        //         cap: KVM_CAP_ARM_RME,
        //         args: [
        //             KVM_CAP_ARM_RME_CONFIG_REALM as u64,
        //             &cfg as *const _ as u64,
        //             0,
        //             0,
        //         ],
        //         ..Default::default()
        //     };

        //     info!("self is {:?}", self);
        //     info!("self.vm_fd is {:?}", self.vm_fd);
        //     info!("Configuring Realm with cfg: {:?}", cfg);

        //     self.vm_fd
        //         .enable_cap(&cap)
        //         .map_err(|_| CCAError::ConfigRealm)?
        // }

        // Configure the hash algo
        let algo = match &realm_config.measurement_algo {
            // Some(ref algo_str) if algo_str == "sha256" => KVM_CAP_ARM_RME_MEASUREMENT_ALGO_SHA256,
            // Some(ref algo_str) if algo_str == "sha512" => KVM_CAP_ARM_RME_MEASUREMENT_ALGO_SHA512,
            Some("sha256") => KVM_CAP_ARM_RME_MEASUREMENT_ALGO_SHA256,
            Some("sha512") => KVM_CAP_ARM_RME_MEASUREMENT_ALGO_SHA512,
            Some(_) => {
                return Err(CCAError::ConfigRealmHashAlgo)
            }
            // Pick a default algorithm to make the life of verifiers easier
            None => KVM_CAP_ARM_RME_MEASUREMENT_ALGO_SHA512,
        };
        info!("algo is {:?}", algo); // algo is 1 => sha512
        let mut cfg = kvm_cap_arm_rme_config_item {
            cfg: KVM_CAP_ARM_RME_CFG_HASH_ALGO,
            ..Default::default()
        };
        
        cfg.__bindgen_anon_1.__bindgen_anon_2.hash_algo = algo;
        info!("cfg is {:?}", cfg);

        let cap = kvm_enable_cap {
            cap: KVM_CAP_ARM_RME,
            args: [
                KVM_CAP_ARM_RME_CONFIG_REALM as u64,
                &cfg as *const _ as u64,
                0,
                0,
            ],
            ..Default::default()
        };
        info!("self is {:?}", self);
        info!("self.vm_fd is {:?}", self.vm_fd);
        info!("Configuring Realm with cfg: {:?}", &cfg);
        info!("cap is {:?}", cap.args[1]);
        // let pointer_value: __u64 = cap.args[1];
        // let cfg_ptr: *const kvm_cap_arm_rme_config_item = pointer_value as *const _;
        // unsafe {
        //     info!("cfg_ptr is {:?}", &*cfg_ptr);
        // }

        self.vm_fd
            .enable_cap(&cap)
            .map_err(|e| {
                info!("Failed to enable capability: {:?}", e);
                info!("Cap struct: {:?}", cap); // Log the cap structure on error
                info!("Cfg struct: {:?}", cfg); // Log the cfg structure on error
                CCAError::ConfigRealmHashAlgo
            })

    }

    // Create the Realm Descriptor
    pub fn arm_rme_realm_create(&self) -> CCAResult<()> {
        info!("arm_rme_realm_create");
        let cap = kvm_enable_cap {
            cap: KVM_CAP_ARM_RME,
            args: [KVM_CAP_ARM_RME_CREATE_RD as u64, 0, 0, 0],
            ..Default::default()
        };
        self.vm_fd
            .enable_cap(&cap)
            .map_err(|_| CCAError::CreateRealm)
    }

    // Register guest RAM regions to be initialized by the Realm
    fn arm_rme_realm_populate(&self, addr: u64, size: u64, populate: bool) -> CCAResult<()> {
        let mut cap = kvm_enable_cap {
            cap: KVM_CAP_ARM_RME,
            ..Default::default()
        };

        let aligned_addr = addr & !0xfff;
        let aligned_size = (size + 0xfff) & !0xfff;

        let (cmd, argp) = if populate {
            let arg = kvm_cap_arm_rme_populate_realm_args {
                populate_ipa_base: aligned_addr,
                populate_ipa_size: aligned_size,
                flags: KVM_ARM_RME_POPULATE_FLAGS_MEASURE,
                ..Default::default()
            };
            (KVM_CAP_ARM_RME_POPULATE_REALM, &arg as *const _ as u64)
        } else {
            let arg = kvm_cap_arm_rme_init_ipa_args {
                init_ipa_base: aligned_addr,
                init_ipa_size: aligned_size,
                ..Default::default()
            };
            (KVM_CAP_ARM_RME_INIT_IPA_REALM, &arg as *const _ as u64)
        };

        cap.args[0] = cmd as u64;
        cap.args[1] = argp;

        self.vm_fd
            .enable_cap(&cap)
            .map_err(|_| CCAError::PopulateRealm)
    }

    /// Finalize the configuration of the Realm
    pub fn arm_rme_realm_finalize(&self) -> CCAResult<()> {
        info!("ARM_RME_REALM_FINALIZE");
        let cap = kvm_enable_cap {
            cap: KVM_CAP_ARM_RME,
            args: [KVM_CAP_ARM_RME_ACTIVATE_REALM as u64, 0, 0, 0],
            ..Default::default()
        };
        self.vm_fd
            .enable_cap(&cap)
            .map_err(|_| CCAError::ActivateRealm)
    }

}