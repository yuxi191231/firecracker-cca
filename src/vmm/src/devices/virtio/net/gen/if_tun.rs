// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// automatically generated by tools/bindgen.sh

#![allow(
    non_camel_case_types,
    non_upper_case_globals,
    dead_code,
    non_snake_case,
    clippy::ptr_as_ptr,
    clippy::undocumented_unsafe_blocks,
    missing_debug_implementations,
    clippy::tests_outside_test_module
)]

pub const ETH_ALEN: u32 = 6;
pub const ETH_TLEN: u32 = 2;
pub const ETH_HLEN: u32 = 14;
pub const ETH_ZLEN: u32 = 60;
pub const ETH_DATA_LEN: u32 = 1500;
pub const ETH_FRAME_LEN: u32 = 1514;
pub const ETH_FCS_LEN: u32 = 4;
pub const ETH_MIN_MTU: u32 = 68;
pub const ETH_MAX_MTU: u32 = 65535;
pub const ETH_P_LOOP: u32 = 96;
pub const ETH_P_PUP: u32 = 512;
pub const ETH_P_PUPAT: u32 = 513;
pub const ETH_P_TSN: u32 = 8944;
pub const ETH_P_ERSPAN2: u32 = 8939;
pub const ETH_P_IP: u32 = 2048;
pub const ETH_P_X25: u32 = 2053;
pub const ETH_P_ARP: u32 = 2054;
pub const ETH_P_BPQ: u32 = 2303;
pub const ETH_P_IEEEPUP: u32 = 2560;
pub const ETH_P_IEEEPUPAT: u32 = 2561;
pub const ETH_P_BATMAN: u32 = 17157;
pub const ETH_P_DEC: u32 = 24576;
pub const ETH_P_DNA_DL: u32 = 24577;
pub const ETH_P_DNA_RC: u32 = 24578;
pub const ETH_P_DNA_RT: u32 = 24579;
pub const ETH_P_LAT: u32 = 24580;
pub const ETH_P_DIAG: u32 = 24581;
pub const ETH_P_CUST: u32 = 24582;
pub const ETH_P_SCA: u32 = 24583;
pub const ETH_P_TEB: u32 = 25944;
pub const ETH_P_RARP: u32 = 32821;
pub const ETH_P_ATALK: u32 = 32923;
pub const ETH_P_AARP: u32 = 33011;
pub const ETH_P_8021Q: u32 = 33024;
pub const ETH_P_ERSPAN: u32 = 35006;
pub const ETH_P_IPX: u32 = 33079;
pub const ETH_P_IPV6: u32 = 34525;
pub const ETH_P_PAUSE: u32 = 34824;
pub const ETH_P_SLOW: u32 = 34825;
pub const ETH_P_WCCP: u32 = 34878;
pub const ETH_P_MPLS_UC: u32 = 34887;
pub const ETH_P_MPLS_MC: u32 = 34888;
pub const ETH_P_ATMMPOA: u32 = 34892;
pub const ETH_P_PPP_DISC: u32 = 34915;
pub const ETH_P_PPP_SES: u32 = 34916;
pub const ETH_P_LINK_CTL: u32 = 34924;
pub const ETH_P_ATMFATE: u32 = 34948;
pub const ETH_P_PAE: u32 = 34958;
pub const ETH_P_AOE: u32 = 34978;
pub const ETH_P_8021AD: u32 = 34984;
pub const ETH_P_802_EX1: u32 = 34997;
pub const ETH_P_PREAUTH: u32 = 35015;
pub const ETH_P_TIPC: u32 = 35018;
pub const ETH_P_LLDP: u32 = 35020;
pub const ETH_P_MRP: u32 = 35043;
pub const ETH_P_MACSEC: u32 = 35045;
pub const ETH_P_8021AH: u32 = 35047;
pub const ETH_P_MVRP: u32 = 35061;
pub const ETH_P_1588: u32 = 35063;
pub const ETH_P_NCSI: u32 = 35064;
pub const ETH_P_PRP: u32 = 35067;
pub const ETH_P_CFM: u32 = 35074;
pub const ETH_P_FCOE: u32 = 35078;
pub const ETH_P_IBOE: u32 = 35093;
pub const ETH_P_TDLS: u32 = 35085;
pub const ETH_P_FIP: u32 = 35092;
pub const ETH_P_80221: u32 = 35095;
pub const ETH_P_HSR: u32 = 35119;
pub const ETH_P_NSH: u32 = 35151;
pub const ETH_P_LOOPBACK: u32 = 36864;
pub const ETH_P_QINQ1: u32 = 37120;
pub const ETH_P_QINQ2: u32 = 37376;
pub const ETH_P_QINQ3: u32 = 37632;
pub const ETH_P_EDSA: u32 = 56026;
pub const ETH_P_DSA_8021Q: u32 = 56027;
pub const ETH_P_IFE: u32 = 60734;
pub const ETH_P_AF_IUCV: u32 = 64507;
pub const ETH_P_802_3_MIN: u32 = 1536;
pub const ETH_P_802_3: u32 = 1;
pub const ETH_P_AX25: u32 = 2;
pub const ETH_P_ALL: u32 = 3;
pub const ETH_P_802_2: u32 = 4;
pub const ETH_P_SNAP: u32 = 5;
pub const ETH_P_DDCMP: u32 = 6;
pub const ETH_P_WAN_PPP: u32 = 7;
pub const ETH_P_PPP_MP: u32 = 8;
pub const ETH_P_LOCALTALK: u32 = 9;
pub const ETH_P_CAN: u32 = 12;
pub const ETH_P_CANFD: u32 = 13;
pub const ETH_P_PPPTALK: u32 = 16;
pub const ETH_P_TR_802_2: u32 = 17;
pub const ETH_P_MOBITEX: u32 = 21;
pub const ETH_P_CONTROL: u32 = 22;
pub const ETH_P_IRDA: u32 = 23;
pub const ETH_P_ECONET: u32 = 24;
pub const ETH_P_HDLC: u32 = 25;
pub const ETH_P_ARCNET: u32 = 26;
pub const ETH_P_DSA: u32 = 27;
pub const ETH_P_TRAILER: u32 = 28;
pub const ETH_P_PHONET: u32 = 245;
pub const ETH_P_IEEE802154: u32 = 246;
pub const ETH_P_CAIF: u32 = 247;
pub const ETH_P_XDSA: u32 = 248;
pub const ETH_P_MAP: u32 = 249;
pub const ETH_P_MCTP: u32 = 250;
pub const TUN_READQ_SIZE: u32 = 500;
pub const TUN_TYPE_MASK: u32 = 15;
pub const IFF_TAP: u32 = 2;
pub const IFF_NO_PI: u32 = 4096;
pub const IFF_VNET_HDR: u32 = 16384;
pub const IFF_MULTI_QUEUE: u32 = 256;
pub const TUN_TX_TIMESTAMP: u32 = 1;
pub const TUN_F_CSUM: u32 = 1;
pub const TUN_F_TSO4: u32 = 2;
pub const TUN_F_TSO6: u32 = 4;
pub const TUN_F_TSO_ECN: u32 = 8;
pub const TUN_F_UFO: u32 = 16;
pub const TUN_PKT_STRIP: u32 = 1;
pub const TUN_FLT_ALLMULTI: u32 = 1;
pub type __u8 = ::std::os::raw::c_uchar;
pub type __u16 = ::std::os::raw::c_ushort;
pub type __u32 = ::std::os::raw::c_uint;
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub struct sock_filter {
    pub code: __u16,
    pub jt: __u8,
    pub jf: __u8,
    pub k: __u32,
}
#[test]
fn bindgen_test_layout_sock_filter() {
    const UNINIT: ::std::mem::MaybeUninit<sock_filter> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<sock_filter>(),
        8usize,
        concat!("Size of: ", stringify!(sock_filter))
    );
    assert_eq!(
        ::std::mem::align_of::<sock_filter>(),
        4usize,
        concat!("Alignment of ", stringify!(sock_filter))
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).code) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(sock_filter),
            "::",
            stringify!(code)
        )
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).jt) as usize - ptr as usize },
        2usize,
        concat!(
            "Offset of field: ",
            stringify!(sock_filter),
            "::",
            stringify!(jt)
        )
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).jf) as usize - ptr as usize },
        3usize,
        concat!(
            "Offset of field: ",
            stringify!(sock_filter),
            "::",
            stringify!(jf)
        )
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).k) as usize - ptr as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(sock_filter),
            "::",
            stringify!(k)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct sock_fprog {
    pub len: ::std::os::raw::c_ushort,
    pub filter: *mut sock_filter,
}
#[test]
fn bindgen_test_layout_sock_fprog() {
    const UNINIT: ::std::mem::MaybeUninit<sock_fprog> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<sock_fprog>(),
        16usize,
        concat!("Size of: ", stringify!(sock_fprog))
    );
    assert_eq!(
        ::std::mem::align_of::<sock_fprog>(),
        8usize,
        concat!("Alignment of ", stringify!(sock_fprog))
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).len) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(sock_fprog),
            "::",
            stringify!(len)
        )
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).filter) as usize - ptr as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(sock_fprog),
            "::",
            stringify!(filter)
        )
    );
}
impl Default for sock_fprog {
    fn default() -> Self {
        let mut s = ::std::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::std::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
