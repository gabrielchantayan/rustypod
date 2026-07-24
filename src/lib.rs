//! rustypod — incremental Rust port of iPod Classic 6G retailOS.
//!
//! Each module ports functions from the original firmware (osos, decrypted
//! from IPSW 35.9.0.4). Every ported function carries its original load
//! address and is verified against the original machine code with
//! `tools/match.py` in the ipod-decomp repo.
//!
//! Naming rule (the "deobfuscation" contract): functions, parameters,
//! locals and globals are named after what they *do* — never Ghidra-style
//! `FUN_*`/`param_*`/`uVar*`/`DAT_*` names.

#![no_std]
#![allow(clippy::missing_safety_doc)]

#[cfg(not(test))]
use core::panic::PanicInfo;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

pub mod libc;
pub mod memchr;
pub mod memcmp;
pub mod memcpy;
pub mod memzero;
pub mod rt_unaligned;
pub mod strcat;
pub mod strchr;
pub mod strcpy;
pub mod strlen_safe;
pub mod strncmp;
pub mod strncpy;
pub mod strstr;
