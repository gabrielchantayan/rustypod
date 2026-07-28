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
//!
//! Layout: modules are organized in folders by subsystem; everything is
//! re-exported flat at the crate root (`crate::printf_helpers`,
//! `crate::rt_div`, ...) so paths stay stable as the tree grows.

#![no_std]
#![allow(clippy::missing_safety_doc)]

#[cfg(not(test))]
use core::panic::PanicInfo;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

pub mod drivers;
pub mod fp;
pub mod fs;
pub mod ft;
pub mod heap;
pub mod kernel;
pub mod libm;
pub mod libc;
pub mod printf;
pub mod runtime;
pub mod scanf;
pub mod stdio;
pub mod strto;
pub mod time;
pub mod util;

// Flat re-exports: existing `crate::<module>` paths keep working.
pub use drivers::*;
pub use fp::*;
pub use fs::*;
pub use ft::*;
pub use heap::*;
pub use kernel::*;
pub use libm::*;
pub use libc::*;
pub use printf::*;
pub use runtime::*;
pub use scanf::*;
pub use stdio::*;
pub use strto::*;
pub use time::*;
pub use util::*;
