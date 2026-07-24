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

// Batch 2: ARM ADS arithmetic / stdlib runtime.
pub mod aeabi_64div;
pub mod aeabi_64shift;
pub mod chval;
pub mod ctype;
pub mod ll_udiv10;
pub mod random;
pub mod rt_div;
pub mod rt_memcpy;
pub mod setjmp;
pub mod strtol;
pub mod strtoull;
pub mod strtoul;

// Batch 3: stdlib control flow, time, errno, printf helpers.
pub mod assert_rt;
pub mod atexit;
pub mod byteswap;
pub mod errno;
pub mod exit;
pub mod localtime;
pub mod mktime;
pub mod mbrtowc;
pub mod printf_helpers;
pub mod qsort;
pub mod raise;
pub mod strtoll;

// Batch 4: printf converters, malloc veneers, scanf front-end.
pub mod malloc_rt;
pub mod printf_d;
pub mod printf_ll;
pub mod printf_o;
pub mod printf_out;
pub mod printf_s;
pub mod printf_wide;
pub mod printf_x;
pub mod scanf_helpers;

// Batch 5: printf core + API, strtod, scanf converters.
pub mod printf_api;
pub mod printf_core;
pub mod scanf_float;
pub mod scanf_int;
pub mod scanf_str;
pub mod strtod;

// Batch 6: soft-float primitives (0x083eae74-0x083ed1ff region).
pub mod fp_compare;
pub mod fp_dadd;
pub mod fp_dconv;
pub mod fp_ddiv;
pub mod fp_dmul;
pub mod fp_fadd;
pub mod fp_fconv;
pub mod fp_fmuldiv;
pub mod fp_misc;
pub mod fp_scalb;
