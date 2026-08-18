//! REAL-ifying a value cell — how the VDBE converts an already-numeric
//! `Mem`/`sqlite3_value` into the SQL REAL storage class in place.
//!
//! - `vdbe_mem_realify` — original: `FUN_0838c024` @ 0x0838c024
//!   (40 bytes, 0x0838c024..0x0838c04c; **2 `bl` call sites**,
//!   binary-scanned from osos.dec). Upstream SQLite's
//!   `sqlite3VdbeMemRealify` (`int sqlite3VdbeMemRealify(Mem *pMem)` in
//!   `vdbemem.c`): compute the cell's numeric value as `double`, store
//!   it in the REAL arm of the value union, replace only the five
//!   `MEM_*` type bits with `MEM_Real`, and return `SQLITE_OK`.
//!
//! ### Extent
//!
//! Confirmed from raw words: 0x0838c048 is `ldmia sp!, {r4,pc}` and the
//! next word, 0x0838c04c, is the `stmdb sp!, {r4,lr}` entry of
//! [`mem_release`](super::mem_release::mem_release). No literal pool —
//! the mask `0x1f`, the type bit `0x8`, and the success return `0` are
//! all immediates.
//!
//! ### Listing
//!
//! ```text
//! 0838c024  stmdb sp!, {r4,lr}
//! 0838c028  mov  r4, r0            @ p_mem
//! 0838c02c  bl   0x0838c7ec        @ sqlite3VdbeRealValue(p_mem)
//! 0838c030  strd r0, r1, [r4, #0x8]@ r = helper result
//! 0838c034  ldrh r0, [r4, #0x1c]   @ flags AFTER helper side effects
//! 0838c038  bic  r0, r0, #0x1f     @ clear five type bits
//! 0838c03c  orr  r0, r0, #0x8      @ MEM_Real
//! 0838c040  strh r0, [r4, #0x1c]
//! 0838c044  mov  r0, #0x0          @ SQLITE_OK
//! 0838c048  ldmia sp!, {r4,pc}
//! ```
//!
//! ### Algorithm
//!
//! One helper call, two stores, no branches. The helper at 0x0838c7ec is
//! upstream SQLite's `sqlite3VdbeRealValue`: it returns the cell's value
//! as `double`, reusing an existing REAL at +0x08 or converting another
//! numeric representation as needed. This wrapper then stores that `f64`
//! into `Mem.r` (+0x08) and read-modify-writes `Mem.flags` (+0x1c): the
//! low five type bits (`MEM_Null` 0x1 / `MEM_Str` 0x2 / `MEM_Int` 0x4 /
//! `MEM_Real` 0x8 / `MEM_Blob` 0x10) are cleared and `MEM_Real` is set,
//! while every attribute bit above them survives. Unlike the sibling
//! [`vdbe_mem_set_double`](super::vdbe_mem_set_double), this function does
//! **not** stamp `value_type` at +0x1e and does **not** release anything —
//! it purely changes the in-place numeric representation and returns
//! `SQLITE_OK` (0).
//!
//! Call sites (binary-scanned):
//!
//! - `bl` @ 0x082b4784 inside `FUN_082b46f8`.
//! - `bl` @ 0x08387e20 inside the large VDBE routine `FUN_08386ef8`.
//!
//! ### Deviations
//!
//! - The helper `sqlite3VdbeRealValue` @ 0x0838c7ec is not ported yet, so
//!   this module keeps it behind the [`VDBE_MEM_REALIFY_OPS`] seam. On the
//!   target build the wired default calls the retailOS load address
//!   directly; host tests install a recording helper.
//! - The port goes through the typed `repr(C)` [`Mem`] with named fields
//!   (whose +0x08/+0x1c offsets are statically asserted on 32-bit targets
//!   in `sqlite/vdbe.rs`) rather than raw byte offsets, so the host build's
//!   wider pointer fields cannot shift the bytes this function touches.

use super::vdbe::Mem;
use super::vdbe_mem_set_null::MEM_TYPE_BITS;

/// `SQLITE_OK` — the original's `mov r0, #0x0` success return.
pub const SQLITE_OK: i32 = 0;

/// The `MEM_Real` type bit stamped into `Mem.flags` (original:
/// `orr r0, r0, #0x8`).
pub const MEM_REAL: u16 = 0x0008;

/// ABI of `sqlite3VdbeRealValue(pMem)` @ 0x0838c7ec: return the cell's
/// numeric value as `double`.
pub type VdbeRealValue = unsafe extern "C" fn(p_mem: *mut Mem) -> f64;

/// RetailOS load address of `sqlite3VdbeRealValue`.
pub const VDBE_REAL_VALUE_ADDRESS: usize = 0x0838_c7ec;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_vdbe_real_value(p_mem: *mut Mem) -> f64 {
    let real_value: VdbeRealValue = core::mem::transmute(VDBE_REAL_VALUE_ADDRESS);
    real_value(p_mem)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_vdbe_real_value(_p_mem: *mut Mem) -> f64 {
    panic!("vdbe_mem_realify requires sqlite3VdbeRealValue @ 0x0838c7ec")
}

/// Indirect dispatch for the unported real-value helper @ 0x0838c7ec.
#[derive(Clone, Copy)]
pub struct VdbeMemRealifyOps {
    /// `sqlite3VdbeRealValue(p_mem)` @ 0x0838c7ec: return `p_mem`'s value
    /// as `double`, converting its current numeric representation as
    /// needed.
    pub real_value: VdbeRealValue,
}

/// Wired default: on target, call the retailOS helper directly; on host,
/// panic unless a test installs a mock.
#[cfg(target_os = "none")]
pub const DEFAULT_VDBE_MEM_REALIFY_OPS: VdbeMemRealifyOps = VdbeMemRealifyOps {
    real_value: retail_vdbe_real_value,
};

/// Wired default: on host, a missing-helper panic until tests install a
/// mock.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_VDBE_MEM_REALIFY_OPS: VdbeMemRealifyOps = VdbeMemRealifyOps {
    real_value: missing_vdbe_real_value,
};

/// The active real-value helper. Host tests install recording mocks.
pub static mut VDBE_MEM_REALIFY_OPS: VdbeMemRealifyOps = DEFAULT_VDBE_MEM_REALIFY_OPS;

/// Reads the real-value slot (volatile — the slot is meant to be swapped
/// at runtime, and a plain read lets LLVM const-fold the default away).
#[inline(always)]
unsafe fn real_value_op() -> VdbeRealValue {
    core::ptr::read_volatile(core::ptr::addr_of!(VDBE_MEM_REALIFY_OPS.real_value))
}

/// vdbe_mem_realify — original: `FUN_0838c024` @ 0x0838c024 (40 bytes;
/// 2 `bl` call sites).
///
/// `sqlite3VdbeMemRealify`: replace `p_mem`'s numeric representation with a
/// REAL one in place. The helper @ 0x0838c7ec (the
/// [`VDBE_MEM_REALIFY_OPS`] slot) computes the cell's `double` value;
/// that value lands in `Mem.r`, the five `Mem.flags` type bits are
/// replaced by `MEM_Real` while attribute bits survive, and the function
/// returns `SQLITE_OK`. `value_type`, payload pointers/ownership, `db`,
/// `n`, `enc` and the integer arm `u` are deliberately untouched by this
/// wrapper.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_mem_realify(p_mem: *mut Mem) -> i32 {
    let value = (real_value_op())(p_mem);
    let mem = &mut *p_mem;
    mem.r = value;
    mem.flags = (mem.flags & !MEM_TYPE_BITS) | MEM_REAL;
    SQLITE_OK
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    /// Serializes tests that swap the real-value slot.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// What the recording helper returns.
    static mut RETURN_BITS: u64 = 0;
    /// How many times the helper ran.
    static mut CALLS: u32 = 0;
    /// Which `Mem *` the helper saw.
    static mut ARG: usize = 0;
    /// Optional flags overwrite the helper performs before returning.
    static mut HELPER_FLAGS_WRITE: Option<u16> = None;
    /// Optional REAL-arm overwrite the helper performs before returning;
    /// proves the wrapper's final store happens after the call.
    static mut HELPER_R_WRITE: Option<u64> = None;

    unsafe extern "C" fn recording_real_value(p_mem: *mut Mem) -> f64 {
        unsafe {
            CALLS += 1;
            ARG = p_mem as usize;
            if let Some(flags) = HELPER_FLAGS_WRITE {
                (*p_mem).flags = flags;
            }
            if let Some(bits) = HELPER_R_WRITE {
                (*p_mem).r = f64::from_bits(bits);
            }
            f64::from_bits(RETURN_BITS)
        }
    }

    /// Restores the wired default helper on drop.
    struct OpsGuard;

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(VDBE_MEM_REALIFY_OPS).write(DEFAULT_VDBE_MEM_REALIFY_OPS);
            }
        }
    }

    /// Takes the module lock, installs the recording helper, and zeroes
    /// its controls/counters. The guards must stay alive for the whole test.
    fn bench() -> (MutexGuard<'static, ()>, OpsGuard) {
        let ops_guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            RETURN_BITS = 0;
            CALLS = 0;
            ARG = 0;
            HELPER_FLAGS_WRITE = None;
            HELPER_R_WRITE = None;
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(VDBE_MEM_REALIFY_OPS),
                VdbeMemRealifyOps {
                    real_value: recording_real_value,
                },
            );
        }
        (ops_guard, OpsGuard)
    }

    /// A `Mem` with distinguishable garbage in every field, so an
    /// unintended write shows up as a mismatch.
    fn garbage_mem(flags: u16, value_type: u8) -> Mem {
        Mem {
            u: 0x0bad_cafe_dead_beef,
            r: f64::from_bits(0x7ff8_0000_5a5a_5a5a),
            db: 0x0bad_1000usize as *mut u8,
            z: 0x0bad_2000usize as *mut u8,
            n: -123_456_789,
            flags,
            value_type,
            enc: 0xa7,
            x_del: 0x0bad_3000usize as *mut u8,
            z_malloc: 0x0bad_4000usize as *mut u8,
        }
    }

    #[test]
    fn helper_is_called_once_on_the_cell_and_result_lands_bit_for_bit() {
        let _guards = bench();
        let bit_patterns = [
            0x0000_0000_0000_0000u64, // +0.0
            0x8000_0000_0000_0000, // -0.0
            0x3ff0_0000_0000_0000, // 1.0
            0xbff0_0000_0000_0000, // -1.0
            0x0000_0000_0000_0001, // smallest subnormal
            0x7fef_ffff_ffff_ffff, // f64::MAX
            0xffef_ffff_ffff_ffff, // f64::MIN
            0x7ff0_0000_0000_0000, // +inf
            0xfff0_0000_0000_0000, // -inf
            0x7ff8_0000_0000_0000, // NaN payloads are stored verbatim here
            0x3fd5_5555_5555_5555, // arbitrary
        ];
        for bits in bit_patterns {
            let mut mem = garbage_mem(0, 0);
            unsafe {
                RETURN_BITS = bits;
                CALLS = 0;
                ARG = 0;
                vdbe_mem_realify(&mut mem);
            }
            assert_eq!(unsafe { CALLS }, 1, "bits={bits:#018x}");
            assert_eq!(unsafe { ARG }, core::ptr::addr_of!(mem) as usize, "bits={bits:#018x}");
            assert_eq!(mem.r.to_bits(), bits, "bits={bits:#018x}");
        }
    }

    #[test]
    fn flags_replace_only_the_type_bits_for_every_prior_value() {
        let _guards = bench();
        let mut mem = garbage_mem(0, 0);
        for flags in 0..=u16::MAX {
            mem.flags = flags;
            unsafe { vdbe_mem_realify(&mut mem) };
            assert_eq!(mem.flags, (flags & !MEM_TYPE_BITS) | MEM_REAL, "flags={flags:#06x}");
        }
    }

    #[test]
    fn final_flags_are_derived_from_the_post_helper_value() {
        let _guards = bench();
        let injected_flags = 0x0fe7u16;
        let mut mem = garbage_mem(0x1234, 0x5a);
        unsafe {
            HELPER_FLAGS_WRITE = Some(injected_flags);
            vdbe_mem_realify(&mut mem);
        }
        assert_eq!(
            mem.flags,
            (injected_flags & !MEM_TYPE_BITS) | MEM_REAL,
            "the original reloads flags after sqlite3VdbeRealValue returns"
        );
    }

    #[test]
    fn value_type_is_untouched_for_every_prior_type() {
        let _guards = bench();
        let mut mem = garbage_mem(0, 0);
        for value_type in 0..=u8::MAX {
            mem.value_type = value_type;
            unsafe { vdbe_mem_realify(&mut mem) };
            assert_eq!(mem.value_type, value_type, "type={value_type:#04x}");
        }
    }

    #[test]
    fn wrapper_store_happens_after_the_helper_returns() {
        let _guards = bench();
        let mut mem = garbage_mem(0, 0);
        unsafe {
            RETURN_BITS = 0x4009_21fb_5444_2d18; // pi
            HELPER_R_WRITE = Some(0x3ff0_0000_0000_0000); // 1.0
            vdbe_mem_realify(&mut mem);
        }
        assert_eq!(mem.r.to_bits(), 0x4009_21fb_5444_2d18);
    }

    #[test]
    fn unrelated_fields_are_byte_for_byte_untouched_when_helper_only_returns() {
        let _guards = bench();
        let before = garbage_mem(0x0fff, 0xa5);
        let mut mem = garbage_mem(0x0fff, 0xa5);
        unsafe { vdbe_mem_realify(&mut mem) };
        assert_eq!(mem.u, before.u);
        assert_eq!(mem.db, before.db);
        assert_eq!(mem.z, before.z);
        assert_eq!(mem.n, before.n);
        assert_eq!(mem.value_type, before.value_type);
        assert_eq!(mem.enc, before.enc);
        assert_eq!(mem.x_del, before.x_del);
        assert_eq!(mem.z_malloc, before.z_malloc);
    }
}
