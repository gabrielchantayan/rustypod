//! SQLite VDBE memory-cell affinity application.
//!
//! `vdbe_mem_apply_affinity` — original: `FUN_082b4694` @ `0x082b4694`
//! (100 bytes, `0x082b4694..0x082b46f8`; **9 `bl` call sites: 8
//! unconditional `bl`, 1 `bleq`; no tail-`b` call sites), binary-scanned
//! from `osos.dec`. The immediately following word, `stmdb sp!, {r0,r1,r2,r3,
//! r4,lr}` @ `0x082b46f8`, starts the distinct numeric-affinity helper; there
//! is no literal pool.
//!
//! This is SQLite 3.5.9's `sqlite3VdbeMemApplyAffinity` (`vdbe.c`). Text
//! affinity stringifies a numeric cell only when it has no string
//! representation, then removes its numeric representations. No-affinity is a
//! no-op. Every other affinity first applies numeric affinity, then applies
//! integer affinity only when that left a REAL representation.
//!
//! The numeric- and integer-affinity helpers at `0x082b46f8` and `0x0838b644`
//! are not ported. They are an explicit dispatch boundary: target builds call
//! their retailOS bodies and host tests install faithful local observations.
//! `sqlite3VdbeMemStringify` @ `0x0838c32c` is already ported and is called
//! directly. No deliberate behavioral deviations.

use super::vdbe::Mem;
use super::vdbe_mem_realify::MEM_REAL;
use super::vdbe_mem_set_int64::MEM_INT;
use super::vdbe_mem_set_str::MEM_STR;
use super::vdbe_mem_stringify::vdbe_mem_stringify;

/// SQLite's TEXT affinity byte (`'a'`, tested by `cmp r1,#0x61`).
pub const SQLITE_AFF_TEXT: u8 = b'a';
/// SQLite's no-affinity byte (`'b'`, tested by `cmp r1,#0x62`).
pub const SQLITE_AFF_NONE: u8 = b'b';

/// The numeric representations cleared after stringification (`MEM_Int | MEM_Real`).
const MEM_NUMERIC: u16 = MEM_INT | MEM_REAL;

/// RetailOS load address of `sqlite3VdbeMemApplyNumericAffinity`.
#[cfg(target_os = "none")]
const VDBE_MEM_APPLY_NUMERIC_AFFINITY_ADDRESS: usize = 0x082b_46f8;
/// RetailOS load address of `sqlite3VdbeIntegerAffinity`.
#[cfg(target_os = "none")]
const VDBE_INTEGER_AFFINITY_ADDRESS: usize = 0x0838_b644;

/// ABI shared by the two unported in-place affinity helpers.
pub type VdbeMemAffinity = unsafe extern "C" fn(p_mem: *mut Mem);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_vdbe_mem_apply_numeric_affinity(p_mem: *mut Mem) {
    let apply_numeric_affinity: VdbeMemAffinity =
        core::mem::transmute(VDBE_MEM_APPLY_NUMERIC_AFFINITY_ADDRESS);
    apply_numeric_affinity(p_mem);
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_vdbe_integer_affinity(p_mem: *mut Mem) {
    let integer_affinity: VdbeMemAffinity = core::mem::transmute(VDBE_INTEGER_AFFINITY_ADDRESS);
    integer_affinity(p_mem);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_vdbe_mem_apply_numeric_affinity(_p_mem: *mut Mem) {
    panic!("vdbe_mem_apply_affinity requires sqlite3VdbeMemApplyNumericAffinity @ 0x082b46f8")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_vdbe_integer_affinity(_p_mem: *mut Mem) {
    panic!("vdbe_mem_apply_affinity requires sqlite3VdbeIntegerAffinity @ 0x0838b644")
}

/// The two affinity operations performed on non-text, non-none input.
#[derive(Clone, Copy)]
pub struct VdbeMemApplyAffinityOps {
    /// `sqlite3VdbeMemApplyNumericAffinity(pMem)` @ `0x082b46f8`.
    pub apply_numeric: VdbeMemAffinity,
    /// `sqlite3VdbeIntegerAffinity(pMem)` @ `0x0838b644`.
    pub integer: VdbeMemAffinity,
}

/// Target defaults branch into the original unported affinity helpers.
#[cfg(target_os = "none")]
pub const DEFAULT_VDBE_MEM_APPLY_AFFINITY_OPS: VdbeMemApplyAffinityOps =
    VdbeMemApplyAffinityOps {
        apply_numeric: retail_vdbe_mem_apply_numeric_affinity,
        integer: retail_vdbe_integer_affinity,
    };

/// Host defaults fail loudly until a test supplies the unported helpers.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_VDBE_MEM_APPLY_AFFINITY_OPS: VdbeMemApplyAffinityOps =
    VdbeMemApplyAffinityOps {
        apply_numeric: missing_vdbe_mem_apply_numeric_affinity,
        integer: missing_vdbe_integer_affinity,
    };

/// Active numeric/integer-affinity operations. Host tests replace this slot.
pub static mut VDBE_MEM_APPLY_AFFINITY_OPS: VdbeMemApplyAffinityOps =
    DEFAULT_VDBE_MEM_APPLY_AFFINITY_OPS;

#[inline(always)]
unsafe fn apply_numeric_op() -> VdbeMemAffinity {
    core::ptr::read_volatile(core::ptr::addr_of!(VDBE_MEM_APPLY_AFFINITY_OPS.apply_numeric))
}

#[inline(always)]
unsafe fn integer_op() -> VdbeMemAffinity {
    core::ptr::read_volatile(core::ptr::addr_of!(VDBE_MEM_APPLY_AFFINITY_OPS.integer))
}

/// vdbe_mem_apply_affinity — original: `FUN_082b4694` @ `0x082b4694` (100
/// bytes; 9 `bl` call sites: 8 unconditional, 1 `bleq`).
///
/// `sqlite3VdbeMemApplyAffinity`: TEXT affinity renders an otherwise numeric
/// cell to text through [`vdbe_mem_stringify`] and then clears `MEM_Int` and
/// `MEM_Real`; NONE preserves the cell. All remaining affinity classes call
/// numeric affinity, and a resulting REAL is passed to integer affinity. The
/// return values of the callees are deliberately ignored, matching the ARM.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_mem_apply_affinity(p_mem: *mut Mem, affinity: u8, enc: u8) {
    if affinity == SQLITE_AFF_TEXT {
        let flags = (*p_mem).flags;
        if flags & MEM_STR == 0 && flags & MEM_NUMERIC != 0 {
            vdbe_mem_stringify(p_mem.cast(), enc);
        }
        (*p_mem).flags &= !MEM_NUMERIC;
        return;
    }

    if affinity == SQLITE_AFF_NONE {
        return;
    }

    (apply_numeric_op())(p_mem);
    if (*p_mem).flags & MEM_REAL != 0 {
        (integer_op())(p_mem);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use super::super::vdbe_mem_set_str::MEM_TERM;
    use super::super::vdbe_mem_stringify::{
        VdbeMemStringifyOps, DEFAULT_VDBE_MEM_STRINGIFY_OPS, VDBE_MEM_STRINGIFY_OPS,
    };
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static STRINGIFY_OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut NUMERIC_CALLS: usize = 0;
    static mut INTEGER_CALLS: usize = 0;
    static mut NUMERIC_FLAGS: u16 = 0;
    static mut FORMATTED: [u8; 32] = [0; 32];
    static mut STRINGIFY_GROW_CALLS: usize = 0;
    static mut STRINGIFY_ENCODING: u8 = 0;

    struct ApplyOpsGuard {
        original: VdbeMemApplyAffinityOps,
    }

    impl Drop for ApplyOpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(VDBE_MEM_APPLY_AFFINITY_OPS),
                    self.original,
                );
            }
        }
    }

    struct StringifyOpsGuard {
        original: VdbeMemStringifyOps,
    }

    impl Drop for StringifyOpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(VDBE_MEM_STRINGIFY_OPS),
                    self.original,
                );
            }
        }
    }

    unsafe extern "C" fn recording_numeric(p_mem: *mut Mem) {
        NUMERIC_CALLS += 1;
        (*p_mem).flags = NUMERIC_FLAGS;
    }

    unsafe extern "C" fn recording_integer(_p_mem: *mut Mem) {
        INTEGER_CALLS += 1;
    }

    unsafe extern "C" fn stringify_grow(p_mem: *mut Mem, size: i32, preserve: i32) -> i32 {
        assert_eq!((size, preserve), (0x20, 0));
        STRINGIFY_GROW_CALLS += 1;
        (*p_mem).z = core::ptr::addr_of_mut!(FORMATTED).cast();
        (*p_mem).z_malloc = core::ptr::addr_of_mut!(FORMATTED).cast();
        0
    }

    unsafe extern "C" fn stringify_snprintf(
        size: i32,
        z: *mut u8,
        _fmt: *const u8,
        _value_bits: u64,
    ) -> i32 {
        assert_eq!(size, 0x20);
        z.write(b'4');
        z.add(1).write(b'2');
        z.add(2).write(0);
        2
    }

    unsafe extern "C" fn stringify_recode(_p_mem: *mut u8, enc: u8) -> i32 {
        STRINGIFY_ENCODING = enc;
        0
    }

    fn mem(flags: u16) -> Mem {
        Mem {
            u: 42,
            r: 42.0,
            db: core::ptr::null_mut(),
            z: core::ptr::null_mut(),
            n: -1,
            flags,
            value_type: 0xa5,
            enc: 0xa5,
            x_del: core::ptr::null_mut(),
            z_malloc: core::ptr::null_mut(),
        }
    }

    fn install_apply_ops() -> ApplyOpsGuard {
        unsafe {
            let original = core::ptr::read_volatile(core::ptr::addr_of!(VDBE_MEM_APPLY_AFFINITY_OPS));
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(VDBE_MEM_APPLY_AFFINITY_OPS),
                VdbeMemApplyAffinityOps {
                    apply_numeric: recording_numeric,
                    integer: recording_integer,
                },
            );
            ApplyOpsGuard { original }
        }
    }

    fn install_stringify_ops() -> StringifyOpsGuard {
        unsafe {
            let original = core::ptr::read_volatile(core::ptr::addr_of!(VDBE_MEM_STRINGIFY_OPS));
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(VDBE_MEM_STRINGIFY_OPS),
                VdbeMemStringifyOps {
                    grow: stringify_grow,
                    snprintf: stringify_snprintf,
                    change_encoding: stringify_recode,
                },
            );
            StringifyOpsGuard { original }
        }
    }

    fn ops_lock() -> MutexGuard<'static, ()> {
        OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn text_affinity_stringifies_numeric_then_drops_numeric_bits() {
        let _ops_lock = ops_lock();
        let _stringify_ops_lock = STRINGIFY_OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _stringify_ops = install_stringify_ops();
        unsafe {
            FORMATTED = [0; 32];
            STRINGIFY_GROW_CALLS = 0;
            STRINGIFY_ENCODING = 0;
            let mut value = mem(MEM_INT | 0x0400);
            vdbe_mem_apply_affinity(&mut value, SQLITE_AFF_TEXT, 3);
            assert_eq!(STRINGIFY_GROW_CALLS, 1);
            assert_eq!(STRINGIFY_ENCODING, 3);
            assert_eq!(&FORMATTED[..3], b"42\0");
            assert_eq!(value.flags, MEM_STR | MEM_TERM | 0x0400);
            assert_eq!(value.n, 2);
            assert_eq!(value.value_type, 0xa5);
        }
    }

    #[test]
    fn text_affinity_never_stringifies_existing_text_and_clears_both_numeric_bits() {
        let _ops_lock = ops_lock();
        let mut value = mem(MEM_STR | MEM_INT | MEM_REAL | 0x0400);
        unsafe { vdbe_mem_apply_affinity(&mut value, SQLITE_AFF_TEXT, 1) };
        assert_eq!(value.flags, MEM_STR | 0x0400);
    }

    #[test]
    fn none_affinity_preserves_the_cell_without_calling_helpers() {
        let _ops_lock = ops_lock();
        let _apply_ops = install_apply_ops();
        unsafe {
            NUMERIC_CALLS = 0;
            INTEGER_CALLS = 0;
            let mut value = mem(MEM_INT | MEM_REAL | 0x0400);
            let before = value.flags;
            vdbe_mem_apply_affinity(&mut value, SQLITE_AFF_NONE, 1);
            assert_eq!(value.flags, before);
            assert_eq!((NUMERIC_CALLS, INTEGER_CALLS), (0, 0));
        }
    }

    #[test]
    fn non_text_affinity_applies_integer_affinity_only_after_numeric_leaves_real() {
        let _ops_lock = ops_lock();
        let _apply_ops = install_apply_ops();
        unsafe {
            NUMERIC_CALLS = 0;
            INTEGER_CALLS = 0;
            NUMERIC_FLAGS = MEM_REAL | 0x0400;
            let mut value = mem(MEM_STR);
            vdbe_mem_apply_affinity(&mut value, b'c', 1);
            assert_eq!((NUMERIC_CALLS, INTEGER_CALLS), (1, 1));
            assert_eq!(value.flags, MEM_REAL | 0x0400);

            NUMERIC_CALLS = 0;
            INTEGER_CALLS = 0;
            NUMERIC_FLAGS = MEM_INT;
            vdbe_mem_apply_affinity(&mut value, b'd', 1);
            assert_eq!((NUMERIC_CALLS, INTEGER_CALLS), (1, 0));
        }
    }
}
