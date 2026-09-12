//! Moving a VDBE value cell transfers its payload ownership.
//!
//! `vdbe_mem_move` — original: `FUN_0838bf78` at load address
//! **0x0838bf78** (56 bytes, 0x0838bf78..0x0838bfb0). The next word at
//! 0x0838bfb0 is the separately linked `sqlite3VdbeMemNulTerminate` entry;
//! there is no literal pool. Decoding every ARM `B`/`BL` immediate in
//! `osos.dec` found **7 direct `bl` call sites**, all unconditional and no
//! predicated or tail-branch callers: 0x083874f8, 0x08387a8c, 0x08387b54,
//! 0x083884b0, 0x0838ac60, 0x0838aca0, and 0x083916c8.
//!
//! The raw body calls `sqlite3VdbeMemRelease(p_to)` @ 0x0838c04c, copies the
//! whole 0x28-byte `Mem` from `p_from` to `p_to` through the IRAM memcpy
//! veneer @ 0x08037df8, then leaves `p_from` as a NULL shell: `flags =
//! MEM_Null`, `xDel = NULL`, and `zMalloc = NULL`. Its other fields, notably
//! `z`, deliberately remain, but no longer claim ownership. This is SQLite
//! 3.5.x's `sqlite3VdbeMemMove` ownership transfer primitive.
//!
//! The target's 0x28-byte memcpy is represented as a typed `Mem` copy. That
//! is exactly the target field set on 32-bit ARM while keeping host pointer
//! fields disjoint. The pre-existing `MEM_SET_OPS` release seam is reused;
//! its target default is the already ported `mem_release`, and its host test
//! seam avoids applying target byte offsets to the wider host layout.
//! The three moved-from stores are volatile solely to preserve the raw
//! `flags`, `xDel`, then `zMalloc` store order.

use super::value_new::MEM_NULL;
use super::vdbe::Mem;
use super::vdbe_mem_set_int64::release_op;

/// vdbe_mem_move — original: `FUN_0838bf78` @ 0x0838bf78 (56 bytes; 7
/// unconditional direct `bl` call sites).
///
/// `sqlite3VdbeMemMove`: release `p_to`'s existing dynamic resources, move
/// the full value cell from `p_from`, then make `p_from` a NULL, non-owning
/// shell. The copied `z`, `x_del`, and `z_malloc` therefore belong solely to
/// `p_to` after this call.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_mem_move(p_to: *mut Mem, p_from: *mut Mem) {
    (release_op())(p_to as *mut u8);
    core::ptr::write(p_to, core::ptr::read(p_from));

    let from = &mut *p_from;
    core::ptr::write_volatile(core::ptr::addr_of_mut!(from.flags), MEM_NULL);
    core::ptr::write_volatile(core::ptr::addr_of_mut!(from.x_del), core::ptr::null_mut());
    core::ptr::write_volatile(core::ptr::addr_of_mut!(from.z_malloc), core::ptr::null_mut());
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::vdbe_mem_set_int64::{
        MemSetOps, DEFAULT_MEM_SET_OPS, MEM_SET_OPS,
    };
    use crate::sqlite::vdbe_mem_set_int64::tests::ops_lock;
    use std::sync::MutexGuard;

    static mut RELEASE_CALLS: u32 = 0;
    static mut RELEASE_ARG: usize = 0;
    static mut RELEASE_SAW_U: u64 = 0;
    static mut RELEASE_SAW_FLAGS: u16 = 0;

    unsafe extern "C" fn recording_mem_release(value: *mut u8) {
        let mem = &*(value as *const Mem);
        RELEASE_CALLS += 1;
        RELEASE_ARG = value as usize;
        RELEASE_SAW_U = mem.u;
        RELEASE_SAW_FLAGS = mem.flags;
    }

    /// Restores the shared release slot after a test's recording mock.
    struct OpsGuard;

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(MEM_SET_OPS).write(DEFAULT_MEM_SET_OPS);
            }
        }
    }

    /// Serializes all users of the shared `MEM_SET_OPS` seam, then records
    /// the release call without applying target-layout release code to a
    /// host-layout `Mem`.
    fn bench() -> (MutexGuard<'static, ()>, OpsGuard) {
        let ops_guard = ops_lock().lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            RELEASE_CALLS = 0;
            RELEASE_ARG = 0;
            RELEASE_SAW_U = 0;
            RELEASE_SAW_FLAGS = 0;
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(MEM_SET_OPS),
                MemSetOps { mem_release: recording_mem_release },
            );
        }
        (ops_guard, OpsGuard)
    }

    fn mem(
        u: u64,
        r: f64,
        db: usize,
        z: usize,
        n: i32,
        flags: u16,
        value_type: u8,
        enc: u8,
        x_del: usize,
        z_malloc: usize,
    ) -> Mem {
        Mem {
            u,
            r,
            db: db as *mut u8,
            z: z as *mut u8,
            n,
            flags,
            value_type,
            enc,
            x_del: x_del as *mut u8,
            z_malloc: z_malloc as *mut u8,
        }
    }

    #[test]
    fn releases_destination_before_transferring_every_source_field() {
        let _guards = bench();
        let mut to = mem(
            0x0123_4567_89ab_cdef,
            -42.5,
            0x1000,
            0x2000,
            -7,
            0x0440,
            3,
            2,
            0x3000,
            0x4000,
        );
        let mut from = mem(
            0xfedc_ba98_7654_3210,
            f64::from_bits(0x7ff8_0000_5a5a_5a5a),
            0x5000,
            0x6000,
            i32::MIN,
            0x0c52,
            4,
            1,
            0x7000,
            0x8000,
        );

        unsafe { vdbe_mem_move(&mut to, &mut from) };

        unsafe {
            assert_eq!(RELEASE_CALLS, 1);
            assert_eq!(RELEASE_ARG, &mut to as *mut Mem as usize);
            assert_eq!(RELEASE_SAW_U, 0x0123_4567_89ab_cdef);
            assert_eq!(RELEASE_SAW_FLAGS, 0x0440);
        }
        assert_eq!(to.u, 0xfedc_ba98_7654_3210);
        assert_eq!(to.r.to_bits(), 0x7ff8_0000_5a5a_5a5a);
        assert_eq!(to.db as usize, 0x5000);
        assert_eq!(to.z as usize, 0x6000);
        assert_eq!(to.n, i32::MIN);
        assert_eq!(to.flags, 0x0c52);
        assert_eq!(to.value_type, 4);
        assert_eq!(to.enc, 1);
        assert_eq!(to.x_del as usize, 0x7000);
        assert_eq!(to.z_malloc as usize, 0x8000);
    }

    #[test]
    fn source_becomes_null_without_losing_the_transferred_payload_pointer() {
        let _guards = bench();
        let mut to = mem(1, 1.0, 0x10, 0x20, 3, 4, 5, 6, 0x30, 0x40);
        let mut from = mem(
            u64::MAX,
            -0.0,
            0x1111,
            0x2222,
            i32::MAX,
            0xffff,
            0xff,
            0xee,
            0x3333,
            0x4444,
        );

        unsafe { vdbe_mem_move(&mut to, &mut from) };

        assert_eq!(from.u, u64::MAX);
        assert_eq!(from.r.to_bits(), (-0.0f64).to_bits());
        assert_eq!(from.db as usize, 0x1111);
        assert_eq!(from.z as usize, 0x2222);
        assert_eq!(from.n, i32::MAX);
        assert_eq!(from.flags, MEM_NULL);
        assert_eq!(from.value_type, 0xff);
        assert_eq!(from.enc, 0xee);
        assert!(from.x_del.is_null());
        assert!(from.z_malloc.is_null());
        assert_eq!(to.z as usize, 0x2222);
        assert_eq!(to.x_del as usize, 0x3333);
        assert_eq!(to.z_malloc as usize, 0x4444);
    }
}
