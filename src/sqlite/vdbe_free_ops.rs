//! Release a contiguous run of VDBE operations.
//!
//! - `vdbe_free_ops` — original: `FUN_08386bf4` @ 0x08386bf4 (80 bytes;
//!   4 direct inbound `bl` call sites, all plain unconditional; no predicated
//!   `bl`). SQLite's `sqlite3VdbeFreeOpArray` range loop.
//!
//! Raw ARM establishes the exact extent `0x08386bf4..0x08386c43`: the final
//! `pop {r4-r6,pc}` is followed by the separately entered `push {r4,lr}` at
//! `0x08386c44`. For every operation in `p->aOp[start..start + count]`, it
//! calls `vdbe_free_p4(op.p4type, op.p4)`, clears all 20 bytes through the
//! IRAM memzero veneer, then sets the opcode byte to 0x17 (`OP_Noop`).
//! Null `p` and null `p->aOp` return; a zero count makes no access.
//!
//! Deliberate deviations: the port calls the verified Rust twins
//! [`vdbe_free_p4`](crate::sqlite::free_p4::vdbe_free_p4) and
//! [`memzero_aligned`](crate::libc::memzero::memzero_aligned) directly rather
//! than reproducing their retailOS call addresses / IRAM veneer. The latter is
//! loaded through a volatile function pointer, preserving the required call
//! instead of allowing LLVM to lower the clear to a builtin. Target pointer
//! fields remain raw 32-bit words, so host fixtures must be below 4 GiB.

use crate::libc::memzero::memzero_aligned;
use crate::sqlite::free_p4::vdbe_free_p4;

const VDBE_OPS_OFFSET: usize = 0x14;
const VDBE_OP_SIZE: usize = 20;
const VDBE_OP_P4TYPE_OFFSET: usize = 1;
const VDBE_OP_P4_OFFSET: usize = 16;
const OP_NOOP: u8 = 0x17;

#[inline(always)]
unsafe fn read_word(address: *const u8) -> u32 {
    unsafe { address.cast::<u32>().read() }
}

/// vdbe_free_ops — original: `FUN_08386bf4` @ 0x08386bf4 (80 bytes; 4 `bl` call sites).
///
/// Release P4 payloads from `count` target-layout `VdbeOp` records beginning
/// at `start`, then convert each record into an `OP_Noop`. The original's
/// counter is an unsigned decrement-and-carry loop: zero performs no work;
/// every other bit pattern consumes records until it wraps to zero.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_free_ops(vdbe: *mut u8, start: u32, mut count: u32) {
    if vdbe.is_null() {
        return;
    }

    let ops = unsafe { read_word(vdbe.add(VDBE_OPS_OFFSET)) } as usize as *mut u8;
    if ops.is_null() {
        return;
    }

    let zero = unsafe {
        core::ptr::read_volatile(
            &(memzero_aligned as unsafe extern "C" fn(*mut u8, usize) -> *mut u8),
        )
    };
    let mut op = unsafe { ops.add(start.wrapping_mul(VDBE_OP_SIZE as u32) as usize) };
    while count != 0 {
        let p4type = unsafe { op.add(VDBE_OP_P4TYPE_OFFSET).read() as i8 as i32 };
        let p4 = unsafe { read_word(op.add(VDBE_OP_P4_OFFSET)) } as usize as *mut u8;
        unsafe { vdbe_free_p4(p4type, p4) };
        unsafe { zero(op, VDBE_OP_SIZE) };
        unsafe { op.write(OP_NOOP) };
        op = unsafe { op.add(VDBE_OP_SIZE) };
        count = count.wrapping_sub(1);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::sqlite::vdbe::P4_STATIC;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    const OPS_OFFSET: usize = 0x100;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::VDBE_FREE_OPS, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    fn fixture() -> Option<*mut u8> {
        let Some(base) = *FIXTURE else {
            assert!(note_missing_u32_fixture("sqlite/vdbe_free_ops"));
            return None;
        };
        let base = base as *mut u8;
        unsafe { base.write_bytes(0, FIXTURE_LEN) };
        Some(base)
    }

    #[test]
    fn null_vdbe_and_null_op_array_leave_memory_untouched() {
        unsafe { vdbe_free_ops(core::ptr::null_mut(), 0, 1) };
        let _guard = FIXTURE_LOCK.lock();
        let Some(base) = fixture() else { return };
        unsafe { vdbe_free_ops(base, 0, 1) };
        assert_eq!(unsafe { base.add(VDBE_OPS_OFFSET).cast::<u32>().read() }, 0);
    }

    #[test]
    fn zero_count_does_not_touch_the_selected_record() {
        let _guard = FIXTURE_LOCK.lock();
        let Some(base) = fixture() else { return };
        let ops = unsafe { base.add(OPS_OFFSET) };
        unsafe { base.add(VDBE_OPS_OFFSET).cast::<u32>().write(ops as u32) };
        unsafe { ops.add(VDBE_OP_SIZE).write_bytes(0xa5, VDBE_OP_SIZE) };
        unsafe { vdbe_free_ops(base, 1, 0) };
        assert!(unsafe { core::slice::from_raw_parts(ops.add(VDBE_OP_SIZE), VDBE_OP_SIZE) }
            .iter()
            .all(|&byte| byte == 0xa5));
    }

    #[test]
    fn releases_only_the_requested_range_and_marks_it_noop() {
        let _guard = FIXTURE_LOCK.lock();
        let Some(base) = fixture() else { return };
        let ops = unsafe { base.add(OPS_OFFSET) };
        unsafe { base.add(VDBE_OPS_OFFSET).cast::<u32>().write(ops as u32) };
        for index in 0..3 {
            let op = unsafe { ops.add(index * VDBE_OP_SIZE) };
            unsafe { op.write_bytes(0xa5, VDBE_OP_SIZE) };
            unsafe { op.add(VDBE_OP_P4TYPE_OFFSET).write(P4_STATIC as u8) };
            unsafe { op.add(VDBE_OP_P4_OFFSET).cast::<u32>().write(1) };
        }

        unsafe { vdbe_free_ops(base, 1, 2) };

        assert_eq!(unsafe { ops.read() }, 0xa5);
        for index in 1..3 {
            let op = unsafe { ops.add(index * VDBE_OP_SIZE) };
            assert_eq!(unsafe { op.read() }, OP_NOOP);
            assert!(unsafe { core::slice::from_raw_parts(op.add(1), VDBE_OP_SIZE - 1) }
                .iter()
                .all(|&byte| byte == 0));
        }
    }
}
