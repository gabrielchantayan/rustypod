//! Service-handler slot bit update.
//!
//! `service_handler_slot_bit_update` — original: `FUN_08193f50` @
//! 0x08193f50 (76 bytes; 18 direct, unconditional `bl` call sites).
//!
//! Raw bytes establish the true extent: 0x08193f50..0x08193f9c, followed by
//! the distinct entry at 0x08193f9c. The 19th instruction is a tail `b` to
//! the separately linked routine at 0x08193fec; Ghidra incorrectly folds that
//! routine into this function. The body selects one of three 0x20-byte slot
//! records, clears bit zero of word +0x0c, sets or clears one bit in word
//! +0x18 according to `enabled`, then restores bit zero only when that bitset
//! is nonzero. It tail-branches to 0x08193fec after the writes.
//!
//! Decoding every ARM `B`/`BL` word in `osos.dec` finds 18 incoming branches:
//! all are unconditional `bl`; there are no predicated calls or tail `b`
//! callers. The raw register shift uses only `bit & 0xff` and yields zero for
//! shift counts 32 through 255, rather than the modulo-32 shift Rust's
//! `wrapping_shl` would perform.
//!
//! Deliberate deviation: the unported tail target @ 0x08193fec is reached by
//! an ordinary indirect call rather than the original tail branch; its
//! identity is not recovered. Firmware calls its verified address directly;
//! host tests replace it through a volatile dispatch seam.

use crate::heap::veneers::heap_panic;
use core::ptr;

type SlotBitUpdateTail = unsafe extern "C" fn(*mut u32);

#[derive(Clone, Copy)]
struct SlotBitUpdateOps {
    tail: SlotBitUpdateTail,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_slot_bit_update_tail(slot_table: *mut u32) {
    let tail: SlotBitUpdateTail = core::mem::transmute(0x0819_3fecusize);
    tail(slot_table);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_slot_bit_update_tail(_slot_table: *mut u32) {}

#[cfg(target_os = "none")]
static mut SLOT_BIT_UPDATE_OPS: SlotBitUpdateOps = SlotBitUpdateOps {
    tail: firmware_slot_bit_update_tail,
};

#[cfg(not(target_os = "none"))]
static mut SLOT_BIT_UPDATE_OPS: SlotBitUpdateOps = SlotBitUpdateOps {
    tail: unavailable_slot_bit_update_tail,
};

#[inline(always)]
unsafe fn slot_bit_update_ops() -> SlotBitUpdateOps {
    ptr::read_volatile(ptr::addr_of!(SLOT_BIT_UPDATE_OPS))
}

/// service_handler_slot_bit_update — original: `FUN_08193f50` @ 0x08193f50
/// (76 bytes; 18 direct unconditional `bl` call sites).
///
/// Updates `bit` in word six of the selected eight-word slot record, and sets
/// bit zero in word three if and only if that updated word is nonzero. Slots
/// three and above terminate through [`heap_panic`]. The tail target at
/// 0x08193fec always runs after the record writes.
///
/// # Safety
///
/// `slot_table` must be the aligned base of at least three eight-word records.
/// The retailOS signed comparison lets negative `slot` values index before the
/// base; this port preserves the unchecked address calculation, so negative
/// slots are not valid Rust memory accesses.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.service_handler_slot_bit_update")]
pub unsafe extern "C" fn service_handler_slot_bit_update(
    slot_table: *mut u32,
    slot: i32,
    bit: u32,
    enabled: u32,
) {
    if slot >= 3 {
        heap_panic();
    }

    let record = slot_table.wrapping_offset(slot.wrapping_shl(3) as isize);
    let status = ptr::read(record.add(3)) & !1;
    ptr::write(record.add(3), status);

    let shift = bit & 0xff;
    let mask = if shift < 32 { 1u32 << shift } else { 0 };
    let bits = ptr::read(record.add(6));
    let bits = if enabled == 0 { bits & !mask } else { bits | mask };
    ptr::write(record.add(6), bits);

    if bits != 0 {
        ptr::write(record.add(3), status | 1);
    }

    (slot_bit_update_ops().tail)(slot_table);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut TAIL_CALLS: u32 = 0;
    static mut TAIL_TABLE: *mut u32 = ptr::null_mut();

    unsafe extern "C" fn recording_tail(slot_table: *mut u32) {
        TAIL_CALLS = TAIL_CALLS.wrapping_add(1);
        TAIL_TABLE = slot_table;
    }

    fn install_recording_tail() -> std::sync::MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            ptr::write_volatile(
                ptr::addr_of_mut!(SLOT_BIT_UPDATE_OPS),
                SlotBitUpdateOps { tail: recording_tail },
            );
            TAIL_CALLS = 0;
            TAIL_TABLE = ptr::null_mut();
        }
        guard
    }

    fn restore_tail(guard: std::sync::MutexGuard<'static, ()>) {
        unsafe {
            ptr::write_volatile(
                ptr::addr_of_mut!(SLOT_BIT_UPDATE_OPS),
                SlotBitUpdateOps { tail: unavailable_slot_bit_update_tail },
            );
        }
        drop(guard);
    }

    #[test]
    fn sets_a_bit_marks_the_record_active_and_then_calls_the_tail() {
        let mut table = [0u32; 24];
        table[8 + 3] = 0xffff_ffff;
        let guard = install_recording_tail();

        unsafe { service_handler_slot_bit_update(table.as_mut_ptr(), 1, 31, 7) };

        assert_eq!(table[8 + 6], 0x8000_0000);
        assert_eq!(table[8 + 3], 0xffff_ffff);
        unsafe {
            assert_eq!(TAIL_CALLS, 1);
            assert_eq!(TAIL_TABLE, table.as_mut_ptr());
        }
        restore_tail(guard);
    }

    #[test]
    fn clears_a_bit_and_clears_only_the_active_status_bit_when_empty() {
        let mut table = [0u32; 24];
        table[16 + 3] = 3;
        table[16 + 6] = 0x8000_0000;
        let guard = install_recording_tail();

        unsafe { service_handler_slot_bit_update(table.as_mut_ptr(), 2, 31, 0) };

        assert_eq!(table[16 + 6], 0);
        assert_eq!(table[16 + 3], 2);
        unsafe { assert_eq!(TAIL_CALLS, 1) };
        restore_tail(guard);
    }

    #[test]
    fn register_shift_counts_above_31_use_arm_zero_mask_semantics() {
        let mut table = [0u32; 24];
        table[3] = 1;
        let guard = install_recording_tail();

        unsafe {
            service_handler_slot_bit_update(table.as_mut_ptr(), 0, 32, 1);
            assert_eq!(table[6], 0);
            assert_eq!(table[3], 0);

            service_handler_slot_bit_update(table.as_mut_ptr(), 0, 0x100, 1);
        }

        assert_eq!(table[6], 1, "the ARM register shift consumes only bits 0..7");
        assert_eq!(table[3], 1);
        unsafe { assert_eq!(TAIL_CALLS, 2) };
        restore_tail(guard);
    }
}
