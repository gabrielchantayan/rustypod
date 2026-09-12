//! `signal_slots_and_clear_values` — original: `FUN_080fd4c0` @ `0x080fd4c0`
//! (80 bytes; eight direct callers, all unconditional `bl`).
//!
//! # Algorithm
//!
//! The owning object's `slot_count` at `+0x468` bounds a contiguous table of
//! 60-byte slot states beginning at `+0x484`. For each slot, a
//! `notification_requested` byte exactly equal to one makes the function call
//! the already ported [`crate::kernel::kobj::mailbox_slot_signal`] on the
//! embedded mailbox slot at `+0x18`, then clears that request byte. It clears
//! the `has_slot_value` and `slot_value` bytes for every slot. Other nonzero
//! notification values neither signal nor change.
//!
//! The original's mailbox pointer is a target-width word. Host builds translate
//! that word directly to [`crate::kernel::csem::csem_signal`], which is the
//! body reached by `mailbox_slot_signal`; this preserves the ARM behavior while
//! avoiding an eight-byte host pointer read from a four-byte firmware field.

#[cfg(not(target_os = "none"))]
use crate::kernel::csem::{csem_signal, CountingSem};
#[cfg(target_os = "none")]
use crate::kernel::kobj::{mailbox_slot_signal, Mailbox};

/// A slot manager's known prefix. The zero-length trailing table begins at the
/// exact firmware offset used by the original.
#[repr(C)]
struct SlotManager {
    _before_slot_count: [u8; 0x468],
    slot_count: u32,
    _before_slots: [u8; 0x18],
    slots: [SlotState; 0],
}

/// The observed 60-byte subset of each slot-table item.
#[repr(C)]
struct SlotState {
    slot_value: u8,
    has_slot_value: u8,
    _before_notification_mailbox: [u8; 0x16],
    #[cfg(target_os = "none")]
    notification_mailbox: *mut Mailbox,
    #[cfg(not(target_os = "none"))]
    notification_mailbox: u32,
    _before_notification_requested: [u8; 4],
    notification_requested: u8,
    _after_notification_requested: [u8; 0x1b],
}

const _: () = assert!(core::mem::size_of::<SlotState>() == 0x3c);
const _: () = assert!(core::mem::offset_of!(SlotManager, slots) == 0x484);
const _: () = assert!(core::mem::offset_of!(SlotState, notification_mailbox) == 0x18);
const _: () = assert!(core::mem::offset_of!(SlotState, notification_requested) == 0x20);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn signal_notification(slot: &mut SlotState) {
    unsafe { mailbox_slot_signal(core::ptr::addr_of_mut!(slot.notification_mailbox)) };
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn signal_notification(slot: &mut SlotState) {
    unsafe { csem_signal(slot.notification_mailbox as usize as *mut CountingSem) };
}

/// Signals slots whose notification request is one, then clears every slot's
/// value-validity state — original: `FUN_080fd4c0` @ `0x080fd4c0` (80 bytes;
/// 8 direct `bl` callers, all unconditional).
///
/// # Safety
///
/// `slot_manager` must point to a writable firmware object containing its
/// declared number of 60-byte slot states at `+0x484`. Every slot whose
/// `notification_requested` byte is one must contain a valid mailbox pointer
/// at `+0x49c`; the original performs no NULL check.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn signal_slots_and_clear_values(slot_manager: *mut SlotManager) {
    let slots = unsafe { (*slot_manager).slots.as_mut_ptr() };
    let mut index = 0u32;

    while index < unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*slot_manager).slot_count)) } {
        let slot = unsafe { &mut *slots.add(index as usize) };
        if unsafe { core::ptr::read_volatile(core::ptr::addr_of!(slot.notification_requested)) } == 1 {
            unsafe { signal_notification(slot) };
            unsafe {
                core::ptr::write_volatile(core::ptr::addr_of_mut!(slot.notification_requested), 0);
            }
        }
        unsafe {
            core::ptr::write_volatile(core::ptr::addr_of_mut!(slot.has_slot_value), 0);
            core::ptr::write_volatile(core::ptr::addr_of_mut!(slot.slot_value), 0);
        }
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    const SLOT_COUNT: usize = 3;
    const SEMAPHORE_OFFSET: usize = 0x600;
    const FIXTURE_LEN: usize = 0x1000;

    #[test]
    fn signals_only_one_and_clears_every_slot_value() {
        let Some(base) = try_map_u32_slab(hints::SLOT_SIGNAL_RESET, FIXTURE_LEN) else {
            assert!(note_missing_u32_fixture("app/slot_signal_reset"));
            return;
        };

        unsafe {
            core::ptr::write_bytes(base, 0, FIXTURE_LEN);
            let manager = base.cast::<SlotManager>();
            (*manager).slot_count = SLOT_COUNT as u32;
            let slots = (*manager).slots.as_mut_ptr();
            let semaphore = base.add(SEMAPHORE_OFFSET).cast::<CountingSem>();
            *semaphore = CountingSem { count: 4, waiter_id: 0x41 };

            (*slots.add(0)).slot_value = 0xa0;
            (*slots.add(0)).has_slot_value = 1;
            (*slots.add(0)).notification_requested = 1;
            (*slots.add(0)).notification_mailbox = semaphore as usize as u32;

            (*slots.add(1)).slot_value = 0xb1;
            (*slots.add(1)).has_slot_value = 1;
            (*slots.add(1)).notification_requested = 2;
            (*slots.add(1)).notification_mailbox = 0;

            (*slots.add(2)).slot_value = 0xc2;
            (*slots.add(2)).has_slot_value = 0;
            (*slots.add(2)).notification_requested = 0;
            (*slots.add(2)).notification_mailbox = 0;

            signal_slots_and_clear_values(manager);

            assert_eq!((*semaphore).count, 3);
            assert_eq!((*slots).notification_requested, 0);
            assert_eq!((*slots.add(1)).notification_requested, 2);
            assert_eq!((*slots.add(2)).notification_requested, 0);
            for index in 0..SLOT_COUNT {
                let slot = &*slots.add(index);
                assert_eq!(slot.slot_value, 0);
                assert_eq!(slot.has_slot_value, 0);
            }

            (*manager).slot_count = 0;
            (*slots).slot_value = 0xd3;
            (*slots).has_slot_value = 1;
            (*slots).notification_requested = 1;
            (*slots).notification_mailbox = semaphore as usize as u32;
            signal_slots_and_clear_values(manager);
            assert_eq!((*semaphore).count, 3);
            assert_eq!((*slots).slot_value, 0xd3);
            assert_eq!((*slots).has_slot_value, 1);
            assert_eq!((*slots).notification_requested, 1);
        }
    }
}
