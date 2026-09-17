//! Registered-entry activation — original: `FUN_0829331c` @ `0x0829331c`.
//!
//! The true extent is 56 bytes (`0x0829331c..0x08293354`): the word at
//! `0x08293354` is the registration-table literal and `0x08293358` begins a
//! distinct push prologue. Raw ARM decoding finds four inbound plain `bl` call
//! sites (`0x08104f80`, `0x08160c44`, `0x08160c50`, and `0x081e1be0`) and no
//! predicated `bl` forms. The body has two unconditional direct `bl`
//! instructions, to `0x08293048` and `0x081076c0`.
//!
//! It finds the keyed four-slot registration record, calls the unrecovered
//! channel flag-setting target with `controller + 0x34` and `entry_id`, then
//! marks byte `+0x13` in that record active. Deliberate deviation: target builds
//! use the fixed retail table and raw call target; host tests inject both.

#[cfg(target_os = "none")]
use crate::app::four_slot_key_index::four_slot_key_index;

const REGISTRATION_TABLE: usize = 0x089d_04c4;
const ENTRY_SIZE: usize = 0x18;
const ENTRY_ACTIVE_OFFSET: usize = 0x13;
const CONTROLLER_CHANNEL_CONTEXT_OFFSET: usize = 0x34;
const RETAIL_CHANNEL_FLAG_SET: usize = 0x0810_76c0;

type ChannelFlagSet = unsafe extern "C" fn(*mut u8, u32);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_channel_flag_set(context: *mut u8, entry_id: u32) {
    let flag_set: ChannelFlagSet = core::mem::transmute(RETAIL_CHANNEL_FLAG_SET);
    flag_set(context, entry_id);
}

/// Activates the registration selected by `entry_id`.
///
/// # Safety
///
/// `controller` must contain a valid target pointer at `+0x34`. The selected
/// key must exist in the four-entry registration table; retailOS intentionally
/// performs no not-found check before modifying that record.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn registered_entry_activate(controller: *mut u8, entry_id: u32) {
    #[cfg(target_os = "none")]
    {
        let slot_index = four_slot_key_index(controller, entry_id) as usize;
        let context = core::ptr::read(controller.add(CONTROLLER_CHANNEL_CONTEXT_OFFSET).cast::<u32>()) as *mut u8;
        retail_channel_flag_set(context, entry_id);
        core::ptr::write((REGISTRATION_TABLE as *mut u8).add(slot_index * ENTRY_SIZE + ENTRY_ACTIVE_OFFSET), 1);
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (controller, entry_id);
        panic!("registered_entry_activate requires retailOS addresses on host");
    }
}

#[cfg(test)]
unsafe fn registered_entry_activate_with_ops(
    controller: *mut u8,
    channel_context: *mut u8,
    entry_id: u32,
    slot_index: usize,
    registration_table: *mut u8,
    flag_set: ChannelFlagSet,
) {
    flag_set(channel_context, entry_id);
    core::ptr::write(registration_table.add(slot_index * ENTRY_SIZE + ENTRY_ACTIVE_OFFSET), 1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static mut EXPECTED_CONTEXT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn flag_set(context: *mut u8, entry_id: u32) {
        assert_eq!(context, EXPECTED_CONTEXT);
        assert_eq!(entry_id, 0x83);
        assert_eq!(CALLS.fetch_add(1, Ordering::SeqCst), 0);
    }

    #[test]
    fn marks_only_selected_registration_after_channel_call() {
        let mut controller = [0u8; CONTROLLER_CHANNEL_CONTEXT_OFFSET + 4];
        let mut context = [0u8; 1];
        let mut table = [0xa5u8; ENTRY_SIZE * 4];
        let selected = 2;
        table[selected * ENTRY_SIZE + ENTRY_ACTIVE_OFFSET] = 0;
        unsafe {
            EXPECTED_CONTEXT = context.as_mut_ptr();
            CALLS.store(0, Ordering::SeqCst);
            registered_entry_activate_with_ops(controller.as_mut_ptr(), context.as_mut_ptr(), 0x83, selected, table.as_mut_ptr(), flag_set);
        }
        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(table[selected * ENTRY_SIZE + ENTRY_ACTIVE_OFFSET], 1);
        assert!(table[..selected * ENTRY_SIZE + ENTRY_ACTIVE_OFFSET].iter().all(|&byte| byte == 0xa5));
        assert!(table[selected * ENTRY_SIZE + ENTRY_ACTIVE_OFFSET + 1..].iter().all(|&byte| byte == 0xa5));
    }

    #[test]
    fn supports_first_registration_entry() {
        let mut controller = [0u8; CONTROLLER_CHANNEL_CONTEXT_OFFSET + 4];
        let mut context = [0u8; 1];
        let mut table = [0xa5u8; ENTRY_SIZE * 4];
        unsafe {
            EXPECTED_CONTEXT = context.as_mut_ptr();
            CALLS.store(0, Ordering::SeqCst);
            registered_entry_activate_with_ops(controller.as_mut_ptr(), context.as_mut_ptr(), 0x83, 0, table.as_mut_ptr(), flag_set);
        }
        assert_eq!(table[ENTRY_ACTIVE_OFFSET], 1);
        assert!(table[ENTRY_ACTIVE_OFFSET + 1..].iter().all(|&byte| byte == 0xa5));
    }
}
