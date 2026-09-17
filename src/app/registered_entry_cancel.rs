//! Registered-entry cancellation prologue — original: `FUN_08293384` @
//! `0x08293384`.
//!
//! The true extent is 88 bytes (`0x08293384..0x082933dc`): the following
//! word is this body's table-address literal and `0x082933e0` starts a new
//! push prologue. Raw ARM decoding finds four inbound plain `bl` call sites
//! (`0x08104f50`, `0x08160bb4`, `0x081e1a64`, and `0x08294acc`) and no
//! predicated `bl` forms. This 22-word body contains two unconditional direct
//! `bl` instructions, to `0x08107700` and `0x08293048`, then tail-branches to
//! `0x082931e4`.
//!
//! It deactivates the channel selected by `entry_id` using the controller's
//! `+0x34` context, locates its four-slot registration record, clears bytes
//! `+0x13` and `+0x14`, clears word `+0x08`, writes `0xff` at `+0x10`, and
//! tail-dispatches the remaining cancellation work. The three external
//! routines do not have recovered semantic identities; target builds call
//! their verified retail addresses. Deliberate deviation: host tests inject
//! those calls and a local registration table because retail RAM is unmapped.

#[cfg(target_os = "none")]
use crate::app::four_slot_key_index::four_slot_key_index;

const REGISTRATION_TABLE: usize = 0x089d_04c4;
const ENTRY_SIZE: usize = 0x18;
const ENTRY_STATE_OFFSET: usize = 0x08;
const ENTRY_BYTE_10_OFFSET: usize = 0x10;
const ENTRY_BYTE_13_OFFSET: usize = 0x13;
const ENTRY_BYTE_14_OFFSET: usize = 0x14;
const CONTROLLER_CHANNEL_CONTEXT_OFFSET: usize = 0x34;
const RETAIL_CHANNEL_DEACTIVATE: usize = 0x0810_7700;
const RETAIL_CANCELLATION_TAIL: usize = 0x0829_31e4;

type ChannelDeactivate = unsafe extern "C" fn(*mut u8, u32);
type CancellationTail = unsafe extern "C" fn(*mut u8, u32);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_channel_deactivate(context: *mut u8, entry_id: u32) {
    let deactivate: ChannelDeactivate = core::mem::transmute(RETAIL_CHANNEL_DEACTIVATE);
    deactivate(context, entry_id);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_cancellation_tail(controller: *mut u8, entry_id: u32) {
    let tail: CancellationTail = core::mem::transmute(RETAIL_CANCELLATION_TAIL);
    tail(controller, entry_id);
}

/// Begins cancellation of the registration selected by `entry_id`.
///
/// # Safety
///
/// `controller` must have a valid target pointer at `+0x34`. The selected key
/// must exist in the four-entry table at `0x089d04c4`; retailOS intentionally
/// performs no not-found check before modifying that record.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn registered_entry_cancel(controller: *mut u8, entry_id: u32) {
    #[cfg(target_os = "none")]
    {
        let channel_context = core::ptr::read(controller.add(CONTROLLER_CHANNEL_CONTEXT_OFFSET).cast::<u32>()) as *mut u8;
        retail_channel_deactivate(channel_context, entry_id);
        let slot_index = four_slot_key_index(controller, entry_id) as usize;
        let entry = (REGISTRATION_TABLE as *mut u8).add(slot_index * ENTRY_SIZE);
        core::ptr::write(entry.add(ENTRY_BYTE_13_OFFSET), 0);
        core::ptr::write(entry.add(ENTRY_BYTE_14_OFFSET), 0);
        core::ptr::write(entry.add(ENTRY_STATE_OFFSET).cast::<u32>(), 0);
        core::ptr::write(entry.add(ENTRY_BYTE_10_OFFSET), 0xff);
        retail_cancellation_tail(controller, entry_id);
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (controller, entry_id);
        panic!("registered_entry_cancel requires retailOS addresses on host");
    }
}

#[cfg(test)]
unsafe fn registered_entry_cancel_with_ops(
    controller: *mut u8,
    channel_context: *mut u8,
    entry_id: u32,
    slot_index: usize,
    registration_table: *mut u8,
    deactivate: ChannelDeactivate,
    tail: CancellationTail,
) {
    deactivate(channel_context, entry_id);
    let entry = registration_table.add(slot_index * ENTRY_SIZE);
    core::ptr::write(entry.add(ENTRY_BYTE_13_OFFSET), 0);
    core::ptr::write(entry.add(ENTRY_BYTE_14_OFFSET), 0);
    core::ptr::write(entry.add(ENTRY_STATE_OFFSET).cast::<u32>(), 0);
    core::ptr::write(entry.add(ENTRY_BYTE_10_OFFSET), 0xff);
    tail(controller, entry_id);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static mut EXPECTED_CONTEXT: *mut u8 = core::ptr::null_mut();
    static mut EXPECTED_CONTROLLER: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn deactivate(context: *mut u8, entry_id: u32) {
        assert_eq!(context, EXPECTED_CONTEXT);
        assert_eq!(entry_id, 0x83);
        assert_eq!(CALLS.fetch_add(1, Ordering::SeqCst), 0);
    }

    unsafe extern "C" fn finish(controller: *mut u8, entry_id: u32) {
        assert_eq!(controller, EXPECTED_CONTROLLER);
        assert_eq!(entry_id, 0x83);
        assert_eq!(CALLS.fetch_add(1, Ordering::SeqCst), 1);
    }

    #[test]
    fn clears_only_selected_registration_entry_between_required_calls() {
        let mut controller = [0u8; CONTROLLER_CHANNEL_CONTEXT_OFFSET + 4];
        let mut context = [0u8; 1];
        let mut table = [0xa5u8; ENTRY_SIZE * 4];
        let selected = 2;
        {
            let entry = &mut table[selected * ENTRY_SIZE..(selected + 1) * ENTRY_SIZE];
            entry[ENTRY_STATE_OFFSET..ENTRY_STATE_OFFSET + 4].copy_from_slice(&0xfeed_beefu32.to_ne_bytes());
            entry[ENTRY_BYTE_10_OFFSET] = 0x44;
            entry[ENTRY_BYTE_13_OFFSET] = 0x55;
            entry[ENTRY_BYTE_14_OFFSET] = 0x66;
        }
        unsafe {
            EXPECTED_CONTEXT = context.as_mut_ptr();
            EXPECTED_CONTROLLER = controller.as_mut_ptr();
            CALLS.store(0, Ordering::SeqCst);
            registered_entry_cancel_with_ops(controller.as_mut_ptr(), context.as_mut_ptr(), 0x83, selected, table.as_mut_ptr(), deactivate, finish);
        }
        let entry = &table[selected * ENTRY_SIZE..(selected + 1) * ENTRY_SIZE];
        assert_eq!(CALLS.load(Ordering::SeqCst), 2);
        assert_eq!(&entry[ENTRY_STATE_OFFSET..ENTRY_STATE_OFFSET + 4], &[0; 4]);
        assert_eq!(entry[ENTRY_BYTE_10_OFFSET], 0xff);
        assert_eq!(entry[ENTRY_BYTE_13_OFFSET], 0);
        assert_eq!(entry[ENTRY_BYTE_14_OFFSET], 0);
        assert!(table[..selected * ENTRY_SIZE].iter().all(|&byte| byte == 0xa5));
        assert!(table[(selected + 1) * ENTRY_SIZE..].iter().all(|&byte| byte == 0xa5));
    }
}
