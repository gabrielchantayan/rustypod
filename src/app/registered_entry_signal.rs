//! Registered-entry mailbox signal — `FUN_08293d4c` @ `0x08293d4c`.
//!
//! True extent: 40 bytes, `0x08293d4c..0x08293d74` (36 instruction
//! bytes plus the table literal at `0x08293d70`; next function starts at
//! `0x08293d74`). Raw A32 scanning verifies two inbound plain BL sites
//! (`0x08105038`, `0x08294e00`), zero predicated BL sites, and two outbound
//! plain BL instructions, to four_slot_key_index and mailbox_slot_signal.
//!
//! Select the first record matching the full entry key, load its +4 pointer
//! to a mailbox slot, signal that slot, and return zero. There is no missing
//! key check: -1 indexes the preceding record, just as in stock code.
//! Deliberate deviation: repr(C) native pointers make host fixtures wider;
//! the target record remains exactly six words. Host callers of the export
//! cannot access retail RAM; tests exercise the same indexed signal helper.
use crate::kernel::kobj::{Mailbox, mailbox_slot_signal};
#[cfg(target_os = "none")]
use crate::app::four_slot_key_index::four_slot_key_index;

#[repr(C)]
struct RegistrationEntry {
    key: u32,
    signal_cell: *mut *mut Mailbox,
    remaining: [u32; 4],
}

#[cfg(target_os = "none")]
const _: () = {
    assert!(core::mem::size_of::<RegistrationEntry>() == 0x18);
    assert!(core::mem::offset_of!(RegistrationEntry, signal_cell) == 4);
};

#[inline(always)]
unsafe fn signal_index(table: *const RegistrationEntry, index: i32) -> u32 {
    let cell = (*table.wrapping_offset(index as isize)).signal_cell;
    mailbox_slot_signal(cell);
    0
}

/// Signal the registered entry's mailbox and return zero.
///
/// # Safety
/// The selected (or preceding, for a missing key) retail record must contain
/// a valid mailbox-slot pointer. The mailbox must satisfy csem_signal's
/// kernel synchronization requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn registered_entry_signal(controller: *mut u8, entry_id: u32) -> u32 {
    #[cfg(target_os = "none")]
    {
        let index = four_slot_key_index(controller, entry_id);
        signal_index(0x089d_04c4 as *const RegistrationEntry, index)
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (controller, entry_id);
        panic!("registered_entry_signal requires retailOS addresses on host")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_records_signal_the_indirect_mailbox_without_touching_neighbors() {
        // Positive counts avoid the unrelated kernel wake gateway. A spare
        // preceding record makes the stock unchecked -1 path valid to test.
        for index in [-1, 0, 3] {
            let mut mailboxes = core::array::from_fn::<_, 5, _>(|i| Mailbox { state: 3, id: 0x100 + i as u32 });
            let mut cells = core::array::from_fn::<_, 5, _>(|i| &mut mailboxes[i] as *mut Mailbox);
            let entries = core::array::from_fn::<_, 5, _>(|i| RegistrationEntry {
                key: i as u32, signal_cell: &mut cells[i], remaining: [0xa5a5a5a5; 4],
            });
            let selected = (index + 1) as usize;
            unsafe { assert_eq!(signal_index(entries.as_ptr().add(1), index), 0); }
            for i in 0..5 {
                assert_eq!(mailboxes[i].state, if i == selected { 2 } else { 3 });
                assert_eq!(mailboxes[i].id, 0x100 + i as u32);
                assert_eq!(cells[i], &mut mailboxes[i] as *mut Mailbox);
                assert_eq!(entries[i].remaining, [0xa5a5a5a5; 4]);
            }
        }
    }

}
