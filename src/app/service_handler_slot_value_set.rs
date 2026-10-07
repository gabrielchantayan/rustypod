//! Service-handler slot value update.
//!
//! Original: `FUN_08138d34` @ 0x08138d34, 48 code bytes
//! [0x08138d34, 0x08138d64). The literal at 0x08138d64 is
//! 0x08ad0f34; the next real function starts at 0x08138d68.
//! Whole-image aligned A32 decoding finds two incoming plain BL calls
//! (0x08192e2c and 0x08193b84), zero predicated incoming BL calls,
//! and zero outgoing BL calls of either kind.
//!
//! Reject slots other than 1 and 2 using unsigned (slot - 1) < 2,
//! then reject signed values >= 3. Otherwise store the value at +0x08
//! of the selected 0x114-byte fixed-table record and return zero.
//! Rejection returns 9 without touching the table. Negative values are
//! intentionally accepted. The context argument is ignored.
//!
//! Deliberate deviation: hosts use the existing shared slot-table fixture
//! instead of the fixed firmware address. The meaning of word +0x08 is
//! not established; no stronger interpretation is assigned to its value.

use super::service_handler_slot_state_set::slot_states;
use core::ptr;

/// Set the selected slot's signed value, returning 0 on success or 9 on rejection.
///
/// # Safety
/// The shared slot table must be writable and access externally serialized.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.service_handler_slot_value_set")]
pub unsafe extern "C" fn service_handler_slot_value_set(_context: *mut u8, slot: u32, value: i32) -> u32 {
    if slot.wrapping_sub(1) >= 2 || value >= 3 {
        return 9;
    }
    let record = unsafe { slot_states().add(slot as usize) };
    unsafe { ptr::write(record.cast::<i32>().add(2), value) };
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::service_handler_slot_state_set::{HOST_SLOT_STATES, SERVICE_HANDLER_SLOT_STATE_SET_TEST_LOCK};

    #[test]
    fn bounds_signed_values_and_record_isolation() {
        let _guard = SERVICE_HANDLER_SLOT_STATE_SET_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let saved = ptr::read(ptr::addr_of!(HOST_SLOT_STATES));
            let table = ptr::addr_of_mut!(HOST_SLOT_STATES).cast::<u32>();
            const WORDS: usize = 3 * 0x114 / 4;
            for slot in [0, 1, 2, 3, 0x8000_0000, u32::MAX] {
                for value in [i32::MIN, -1, 0, 1, 2, 3, i32::MAX] {
                    let mut expected = [0xa5a5_5a5au32; WORDS];
                    ptr::copy_nonoverlapping(expected.as_ptr(), table, WORDS);
                    let accepted = (slot == 1 || slot == 2) && value < 3;
                    if accepted {
                        expected[slot as usize * 69 + 2] = value as u32;
                    }
                    let result = service_handler_slot_value_set(ptr::null_mut(), slot, value);
                    let actual = core::slice::from_raw_parts(table, WORDS);
                    // Restore before assertions so a failure cannot leak fixture state.
                    let observed = <[u32; WORDS]>::try_from(actual).unwrap();
                    ptr::write(ptr::addr_of_mut!(HOST_SLOT_STATES), saved);
                    assert_eq!(result, if accepted { 0 } else { 9 }, "slot={slot}, value={value}");
                    assert_eq!(observed, expected, "slot={slot}, value={value}");
                }
            }
        }
    }
}
