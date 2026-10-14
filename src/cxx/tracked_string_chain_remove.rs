//! Remove an owned string chain from a tracked slot array.
//!
//! `FUN_083d53f0` @ 0x083d53f0: true extent 76 bytes,
//! [0x083d53f0, 0x083d543c), ending in POP before the next independent PUSH.
//! Raw aligned A32 decoding finds one incoming BLNE at 0x081ee44c, zero
//! incoming plain BLs; two outgoing plain BLs and zero predicated BLs.
//! Reject negative indices and indices >= signed capacity; ignore NULL slots.
//! Drain the selected StringChain, delete its returned owner, reload slot
//! storage, clear the slot, and decrement the current used count modulo 2^32.
//! Ghidra's noreturn delete annotation incorrectly truncates the last 28 bytes.
//! Deliberate deviations: native pointer fields widen on hosts; slot words
//! remain u32. LLVM may replace predication with branches. Internal generic
//! lifecycle injection tests storage/count changes without new firmware seams.
//! Host integration coverage drains a real empty StringChain and unmaps its
//! owner before checking the slot/count update. ARM retains both BLs and the
//! storage/count reloads, but adds a frame pointer and changes registers.

use super::tracked_slot_array_construct::TrackedSlotArray;
use super::string_chain_clear::{string_chain_clear, StringChain};
use crate::heap::veneers::operator_delete;

unsafe fn remove_with(
    array: *mut TrackedSlotArray, index: i32,
    clear: impl FnOnce(*mut StringChain) -> *mut StringChain,
    delete: impl FnOnce(*mut u8),
) {
    if index < 0 || ((*array).slots as i32) <= index {
        return;
    }
    let chain = (*array).data.add(index as usize).read();
    if chain == 0 {
        return;
    }
    let cleared = clear(chain as usize as *mut StringChain);
    delete(cleared.cast());
    (*array).data.add(index as usize).write(0);
    (*array).used = (*array).used.wrapping_sub(1);
}

/// # Safety
/// For nonnegative indices, `array` must be a valid writable tracked array.
/// In-range slots must be readable/writable; nonzero entries must uniquely own
/// valid StringChains suitable for tag-2 deletion. Lifecycle calls must leave
/// the array and its current slot storage valid.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tracked_string_chain_remove(array: *mut TrackedSlotArray, index: i32) {
    remove_with(array, index, |chain| string_chain_clear(chain), |owner| operator_delete(owner));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn array(data: &mut [u32], used: u32) -> TrackedSlotArray {
        TrackedSlotArray {
            data: data.as_mut_ptr(), slots: data.len() as u32, used,
            options: 0x1234, growth: 2, tracker_label: core::ptr::null_mut(),
        }
    }

    #[test]
    fn signed_bounds_and_null_slots_leave_state_unchanged() {
        unsafe {
            tracked_string_chain_remove(core::ptr::null_mut(), -1);
            for capacity in [0, 3, 0x8000_0000, u32::MAX] {
                for index in [i32::MIN, -1, 0, 2, 3, i32::MAX] {
                    let mut slots = [0, 17, 0];
                    let mut owner = array(&mut slots, 7);
                    owner.slots = capacity;
                    if index >= 0 && index < capacity as i32 && index == 1 { continue; }
                    remove_with(&mut owner, index, |_| panic!("unexpected clear"), |_| panic!("unexpected delete"));
                    assert_eq!(slots, [0, 17, 0]);
                    assert_eq!(owner.used, 7);
                    assert_eq!(owner.options, 0x1234);
                }
            }
        }
    }

    #[test]
    fn empty_chain_owner_is_disposed_before_slot_is_cleared() {
        let Some(storage) = crate::testing::try_map_u32_slab(
            crate::testing::hints::TRACKED_STRING_CHAIN_REMOVE, 4096,
        ) else {
            crate::testing::note_missing_u32_fixture("tracked_string_chain_remove");
            return;
        };
        unsafe {
            let chain = storage.cast::<StringChain>();
            chain.write(StringChain { head: core::ptr::null_mut(), scratch: chain.cast() });
            let mut slots = [chain as usize as u32];
            let mut owner = array(&mut slots, 1);
            let pointer = &mut owner as *mut TrackedSlotArray;
            remove_with(pointer, 0, |chain| string_chain_clear(chain), |returned| {
                assert!((*returned.cast::<StringChain>()).head.is_null());
                assert_eq!((*returned.cast::<StringChain>()).scratch, chain.cast());
                assert_eq!((*pointer).data.read(), chain as usize as u32);
                assert_eq!((*pointer).used, 1);
                extern "C" { fn munmap(address: *mut u8, length: usize) -> i32; }
                assert_eq!(munmap(returned, 4096), 0);
            });
            assert_eq!(slots, [0]);
            assert_eq!(owner.used, 0);
        }
    }

    #[test]
    fn every_populated_slot_is_removed_once_including_capacity_minus_one() {
        for index in 0..3 {
            let mut slots = [11, 22, 33];
            let mut owner = array(&mut slots, 3);
            unsafe {
                remove_with(&mut owner, index, |chain| chain, |_| {});
                let mut expected = [11, 22, 33];
                expected[index as usize] = 0;
                assert_eq!(slots, expected);
                assert_eq!(owner.used, 2);
                remove_with(&mut owner, index, |_| panic!("cleared twice"), |_| panic!("deleted twice"));
                assert_eq!(slots, expected);
                assert_eq!(owner.used, 2);
            }
        }
    }

    #[test]
    fn lifecycle_reload_clear_and_wrapping_count() {
        for used in [0, 1, u32::MAX] {
            let mut old = [11, 22, 33];
            let mut replacement = [44, 55, 66];
            let mut owner = array(&mut old, 8);
            let pointer = &mut owner as *mut TrackedSlotArray;
            let mut cleared = false;
            unsafe {
                remove_with(pointer, 1, |chain| {
                    assert_eq!(chain as usize, 22);
                    assert_eq!((*pointer).used, 8);
                    cleared = true;
                    77usize as *mut StringChain
                }, |returned| {
                    assert_eq!(returned as usize, 77);
                    assert_eq!((*pointer).data.add(1).read(), 22);
                    (*pointer).data = replacement.as_mut_ptr();
                    (*pointer).used = used;
                });
                assert!(cleared);
                assert_eq!(old, [11, 22, 33]);
                assert_eq!(replacement, [44, 0, 66]);
                assert_eq!(owner.used, used.wrapping_sub(1));
                assert_eq!(owner.slots, 3);
                assert_eq!(owner.options, 0x1234);
                assert_eq!(owner.growth, 2);
                assert!(owner.tracker_label.is_null());
                remove_with(pointer, 1, |_| panic!("repeated clear"), |_| panic!("repeated delete"));
                assert_eq!(owner.used, used.wrapping_sub(1));
            }
        }
    }
}
