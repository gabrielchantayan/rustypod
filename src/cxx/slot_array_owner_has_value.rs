//! Slot presence predicate — original: `FUN_081ef074` @ `0x081ef074`.
//!
//! True extent: 20 bytes, ending with pop {pc} at 0x081ef084; the next
//! function starts at 0x081ef088. Raw-word scanning finds two inbound plain
//! BLs (0x081ee60c, 0x081ee964), zero predicated BLs, and one outbound plain
//! BL to the existing slot_array_owner_get at 0x081ef078.
//! Algorithm: forward owner and signed index to the checked getter, then
//! normalize its returned target word to exactly zero or one. No deliberate
//! behavioral deviations; reuse the getter's volatile target-width accesses.

use super::slot_array_owner_get::{slot_array_owner_get, SlotArrayOwner};

/// Return one for a nonzero slot value, zero for an empty or invalid slot.
///
/// # Safety
/// The owner and its slot array must meet `slot_array_owner_get`'s readable
/// memory requirements; in-range indices require readable element storage.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn slot_array_owner_has_value(owner: *const SlotArrayOwner, index: i32) -> u32 {
    (slot_array_owner_get(owner, index) != 0) as u32
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::slot_array_index_in_bounds::SlotArray;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SLOT_ARRAY_OWNER_HAS_VALUE, 0x1000)
            .map(|pointer| pointer as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn normalizes_values_and_rejects_invalid_indices_without_storage_reads() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(base) = *FIXTURE else {
            assert!(note_missing_u32_fixture("cxx/slot_array_owner_has_value"));
            return;
        };
        unsafe {
            let slots = base as *mut SlotArray;
            let storage = (base + 0x100) as *mut u32;
            let values = [0, 1, 0x8000_0000, u32::MAX, 0];
            for (index, value) in values.iter().enumerate() {
                storage.add(index).write(*value);
            }
            slots.write(SlotArray { storage: storage as usize as u32, capacity: 5, count: 0 });
            let owner = SlotArrayOwner {
                opaque_00: 0, opaque_04: 0, opaque_08: 0, slots: base as u32,
            };
            for (index, expected) in [0, 1, 1, 1, 0].iter().enumerate() {
                assert_eq!(slot_array_owner_has_value(&owner, index as i32), *expected);
            }
            (*slots).storage = 0;
            for index in [i32::MIN, -1, 5, i32::MAX] {
                assert_eq!(slot_array_owner_has_value(&owner, index), 0);
            }
            for capacity in [0, -1] {
                (*slots).capacity = capacity;
                assert_eq!(slot_array_owner_has_value(&owner, 0), 0);
            }
        }
    }
}
