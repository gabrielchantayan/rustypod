//! Constructs three adjacent states with distinct, unrecovered vtables.
//!
//! Original: `FUN_081f4058` @ `0x081f4058`; true size 32 bytes,
//! ending before the independent reset function at `0x081f4078`.
//! Raw decoding verifies three outbound plain BLs and zero predicated BLs.
//! Whole-image branch decoding finds two inbound plain BLs at `0x081e5cdc`
//! and `0x08206c40`, with zero predicated BLs.
//!
//! Algorithm: construct 16-byte records at +0, +16 and +32 in that order.
//! Each resident constructor calls `base_vtable_state_init` (0x081215c8),
//! then replaces its vtable with 0x08988044, 0x08989aa4 or 0x08992394.
//! All callees preserve r0; subtracting 32 returns the original storage.
//!
//! Deliberate deviation: inline the verified derived-vtable replacement from
//! 0x08167444, 0x0818dccc and 0x0820c7fc, reusing the existing base initializer
//! rather than adding firmware seams. No concrete class identity is claimed.

use super::base_vtable_state_init::{base_vtable_state_init, BaseVtableState};

/// Constructs exactly three target-layout records and returns `storage`.
///
/// # Safety
/// `storage` must name three contiguous, writable, word-aligned records
/// (48 bytes). As in retailOS, there are no NULL or bounds checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn triple_vtable_state_construct(storage: *mut BaseVtableState) -> *mut BaseVtableState {
    unsafe {
        let first = base_vtable_state_init(storage);
        (*first).vtable = 0x0898_8044;
        let middle = base_vtable_state_init(first.add(1));
        (*middle).vtable = 0x0898_9aa4;
        let last = base_vtable_state_init(middle.add(1));
        (*last).vtable = 0x0899_2394;
        last.sub(2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructs_distinct_records_without_overwriting_neighbors() {
        for seed in [0, u32::MAX, 0x1357_9bdf] {
            let mut words = [seed; 14];
            words[0] = 0x1234_5678;
            words[13] = 0x8765_4321;
            let start = unsafe { words.as_mut_ptr().add(1).cast::<BaseVtableState>() };
            assert_eq!(unsafe { triple_vtable_state_construct(start) }, start);
            assert_eq!(words, [
                0x1234_5678,
                0x0898_8044, 0, u32::MAX, u32::MAX,
                0x0898_9aa4, 0, u32::MAX, u32::MAX,
                0x0899_2394, 0, u32::MAX, u32::MAX,
                0x8765_4321,
            ]);
        }
    }

    #[test]
    fn reconstruction_replaces_live_state_and_remains_repeatable() {
        let mut records = core::array::from_fn::<_, 3, _>(|i| BaseVtableState {
            vtable: 0x1000 + i as u32,
            state: 1 << i,
            first_sentinel: i as u32,
            second_sentinel: 100 + i as u32,
        });
        for _ in 0..2 {
            unsafe { triple_vtable_state_construct(records.as_mut_ptr()); }
            for (record, vtable) in records.iter().zip([0x0898_8044, 0x0898_9aa4, 0x0899_2394]) {
                assert_eq!([record.vtable, record.state, record.first_sentinel, record.second_sentinel],
                    [vtable, 0, u32::MAX, u32::MAX]);
            }
        }
    }
}
