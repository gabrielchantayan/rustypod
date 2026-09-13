//! Reading a nested container's item count.
//!
//! Original: `FUN_08147600` @ 0x08147600 (12 bytes; 6 verified plain `bl`
//! call sites, 0 predicated). Raw disassembly is `ldr r0,[r0,#0xa4]; ldr
//! r0,[r0,#4]; bx lr`; the next separately linked function begins at
//! 0x0814760c. It loads the owner's nested container at word 41, then returns
//! that container's item-count word.
//!
//! Deliberate deviations: none. Both pointer fields are modeled as target-width
//! `u32` words, so host fixtures use a below-4-GiB mapping.

/// Owner word containing its nested container's target pointer.
const NESTED_CONTAINER_WORD: usize = 41;
/// Nested container word containing its item count.
const CONTAINER_ITEM_COUNT_WORD: usize = 1;

/// nested_container_item_count — original: `FUN_08147600` @ 0x08147600
/// (12 bytes; 6 verified plain `bl` call sites, 0 predicated).
///
/// Returns the item count stored in the nested container referenced by
/// `owner[NESTED_CONTAINER_WORD]`. The retailOS code has no NULL guards for
/// either pointer; this port preserves that contract.
///
/// # Safety
/// `owner` must be valid for an aligned `u32` read at word 41. Its target-width
/// nested-container pointer must name storage valid for an aligned `u32` read
/// at word 1.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn nested_container_item_count(owner: *const u32) -> u32 {
    let container = (*owner.add(NESTED_CONTAINER_WORD) as usize) as *const u32;
    *container.add(CONTAINER_ITEM_COUNT_WORD)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};

    const FIXTURE_LEN: usize = 0x1000;
    const CONTAINER_OFFSET: usize = 0x200;

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::NESTED_CONTAINER_ITEM_COUNT, FIXTURE_LEN)
            .map(|pointer| pointer as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    fn fixture(item_count: u32) -> Option<*mut u32> {
        let base = (*FIXTURE)? as *mut u8;
        unsafe {
            core::ptr::write_bytes(base, 0, FIXTURE_LEN);
            let owner = base.cast::<u32>();
            let container = base.add(CONTAINER_OFFSET).cast::<u32>();
            owner
                .add(NESTED_CONTAINER_WORD)
                .write(container as usize as u32);
            container.add(CONTAINER_ITEM_COUNT_WORD).write(item_count);
            Some(owner)
        }
    }

    #[test]
    fn reads_zero_item_count() {
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(owner) = fixture(0) else {
            assert!(note_missing_u32_fixture("util/nested_container_item_count"));
            return;
        };

        assert_eq!(unsafe { nested_container_item_count(owner) }, 0);
    }

    #[test]
    fn preserves_full_width_item_count() {
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(owner) = fixture(u32::MAX) else {
            assert!(note_missing_u32_fixture("util/nested_container_item_count"));
            return;
        };

        assert_eq!(unsafe { nested_container_item_count(owner) }, u32::MAX);
    }
}
