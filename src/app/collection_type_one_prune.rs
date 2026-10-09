//! Remove type-one entries from an embedded collection.

use core::ptr;
use crate::app::vtable_set::{iterator_state_construct, iterator_state_next, iterator_state_seek, iterator_state_cleanup};

/// collection_type_one_prune — original: `FUN_08100678` @ 0x08100678.
/// True size: 120 bytes, ending at the distinct prologue at 0x081006f0.
/// Verified raw callers: two plain BL (0x081011a0, 0x0810188c), zero
/// predicated BL. The body contains five plain BL and zero predicated BL.
///
/// Clears owner+0x90 before constructing a five-word iterator over owner+0x28
/// at -2. For each entry whose first byte equals 1, invokes the stock
/// find-and-remove helper with (collection, entry), clears the entry local,
/// and seeks back to -2. Always cleans up the iterator after exhaustion.
///
/// Deliberate deviations: the iterator local is zero-initialized; its
/// constructor owns every subsequently read field. The unported helper at
/// 0x0839c084 remains a stock firmware call, with a test-only replacement.
/// Raw r1 at 0x081006b8 is the entry loaded at 0x081006a4, not an omitted
/// argument as suggested by Ghidra's caller decompile.
///
/// # Safety
/// `owner` must contain a valid collection at +0x28 and writable byte +0x90.
/// Yielded entries must be readable and accepted by the collection's removal
/// helper. As in retailOS, removal must make progress for iteration to end.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn collection_type_one_prune(owner: *mut u8) {
    owner.add(0x90).write(0);
    let collection = owner.add(0x28);
    let mut iterator = [0u32; 5];
    let state = iterator.as_mut_ptr();
    let mut entry = ptr::null_mut::<u8>();
    iterator_state_construct(state, collection, -2);
    while iterator_state_next(state, ptr::addr_of_mut!(entry).cast()) != 0 {
        if entry.read() == 1 {
            #[cfg(test)]
            let remove = ptr::read_volatile(ptr::addr_of!(COLLECTION_REMOVE_ENTRY));
            #[cfg(not(test))]
            let remove: unsafe extern "C" fn(*mut u8, *mut u8) -> i32 =
                core::mem::transmute(0x0839c084usize);
            remove(collection, entry);
            entry = ptr::null_mut();
            iterator_state_seek(state, -2);
        }
    }
    iterator_state_cleanup(state);
}

#[cfg(test)]
static mut COLLECTION_REMOVE_ENTRY: unsafe extern "C" fn(*mut u8, *mut u8) -> i32 = missing_remove;
#[cfg(test)]
unsafe extern "C" fn missing_remove(_: *mut u8, _: *mut u8) -> i32 {
    panic!("collection removal fixture not installed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::vtable_set::{tests::{SLOT_TEST_LOCK, SlotGuard}, ITERATOR_STATE_FETCH, ITERATOR_STATE_REFRESH};
    use crate::testing::{hints, try_map_u32_slab};

    // Fixture collection: count at target word +4, followed by byte-valued
    // entries at +0x20. Removal compacts them, making stale cursors skip items.
    unsafe extern "C" fn refresh(state: *mut u32) {
        let position = state.add(2).read() as i32;
        state.add(3).write(if position == -2 { 0 } else { position.wrapping_add(1) as u32 });
    }

    unsafe extern "C" fn fetch(state: *mut u32, out: *mut u8) -> u32 {
        let collection = state.read() as usize as *mut u8;
        assert_eq!(collection.sub(0x28).add(0x90).read(), 0);
        let position = state.add(2).read() as i32;
        let count = collection.add(4).cast::<u32>().read();
        if position < 0 || position as u32 >= count { return 0; }
        out.cast::<*mut u8>().write(collection.add(0x20 + position as usize));
        1
    }

    unsafe extern "C" fn remove(collection: *mut u8, entry: *mut u8) -> i32 {
        let index = entry.offset_from(collection.add(0x20)) as usize;
        let count = collection.add(4).cast::<u32>();
        let len = count.read() as usize;
        assert!(index < len);
        assert_eq!(entry.read(), 1);
        ptr::copy(entry.add(1), entry, len - index - 1);
        count.write((len - 1) as u32);
        index as i32
    }

    #[test]
    fn pruning_restarts_after_compaction_and_preserves_other_types() {
        let _lock = SLOT_TEST_LOCK.lock();
        let _restore = SlotGuard;
        let Some(owner) = try_map_u32_slab(hints::COLLECTION_TYPE_ONE_PRUNE, 0x1000) else { return; };
        unsafe {
            ptr::addr_of_mut!(ITERATOR_STATE_REFRESH).write_volatile(refresh);
            ptr::addr_of_mut!(ITERATOR_STATE_FETCH).write_volatile(fetch);
            ptr::addr_of_mut!(COLLECTION_REMOVE_ENTRY).write_volatile(remove);
            for (input, expected) in [
                (&[][..], &[][..]),
                (&[0, 2, 255][..], &[0, 2, 255][..]),
                (&[1][..], &[][..]),
                (&[1, 1, 1][..], &[][..]),
                (&[0, 1, 1, 2, 1, 255, 1][..], &[0, 2, 255][..]),
            ] {
                ptr::write_bytes(owner, 0xa5, 0x1000);
                let collection = owner.add(0x28);
                collection.add(4).cast::<u32>().write(input.len() as u32);
                collection.add(0x0c).cast::<u32>().write(0);
                ptr::copy_nonoverlapping(input.as_ptr(), collection.add(0x20), input.len());
                collection_type_one_prune(owner);
                assert_eq!(owner.add(0x90).read(), 0);
                assert_eq!(owner.add(0x8f).read(), 0xa5);
                assert_eq!(owner.add(0x91).read(), 0xa5);
                assert_eq!(collection.add(4).cast::<u32>().read() as usize, expected.len());
                assert_eq!(core::slice::from_raw_parts(collection.add(0x20), expected.len()), expected);
            }
            ptr::addr_of_mut!(COLLECTION_REMOVE_ENTRY).write_volatile(missing_remove);
        }
    }
}
