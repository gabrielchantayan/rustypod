//! Intrusive linked-list append — original: `FUN_0828013c` @ **0x0828013c**
//! (40 bytes, 0x0828013c..0x08280164, 10 ARM instructions, no literal pool).
//! The next separately linked function begins at 0x08280164. Raw ARM decoding
//! finds **4 direct `bl` call sites**, all unconditional plain `bl` (zero
//! predicated `bl` forms): 0x081c1e78, 0x081c1e84, 0x081c1e90, and 0x081c7df8.
//!
//! Appends a nonzero opaque node word to a two-word list anchor. An empty
//! anchor receives the node as its head; otherwise the old tail's first word
//! becomes the node. The anchor tail is always replaced. A zero node leaves
//! memory untouched and returns one; successful insertion returns zero.
//!
//! # Deliberate deviations
//!
//! The firmware represents both node links and node addresses as 32-bit words.
//! The Rust ABI keeps the node as `u32`, rather than a host pointer, so target
//! offsets and stores remain exact on 64-bit host test builds.

/// Two target-width words holding an intrusive-list head and tail.
#[repr(C)]
pub struct LinkedListAnchor {
    pub head: u32,
    pub tail: u32,
}

/// Allocate an empty intrusive-list anchor — `FUN_080b3eac` @ 0x080b3eac.
///
/// True extent: 20 bytes, [0x080b3eac, 0x080b3ec0), not Ghidra's 36.
/// Whole-image A32 decoding verifies two incoming plain BLs (0x081c1d1c,
/// 0x081c7dec), zero predicated incoming BLs, and one outgoing plain BL
/// to operator_new @ 0x082aadd4. Allocate eight bytes, then tail-transfer
/// to 0x08280164, which clears the head and tail and preserves r0.
///
/// Deliberate deviations: inline the verified two-store initializer rather
/// than introducing another port/seam; reuse the existing tag-2 allocator.
/// Target-width fields preserve the eight-byte layout on hosts. As in stock,
/// allocation failure is not checked: the allocator must return writable,
/// word-aligned storage, or execution faults.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn linked_list_new() -> *mut LinkedListAnchor {
    let anchor = unsafe { crate::heap::veneers::operator_new(8) }.cast::<LinkedListAnchor>();
    unsafe {
        core::ptr::addr_of_mut!((*anchor).head).write(0);
        core::ptr::addr_of_mut!((*anchor).tail).write(0);
    }
    anchor
}

/// Appends `node` to `anchor`, returning zero on success and one for a null
/// node. Every nonzero `anchor.tail` must be a writable node whose first word
/// is its next-link field; as in retailOS, `anchor` is not NULL-checked.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.linked_list_append")]
pub unsafe extern "C" fn linked_list_append(anchor: *mut LinkedListAnchor, node: u32) -> u32 {
    if node == 0 {
        return 1;
    }

    let tail = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*anchor).tail)) };
    if tail == 0 {
        unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!((*anchor).head), node) };
    } else {
        unsafe { core::ptr::write_volatile(tail as usize as *mut u32, node) };
    }
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!((*anchor).tail), node) };
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex as TestMutex};

    const WORDS: usize = 5;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::LINKED_LIST_APPEND, WORDS * core::mem::size_of::<u32>())
            .map(|address| address as usize)
    });
    static TEST_LOCK: TestMutex<()> = TestMutex::new(());

    fn slab() -> Option<*mut u32> {
        (*SLAB).map(|address| address as *mut u32)
    }

    #[test]
    fn new_clears_dirty_anchor_without_touching_neighbor_words() {
        let _guard = crate::heap::veneers::tests::mock_heap();
        let mut words = [0x1234_5678, u32::MAX, 0x89ab_cdef, 0xa5a5_a5a5];
        let storage = unsafe { words.as_mut_ptr().add(1) };
        crate::heap::veneers::tests::set_alloc_ret(storage.cast());
        let anchor = unsafe { linked_list_new() };
        assert_eq!(anchor.cast::<u32>(), storage);
        assert_eq!(words, [0x1234_5678, 0, 0, 0xa5a5_a5a5]);
        assert_eq!(unsafe { linked_list_append(anchor, 0) }, 1);
        assert_eq!(words, [0x1234_5678, 0, 0, 0xa5a5_a5a5]);
    }

    #[test]
    fn appends_to_empty_then_nonempty_anchor() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(words) = slab() else {
            assert!(note_missing_u32_fixture("util/linked_list_append"));
            return;
        };
        unsafe {
            core::ptr::write_bytes(words, 0, WORDS);
            let anchor = words.cast::<LinkedListAnchor>();
            let first = words.add(2) as usize as u32;
            let second = words.add(3) as usize as u32;

            assert_eq!(linked_list_append(anchor, first), 0);
            assert_eq!((*anchor).head, first);
            assert_eq!((*anchor).tail, first);
            assert_eq!(*words.add(2), 0);

            assert_eq!(linked_list_append(anchor, second), 0);
            assert_eq!((*anchor).head, first);
            assert_eq!((*anchor).tail, second);
            assert_eq!(*words.add(2), second);
            assert_eq!(*words.add(3), 0);
        }
    }

    #[test]
    fn null_node_preserves_every_word() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(words) = slab() else {
            assert!(note_missing_u32_fixture("util/linked_list_append"));
            return;
        };
        unsafe {
            let anchor = words.cast::<LinkedListAnchor>();
            let tail = words.add(2) as usize as u32;
            *words = 0x1111_1111;
            *words.add(1) = tail;
            *words.add(2) = 0x3333_3333;
            *words.add(3) = 0x4444_4444;
            *words.add(4) = 0x5555_5555;

            assert_eq!(linked_list_append(anchor, 0), 1);
            assert_eq!(*words, 0x1111_1111);
            assert_eq!(*words.add(1), tail);
            assert_eq!(*words.add(2), 0x3333_3333);
            assert_eq!(*words.add(3), 0x4444_4444);
            assert_eq!(*words.add(4), 0x5555_5555);
        }
    }
}
