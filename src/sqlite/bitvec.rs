//! SQLite's adaptive `Bitvec` ownership cleanup.
//!
//! The 512-byte target object starts with `iSize`, `nSet`, and `iDivisor`.
//! For sets at most 4,000 bits wide, the remaining 500 bytes are an inline
//! bitmap. A nonzero `iDivisor` instead selects the 125-slot child-pointer
//! representation. This is SQLite 3.5.9's `bitvec.c` layout.

use crate::heap::tracked::tracked_free;

/// Number of words/pointers in a target `Bitvec` union.
pub const BITVEC_NPTR: usize = 125;

/// SQLite's adaptive bitmap / child-node set.
///
/// `children` overlays the inline bitmap. It is read only when `i_divisor` is
/// nonzero, so the widened host pointers cannot be mistaken for bitmap words.
#[repr(C)]
pub struct Bitvec {
    /// +0x00: number of bits represented.
    pub size: u32,
    /// +0x04: number of bits currently set.
    pub n_set: u32,
    /// +0x08: zero for the inline bitmap; nonzero for child pointers.
    pub i_divisor: u32,
    /// +0x0c on ARM: inline bitmap or 125 recursive child pointers.
    pub children: [*mut Bitvec; BITVEC_NPTR],
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x0c] = [0; core::mem::offset_of!(Bitvec, children)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x200] = [0; core::mem::size_of::<Bitvec>()];

/// sqlite3_bitvec_destroy — original `FUN_08370588` @ `0x08370588`
/// (64 bytes, `0x08370588..0x083705c8`; **9 direct `bl` call sites**, all
/// unconditional, and no incoming tail `b`, verified by decoding every ARM
/// B/BL word in `osos.dec`).
///
/// A NULL node is ignored. A node with a nonzero divisor recursively destroys
/// all 125 child slots in ascending order; each recursive NULL is ignored.
/// The node itself is then released through SQLite's tracked allocator. This
/// preserves the raw function's tail branch to `tracked_free` as an equivalent
/// direct Rust call. Deliberate deviation: named `#[repr(C)]` fields model the
/// target union instead of literal offsets, so host pointer widening cannot
/// overlap target fields.
///
/// # Safety
///
/// `bitvec` must be NULL or a live tracked-allocation payload containing a
/// valid [`Bitvec`]. When `i_divisor` is nonzero, every child slot must be NULL
/// or another valid tracked `Bitvec` payload, without cycles.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.sqlite3_bitvec_destroy")]
pub unsafe extern "C" fn sqlite3_bitvec_destroy(bitvec: *mut Bitvec) {
    if bitvec.is_null() {
        return;
    }

    if (*bitvec).i_divisor != 0 {
        let mut index = 0;
        while index < BITVEC_NPTR {
            sqlite3_bitvec_destroy((*bitvec).children[index]);
            index += 1;
        }
    }

    tracked_free(bitvec.cast());
}
#[cfg(test)]
mod tests {
    extern crate std;
    use super::{sqlite3_bitvec_destroy, Bitvec, BITVEC_NPTR};
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::{HeapVeneerOps, HEAP_OPS};
    use parking_lot::Mutex;
    use std::boxed::Box;
    use std::vec;
    use std::vec::Vec;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static FREED: Mutex<Vec<(usize, usize)>> = Mutex::new(Vec::new());

    unsafe extern "C" fn record_free(
        _heap: *mut HeapDescriptorDescriptor,
        block: *mut u8,
        tag: usize,
    ) {
        FREED.lock().push((block as usize, tag));
    }

    struct HeapOpsGuard(HeapVeneerOps);

    impl Drop for HeapOpsGuard {
        fn drop(&mut self) {
            unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(HEAP_OPS), self.0) };
        }
    }

    unsafe fn install_free_recorder() -> HeapOpsGuard {
        let saved = core::ptr::read_volatile(core::ptr::addr_of!(HEAP_OPS));
        let mut replacement = saved;
        replacement.free = record_free;
        core::ptr::write_volatile(core::ptr::addr_of_mut!(HEAP_OPS), replacement);
        HeapOpsGuard(saved)
    }

    /// A live `Bitvec` payload with the exact tracked-free header immediately
    /// before it. The recorder owns no allocation, so the backing bytes remain
    /// valid until this fixture drops.
    struct TrackedBitvec {
        storage: Box<[u8]>,
        node: *mut Bitvec,
        raw: *mut u8,
    }

    impl TrackedBitvec {
        fn new(divisor: u32) -> Self {
            let mut storage = vec![0; core::mem::size_of::<Bitvec>() + 80].into_boxed_slice();
            let raw = storage.as_mut_ptr();
            let base = unsafe { raw.add(8) };
            let node = ((base as usize + 36 + 31) & !31) as *mut Bitvec;
            assert!((node as usize) + core::mem::size_of::<Bitvec>() <= (raw as usize) + storage.len());

            unsafe {
                (raw as *mut i32).write(0);
                (raw.add(4) as *mut i32).write(0);
                (node.cast::<u8>().sub(4) as *mut u32).write((node as usize - base as usize) as u32);
                node.write(Bitvec {
                    size: 0,
                    n_set: 0,
                    i_divisor: divisor,
                    children: [core::ptr::null_mut(); BITVEC_NPTR],
                });
            }

            Self { storage, node, raw }
        }
    }

    #[test]
    fn null_is_ignored() {
        unsafe { sqlite3_bitvec_destroy(core::ptr::null_mut()) };
    }

    #[test]
    fn inline_bitmap_words_are_not_treated_as_children() {
        let _guard = TEST_LOCK.lock();
        let _heap_ops = unsafe { install_free_recorder() };
        FREED.lock().clear();

        let parent = TrackedBitvec::new(0);
        let child = TrackedBitvec::new(0);
        unsafe { (*parent.node).children[0] = child.node };
        unsafe { sqlite3_bitvec_destroy(parent.node) };

        assert_eq!(*FREED.lock(), vec![(parent.raw as usize, 57)]);
        assert!(!child.storage.is_empty());
    }

    #[test]
    fn child_nodes_are_destroyed_in_slot_order_before_parent() {
        let _guard = TEST_LOCK.lock();
        let _heap_ops = unsafe { install_free_recorder() };
        FREED.lock().clear();

        let parent = TrackedBitvec::new(1);
        let first = TrackedBitvec::new(0);
        let last = TrackedBitvec::new(0);
        unsafe {
            (*parent.node).children[0] = first.node;
            (*parent.node).children[BITVEC_NPTR - 1] = last.node;
            sqlite3_bitvec_destroy(parent.node);
        }

        assert_eq!(
            *FREED.lock(),
            vec![(first.raw as usize, 57), (last.raw as usize, 57), (parent.raw as usize, 57)],
            "all NULL slots are no-ops; non-NULL descendants precede their owner"
        );
        assert!(!first.storage.is_empty() && !last.storage.is_empty());
    }
}
