//! SQLite's adaptive `Bitvec` ownership cleanup.
//!
//! The 512-byte target object starts with `iSize`, `nSet`, and `iDivisor`.
//! For sets at most 4,000 bits wide, the remaining 500 bytes are an inline
//! bitmap. A nonzero `iDivisor` instead selects the 125-slot child-pointer
//! representation. This is SQLite 3.5.9's `bitvec.c` layout.

use crate::heap::tracked::tracked_free;

/// Number of words/pointers in a target `Bitvec` union.
pub const BITVEC_NPTR: usize = 125;

/// SQLite's adaptive bitmap / child-pointer/hash-table storage.
///
/// On ARM this union occupies exactly the 500 bytes after the three-word
/// header. On a 64-bit host, the child view is wider, but the bitmap and hash
/// views retain their target element widths.
#[repr(C)]
pub union BitvecStorage {
    /// Inline bit set for vectors no wider than 4,000 bits.
    pub bitmap: [u8; 500],
    /// Open-addressed set members for a wide vector without child nodes.
    pub hashes: [u32; BITVEC_NPTR],
    /// Recursive child vectors for a wide vector with a divisor.
    pub children: [*mut Bitvec; BITVEC_NPTR],
}

/// SQLite's adaptive bitmap / child-node set.
#[repr(C)]
pub struct Bitvec {
    /// +0x00: number of bits represented.
    pub size: u32,
    /// +0x04: number of bits currently set.
    pub n_set: u32,
    /// +0x08: zero for bitmap/hash storage; nonzero for child pointers.
    pub i_divisor: u32,
    /// +0x0c on ARM: inline bitmap, hashes, or 125 recursive child pointers.
    pub storage: BitvecStorage,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x0c] = [0; core::mem::offset_of!(Bitvec, storage)];
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
            sqlite3_bitvec_destroy((*bitvec).storage.children[index]);
            index += 1;
        }
    }

    tracked_free(bitvec.cast());
}

/// sqlite3_bitvec_test — original `FUN_08370738` @ `0x08370738`
/// (184 bytes, `0x08370738..0x083707f0`; **8 direct `bl` call sites**, all
/// unconditional, verified by decoding every ARM B/BL word in `osos.dec`).
///
/// Returns false for a NULL vector, zero bit number, or a bit outside the
/// vector's declared size. Small vectors test their inline bitmap. Larger
/// vectors either descend through the divisor-selected child and residual bit
/// number, or probe their 125-slot linear hash table using `(bit * 37) % 125`.
/// The division helper preserves the retailOS quotient/remainder split.
///
/// Deliberate deviation: the target's union is a named [`BitvecStorage`]
/// rather than overlapping literal byte offsets, so host pointer widening
/// cannot make the bitmap or hash views overlap incorrectly.
///
/// # Safety
///
/// `bitvec` must be NULL or point to a valid target-layout [`Bitvec`]. A
/// nonzero divisor requires valid child pointers for every non-NULL child.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.sqlite3_bitvec_test")]
pub unsafe extern "C" fn sqlite3_bitvec_test(mut bitvec: *const Bitvec, mut bit: u32) -> u32 {
    loop {
        if bitvec.is_null() || (*bitvec).size < bit || bit == 0 {
            return 0;
        }

        if (*bitvec).size <= 4_000 {
            let bit = bit - 1;
            let mask = 1u8 << (bit & 7);
            return ((*(*bitvec).storage.bitmap.get_unchecked((bit >> 3) as usize) & mask) != 0) as u32;
        }

        let divisor = (*bitvec).i_divisor;
        if divisor != 0 {
            let mut remainder = 0;
            let child_index = crate::runtime::rt_div::__rt_udivmod(
                bit - 1,
                divisor,
                core::ptr::addr_of_mut!(remainder),
            );
            bitvec = *(*bitvec).storage.children.get_unchecked(child_index as usize);
            bit = remainder.wrapping_add(1);
            continue;
        }

        let mut remainder = 0;
        crate::runtime::rt_div::__rt_udivmod(
            bit.wrapping_mul(37),
            BITVEC_NPTR as u32,
            core::ptr::addr_of_mut!(remainder),
        );
        loop {
            let candidate = *(*bitvec).storage.hashes.get_unchecked(remainder as usize);
            if candidate == 0 {
                return 0;
            }
            if candidate == bit {
                return 1;
            }
            remainder += 1;
            if remainder == BITVEC_NPTR as u32 {
                remainder = 0;
            }
        }
    }
}
#[cfg(test)]
mod tests {
    extern crate std;
    use super::{sqlite3_bitvec_destroy, sqlite3_bitvec_test, Bitvec, BitvecStorage, BITVEC_NPTR};
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
                    storage: BitvecStorage { children: [core::ptr::null_mut(); BITVEC_NPTR] },
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
        unsafe { (*parent.node).storage.children[0] = child.node };
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
            (*parent.node).storage.children[0] = first.node;
            (*parent.node).storage.children[BITVEC_NPTR - 1] = last.node;
            sqlite3_bitvec_destroy(parent.node);
        }

        assert_eq!(
            *FREED.lock(),
            vec![(first.raw as usize, 57), (last.raw as usize, 57), (parent.raw as usize, 57)],
            "all NULL slots are no-ops; non-NULL descendants precede their owner"
        );
        assert!(!first.storage.is_empty() && !last.storage.is_empty());
    }

    #[test]
    fn test_rejects_null_zero_and_out_of_range_bits() {
        let bitvec = Box::new(Bitvec {
            size: 1,
            n_set: 0,
            i_divisor: 0,
            storage: BitvecStorage { bitmap: [0; 500] },
        });

        unsafe {
            assert_eq!(sqlite3_bitvec_test(core::ptr::null(), 1), 0);
            assert_eq!(sqlite3_bitvec_test(bitvec.as_ref(), 0), 0);
            assert_eq!(sqlite3_bitvec_test(bitvec.as_ref(), 2), 0);
        }
    }

    #[test]
    fn test_reads_inline_bitmap_first_and_last_bits() {
        let mut bitvec = Box::new(Bitvec {
            size: 4_000,
            n_set: 2,
            i_divisor: 0,
            storage: BitvecStorage { bitmap: [0; 500] },
        });
        unsafe {
            bitvec.storage.bitmap[0] = 0x01;
            bitvec.storage.bitmap[499] = 0x80;
            assert_eq!(sqlite3_bitvec_test(bitvec.as_ref(), 1), 1);
            assert_eq!(sqlite3_bitvec_test(bitvec.as_ref(), 4_000), 1);
            assert_eq!(sqlite3_bitvec_test(bitvec.as_ref(), 2), 0);
        }
    }

    #[test]
    fn test_descends_using_quotient_and_remainder() {
        let mut child = Box::new(Bitvec {
            size: 4_000,
            n_set: 1,
            i_divisor: 0,
            storage: BitvecStorage { bitmap: [0; 500] },
        });
        let mut parent = Box::new(Bitvec {
            size: 4_001,
            n_set: 1,
            i_divisor: 4_000,
            storage: BitvecStorage { children: [core::ptr::null_mut(); BITVEC_NPTR] },
        });
        unsafe {
            child.storage.bitmap[0] = 0x01;
            parent.storage.children[1] = child.as_mut();
            assert_eq!(sqlite3_bitvec_test(parent.as_ref(), 4_001), 1);
            parent.storage.children[1] = core::ptr::null_mut();
            assert_eq!(sqlite3_bitvec_test(parent.as_ref(), 4_001), 0);
        }
    }

    #[test]
    fn test_probes_hash_table_across_final_slot() {
        let mut bitvec = Box::new(Bitvec {
            size: 4_001,
            n_set: 2,
            i_divisor: 0,
            storage: BitvecStorage { hashes: [0; BITVEC_NPTR] },
        });
        unsafe {
            bitvec.storage.hashes[124] = 27;
            bitvec.storage.hashes[0] = 152;
            assert_eq!(sqlite3_bitvec_test(bitvec.as_ref(), 152), 1);
            assert_eq!(sqlite3_bitvec_test(bitvec.as_ref(), 277), 0);
        }
    }
}
