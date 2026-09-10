//! `trivial_vector8_destruct` — originals: `FUN_083e1ae4` @ 0x083e1ae4 and
//! `FUN_083e717c` @ 0x083e717c (64 bytes each).
//!
//! Source: `ipod-decomp/decomp/c/038/083e1ae4_FUN_083e1ae4.c` and
//! `ipod-decomp/decomp/c/038/083e717c_FUN_083e717c.c`.
//!
//! The destructors walk the half-open `[begin, end)` range in eight-byte
//! increments. Their element destructors were optimized away because the
//! elements are trivial; the walks are nevertheless retained exactly. They
//! then release the backing allocation and return the vector.
//!
//! Raw ARM confirms both are semantically identical 64-byte spans: they perform
//! the walk, compute `(capacity - begin) >> 3`, clear r2, then call
//! `FUN_08266f2c`. The 0x083e717c instance has ten direct ARM `bl` callers,
//! all unconditional; decoding every ARM B/BL word finds no predicated `bl`
//! or tail `b` callers. That cleanup routine's recovered C signature has only
//! its first argument, so r1/r2 are dead auxiliary registers. The port retains
//! the descriptor reads and calculation while reaching the existing allocator
//! `free` seam with the sole live cleanup argument. The vector descriptor is
//! never written.

type StorageFree = unsafe extern "C" fn(*mut u8);

/// Routes the original cleanup call through the ported allocator seam.
#[inline(never)]
unsafe extern "C" fn free_storage(storage: *mut u8) {
    crate::runtime::malloc_rt::free(storage);
}

/// Destroys a vector whose elements occupy eight bytes, releases its backing
/// allocation, and returns `vector`. `vector` must address three consecutive
/// pointer-width fields: `{begin, end, capacity}`; the range must advance from
/// `begin` to `end` in eight-byte increments, as required by the raw loop.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.trivial_vector8_destruct")]
#[inline(never)]
pub unsafe extern "C" fn trivial_vector8_destruct(vector: *mut *mut u8) -> *mut *mut u8 {
    unsafe { trivial_vector8_destruct_with(vector, free_storage) }
}

/// Separates the raw walk and cleanup call from the allocator seam so host
/// tests can observe the released pointer without freeing fixture data.
#[inline(always)]
unsafe fn trivial_vector8_destruct_with(vector: *mut *mut u8, release: StorageFree) -> *mut *mut u8 {
    unsafe {
        let begin = vector.read();
        let end = vector.add(1).read();
        let capacity = vector.add(2).read();

        let mut current = begin;
        while current != end {
            current = current.wrapping_add(8);
            core::hint::black_box(current);
        }

        let capacity_slots = (capacity as usize).wrapping_sub(begin as usize) >> 3;
        core::hint::black_box(capacity_slots);
        release(begin);
        vector
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static FREE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static FREED_STORAGE: AtomicUsize = AtomicUsize::new(0);
    unsafe extern "C" fn record_free(storage: *mut u8) {
        FREE_CALLS.fetch_add(1, Ordering::SeqCst);
        FREED_STORAGE.store(storage as usize, Ordering::SeqCst);
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct VectorStorage {
        before: usize,
        begin: *mut u8,
        end: *mut u8,
        capacity: *mut u8,
        after: usize,
    }

    #[test]
    fn walks_trivial_elements_releases_begin_and_never_writes_the_descriptor() {
        let mut allocation = [0u8; 32];
        let mut vector = VectorStorage {
            before: 0x1122_3344_5566_7788,
            begin: allocation.as_mut_ptr(),
            end: unsafe { allocation.as_mut_ptr().add(16) },
            capacity: unsafe { allocation.as_mut_ptr().add(32) },
            after: 0x8877_6655_4433_2211,
        };
        let before = vector;
        FREE_CALLS.store(0, Ordering::SeqCst);
        FREED_STORAGE.store(0, Ordering::SeqCst);

        let result = unsafe { trivial_vector8_destruct_with(&mut vector.begin, record_free) };

        assert_eq!(result, core::ptr::addr_of_mut!(vector.begin));
        assert_eq!(vector.before, before.before, "prefix guard");
        assert_eq!(vector.begin, before.begin, "begin");
        assert_eq!(vector.end, before.end, "end");
        assert_eq!(vector.capacity, before.capacity, "capacity");
        assert_eq!(vector.after, before.after, "suffix guard");
        assert_eq!(FREE_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(FREED_STORAGE.load(Ordering::SeqCst), before.begin as usize);

        let mut empty_allocation = [0u8; 8];
        let mut empty_vector = VectorStorage {
            before: 0x1020_3040_5060_7080,
            begin: empty_allocation.as_mut_ptr(),
            end: empty_allocation.as_mut_ptr(),
            capacity: unsafe { empty_allocation.as_mut_ptr().add(8) },
            after: 0x8070_6050_4030_2010,
        };
        let empty_before = empty_vector;
        FREE_CALLS.store(0, Ordering::SeqCst);
        FREED_STORAGE.store(0, Ordering::SeqCst);

        let empty_result = unsafe { trivial_vector8_destruct_with(&mut empty_vector.begin, record_free) };

        assert_eq!(empty_result, core::ptr::addr_of_mut!(empty_vector.begin));
        assert_eq!(empty_vector.before, empty_before.before, "empty prefix guard");
        assert_eq!(empty_vector.begin, empty_before.begin, "empty begin");
        assert_eq!(empty_vector.end, empty_before.end, "empty end");
        assert_eq!(empty_vector.capacity, empty_before.capacity, "empty capacity");
        assert_eq!(empty_vector.after, empty_before.after, "empty suffix guard");
        assert_eq!(FREE_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(FREED_STORAGE.load(Ordering::SeqCst), empty_before.begin as usize);
    }
}
