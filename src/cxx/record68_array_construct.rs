//! Three-word 68-byte-record array constructor at `0x08242ef4`.
//!
//! True extent: 44 bytes (`0x08242ef4..0x08242f20`), including the literal
//! at `0x08242f1c`; executable body: 40 bytes. Raw aligned ARM BL decoding
//! finds two plain incoming calls and zero predicated calls. The body has
//! one plain BL to `0x082ab288` and zero predicated BLs.
//! Clears the used count, stores the requested capacity, allocates capacity
//! elements of size 0x44 with opaque initializer word 0x0824c3d4, stores the
//! returned allocation word, and returns the original object address.
//! Deliberate deviations: none. The allocator uses its existing helper seam;
//! the initializer's identity is not inferred. Pointer storage stays 32-bit
//! even on hosts, matching the three target words rather than host pointers.

/// `array` must point to three writable, aligned target words.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record68_array_construct(array: *mut u32, capacity: u32) -> *mut u32 {
    array.add(1).write(0);
    array.add(2).write(capacity);
    let allocation = crate::runtime::cpp_array_allocate_without_header::cpp_array_allocate_without_header(
        0x44, capacity, 0x0824_c3d4,
    );
    array.write(allocation as usize as u32);
    array
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::pair_header::{PairHeaderElementArrayOps, PAIR_HEADER_ELEMENT_ARRAY_OPS};

    static mut OBJECT: *mut u32 = core::ptr::null_mut();
    static mut CAPACITY: u32 = 0;
    static mut ALLOCATION: u32 = 0;

    unsafe extern "C" fn allocate(
        this: *mut u32, count: u32, size: u32, header: u32, argument: u32,
        initializer: u32, context: u32, allocator: u32, allocator_context: u32,
        flags: u32, zero: u32,
    ) -> *mut u32 {
        assert!(this.is_null());
        assert_eq!(count, CAPACITY);
        assert_eq!(size, 0x44);
        assert_eq!(initializer, 0x0824_c3d4);
        assert_eq!([header, argument, context, allocator, allocator_context, flags, zero], [0; 7]);
        // The header is initialized before allocation, but the old allocation
        // word is untouched until the helper returns.
        assert_eq!(core::slice::from_raw_parts(OBJECT, 3), &[0xdead_beef, 0, CAPACITY]);
        ALLOCATION as usize as *mut u32
    }

    struct Restore(PairHeaderElementArrayOps);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(PAIR_HEADER_ELEMENT_ARRAY_OPS).write_volatile(self.0); }
        }
    }

    #[test]
    fn initializes_header_before_allocation_and_preserves_word_boundaries() {
        let _lock = match crate::testing::CPP_ARRAY_OPS_TEST_LOCK.lock() {
            Ok(guard) => guard,
            Err(error) => panic!("array helper test lock poisoned: {}", error),
        };
        unsafe {
            let _restore = Restore(core::ptr::addr_of!(PAIR_HEADER_ELEMENT_ARRAY_OPS).read_volatile());
            core::ptr::addr_of_mut!(PAIR_HEADER_ELEMENT_ARRAY_OPS).write_volatile(
                PairHeaderElementArrayOps { reset: allocate },
            );
            for (capacity, allocation) in [(0, 0), (2, 0x1234_5000), (16, 0), (u32::MAX, 0xffff_fffc)] {
                let mut words = [0x1122_3344, 0xdead_beef, 0xaaaa_aaaa, 0xbbbb_bbbb, 0x5566_7788];
                OBJECT = words.as_mut_ptr().add(1);
                CAPACITY = capacity;
                ALLOCATION = allocation;
                assert_eq!(record68_array_construct(OBJECT, capacity), OBJECT);
                assert_eq!(words, [0x1122_3344, allocation, 0, capacity, 0x5566_7788]);
            }
        }
    }
}
