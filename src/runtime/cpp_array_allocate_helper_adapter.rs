//! ARM ADS array allocation helper adapter.
//!
//! Original: `FUN_082ab400` @ `0x082ab400`, exactly 84 bytes through
//! `0x082ab454`, the next real prologue. Raw A32 words verify two incoming
//! plain BLs (0x082ab280, 0x082ab2a8), zero predicated BLs, and one outgoing
//! plain BL to 0x082b498c, zero predicated.
//!
//! Expands (count, size, header_bytes, initializer, initializer_context) to
//! (null, count, size, header_bytes, 0, initializer, initializer_context,
//! 0, 0, 0, 0). No arithmetic or validation is performed; r0 survives the
//! epilogue, so Ghidra's void return is incorrect.
//!
//! Deliberate deviation: the unported 0x082b498c dependency uses the existing
//! exact-ABI PAIR_HEADER_ELEMENT_ARRAY_OPS seam, as in neighboring ports.
//! This port does not implement the dependency's allocation algorithm.

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cpp_array_allocate_helper_adapter(
    element_count: u32,
    element_size: u32,
    allocation_header_bytes: u32,
    element_initializer: u32,
    initializer_context: u32,
) -> *mut u32 {
    let allocate = core::ptr::addr_of!(crate::cxx::pair_header::PAIR_HEADER_ELEMENT_ARRAY_OPS.reset)
        .read_volatile();
    allocate(
        core::ptr::null_mut(), element_count, element_size, allocation_header_bytes,
        0, element_initializer, initializer_context, 0, 0, 0, 0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::pair_header::{PairHeaderElementArrayOps, PAIR_HEADER_ELEMENT_ARRAY_OPS};

    static mut STORAGE: [u32; 8] = [0; 8];

    // Bounded behavioral model of the dependency's header and initializer paths.
    // Initializer tokens are not host function pointers narrowed to ARM words.
    unsafe extern "C" fn bounded_helper(
        destination: *mut u32, count: u32, size: u32, header: u32,
        source: u32, initializer: u32, _context: u32,
        allocator: u32, _allocator_context: u32, _flags: u32, zero: u32,
    ) -> *mut u32 {
        assert!(destination.is_null());
        assert_eq!((source, allocator, zero), (0, 0, 0));
        let bytes = count.checked_mul(size).and_then(|n| n.checked_add(header));
        if !matches!(bytes, Some(0..=32)) { return core::ptr::null_mut(); }
        let result = core::ptr::addr_of_mut!(STORAGE).cast::<u8>().add(header as usize).cast::<u32>();
        if header != 0 {
            result.sub(2).write(size);
            result.sub(1).write(count);
        }
        if initializer == 1 {
            for index in 0..count {
                result.cast::<u8>().add((index * size) as usize).cast::<u32>().write(0xabc0_0000);
            }
        }
        result
    }

    struct OpsGuard(PairHeaderElementArrayOps);
    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(PAIR_HEADER_ELEMENT_ARRAY_OPS).write_volatile(self.0); }
        }
    }

    #[test]
    fn header_empty_array_and_allocation_failure() {
        let _lock = crate::testing::CPP_ARRAY_OPS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let _restore = OpsGuard(core::ptr::addr_of!(PAIR_HEADER_ELEMENT_ARRAY_OPS).read_volatile());
            core::ptr::addr_of_mut!(PAIR_HEADER_ELEMENT_ARRAY_OPS).write_volatile(
                PairHeaderElementArrayOps { reset: bounded_helper },
            );
            STORAGE = [0xfeed_face; 8];
            let array = cpp_array_allocate_helper_adapter(3, 4, 8, 1, 0);
            assert_eq!(array.sub(2).read(), 4);
            assert_eq!(array.sub(1).read(), 3);
            assert_eq!(core::slice::from_raw_parts(array, 3), &[0xabc0_0000; 3]);
            assert_eq!(array.add(3).read(), 0xfeed_face);

            STORAGE = [0xfeed_face; 8];
            let empty = cpp_array_allocate_helper_adapter(0, 4, 0, 1, 0);
            assert_eq!(empty, core::ptr::addr_of_mut!(STORAGE).cast::<u32>());
            assert_eq!(empty.read(), 0xfeed_face);
            let failed = cpp_array_allocate_helper_adapter(u32::MAX, 4, 8, 1, 0);
            assert!(failed.is_null());
            assert_eq!(empty.read(), 0xfeed_face);
        }
    }
}
