//! ARM ADS array allocation with caller-supplied callbacks.
//!
//! Original: `FUN_082ab454` @ `0x082ab454`, exactly 96 bytes, ending at
//! the next prologue at `0x082ab4b4`. Raw A32 decoding verifies two plain
//! incoming BLs (0x08267000, 0x082a70f4), zero predicated BLs, and one
//! outgoing plain BL to 0x082b498c (zero predicated).
//!
//! Rotates seven ARM words into the shared eleven-word array helper ABI:
//! (0, count, size, header_bytes, 0, initializer, initializer_context,
//! allocator, allocator_context, 0, 0). The helper result survives in r0;
//! Ghidra's void return is incorrect. No size arithmetic or validation is
//! performed by this adapter, and callback words remain opaque.
//!
//! Deliberate deviation: the unported helper remains behind the existing
//! `PAIR_HEADER_ELEMENT_ARRAY_OPS` exact-ABI seam, as in neighboring ports.
//! Its allocation/constructor behavior is not implemented by this port.

/// Allocates an array through the shared helper, preserving its pointer result.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cpp_array_allocate_with_callbacks(
    element_count: u32,
    element_size: u32,
    allocation_header_bytes: u32,
    element_initializer: u32,
    initializer_context: u32,
    allocator_callback: u32,
    allocator_context: u32,
) -> *mut u32 {
    let allocate = core::ptr::addr_of!(crate::cxx::pair_header::PAIR_HEADER_ELEMENT_ARRAY_OPS.reset)
        .read_volatile();
    allocate(
        core::ptr::null_mut(), element_count, element_size, allocation_header_bytes,
        0, element_initializer, initializer_context, allocator_callback,
        allocator_context, 0, 0,
    )
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::pair_header::{PairHeaderElementArrayOps, PAIR_HEADER_ELEMENT_ARRAY_OPS};

    // Bounded behavioral fixture for the raw helper's allocation/header and
    // unary-constructor paths. Tokens select a failing allocator or constructor;
    // they are not truncated host function pointers.
    static mut STORAGE: [u32; 8] = [0; 8];
    static mut CONSTRUCTIONS: u32 = 0;

    unsafe extern "C" fn bounded_array_helper(
        destination: *mut u32, count: u32, size: u32, header: u32,
        _source: u32, initializer: u32, _initializer_context: u32,
        allocator: u32, _allocator_context: u32, _flags: u32, _zero: u32,
    ) -> *mut u32 {
        if allocator == 2 { return core::ptr::null_mut(); }
        let bytes = count.wrapping_mul(size).wrapping_add(header);
        if bytes > 32 { return core::ptr::null_mut(); }
        let base = core::ptr::addr_of_mut!(STORAGE).cast::<u32>();
        let result = if destination.is_null() {
            base.cast::<u8>().add(header as usize).cast::<u32>()
        } else { destination };
        if header != 0 {
            result.sub(2).write(size);
            result.sub(1).write(count);
        }
        if initializer == 1 {
            for index in 0..(count as i32).max(0) as usize {
                result.cast::<u8>().add(index * size as usize).cast::<u32>().write(0xabc0_0000);
                CONSTRUCTIONS += 1;
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
    fn allocated_header_and_elements_are_consumer_visible() {
        let _lock = crate::testing::CPP_ARRAY_OPS_TEST_LOCK.lock().unwrap();
        unsafe {
            let _restore = OpsGuard(core::ptr::addr_of!(PAIR_HEADER_ELEMENT_ARRAY_OPS).read_volatile());
            core::ptr::addr_of_mut!(PAIR_HEADER_ELEMENT_ARRAY_OPS).write_volatile(
                PairHeaderElementArrayOps { reset: bounded_array_helper },
            );
            STORAGE = [0xfeed_face; 8];
            CONSTRUCTIONS = 0;
            let result = cpp_array_allocate_with_callbacks(3, 4, 8, 1, 0, 1, 0);
            assert_eq!(result.sub(2).read(), 4);
            assert_eq!(result.sub(1).read(), 3);
            assert_eq!(core::slice::from_raw_parts(result, 3), &[0xabc0_0000; 3]);
            assert_eq!(result.add(3).read(), 0xfeed_face);
            assert_eq!(CONSTRUCTIONS, 3);

            STORAGE = [0xfeed_face; 8];
            CONSTRUCTIONS = 0;
            let empty = cpp_array_allocate_with_callbacks(0, 4, 8, 1, 0, 1, 0);
            assert_eq!(empty.sub(1).read(), 0);
            assert_eq!(empty.read(), 0xfeed_face);
            assert_eq!(CONSTRUCTIONS, 0);

            let failed = cpp_array_allocate_with_callbacks(3, 4, 8, 1, 0, 2, 0);
            assert!(failed.is_null());
            assert_eq!(empty.read(), 0xfeed_face);
            assert_eq!(CONSTRUCTIONS, 0);
        }
    }
}
