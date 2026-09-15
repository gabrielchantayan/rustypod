//! cpp_array_allocate — original: `FUN_082ab264` @ `0x082ab264`
//! (36 bytes; source: `ipod-decomp/decomp/c/029/082ab264_FUN_082ab264.c`).
//!
//! Raw ARM establishes the exact extent `0x082ab264..0x082ab288`; the next
//! separately linked adapter starts at `0x082ab288`. Decoding every aligned
//! ARM B/BL word in `osos.dec` finds five direct callers: five plain `bl` and
//! zero predicated `bl`. The sole body call is the plain `bl 0x082ab400`.
//!
//! The adapter rotates `(element_size, element_count, element_initializer,
//! initializer_context)` into the eleven-word, still-unported
//! `FUN_082b498c` array-helper ABI through its 0x082ab400 forwarding wrapper:
//! `(0, element_count, element_size, 8, 0, element_initializer,
//! initializer_context, 0, 0, 0, 0)`. The helper's pointer result is left in
//! r0 through `pop {ip, pc}`; Ghidra's `void` return is therefore incorrect.
//!
//! Deliberate deviation: `FUN_082b498c` remains unported, so this uses its
//! existing exact-ABI `PAIR_HEADER_ELEMENT_ARRAY_OPS` seam rather than naming
//! or reimplementing that helper.

const ARRAY_ALLOCATION_HEADER_BYTES: u32 = 8;

/// Allocates an ARM ADS array and returns the raw helper result.
///
/// The initializer words are opaque ARM words; the helper interprets them.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cpp_array_allocate(
    element_size: u32,
    element_count: u32,
    element_initializer: u32,
    initializer_context: u32,
) -> *mut u32 {
    let allocate = core::ptr::addr_of!(crate::cxx::pair_header::PAIR_HEADER_ELEMENT_ARRAY_OPS.reset)
        .read_volatile();
    allocate(
        core::ptr::null_mut(),
        element_count,
        element_size,
        ARRAY_ALLOCATION_HEADER_BYTES,
        0,
        element_initializer,
        initializer_context,
        0,
        0,
        0,
        0,
    )
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::pair_header::{PairHeaderElementArrayOps, PAIR_HEADER_ELEMENT_ARRAY_OPS};

    static mut ARGS: [u32; 10] = [0; 10];
    static mut CALLS: u32 = 0;
    static mut RESULT: *mut u32 = core::ptr::null_mut();

    unsafe extern "C" fn record_allocate(
        this: *mut u32,
        field_count: u32,
        field_size: u32,
        allocation_header_bytes: u32,
        initializer_argument: u32,
        element_initializer: u32,
        initializer_context: u32,
        allocator_callback: u32,
        allocator_context: u32,
        allocation_flags: u32,
        zero_initialize: u32,
    ) -> *mut u32 {
        unsafe {
            ARGS = [
                this as usize as u32, field_count, field_size, allocation_header_bytes,
                initializer_argument, element_initializer, initializer_context,
                allocator_callback, allocator_context, allocation_flags | zero_initialize,
            ];
            CALLS += 1;
            RESULT
        }
    }

    struct OpsGuard {
        previous: PairHeaderElementArrayOps,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(PAIR_HEADER_ELEMENT_ARRAY_OPS).write_volatile(self.previous)
            }
        }
    }

    fn install_recorder(result: *mut u32) -> OpsGuard {
        let lock = crate::testing::CPP_ARRAY_OPS_TEST_LOCK.lock().unwrap();
        unsafe {
            let previous = core::ptr::addr_of!(PAIR_HEADER_ELEMENT_ARRAY_OPS).read_volatile();
            core::ptr::addr_of_mut!(PAIR_HEADER_ELEMENT_ARRAY_OPS).write_volatile(PairHeaderElementArrayOps {
                reset: record_allocate,
            });
            ARGS = [0; 10];
            CALLS = 0;
            RESULT = result;
            OpsGuard { previous, _lock: lock }
        }
    }

    #[test]
    fn forwards_zero_count_and_opaque_initializer_words() {
        let sentinel = 0x1234_5000usize as *mut u32;
        let _ops = install_recorder(sentinel);
        let result = unsafe { cpp_array_allocate(8, 0, 0x0810_1080, 0) };
        assert_eq!(result, sentinel);
        unsafe {
            assert_eq!(CALLS, 1);
            assert_eq!(ARGS, [0, 0, 8, 8, 0, 0x0810_1080, 0, 0, 0, 0]);
        }
    }

    #[test]
    fn preserves_all_nondefault_words_without_validation() {
        let sentinel = 0xfeed_0000usize as *mut u32;
        let _ops = install_recorder(sentinel);
        let result = unsafe { cpp_array_allocate(u32::MAX, u32::MAX, 0xdead_beef, 0xcafe_babe) };
        assert_eq!(result, sentinel);
        unsafe {
            assert_eq!(CALLS, 1);
            assert_eq!(ARGS, [0, u32::MAX, u32::MAX, 8, 0, 0xdead_beef, 0xcafe_babe, 0, 0, 0]);
        }
    }
}
