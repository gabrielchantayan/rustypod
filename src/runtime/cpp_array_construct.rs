//! cpp_array_construct — original: `FUN_082ab234` @ `0x082ab234`
//! (32 bytes; source: `ipod-decomp/decomp/c/029/082ab234_FUN_082ab234.c`).
//!
//! The ARM ADS four-argument array-constructor adapter. 41 `bl` call sites
//! and zero predicated forms, verified by decoding every B/BL word in
//! `osos.dec`; callers across the whole image build C++ object arrays
//! through it (`FUN_082ab234(array, ctor, 0x18, 4)` and similar). Ghidra's
//! 32-byte extent is exact for once: eight instructions, and the next
//! function (`cpp_finalise_null_guard` @ 0x082ab254, ported in
//! `heap/veneers`) starts immediately after. The full retail body:
//!
//! ```text
//! mov   ip, r1        ; ip = element_ctor
//! mov   r1, r3        ; r1 = element_count
//! push  {r3, lr}
//! mov   r3, #0
//! str   r3, [sp]      ; stack arg 5 = 0 (initializer_context)
//! mov   r3, ip        ; r3 = element_ctor
//! bl    0x082ab398    ; pair_header_grand_base_reset
//! pop   {ip, pc}
//! ```
//!
//! It rotates the ADS `(array, ctor, elem_size, count)` convention into the
//! five-word helper ABI `(array, count, elem_size, ctor, 0)` and forwards to
//! the now-ported wrapper @ 0x082ab398
//! ([`crate::cxx::pair_header::pair_header_grand_base_reset`]), which
//! materializes the eleven-word `FUN_082b498c` helper call. Retail r0 on
//! exit carries the helper's pointer result straight through both wrappers
//! (neither clobbers it), and callers depend on that: the 0x081b80b4 site
//! stores into `ret + 0x60` and feeds `ret + 100` to the next adapter call,
//! and the 0x0816a6e4 site returns `ret - 4` as the finished object. Ghidra
//! types the adapter `void`; the binary proves otherwise, so the port
//! returns the pointer. `element_ctor` is a `void (*)(void *)` constructor
//! passed as a raw word, matching the callee port's `u32` typing — the
//! firmware treats it as data until the helper calls it.

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cpp_array_construct(
    array: *mut u32,
    element_ctor: u32,
    element_size: u32,
    element_count: u32,
) -> *mut u32 {
    crate::cxx::pair_header::pair_header_grand_base_reset(
        array,
        element_count,
        element_size,
        element_ctor,
        0,
    )
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::cxx::pair_header::{
        PairHeaderElementArrayOps, PAIR_HEADER_ELEMENT_ARRAY_OPS,
    };
    use std::vec;

    type ResetFn = unsafe extern "C" fn(
        *mut u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32,
    ) -> *mut u32;

    static mut SEEN: [usize; 11] = [0; 11];
    static mut CALLS: usize = 0;

    /// Stand-in return that is provably not the incoming array pointer.
    const HELPER_RESULT_SENTINEL_OFFSET: usize = 7;

    unsafe extern "C" fn recording_reset(
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
        core::ptr::addr_of_mut!(SEEN).write_volatile([
            this as usize,
            field_count as usize,
            field_size as usize,
            allocation_header_bytes as usize,
            initializer_argument as usize,
            element_initializer as usize,
            initializer_context as usize,
            allocator_callback as usize,
            allocator_context as usize,
            allocation_flags as usize,
            zero_initialize as usize,
        ]);
        let calls = core::ptr::addr_of_mut!(CALLS);
        calls.write_volatile(calls.read_volatile() + 1);
        this.add(HELPER_RESULT_SENTINEL_OFFSET)
    }

    struct OpsGuard {
        previous: ResetFn,
    }

    impl OpsGuard {
        fn install() -> Self {
            let previous = unsafe {
                core::ptr::addr_of!(PAIR_HEADER_ELEMENT_ARRAY_OPS.reset).read_volatile()
            };
            unsafe {
                core::ptr::addr_of_mut!(PAIR_HEADER_ELEMENT_ARRAY_OPS).write_volatile(
                    PairHeaderElementArrayOps { reset: recording_reset },
                );
            }
            OpsGuard { previous }
        }
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(PAIR_HEADER_ELEMENT_ARRAY_OPS).write_volatile(
                    PairHeaderElementArrayOps { reset: self.previous },
                );
            }
        }
    }

    fn reset_recording() {
        unsafe {
            core::ptr::addr_of_mut!(SEEN).write_volatile([0; 11]);
            core::ptr::addr_of_mut!(CALLS).write_volatile(0);
        }
    }

    fn seen() -> [usize; 11] {
        unsafe { core::ptr::addr_of!(SEEN).read_volatile() }
    }

    fn calls() -> usize {
        unsafe { core::ptr::addr_of!(CALLS).read_volatile() }
    }

    /// The adapter rotates `(array, ctor, size, count)` into the helper ABI
    /// slots `(array, count, size, ctor, 0)` and zero-fills every other word,
    /// exactly as the retail register shuffle does.
    #[test]
    fn rotates_ads_arguments_into_helper_abi() {
        let _lock = crate::testing::CPP_ARRAY_OPS_TEST_LOCK.lock().unwrap();
        let _guard = OpsGuard::install();
        unsafe {
            reset_recording();
            let mut storage = vec![0u32; 4];

            cpp_array_construct(storage.as_mut_ptr(), 0x0828_3a74, 0x18, 4);

            assert_eq!(calls(), 1);
            assert_eq!(
                seen(),
                [
                    storage.as_mut_ptr() as usize,
                    4,            // element_count -> field_count (r3 -> r1)
                    0x18,         // element_size stays in r2
                    0,            // allocation_header_bytes
                    0,            // initializer_argument
                    0x0828_3a74,  // element_ctor -> element_initializer (r1 -> r3)
                    0,            // initializer_context: the pushed zero word
                    0,            // allocator_callback
                    0,            // allocator_context
                    0,            // allocation_flags
                    0,            // zero_initialize
                ]
            );
        }
    }

    /// Retail r0 carries the helper's pointer result through both wrappers;
    /// callers chain on it. A sentinel distinct from `array` proves the
    /// adapter forwards r0 instead of re-deriving the input pointer.
    #[test]
    fn forwards_helper_pointer_result() {
        let _lock = crate::testing::CPP_ARRAY_OPS_TEST_LOCK.lock().unwrap();
        let _guard = OpsGuard::install();
        unsafe {
            reset_recording();
            let mut storage = vec![0u32; 16];

            let returned = cpp_array_construct(storage.as_mut_ptr(), 0x1000, 0xc, 0xb);

            assert_eq!(
                returned,
                storage.as_mut_ptr().add(HELPER_RESULT_SENTINEL_OFFSET)
            );
        }
    }

    /// Degenerate arguments are forwarded verbatim — the adapter performs no
    /// validation, null check, or clamping of its own (zero predicated call
    /// sites means callers never gate it either).
    #[test]
    fn forwards_extreme_words_verbatim() {
        let _lock = crate::testing::CPP_ARRAY_OPS_TEST_LOCK.lock().unwrap();
        let _guard = OpsGuard::install();
        unsafe {
            reset_recording();
            let mut storage = vec![0u32; 4];

            cpp_array_construct(storage.as_mut_ptr(), 0, 0xffff_ffff, 0);

            assert_eq!(calls(), 1);
            assert_eq!(
                seen(),
                [
                    storage.as_mut_ptr() as usize,
                    0,
                    0xffff_ffff,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ]
            );
        }
    }
}
