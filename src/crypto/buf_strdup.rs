//! OpenSSL BUF_strdup heap-string duplication.

use core::ffi::c_char;

use crate::drivers::ata_cmd::traced_alloc;
use crate::kernel::diag_ring_record::diag_ring_record;
use crate::libc::rt_memcpy::__rt_memcpy;
use crate::libc::strlen::strlen;

/// `BUF_strdup` — original: `FUN_08042220` @ **0x08042220** (108 bytes,
/// `0x08042220..0x0804228c`; the independently decoded `strlcat` begins at
/// `0x0804228c`). Raw words verify three plain `bl` instructions (strlen @
/// `0x08392478`, traced_alloc @ `0x08043c18`, and the `__rt_memcpy` veneer @
/// `0x08037db0`) and no predicated `bl` instructions.
///
/// Returns NULL for a NULL source. Otherwise measures the unguarded C string,
/// allocates its length plus terminator with `(tag1, tag2) = (0, 0)`, and
/// copies that many bytes. Allocation failure records `(7, 0x66, 0x41, 0, 0)`
/// in the diagnostic ring and returns NULL.
///
/// Deliberate deviation: calls the Rust ports of strlen and `__rt_memcpy`
/// directly instead of the retail veneer addresses; the observed ABI and
/// byte-copy semantics are unchanged.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn buf_strdup(source: *const c_char) -> *mut c_char {
    if source.is_null() {
        return core::ptr::null_mut();
    }

    let byte_count = strlen(source.cast::<u8>()).wrapping_add(1);
    let duplicate = traced_alloc(byte_count as i32, 0, 0);
    if duplicate.is_null() {
        diag_ring_record(7, 0x66, 0x41, 0, 0);
        return core::ptr::null_mut();
    }

    __rt_memcpy(duplicate, source.cast::<u8>(), byte_count);
    duplicate.cast::<c_char>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::ata_cmd::{missing_allocator, TracedAllocHooks, TRACED_ALLOC_HOOKS};
    use crate::testing::TRACED_ALLOC_TEST_LOCK;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut ALLOCATION: [u8; 16] = [0; 16];
    static mut REQUEST: (i32, u32, u32) = (0, 0, 0);

    unsafe extern "C" fn record_alloc(size: i32, tag1: u32, tag2: u32) -> *mut u8 {
        REQUEST = (size, tag1, tag2);
        core::ptr::addr_of_mut!(ALLOCATION).cast::<u8>()
    }

    struct AllocReset(TracedAllocHooks);

    impl Drop for AllocReset {
        fn drop(&mut self) {
            unsafe { TRACED_ALLOC_HOOKS = self.0; }
        }
    }

    #[test]
    fn duplicates_empty_and_nonempty_c_strings_including_terminator() {
        let _test_guard = TEST_LOCK.lock();
        let _alloc_guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap();
        let _reset = unsafe { AllocReset(TRACED_ALLOC_HOOKS) };
        unsafe { TRACED_ALLOC_HOOKS = TracedAllocHooks { alloc: record_alloc, trace: None }; }

        for source in [c"", c"iPod"] {
            unsafe { ALLOCATION = [0xa5; 16]; }
            let duplicate = unsafe { buf_strdup(source.as_ptr()) };
            assert_eq!(duplicate, unsafe { core::ptr::addr_of_mut!(ALLOCATION).cast::<c_char>() });
            assert_eq!(unsafe { REQUEST }, ((source.to_bytes().len() + 1) as i32, 0, 0));
            assert_eq!(unsafe { &ALLOCATION[..source.to_bytes_with_nul().len()] }, source.to_bytes_with_nul());
        }
    }

    #[test]
    fn null_source_and_allocation_failure_return_null() {
        let _test_guard = TEST_LOCK.lock();
        let _alloc_guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap();
        let _reset = unsafe { AllocReset(TRACED_ALLOC_HOOKS) };
        unsafe { TRACED_ALLOC_HOOKS = TracedAllocHooks { alloc: missing_allocator, trace: None }; }

        assert!(unsafe { buf_strdup(core::ptr::null()) }.is_null());
        assert!(unsafe { buf_strdup(c"allocation failure".as_ptr()) }.is_null());
    }
}
