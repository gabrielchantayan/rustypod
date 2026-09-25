//! X.509v3 extension configuration-value list construction.

use core::ffi::c_char;

use crate::crypto::buf_strdup::buf_strdup;
use crate::cxx::object_flags::namespace_provider_push;
use crate::drivers::ata_cmd::{ata_call_with_zero, traced_alloc, traced_free};
use crate::kernel::diag_ring_record::diag_ring_record;

/// x509v3_add_value — original: `FUN_0806ea5c` @ **0x0806ea5c**
/// (220 bytes, `0x0806ea5c..0x0806eb38`; `FUN_0806eb38` begins immediately
/// afterward, so Ghidra's reported extent is exact).
///
/// Decoding every ARM B/BL word in `osos.dec` verifies 12 direct inbound call
/// sites: nine unconditional `bl` and three `blne` calls. The conditional
/// callers gate configuration assembly on their own flags; this function has
/// no corresponding flag argument or implicit guard.
///
/// Duplicates each non-NULL `name` and `value`, allocates a 12-byte target-word
/// `{section = NULL, name, value}` record through `traced_alloc(12, 0, 0)`,
/// lazily creates the destination stack in `*values` when needed, and appends
/// the record. A nonzero append result transfers ownership and returns 1. Any
/// failure logs `(0x22, 0x69, 0x41, 0, 0)`, releases the record and whichever
/// string copies exist in that order, then returns 0. As in ARM, `values` has
/// no NULL guard before its dereference.
///
/// Deliberate deviation: the existing stack factory at `0x08369778` still
/// dispatches through its existing `ATA_HANDLE_HOOKS` seam until
/// `FUN_083696f4` is ported. Target-word record fields use `usize` indices:
/// they are +0x00/+0x04/+0x08 on ARM and remain disjoint on 64-bit host tests.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn x509v3_add_value(
    name: *const c_char,
    value: *const c_char,
    values: *mut *mut usize,
) -> u32 {
    let mut name_copy = core::ptr::null_mut();
    let mut value_copy = core::ptr::null_mut();
    let mut entry = core::ptr::null_mut::<usize>();

    if !name.is_null() {
        name_copy = buf_strdup(name);
        if name_copy.is_null() {
            return x509v3_add_value_failure(entry, name_copy, value_copy);
        }
    }
    if !value.is_null() {
        value_copy = buf_strdup(value);
        if value_copy.is_null() {
            return x509v3_add_value_failure(entry, name_copy, value_copy);
        }
    }

    entry = traced_alloc(12, 0, 0).cast::<usize>();
    if entry.is_null() {
        return x509v3_add_value_failure(entry, name_copy, value_copy);
    }

    if (*values).is_null() {
        *values = ata_call_with_zero().cast::<usize>();
        if (*values).is_null() {
            return x509v3_add_value_failure(entry, name_copy, value_copy);
        }
    }

    entry.add(0).write(0);
    entry.add(1).write(name_copy as usize);
    entry.add(2).write(value_copy as usize);
    if namespace_provider_push(*values, entry as usize) != 0 {
        return 1;
    }

    x509v3_add_value_failure(entry, name_copy, value_copy)
}

#[inline(never)]
unsafe fn x509v3_add_value_failure(
    entry: *mut usize,
    name_copy: *mut c_char,
    value_copy: *mut c_char,
) -> u32 {
    diag_ring_record(0x22, 0x69, 0x41, 0, 0);
    if !entry.is_null() {
        traced_free(entry.cast::<u8>());
    }
    if !name_copy.is_null() {
        traced_free(name_copy.cast::<u8>());
    }
    if !value_copy.is_null() {
        traced_free(value_copy.cast::<u8>());
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::ata_cmd::{
        missing_allocator, TracedAllocHooks, TracedFreeHooks, TRACED_ALLOC_HOOKS,
        TRACED_FREE_HOOKS, TRACED_FREE_TEST_LOCK,
    };
    use crate::testing::TRACED_ALLOC_TEST_LOCK;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut DUPLICATE_CALLS: usize = 0;
    static mut DUPLICATE_FAIL_CALL: usize = 0;
    static mut DUPLICATES: [[u8; 16]; 2] = [[0; 16]; 2];
    static mut ENTRY: [usize; 3] = [0; 3];
    static mut ENTRY_ALLOCATIONS: usize = 0;
    static mut FREE_CALLS: [usize; 3] = [0; 3];
    static mut FREE_CALL_COUNT: usize = 0;

    struct HookReset;

    impl Drop for HookReset {
        fn drop(&mut self) {
            unsafe {
                TRACED_ALLOC_HOOKS = TracedAllocHooks { alloc: missing_allocator, trace: None };
                TRACED_FREE_HOOKS = TracedFreeHooks { free: missing_free, trace: None };
            }
        }
    }

    unsafe extern "C" fn missing_free(_block: *mut u8) {}

    unsafe extern "C" fn allocate_entry(size: i32, tag1: u32, tag2: u32) -> *mut u8 {
        assert_eq!((tag1, tag2), (0, 0));
        if size == 12 {
            ENTRY_ALLOCATIONS += 1;
            return core::ptr::addr_of_mut!(ENTRY).cast::<u8>();
        }
        let call = DUPLICATE_CALLS;
        DUPLICATE_CALLS += 1;
        if call + 1 == DUPLICATE_FAIL_CALL {
            return core::ptr::null_mut();
        }
        assert!(size > 0 && size <= 16);
        core::ptr::addr_of_mut!(DUPLICATES[call]).cast::<u8>()
    }

    unsafe extern "C" fn record_free(block: *mut u8) {
        FREE_CALLS[FREE_CALL_COUNT] = block as usize;
        FREE_CALL_COUNT += 1;
    }

    struct ProviderFixture {
        object: [usize; 4],
        entries: [usize; 4],
    }

    impl ProviderFixture {
        fn new() -> Self {
            Self { object: [0, 0, 0, 4], entries: [0; 4] }
        }

        fn bind_entries(&mut self) {
            self.object[1] = self.entries.as_mut_ptr() as usize;
        }
    }

    fn install_hooks(fail_duplicate_call: usize) {
        unsafe {
            DUPLICATE_CALLS = 0;
            DUPLICATE_FAIL_CALL = fail_duplicate_call;
            DUPLICATES = [[0; 16]; 2];
            ENTRY = [usize::MAX; 3];
            ENTRY_ALLOCATIONS = 0;
            FREE_CALLS = [0; 3];
            FREE_CALL_COUNT = 0;
            TRACED_ALLOC_HOOKS = TracedAllocHooks { alloc: allocate_entry, trace: None };
            TRACED_FREE_HOOKS = TracedFreeHooks { free: record_free, trace: None };
        }
    }

    #[test]
    fn appends_a_three_word_record_and_transfers_copies() {
        let _test_guard = TEST_LOCK.lock();
        let _alloc_guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap();
        let _free_guard = TRACED_FREE_TEST_LOCK.lock();
        let _reset = HookReset;
        install_hooks(0);
        let mut fixture = ProviderFixture::new();
        fixture.bind_entries();
        let mut values = fixture.object.as_mut_ptr();

        let result = unsafe { x509v3_add_value(c"issuer".as_ptr(), c"serial".as_ptr(), &mut values) };

        assert_eq!(result, 1);
        assert_eq!(unsafe { DUPLICATE_CALLS }, 2);
        assert_eq!(unsafe { ENTRY_ALLOCATIONS }, 1);
        assert_eq!(fixture.object[0], 1);
        assert_eq!(fixture.entries[0], unsafe { core::ptr::addr_of!(ENTRY) as usize });
        assert_eq!(unsafe { ENTRY[0] }, 0);
        assert_eq!(unsafe { ENTRY[1] }, unsafe { core::ptr::addr_of!(DUPLICATES[0]).cast::<c_char>() as usize });
        assert_eq!(unsafe { ENTRY[2] }, unsafe { core::ptr::addr_of!(DUPLICATES[1]).cast::<c_char>() as usize });
        assert_eq!(unsafe { FREE_CALL_COUNT }, 0);
    }

    #[test]
    fn second_duplicate_failure_releases_only_the_first_copy() {
        let _test_guard = TEST_LOCK.lock();
        let _alloc_guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap();
        let _free_guard = TRACED_FREE_TEST_LOCK.lock();
        let _reset = HookReset;
        install_hooks(2);
        let mut fixture = ProviderFixture::new();
        fixture.bind_entries();
        let mut values = fixture.object.as_mut_ptr();

        assert_eq!(unsafe { x509v3_add_value(c"name".as_ptr(), c"value".as_ptr(), &mut values) }, 0);
        assert_eq!(unsafe { DUPLICATE_CALLS }, 2);
        assert_eq!(unsafe { ENTRY_ALLOCATIONS }, 0);
        assert_eq!(fixture.object[0], 0);
        assert_eq!(unsafe { FREE_CALL_COUNT }, 1);
        assert_eq!(unsafe { FREE_CALLS[0] }, unsafe { core::ptr::addr_of!(DUPLICATES[0]).cast::<c_char>() as usize });
    }
}
