//! X509 store constructor: FUN_0807061c @ 0x0807061c.
//! True extent 144 bytes through 0x080706ac (140 code bytes and the
//! comparator literal at 0x080706a8); the next entry loads object +0x0c.
//! Raw word decoding: two incoming plain BLs, four outgoing plain BLs,
//! zero predicated BLs in either direction.
//!
//! Allocate 19 words, create the comparator-backed object cache and the
//! zero-parameter lookup stack, clear callbacks/state, initialize class-4
//! ex-data at +0x3c, and set references to one. Only the outer allocation
//! failure returns NULL; nested failures and the ex-data result are ignored.
//!
//! Deviations: reuse the existing traced allocator, handle factory (whose
//! historical ATA name does not describe this crypto use), and ex-data
//! ports and their host seams. Word indices preserve four-byte target
//! spacing on hosts. The comparator remains the verified firmware address
//! 0x08088958, not a newly invented callable seam.

use crate::drivers::ata_cmd::{traced_alloc, ata_handle_factory, ata_call_with_zero};
use super::new_ex_data::crypto_new_ex_data;

/// Construct a stock-layout X509 store.
///
/// # Safety
/// The installed allocator must return aligned, writable storage for each
/// request. The installed ex-data implementation must accept a complete
/// 76-byte stock store and its two-word ex-data field. Stored pointer words
/// require allocations below 4 GiB on hosts.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn x509_store_new() -> *mut u32 {
    let store = unsafe { traced_alloc(0x4c, 0, 0) }.cast::<u32>();
    if store.is_null() { return store; }
    unsafe {
        store.add(1).write(ata_handle_factory(0x08088958) as usize as u32);
        store.write(1);
        store.add(2).write(ata_call_with_zero() as usize as u32);
        for index in [6, 7, 4, 5, 3, 8, 9, 10, 11, 12, 13, 14] {
            store.add(index).write(0);
        }
        crypto_new_ex_data(4, store.cast(), store.add(15).cast());
        store.add(18).write(0);
        store.add(17).write(1);
    }
    store
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::ata_cmd::{TRACED_ALLOC_HOOKS, TracedAllocHooks};
    use super::super::new_ex_data::{CRYPTO_EX_DATA_OPS, CRYPTO_EX_DATA_OPS_TEST_LOCK, CryptoExDataOps};
    use core::ffi::c_void;

    static mut ARENA: *mut u32 = core::ptr::null_mut();
    static mut CALL: usize = 0;
    static mut FAIL: usize = usize::MAX;
    static mut EX_RESULT: i32 = 0;

    unsafe extern "C" fn allocate(size: i32, _: u32, _: u32) -> *mut u8 {
        unsafe {
            let call = CALL;
            CALL += 1;
            if call == FAIL { return core::ptr::null_mut(); }
            let block = ARENA.add(call * 32);
            for i in 0..(size as usize / 4) { block.add(i).write(0xa5a5a5a5); }
            block.cast()
        }
    }
    unsafe extern "C" fn initialized() -> bool { true }
    unsafe extern "C" fn initialize() { unreachable!() }
    unsafe extern "C" fn ex_data(_: i32, object: *mut c_void, data: *mut c_void) -> i32 {
        unsafe {
            let store = object.cast::<u32>();
            assert_eq!(data, store.add(15).cast());
            assert_eq!(store.read(), 1);
            for i in 3..15 { assert_eq!(store.add(i).read(), 0); }
            // The constructor must leave ex-data to its implementation.
            assert_eq!(store.add(15).read(), 0xa5a5a5a5);
            store.add(15).write(0x12345678);
            store.add(16).write(0x87654321);
            EX_RESULT
        }
    }
    struct Restore(TracedAllocHooks, CryptoExDataOps);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(TRACED_ALLOC_HOOKS).write(self.0);
                core::ptr::addr_of_mut!(CRYPTO_EX_DATA_OPS).write(self.1);
            }
        }
    }
    #[test]
    fn allocation_failures_and_ex_data_failure_preserve_stock_behavior() {
        let _alloc = crate::testing::TRACED_ALLOC_TEST_LOCK.lock();
        let _ex = CRYPTO_EX_DATA_OPS_TEST_LOCK.lock();
        let Some(arena) = crate::testing::try_map_u32_slab(crate::testing::hints::X509_STORE_NEW, 0x1000) else { return; };
        unsafe {
            let _restore = Restore(core::ptr::addr_of!(TRACED_ALLOC_HOOKS).read(), core::ptr::addr_of!(CRYPTO_EX_DATA_OPS).read());
            TRACED_ALLOC_HOOKS = TracedAllocHooks { alloc: allocate, trace: None };
            CRYPTO_EX_DATA_OPS = CryptoExDataOps { is_initialized: initialized, initialize, new_ex_data: ex_data };
            ARENA = arena.cast();
            for fail in [usize::MAX, 0, 1, 3] {
                for result in [0, 1, -1] {
                    CALL = 0; FAIL = fail; EX_RESULT = result;
                    let store = x509_store_new();
                    if fail == 0 { assert!(store.is_null()); assert_eq!(CALL, 1); continue; }
                    assert_eq!(store, ARENA);
                    assert_eq!(store.add(17).read(), 1);
                    assert_eq!(store.add(18).read(), 0);
                    assert_eq!(store.add(15).read(), 0x12345678);
                    assert_eq!(store.add(16).read(), 0x87654321);
                    let cache = store.add(1).read();
                    if fail == 1 { assert_eq!(cache, 0); }
                    else {
                        let cache = cache as usize as *const u32;
                        assert_eq!(cache.add(4).read(), 0x08088958);
                        assert_eq!(cache.add(3).read(), 4);
                    }
                    let lookups = store.add(2).read();
                    if fail == 3 { assert_eq!(lookups, 0); }
                    else { assert_eq!((lookups as usize as *const u32).add(4).read(), 0); }
                }
            }
        }
    }
}
