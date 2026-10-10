//! Collection-backed crypto context destruction.
//!
//! `crypto_collection_context_destroy` — `FUN_080704f8` @ `0x080704f8`.
//! True extent: 124 bytes, `0x080704f8..0x08070574` (120 instruction
//! bytes and one callback literal). Raw A32 scan: two inbound BLs, one
//! unconditional and one BLNE; body: seven unconditional BLs, no predicated
//! BL, and a final tail B to traced_free.
//!
//! NULL returns. Capture the +0x08 collection, reload its signed count each
//! iteration, prepare then destroy each entry, and destroy the collection.
//! Drain +0x04 using the fixed tagged-entry destructor, release class-4
//! ex-data at +0x3c, then free the context. No reference-count gate or stores.
//!
//! Deviations: host object/collection slots are pointer-sized and the host
//! indexed accessor uses that layout (the existing accessor instead embeds
//! an eight-byte host pointer at byte +4). Target calls the ported accessor.
//! Unported entry services use verified stock addresses, with host hooks;
//! the fixed callback literal 0x080e0a40 resolves to image 0x080eb918 under
//! the documented +0xaed8 skew, whose raw body dispatches tag 1/2 then frees.
//! The original final tail B is an ordinary returning Rust call.

use core::ffi::c_void;
use crate::cxx::object_flags::{namespace_provider_count, namespace_provider_destroy,
    namespace_provider_each_then_destroy};
use crate::crypto::free_ex_data::crypto_free_ex_data;
use crate::drivers::ata_cmd::traced_free;

/// Verified unported entry operations; prepare's result is deliberately ignored.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct CollectionEntryOps {
    pub prepare: unsafe extern "C" fn(*mut u32) -> u32,
    pub destroy: unsafe extern "C" fn(*mut u32),
    pub tagged_destroy: unsafe extern "C" fn(usize),
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_prepare(_: *mut u32) -> u32 {
    panic!("collection context requires installed entry prepare")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_destroy(_: *mut u32) {
    panic!("collection context requires installed entry destroy")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_tagged_destroy(_: usize) {
    panic!("collection context requires installed tagged-entry destroy")
}
#[cfg(not(target_os = "none"))]
pub static mut COLLECTION_ENTRY_OPS: CollectionEntryOps = CollectionEntryOps {
    prepare: missing_prepare, destroy: missing_destroy, tagged_destroy: missing_tagged_destroy,
};

#[inline(always)]
unsafe fn prepare_entry(entry: *mut u32) {
    #[cfg(target_os = "none")]
    {
        let prepare: unsafe extern "C" fn(*mut u32) -> u32 = core::mem::transmute(0x0806_f228usize);
        let _ = prepare(entry);
    }
    #[cfg(not(target_os = "none"))]
    { let _ = (core::ptr::read_volatile(core::ptr::addr_of!(COLLECTION_ENTRY_OPS)).prepare)(entry); }
}
#[inline(always)]
unsafe fn destroy_entry(entry: *mut u32) {
    #[cfg(target_os = "none")]
    {
        let destroy: unsafe extern "C" fn(*mut u32) = core::mem::transmute(0x0806_f1f8usize);
        destroy(entry);
    }
    #[cfg(not(target_os = "none"))]
    { (core::ptr::read_volatile(core::ptr::addr_of!(COLLECTION_ENTRY_OPS)).destroy)(entry); }
}
unsafe extern "C" fn destroy_tagged_entry(entry: usize) {
    #[cfg(target_os = "none")]
    {
        let destroy: unsafe extern "C" fn(usize) = core::mem::transmute(0x080e_0a40usize);
        destroy(entry);
    }
    #[cfg(not(target_os = "none"))]
    { (core::ptr::read_volatile(core::ptr::addr_of!(COLLECTION_ENTRY_OPS)).tagged_destroy)(entry); }
}

/// Destroy both owned collections, embedded class-4 ex-data, and the context.
///
/// # Safety
/// A non-null context must have at least 19 word slots (0x4c target bytes).
/// Collection pointers and entries must satisfy the retail entry services and
/// collection destructors. In particular, the first collection's entries are
/// not null-guarded before prepare, and callbacks may mutate its signed count.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn crypto_collection_context_destroy(context: *mut usize) {
    if context.is_null() { return; }
    let entries = context.add(2).read_volatile() as *mut usize;
    let mut index = 0u32;
    while namespace_provider_count(entries.cast()) > index as i32 {
        #[cfg(target_os = "none")]
        let entry = crate::cxx::object_flags::namespace_provider_at(entries.cast(), index) as *mut u32;
        #[cfg(not(target_os = "none"))]
        let entry = (entries.add(1).read_volatile() as *const usize)
            .add(index as usize).read_volatile() as *mut u32;
        prepare_entry(entry);
        destroy_entry(entry);
        index = index.wrapping_add(1);
    }
    namespace_provider_destroy(entries);
    namespace_provider_each_then_destroy(context.add(1).read_volatile() as *mut usize, destroy_tagged_entry);
    crypto_free_ex_data(4, context.cast::<c_void>(), context.add(15).cast::<c_void>());
    traced_free(context.cast());
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::drivers::ata_cmd::{TracedFreeHooks, TRACED_FREE_HOOKS, TRACED_FREE_TEST_LOCK};
    use crate::crypto::free_ex_data::{CryptoExDataOps, CRYPTO_EX_DATA_OPS, CRYPTO_EX_DATA_OPS_TEST_LOCK};
    use std::vec::Vec;
    static EVENTS: parking_lot::Mutex<Vec<(u32, usize)>> = parking_lot::Mutex::new(Vec::new());
    static mut SHRINK: *mut usize = core::ptr::null_mut();
    unsafe extern "C" fn prepare(entry: *mut u32) -> u32 {
        EVENTS.lock().push((1, entry as usize));
        if !SHRINK.is_null() { SHRINK.write(1); }
        0 // A false prepare result must not suppress destruction.
    }
    unsafe extern "C" fn destroy(entry: *mut u32) { EVENTS.lock().push((2, entry as usize)); }
    unsafe extern "C" fn tagged(entry: usize) { EVENTS.lock().push((3, entry)); }
    unsafe extern "C" fn free(block: *mut u8) { EVENTS.lock().push((4, block as usize)); }
    unsafe extern "C" fn initialized() -> bool { true }
    unsafe extern "C" fn initialize() { unreachable!() }
    unsafe extern "C" fn ex_data(class: i32, object: *mut c_void, data: *mut c_void) {
        assert_eq!(class, 4);
        assert_eq!(data, (object as *mut usize).add(15).cast());
        EVENTS.lock().push((5, object as usize));
    }
    struct Reset(CollectionEntryOps, TracedFreeHooks, CryptoExDataOps);
    impl Drop for Reset {
        fn drop(&mut self) { unsafe {
            core::ptr::addr_of_mut!(COLLECTION_ENTRY_OPS).write(self.0);
            core::ptr::addr_of_mut!(TRACED_FREE_HOOKS).write(self.1);
            core::ptr::addr_of_mut!(CRYPTO_EX_DATA_OPS).write(self.2);
            SHRINK = core::ptr::null_mut();
        } }
    }
    unsafe fn install() -> Reset {
        let reset = Reset(core::ptr::addr_of!(COLLECTION_ENTRY_OPS).read(),
            core::ptr::addr_of!(TRACED_FREE_HOOKS).read(), core::ptr::addr_of!(CRYPTO_EX_DATA_OPS).read());
        core::ptr::addr_of_mut!(COLLECTION_ENTRY_OPS).write(CollectionEntryOps { prepare, destroy, tagged_destroy: tagged });
        core::ptr::addr_of_mut!(TRACED_FREE_HOOKS).write(TracedFreeHooks { free, trace: None });
        core::ptr::addr_of_mut!(CRYPTO_EX_DATA_OPS).write(CryptoExDataOps { is_initialized: initialized, initialize, free_ex_data: ex_data });
        EVENTS.lock().clear();
        reset
    }
    #[test]
    fn null_and_absent_or_negative_collections() {
        let _heap = TRACED_FREE_TEST_LOCK.lock();
        let _ex = CRYPTO_EX_DATA_OPS_TEST_LOCK.lock();
        unsafe {
            let _reset = install();
            crypto_collection_context_destroy(core::ptr::null_mut());
            assert_eq!(*EVENTS.lock(), []);
            for count in [0usize, u32::MAX as usize] {
                EVENTS.lock().clear();
                let mut providers = [count, 0, 0, 0, 0];
                let mut context = [0usize; 19];
                context[2] = providers.as_mut_ptr() as usize;
                let owner = context.as_mut_ptr() as usize;
                crypto_collection_context_destroy(context.as_mut_ptr());
                assert_eq!(*EVENTS.lock(), [(4, providers.as_mut_ptr() as usize), (5, owner), (4, owner)]);
            }
            EVENTS.lock().clear();
            let mut context = [0usize; 19];
            let owner = context.as_mut_ptr() as usize;
            crypto_collection_context_destroy(context.as_mut_ptr());
            assert_eq!(*EVENTS.lock(), [(5, owner), (4, owner)]);
        }
    }
    #[test]
    fn count_mutation_prepare_failure_and_two_collection_release_order() {
        let _heap = TRACED_FREE_TEST_LOCK.lock();
        let _ex = CRYPTO_EX_DATA_OPS_TEST_LOCK.lock();
        unsafe {
            let _reset = install();
            let mut first_table = [0x1234usize, 0x5678];
            let mut first = [2usize, first_table.as_mut_ptr() as usize, 0, 0, 0];
            let mut second_table = [0usize, 0xabcd];
            let mut second = [2usize, second_table.as_mut_ptr() as usize, 0, 0, 0];
            let mut context = [0usize; 19];
            context[1] = second.as_mut_ptr() as usize;
            context[2] = first.as_mut_ptr() as usize;
            context[0] = 99; // No reference-count check.
            SHRINK = first.as_mut_ptr();
            let owner = context.as_mut_ptr() as usize;
            let before = context;
            crypto_collection_context_destroy(context.as_mut_ptr());
            assert_eq!(*EVENTS.lock(), [(1, 0x1234), (2, 0x1234),
                (4, first_table.as_mut_ptr() as usize), (4, first.as_mut_ptr() as usize),
                (3, 0xabcd), (4, second_table.as_mut_ptr() as usize),
                (4, second.as_mut_ptr() as usize), (5, owner), (4, owner)]);
            assert_eq!(context, before);
        }
    }
}
