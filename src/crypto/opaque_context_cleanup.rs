//! Teardown for an opaque OpenSSL-adjacent context.
//!
//! `opaque_crypto_context_cleanup` — retailOS `FUN_0806fe48` @ `0x0806fe48`
//! (88 bytes, `0x0806fe48..0x0806fea0`; 84 instruction bytes followed by the
//! teardown-callback literal `0x08065d2c`). The next separately entered
//! function begins at `0x0806fea4` with `push {r4,lr}`. Raw ARM decoding finds
//! two plain direct `bl` instructions (`0x083697ac`, `0x080439e0`) and one
//! predicated indirect `blxne` through the context's +0x44 callback.
//!
//! # Algorithm
//!
//! Invoke the optional +0x44 context callback with the context. If the +0x54
//! namespace-provider collection is present, drain it using the fixed literal
//! callback at `0x08065d2c`, then clear +0x54. Release embedded OpenSSL ex-data
//! with class 5 at +0x6c and clear its two words (+0x6c/+0x70).
//!
//! # Deliberate deviations
//!
//! The collection-entry callback begins at a condition-code-sensitive literal
//! address whose concrete identity is unrecovered. Target builds invoke that
//! verified address; host builds use a volatile seam. The opaque object is
//! addressed as target-width words, preserving all target offsets on hosts
//! whose pointers are wider than four bytes.

use core::ffi::c_void;

use crate::crypto::free_ex_data::crypto_free_ex_data;
use crate::cxx::object_flags::{namespace_provider_each_then_destroy, NamespaceProviderTeardown};

const CONTEXT_CALLBACK_WORD: usize = 0x44 / 4;
const PROVIDERS_WORD: usize = 0x54 / 4;
const EX_DATA_WORD: usize = 0x6c / 4;
const CONTEXT_PROVIDER_TEARDOWN: usize = 0x0806_5d2c;

/// Callback stored at target offset +0x44.
pub type OpaqueContextCallback = unsafe extern "C" fn(context: *mut u32);

#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_CONTEXT_CALLBACK: OpaqueContextCallback = missing_opaque_context_callback;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_opaque_context_callback(_context: *mut u32) {
    panic!("opaque_crypto_context_cleanup requires installed context callback")
}

#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_CONTEXT_PROVIDER_TEARDOWN: NamespaceProviderTeardown =
    missing_opaque_context_provider_teardown;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_opaque_context_provider_teardown(_entry: usize) {
    panic!("opaque_crypto_context_cleanup requires installed provider teardown")
}

#[inline(always)]
unsafe extern "C" fn context_provider_teardown(entry: usize) {
    #[cfg(target_os = "none")]
    {
        let teardown: NamespaceProviderTeardown = core::mem::transmute(CONTEXT_PROVIDER_TEARDOWN);
        teardown(entry);
    }
    #[cfg(not(target_os = "none"))]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(OPAQUE_CONTEXT_PROVIDER_TEARDOWN))(entry);
    }
}

/// opaque_crypto_context_cleanup — original: `FUN_0806fe48` @ `0x0806fe48`
/// (88 bytes: 84 code bytes plus callback literal; two plain direct `bl` and
/// one predicated indirect `blxne` in its body).
///
/// Runs the optional context callback, drains its provider collection, releases
/// class-5 ex-data, and clears the collection and ex-data target words.
///
/// # Safety
///
/// `context` must reference at least 0x74 readable and writable bytes. Every
/// nonzero callback or provider word must satisfy its retailOS callee's
/// contract.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_crypto_context_cleanup(context: *mut u32) {
    let callback_word = context.add(CONTEXT_CALLBACK_WORD).read_volatile();
    if callback_word != 0 {
        #[cfg(target_os = "none")]
        {
            let callback: OpaqueContextCallback = core::mem::transmute(callback_word as usize);
            callback(context);
        }
        #[cfg(not(target_os = "none"))]
        {
            core::ptr::read_volatile(core::ptr::addr_of!(OPAQUE_CONTEXT_CALLBACK))(context);
        }
    }

    let providers = context.add(PROVIDERS_WORD).read_volatile();
    if providers != 0 {
        namespace_provider_each_then_destroy(
            providers as usize as *mut usize,
            context_provider_teardown,
        );
        context.add(PROVIDERS_WORD).write_volatile(0);
    }

    let ex_data = context.add(EX_DATA_WORD);
    crypto_free_ex_data(5, context.cast::<c_void>(), ex_data.cast::<c_void>());
    ex_data.write_volatile(0);
    ex_data.add(1).write_volatile(0);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::crypto::free_ex_data::{CryptoExDataOps, CRYPTO_EX_DATA_OPS, CRYPTO_EX_DATA_OPS_TEST_LOCK};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLBACK_CONTEXT: *mut u32 = core::ptr::null_mut();
    static mut EX_DATA_CALL: (i32, *mut c_void, *mut c_void) = (0, core::ptr::null_mut(), core::ptr::null_mut());

    unsafe extern "C" fn record_context_callback(context: *mut u32) {
        CALLBACK_CONTEXT = context;
    }
    unsafe extern "C" fn ex_data_initialized() -> bool { true }
    unsafe extern "C" fn initialize_ex_data() {}
    unsafe extern "C" fn record_ex_data(class_index: i32, object: *mut c_void, ex_data: *mut c_void) {
        EX_DATA_CALL = (class_index, object, ex_data);
    }

    struct ExDataOpsReset(CryptoExDataOps);
    impl Drop for ExDataOpsReset {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(CRYPTO_EX_DATA_OPS).write(self.0) };
        }
    }

    struct CallbackReset(OpaqueContextCallback);
    impl Drop for CallbackReset {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(OPAQUE_CONTEXT_CALLBACK).write(self.0) };
        }
    }

    unsafe fn install_context_callback() -> CallbackReset {
        let saved = core::ptr::read_volatile(core::ptr::addr_of!(OPAQUE_CONTEXT_CALLBACK));
        core::ptr::addr_of_mut!(OPAQUE_CONTEXT_CALLBACK).write(record_context_callback);
        CallbackReset(saved)
    }

    unsafe fn install_ex_data_ops() -> ExDataOpsReset {
        let saved = core::ptr::read_volatile(core::ptr::addr_of!(CRYPTO_EX_DATA_OPS));
        core::ptr::addr_of_mut!(CRYPTO_EX_DATA_OPS).write(CryptoExDataOps {
            is_initialized: ex_data_initialized,
            initialize: initialize_ex_data,
            free_ex_data: record_ex_data,
        });
        ExDataOpsReset(saved)
    }

    #[test]
    fn cleanup_calls_optional_callback_releases_embedded_ex_data_and_clears_words() {
        let _crypto = CRYPTO_EX_DATA_OPS_TEST_LOCK.lock();
        let _serial = TEST_LOCK.lock();
        unsafe {
            let _reset = install_ex_data_ops();
            let _callback_reset = install_context_callback();
            CALLBACK_CONTEXT = core::ptr::null_mut();
            EX_DATA_CALL = (0, core::ptr::null_mut(), core::ptr::null_mut());
            let mut context = [0u32; 29];
            context[CONTEXT_CALLBACK_WORD] = 1;
            context[EX_DATA_WORD] = 0x1234_5678;
            context[EX_DATA_WORD + 1] = 0x8765_4321;

            opaque_crypto_context_cleanup(context.as_mut_ptr());

            assert_eq!(CALLBACK_CONTEXT, context.as_mut_ptr());
            assert_eq!(EX_DATA_CALL, (5, context.as_mut_ptr().cast(), context.as_mut_ptr().add(EX_DATA_WORD).cast()));
            assert_eq!(context[PROVIDERS_WORD], 0);
            assert_eq!(context[EX_DATA_WORD], 0);
            assert_eq!(context[EX_DATA_WORD + 1], 0);
        }
    }

    #[test]
    fn cleanup_skips_absent_callback_and_provider_collection() {
        let _crypto = CRYPTO_EX_DATA_OPS_TEST_LOCK.lock();
        let _serial = TEST_LOCK.lock();
        unsafe {
            let _reset = install_ex_data_ops();
            CALLBACK_CONTEXT = core::ptr::null_mut();
            let mut context = [0u32; 29];
            opaque_crypto_context_cleanup(context.as_mut_ptr());
            assert!(CALLBACK_CONTEXT.is_null());
            assert_eq!(EX_DATA_CALL.0, 5);
            assert_eq!(context[EX_DATA_WORD..=EX_DATA_WORD + 1], [0, 0]);
        }
    }
}
