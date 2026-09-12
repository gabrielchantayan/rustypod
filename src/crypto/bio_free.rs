//! OpenSSL's `BIO_free` destructor.
//!
//! Port: `bio_free` — retailOS `FUN_0803d3c8` @ `0x0803d3c8` (**140
//! bytes**, `0x0803d3c8..0x0803d454`; the separately linked `BIO_free_all`
//! sibling starts at `0x0803d454`). Decoding every ARM B/BL word in
//! `osos.dec` finds **8 direct call sites**: six unconditional `bl`
//! (`0x0803d46c`, `0x080437a4`, `0x080eee64`, `0x08272908`, `0x082d4104`,
//! `0x082d4824`) and two `blne` calls (`0x082d483c`, `0x082d487c`); there
//! are no tail branches or raw-image data words holding this address.
//!
//! # Algorithm
//!
//! A null `BIO` returns zero. Otherwise decrement its `references` through
//! `CRYPTO_add_lock` with `CRYPTO_LOCK_BIO` (21); a positive result preserves
//! the object and returns one. At the final reference, an installed BIO
//! callback receives `(bio, BIO_CB_FREE=1, NULL, 0, 0, 1)` and a non-positive
//! answer cancels teardown. The function then releases the embedded ex-data
//! through `CRYPTO_free_ex_data(0, bio, &bio->ex_data)`. Finally, it calls
//! `OPENSSL_free` only when both `bio->method` and its `destroy` word are
//! nonzero, then returns one.
//!
//! # Deliberate deviations
//!
//! `CRYPTO_free_ex_data` at `0x080439e0` is not ported. Target builds call its
//! verified entry directly; host builds use [`BIO_FREE_OPS`]. The callback is
//! likewise a raw target-width code word, so host builds use that same narrow
//! dispatch model. The final `destroy` word is deliberately only inspected:
//! raw ARM calls `traced_free` conditionally and never invokes that slot.

use core::ffi::c_void;
use core::ptr;

use crate::crypto::add_lock::crypto_add_lock;
use crate::crypto::bio_ctrl::{Bio, BioExData, BioMethod};
use crate::drivers::ata_cmd::traced_free;

const CRYPTO_FREE_EX_DATA_ADDRESS: usize = 0x0804_39e0;
const CRYPTO_LOCK_BIO: i32 = 0x15;
const BIO_CB_FREE: u32 = 1;

type BioFreeCallback = unsafe extern "C" fn(*mut Bio, u32, *mut c_void, i32, i32, i32) -> i32;
type CryptoFreeExData = unsafe extern "C" fn(i32, *mut Bio, *mut BioExData);

/// Host model for the two indirect boundaries in [`bio_free`].
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct BioFreeOps {
    pub callback: BioFreeCallback,
    pub free_ex_data: CryptoFreeExData,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_bio_free_callback(
    _bio: *mut Bio,
    _operation: u32,
    _parg: *mut c_void,
    _cmd: i32,
    _larg: i32,
    _return_value: i32,
) -> i32 {
    panic!("bio_free requires installed host BIO_FREE_OPS for a callback")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_crypto_free_ex_data(
    _class_index: i32,
    _bio: *mut Bio,
    _ex_data: *mut BioExData,
) {
    panic!("bio_free requires installed host BIO_FREE_OPS for ex-data")
}

/// Host-only execution model for the unported ex-data helper and raw callback
/// word. Target builds call their original addresses directly.
#[cfg(not(target_os = "none"))]
pub static mut BIO_FREE_OPS: BioFreeOps = BioFreeOps {
    callback: missing_bio_free_callback,
    free_ex_data: missing_crypto_free_ex_data,
};

#[inline(always)]
unsafe fn invoke_callback(
    bio: *mut Bio,
    operation: u32,
    parg: *mut c_void,
    cmd: i32,
    larg: i32,
    return_value: i32,
) -> i32 {
    #[cfg(target_os = "none")]
    {
        let callback: BioFreeCallback = unsafe { core::mem::transmute((*bio).callback as usize) };
        unsafe { callback(bio, operation, parg, cmd, larg, return_value) }
    }

    #[cfg(not(target_os = "none"))]
    {
        let ops = unsafe { ptr::read_volatile(ptr::addr_of!(BIO_FREE_OPS)) };
        unsafe { (ops.callback)(bio, operation, parg, cmd, larg, return_value) }
    }
}

#[inline(always)]
unsafe fn free_ex_data(bio: *mut Bio) {
    #[cfg(target_os = "none")]
    {
        let free_ex_data: CryptoFreeExData = unsafe { core::mem::transmute(CRYPTO_FREE_EX_DATA_ADDRESS) };
        unsafe { free_ex_data(0, bio, ptr::addr_of_mut!((*bio).ex_data)) };
    }

    #[cfg(not(target_os = "none"))]
    {
        let ops = unsafe { ptr::read_volatile(ptr::addr_of!(BIO_FREE_OPS)) };
        unsafe { (ops.free_ex_data)(0, bio, ptr::addr_of_mut!((*bio).ex_data)) };
    }
}

/// bio_free — original: `FUN_0803d3c8` @ 0x0803d3c8 (140 bytes; 6 direct
/// `bl` and 2 `blne` call sites, binary-verified from `osos.dec`).
///
/// Decrements a BIO reference count, invokes its final-release callback and
/// releases its ex-data. The raw routine frees the BIO allocation only if the
/// method and method `destroy` word are both nonzero; it does not call that
/// destroy word.
///
/// # Safety
///
/// A non-null `bio` must be a writable, target-layout [`Bio`]. Its nonzero
/// `method` word must point to a readable target-layout [`BioMethod`]. A
/// nonzero callback word and the active ex-data dispatcher must obey their C
/// ABIs.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bio_free(bio: *mut Bio) -> i32 {
    if bio.is_null() {
        return 0;
    }

    if unsafe { crypto_add_lock(ptr::addr_of_mut!((*bio).references), -1, CRYPTO_LOCK_BIO, ptr::null(), 0) } > 0 {
        return 1;
    }

    if unsafe { (*bio).callback } != 0
        && unsafe { invoke_callback(bio, BIO_CB_FREE, ptr::null_mut(), 0, 0, 1) } <= 0
    {
        return 0;
    }

    unsafe { free_ex_data(bio) };

    let method = unsafe { (*bio).method as usize as *const BioMethod };
    if !method.is_null() && unsafe { (*method).destroy } != 0 {
        unsafe { traced_free(bio.cast()) };
    }

    1
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::ata_cmd::{TracedFreeHooks, TRACED_FREE_HOOKS, TRACED_FREE_TEST_LOCK};
    use crate::kernel::resource_op::{
        missing_registry_acquire, missing_registry_release, ResourceOpHooks,
        RESOURCE_OP_HOOKS, RESOURCE_OP_HOOKS_TEST_LOCK,
    };
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::{Mutex, MutexGuard};
    use std::sync::{atomic::{AtomicI32, Ordering}, LazyLock};
    use std::vec::Vec;

    const FIXTURE_LEN: usize = 0x1000;
    const METHOD_OFFSET: usize = 0x100;
    const PRESENT_POINTER: u32 = 1;

    static BIO_FREE_TEST_LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::BIO_FREE, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static EVENTS: Mutex<Vec<Event>> = Mutex::new(Vec::new());
    static CALLBACK_RESULT: AtomicI32 = AtomicI32::new(1);

    #[derive(Debug, PartialEq, Eq)]
    enum Event {
        Callback(usize, u32, usize, i32, i32, i32),
        ExData(i32, usize, usize),
        Free(usize),
    }

    unsafe extern "C" fn recording_callback(
        bio: *mut Bio,
        operation: u32,
        parg: *mut c_void,
        cmd: i32,
        larg: i32,
        return_value: i32,
    ) -> i32 {
        EVENTS.lock().push(Event::Callback(bio as usize, operation, parg as usize, cmd, larg, return_value));
        CALLBACK_RESULT.load(Ordering::SeqCst)
    }

    unsafe extern "C" fn recording_ex_data(class_index: i32, bio: *mut Bio, ex_data: *mut BioExData) {
        EVENTS.lock().push(Event::ExData(class_index, bio as usize, ex_data as usize));
    }

    unsafe extern "C" fn recording_free(block: *mut u8) {
        EVENTS.lock().push(Event::Free(block as usize));
    }

    struct BioFreeOpsGuard {
        saved: BioFreeOps,
    }

    impl BioFreeOpsGuard {
        unsafe fn install() -> Self {
            let saved = unsafe { ptr::read_volatile(ptr::addr_of!(BIO_FREE_OPS)) };
            unsafe {
                ptr::addr_of_mut!(BIO_FREE_OPS).write(BioFreeOps {
                    callback: recording_callback,
                    free_ex_data: recording_ex_data,
                });
            }
            Self { saved }
        }
    }

    impl Drop for BioFreeOpsGuard {
        fn drop(&mut self) {
            unsafe { ptr::addr_of_mut!(BIO_FREE_OPS).write(self.saved) };
        }
    }

    struct ResourceHooksGuard {
        _lock: MutexGuard<'static, ()>,
        saved: ResourceOpHooks,
    }

    impl ResourceHooksGuard {
        unsafe fn install() -> Self {
            let lock = RESOURCE_OP_HOOKS_TEST_LOCK.lock();
            let saved = unsafe { ptr::read_volatile(ptr::addr_of!(RESOURCE_OP_HOOKS)) };
            unsafe {
                ptr::addr_of_mut!(RESOURCE_OP_HOOKS).write(ResourceOpHooks {
                    static_op: None,
                    add_lock_callback: None,
                    context_id: None,
                    object_op: None,
                    acquire: missing_registry_acquire,
                    release: missing_registry_release,
                });
            }
            Self { _lock: lock, saved }
        }
    }

    impl Drop for ResourceHooksGuard {
        fn drop(&mut self) {
            unsafe { ptr::addr_of_mut!(RESOURCE_OP_HOOKS).write(self.saved) };
        }
    }

    struct FreeHooksGuard {
        _lock: MutexGuard<'static, ()>,
        saved: TracedFreeHooks,
    }

    impl FreeHooksGuard {
        unsafe fn install() -> Self {
            let lock = TRACED_FREE_TEST_LOCK.lock();
            let saved = unsafe { ptr::read_volatile(ptr::addr_of!(TRACED_FREE_HOOKS)) };
            unsafe {
                ptr::addr_of_mut!(TRACED_FREE_HOOKS).write(TracedFreeHooks {
                    free: recording_free,
                    trace: None,
                });
            }
            Self { _lock: lock, saved }
        }
    }

    impl Drop for FreeHooksGuard {
        fn drop(&mut self) {
            unsafe { ptr::addr_of_mut!(TRACED_FREE_HOOKS).write(self.saved) };
        }
    }

    fn fixture() -> Option<(*mut Bio, *mut BioMethod)> {
        let base = *SLAB.as_ref()? as *mut u8;
        unsafe {
            ptr::write_bytes(base, 0, FIXTURE_LEN);
            let bio = base.cast::<Bio>();
            let method = base.add(METHOD_OFFSET).cast::<BioMethod>();
            (*bio).method = method as usize as u32;
            Some((bio, method))
        }
    }

    fn install() -> (ResourceHooksGuard, FreeHooksGuard, BioFreeOpsGuard) {
        unsafe { (ResourceHooksGuard::install(), FreeHooksGuard::install(), BioFreeOpsGuard::install()) }
    }

    fn reset_events(callback_result: i32) {
        EVENTS.lock().clear();
        CALLBACK_RESULT.store(callback_result, Ordering::SeqCst);
    }

    #[test]
    fn null_bio_returns_zero_without_any_dispatch() {
        let _serial = BIO_FREE_TEST_LOCK.lock();
        let (_resource, _free, _ops) = install();
        reset_events(1);

        assert_eq!(unsafe { bio_free(ptr::null_mut()) }, 0);
        assert!(EVENTS.lock().is_empty());
    }

    #[test]
    fn shared_bio_decrements_reference_without_teardown() {
        let _serial = BIO_FREE_TEST_LOCK.lock();
        let (_resource, _free, _ops) = install();
        let Some((bio, _method)) = fixture() else {
            note_missing_u32_fixture("crypto::bio_free");
            return;
        };
        unsafe { (*bio).references = 2 };
        reset_events(1);

        assert_eq!(unsafe { bio_free(bio) }, 1);
        assert_eq!(unsafe { (*bio).references }, 1);
        assert!(EVENTS.lock().is_empty());
    }

    #[test]
    fn callback_can_cancel_final_release_after_reference_reaches_zero() {
        let _serial = BIO_FREE_TEST_LOCK.lock();
        let (_resource, _free, _ops) = install();
        let Some((bio, _method)) = fixture() else {
            note_missing_u32_fixture("crypto::bio_free");
            return;
        };
        unsafe {
            (*bio).references = 1;
            (*bio).callback = PRESENT_POINTER;
        }
        reset_events(0);

        assert_eq!(unsafe { bio_free(bio) }, 0);
        assert_eq!(unsafe { (*bio).references }, 0);
        assert_eq!(
            *EVENTS.lock(),
            [Event::Callback(bio as usize, BIO_CB_FREE, 0, 0, 0, 1)],
        );
    }

    #[test]
    fn final_release_orders_callback_ex_data_then_free_when_destroy_word_exists() {
        let _serial = BIO_FREE_TEST_LOCK.lock();
        let (_resource, _free, _ops) = install();
        let Some((bio, method)) = fixture() else {
            note_missing_u32_fixture("crypto::bio_free");
            return;
        };
        unsafe {
            (*bio).references = 1;
            (*bio).callback = PRESENT_POINTER;
            (*method).destroy = PRESENT_POINTER;
        }
        reset_events(1);

        assert_eq!(unsafe { bio_free(bio) }, 1);
        assert_eq!(unsafe { (*bio).references }, 0);
        assert_eq!(
            *EVENTS.lock(),
            [
                Event::Callback(bio as usize, BIO_CB_FREE, 0, 0, 0, 1),
                Event::ExData(0, bio as usize, unsafe { ptr::addr_of_mut!((*bio).ex_data) as usize }),
                Event::Free(bio as usize),
            ],
        );
    }

    #[test]
    fn missing_method_or_destroy_skips_only_the_final_free() {
        let _serial = BIO_FREE_TEST_LOCK.lock();
        let (_resource, _free, _ops) = install();
        let Some((bio, method)) = fixture() else {
            note_missing_u32_fixture("crypto::bio_free");
            return;
        };
        unsafe {
            (*bio).references = 1;
            (*bio).method = 0;
        }
        reset_events(1);

        assert_eq!(unsafe { bio_free(bio) }, 1);
        assert_eq!(
            *EVENTS.lock(),
            [Event::ExData(0, bio as usize, unsafe { ptr::addr_of_mut!((*bio).ex_data) as usize })],
        );

        unsafe {
            (*bio).references = 1;
            (*bio).method = method as usize as u32;
            (*method).destroy = 0;
        }
        reset_events(1);
        assert_eq!(unsafe { bio_free(bio) }, 1);
        assert_eq!(
            *EVENTS.lock(),
            [Event::ExData(0, bio as usize, unsafe { ptr::addr_of_mut!((*bio).ex_data) as usize })],
        );
    }
}
