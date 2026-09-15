//! The ATA work-loop fixed singleton accessor.
//!
//! Port:
//! - [`ata_work_loop_get`] — original: `FUN_0811f634` @ 0x0811f634
//!   (72 bytes: 18 instruction words plus a 4-word literal pool; **5
//!   unconditional plain `bl` call sites, no predicated forms**, verified by
//!   decoding every ARM B/BL word in osos.dec).
//!
//! The accessor is an ADS function-local static over the ATA work-loop object
//! at 0x08b2f7f8. Its constructor, `FUN_0811f68c`, initializes its one-time
//! base then its 0x20-byte state object at +0x08. That constructor is not yet
//! ported, so [`ATA_WORK_LOOP_CONSTRUCTOR`] preserves the direct-call boundary.

use core::ffi::c_void;

use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::cxa_atexit;

/// Exact object extent observed through `FUN_0811f68c`: the state subobject
/// starts at +0x08 and occupies 0x20 bytes.
pub const ATA_WORK_LOOP_SIZE: usize = 0x28;

/// The common ADS `__dso_handle`, pool word @ 0x0811f684.
const DSO_HANDLE: i32 = 0x089ca09c;

/// The one-time guard, original word @ 0x08a0edf0.
pub static mut ATA_WORK_LOOP_GUARD: u32 = 0;

/// Fixed ATA work-loop storage, original object @ 0x08b2f7f8.
#[repr(C, align(4))]
pub struct AtaWorkLoopStorage {
    bytes: [u8; ATA_WORK_LOOP_SIZE],
}

pub static mut ATA_WORK_LOOP: AtaWorkLoopStorage = AtaWorkLoopStorage {
    bytes: [0; ATA_WORK_LOOP_SIZE],
};

/// An ADS C++ constructor: it receives storage and returns `this` in r0.
pub type Constructor = unsafe extern "C" fn(this: *mut u8) -> *mut u8;

/// Host-safe default for the unported `FUN_0811f68c` constructor.
unsafe extern "C" fn zeroing_ata_work_loop_constructor(this: *mut u8) -> *mut u8 {
    for offset in 0..ATA_WORK_LOOP_SIZE {
        this.add(offset).write_volatile(0);
    }
    this
}

/// Dispatch seam for unported ATA work-loop constructor `FUN_0811f68c`.
pub static mut ATA_WORK_LOOP_CONSTRUCTOR: Constructor = zeroing_ata_work_loop_constructor;

/// `FUN_081147e8`, the pool destructor, is unported and its three-argument
/// dispatch ABI cannot safely run from the one-argument shutdown chain.
unsafe extern "C" fn ata_work_loop_destructor(_object: *mut c_void) {}

/// ata_work_loop_get — original: `FUN_0811f634` @ 0x0811f634 (72 bytes:
/// 56 bytes of code plus a 4-word literal pool; 5 unconditional plain `bl`
/// call sites, no predicated forms, binary-verified).
///
/// Returns the fixed ATA work-loop object and initializes it once. The fast
/// path tests guard bit 0; the slow path acquires the full guard, constructs
/// the object, registers the constructor result with `cxa_atexit`, then
/// releases the guard.
///
/// Deliberate deviations: fixed firmware addresses are crate statics, the
/// unported constructor is a replaceable seam, and the unported destructor is
/// a shutdown-safe no-op because its retail entry requires three arguments.
/// Consequently this accessor is not hook-ready with its default constructor.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ata_work_loop_get() -> *mut u8 {
    let guard = core::ptr::addr_of_mut!(ATA_WORK_LOOP_GUARD);
    let object = core::ptr::addr_of_mut!(ATA_WORK_LOOP).cast::<u8>();
    if (core::ptr::read_volatile(guard) & 1) == 0 && cxa_guard_acquire(guard) != 0 {
        let this = core::ptr::read_volatile(core::ptr::addr_of!(ATA_WORK_LOOP_CONSTRUCTOR))(object);
        cxa_atexit(this.cast::<c_void>(), ata_work_loop_destructor, DSO_HANDLE);
        cxa_guard_release(guard);
    }
    object
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::runtime::shutdown_chain::{
        lib_shutdown_chain, shutdown_chain_head, ShutdownNode, SHUTDOWN_ALLOC, SHUTDOWN_FREE,
    };
    use core::ptr;
    use std::boxed::Box;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static ATA_WORK_LOOP_LOCK: Mutex<()> = Mutex::new(());
    static mut CONSTRUCTOR_ARGUMENTS: Vec<*mut u8> = Vec::new();
    static mut CONSTRUCTOR_RESULT: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn recording_constructor(this: *mut u8) -> *mut u8 {
        (*ptr::addr_of_mut!(CONSTRUCTOR_ARGUMENTS)).push(this);
        this.add(ATA_WORK_LOOP_SIZE - 1).write_volatile(0x5a);
        ptr::read_volatile(ptr::addr_of!(CONSTRUCTOR_RESULT))
    }

    unsafe extern "C" fn box_alloc(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<ShutdownNode>());
        Box::into_raw(Box::new(ShutdownNode {
            next: ptr::null_mut(), arg: ptr::null_mut(), handler: ata_work_loop_destructor, key: 0,
        })) as *mut u8
    }

    unsafe extern "C" fn box_free(block: *mut u8) {
        drop(Box::from_raw(block as *mut ShutdownNode));
    }

    fn storage() -> *mut u8 {
        ptr::addr_of_mut!(ATA_WORK_LOOP).cast::<u8>()
    }

    fn reset() -> MutexGuard<'static, ()> {
        let lock = ATA_WORK_LOOP_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            ATA_WORK_LOOP_GUARD = 0;
            for offset in 0..ATA_WORK_LOOP_SIZE {
                storage().add(offset).write(0xa5);
            }
            ATA_WORK_LOOP_CONSTRUCTOR = zeroing_ata_work_loop_constructor;
            CONSTRUCTOR_RESULT = storage();
            (*ptr::addr_of_mut!(CONSTRUCTOR_ARGUMENTS)).clear();
            SHUTDOWN_ALLOC = box_alloc;
            SHUTDOWN_FREE = box_free;
            *shutdown_chain_head() = ptr::null_mut();
        }
        lock
    }

    fn restore(lock: MutexGuard<'static, ()>) {
        unsafe {
            lib_shutdown_chain(0);
            SHUTDOWN_ALLOC = crate::malloc_rt::malloc;
            SHUTDOWN_FREE = crate::malloc_rt::free;
            ATA_WORK_LOOP_CONSTRUCTOR = zeroing_ata_work_loop_constructor;
            ATA_WORK_LOOP_GUARD = 0;
        }
        drop(lock);
    }

    #[test]
    fn first_call_constructs_registers_and_returns_fixed_storage() {
        let lock = reset();
        unsafe {
            ATA_WORK_LOOP_CONSTRUCTOR = recording_constructor;
            assert_eq!(ata_work_loop_get(), storage());
            assert_eq!(*ptr::addr_of!(CONSTRUCTOR_ARGUMENTS), std::vec![storage()]);
            assert_eq!(ptr::read_volatile(ptr::addr_of!(ATA_WORK_LOOP_GUARD)), 1);
            assert_eq!(storage().add(ATA_WORK_LOOP_SIZE - 1).read(), 0x5a);
            let head = *shutdown_chain_head();
            assert!(!head.is_null());
            assert_eq!((*head).arg as *mut u8, storage());
            assert_eq!((*head).handler as usize, ata_work_loop_destructor as usize);
            assert_eq!((*head).key, DSO_HANDLE);
        }
        restore(lock);
    }

    #[test]
    fn initialized_guard_skips_constructor_and_registration() {
        let lock = reset();
        unsafe {
            ATA_WORK_LOOP_CONSTRUCTOR = recording_constructor;
            ata_work_loop_get();
            storage().add(0x14).write(0x33);
            assert_eq!(ata_work_loop_get(), storage());
            assert_eq!((*ptr::addr_of!(CONSTRUCTOR_ARGUMENTS)).len(), 1);
            assert_eq!(storage().add(0x14).read(), 0x33);
            assert!((*(*shutdown_chain_head())).next.is_null());
        }
        restore(lock);
    }

    #[test]
    fn bit_zero_clear_nonzero_guard_is_refused_by_acquire() {
        let lock = reset();
        unsafe {
            ATA_WORK_LOOP_CONSTRUCTOR = recording_constructor;
            ATA_WORK_LOOP_GUARD = 2;
            assert_eq!(ata_work_loop_get(), storage());
            assert!((*ptr::addr_of!(CONSTRUCTOR_ARGUMENTS)).is_empty());
            assert_eq!(ptr::read_volatile(ptr::addr_of!(ATA_WORK_LOOP_GUARD)), 2);
            assert!(shutdown_chain_head().read().is_null());
            assert_eq!(storage().read(), 0xa5);
        }
        restore(lock);
    }

    #[test]
    fn registration_uses_constructor_result_but_return_is_fixed_storage() {
        let lock = reset();
        unsafe {
            ATA_WORK_LOOP_CONSTRUCTOR = recording_constructor;
            CONSTRUCTOR_RESULT = storage().add(8);
            assert_eq!(ata_work_loop_get(), storage());
            assert_eq!((*(*shutdown_chain_head())).arg as *mut u8, storage().add(8));
        }
        restore(lock);
    }
}
