//! The no-content-layout default resource-name accessor.
//!
//! Port: [`viewer_no_content_layout_default_resource_name`] — original:
//! `FUN_081b1068` @ `0x081b1068` (**100 bytes**: 84 bytes of code through
//! `0x081b10bc` plus its four-word literal pool through `0x081b10c8`; the
//! next separately linked function starts at `0x081b10cc`). Decoding every
//! ARM B/BL word in `osos.dec` found **14 direct callers**: 14 unconditional
//! `bl`, zero predicated forms, and no tail `b`.
//!
//! The returned literal is `0x089ca631`, one byte into the data sequence
//! `"ssViewer_No_Content_Layout_Default\\0"`, so its resource name is
//! `"sViewer_No_Content_Layout_Default"`. The preceding byte and aligned word
//! at `0x089ca630` / `+4` are used by the compiler's function-local-static
//! guard sequence despite being initialized resource data: retail's guard
//! word is `0x72657765` (`"ewer"`), whose bit 0 is set, so the initializer is
//! normally skipped.
//!
//! ## Algorithm
//!
//! Test guard bit 0; if clear and `cxa_guard_acquire` succeeds, register the
//! pointer at base + 1 with the raw, real destructor entry `0x081a631c`, then
//! release the guard. Set the base byte to one only if zero, and return base +
//! 1. The registered target is a real function entry: it calls
//! `0x081de270(object, 11)` and stores one at object + `0xd6`.
//!
//! ## Deliberate deviations
//!
//! Device builds retain the fixed firmware data and raw destructor target.
//! Host builds model that initial resource-data prefix in aligned private
//! storage and use an inert destructor because the retail target is not linked
//! into a host process. This preserves the accessible return string and all
//! guard/registration branches without inventing a dispatch seam.

use core::ffi::c_void;
use core::ptr;

use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::{cxa_atexit, ShutdownHandlerFn};

/// Volatile call binding for the already-ported ADS registration routine.
///
/// This is not an unported-callee seam: it permanently names
/// [`cxa_atexit`], but prevents LLVM from inlining the complete shutdown-node
/// allocation sequence into this small accessor.
type CxaAtexit = unsafe extern "C" fn(*mut c_void, ShutdownHandlerFn, i32) -> i32;
static mut RESOURCE_NAME_CXA_ATEXIT: CxaAtexit = cxa_atexit;

/// Equivalent call binding for the deliberately empty release routine. Its
/// volatile load preserves the retail `bl` even though the port's body is a
/// no-op.
static mut RESOURCE_NAME_CXA_GUARD_RELEASE: unsafe extern "C" fn(*mut u32) = cxa_guard_release;

#[inline(always)]
unsafe fn resource_name_cxa_atexit() -> CxaAtexit {
    ptr::read_volatile(ptr::addr_of!(RESOURCE_NAME_CXA_ATEXIT))
}

#[inline(always)]
unsafe fn resource_name_cxa_guard_release() -> unsafe extern "C" fn(*mut u32) {
    ptr::read_volatile(ptr::addr_of!(RESOURCE_NAME_CXA_GUARD_RELEASE))
}

/// The byte sequence at retail address `0x089ca630`.
const RESOURCE_STORAGE_BYTES: [u8; 35] = *b"ssViewer_No_Content_Layout_Default\0";

/// The shared ADS `__dso_handle` literal at `0x081b10c0`.
const DSO_HANDLE: i32 = 0x089c_a09c;

/// The real storage address, literal-pool word at `0x081b10bc`.
#[cfg(target_os = "none")]
const RESOURCE_STORAGE_ADDRESS: *mut u8 = 0x089c_a630usize as *mut u8;

/// The target's `ldr [base, #4]` requires the resource prefix to be word
/// aligned; host fixtures retain that property.
#[repr(align(4))]
struct ResourceStorage([u8; 35]);

/// Host model of the resource-data prefix at `0x089ca630`.
#[cfg(not(target_os = "none"))]
static mut HOST_RESOURCE_STORAGE: ResourceStorage = ResourceStorage(RESOURCE_STORAGE_BYTES);

#[inline(always)]
unsafe fn resource_storage() -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        RESOURCE_STORAGE_ADDRESS
    }

    #[cfg(not(target_os = "none"))]
    {
        ptr::addr_of_mut!(HOST_RESOURCE_STORAGE).cast::<u8>()
    }
}

/// Returns the real registered destructor entry, rather than assigning it a
/// semantic identity not established by the bytes.
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn resource_name_destructor() -> ShutdownHandlerFn {
    core::mem::transmute(0x081a_631cusize)
}

/// The retail destructor cannot execute in a host process.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_resource_name_destructor(_object: *mut c_void) {}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn resource_name_destructor() -> ShutdownHandlerFn {
    host_resource_name_destructor
}

/// viewer_no_content_layout_default_resource_name — original: `FUN_081b1068`
/// @ `0x081b1068` (100 bytes: 84 code + 16-byte literal pool; 14 direct,
/// unconditional `bl` callers, zero predicated forms, binary-verified).
///
/// Returns the fixed `"sViewer_No_Content_Layout_Default"` resource name.
/// The unusual guard is faithful: if the word at base + 4 has bit 0 clear,
/// acquire it, register base + 1 for shutdown, and release it. A nonzero
/// bit-0-clear guard reaches `cxa_guard_acquire` but is refused there.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.viewer_no_content_layout_default_resource_name")]
pub unsafe extern "C" fn viewer_no_content_layout_default_resource_name() -> *mut u8 {
    let storage = resource_storage();
    let guard = storage.add(4).cast::<u32>();
    if (ptr::read_volatile(guard) & 1) == 0 && cxa_guard_acquire(guard) != 0 {
        resource_name_cxa_atexit()(storage.add(1).cast::<c_void>(), resource_name_destructor(), DSO_HANDLE);
        resource_name_cxa_guard_release()(guard);
    }
    if ptr::read_volatile(storage) == 0 {
        ptr::write_volatile(storage, 1);
    }
    storage.add(1)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::runtime::shutdown_chain::{
        lib_shutdown_chain, shutdown_chain_head, ShutdownNode, SHUTDOWN_ALLOC, SHUTDOWN_FREE,
    };
    use std::boxed::Box;
    use std::sync::{Mutex, MutexGuard};

    /// Serializes this module's resource storage and shutdown-chain fixture.
    static RESOURCE_NAME_LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn box_alloc(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<ShutdownNode>());
        Box::into_raw(Box::new(ShutdownNode {
            next: ptr::null_mut(),
            arg: ptr::null_mut(),
            handler: host_resource_name_destructor,
            key: 0,
        })) as *mut u8
    }

    unsafe extern "C" fn box_free(block: *mut u8) {
        drop(Box::from_raw(block as *mut ShutdownNode));
    }

    fn storage() -> *mut u8 {
        unsafe { ptr::addr_of_mut!(HOST_RESOURCE_STORAGE).cast::<u8>() }
    }

    fn reset() -> MutexGuard<'static, ()> {
        let guard = RESOURCE_NAME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            HOST_RESOURCE_STORAGE.0 = RESOURCE_STORAGE_BYTES;
            SHUTDOWN_ALLOC = box_alloc;
            SHUTDOWN_FREE = box_free;
            *shutdown_chain_head() = ptr::null_mut();
        }
        guard
    }

    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            lib_shutdown_chain(0);
            SHUTDOWN_ALLOC = crate::malloc_rt::malloc;
            SHUTDOWN_FREE = crate::malloc_rt::free;
            HOST_RESOURCE_STORAGE.0 = RESOURCE_STORAGE_BYTES;
            *shutdown_chain_head() = ptr::null_mut();
        }
        drop(guard);
    }

    #[test]
    fn returns_the_initialized_retail_resource_name() {
        let guard = reset();
        unsafe {
            let result = viewer_no_content_layout_default_resource_name();
            assert_eq!(result, storage().add(1));
            assert_eq!(core::slice::from_raw_parts(result, 33), b"sViewer_No_Content_Layout_Default");
            assert_eq!(ptr::read_volatile(storage().add(4).cast::<u32>()), 0x7265_7765);
            assert!((*shutdown_chain_head()).is_null());
        }
        restore(guard);
    }

    #[test]
    fn clear_guard_registers_the_offset_resource_pointer() {
        let guard = reset();
        unsafe {
            let guard_word = storage().add(4).cast::<u32>();
            ptr::write_volatile(guard_word, 0);
            let result = viewer_no_content_layout_default_resource_name();
            let node = *shutdown_chain_head();
            assert_eq!(result, storage().add(1));
            assert_eq!(ptr::read_volatile(guard_word), 1);
            assert!(!node.is_null());
            assert_eq!((*node).arg, storage().add(1).cast::<c_void>());
            assert_eq!((*node).key, DSO_HANDLE);
        }
        restore(guard);
    }

    #[test]
    fn nonzero_bit_clear_guard_is_refused_without_registration() {
        let guard = reset();
        unsafe {
            let guard_word = storage().add(4).cast::<u32>();
            ptr::write_volatile(guard_word, 2);
            assert_eq!(viewer_no_content_layout_default_resource_name(), storage().add(1));
            assert_eq!(ptr::read_volatile(guard_word), 2);
            assert!((*shutdown_chain_head()).is_null());
        }
        restore(guard);
    }
}
