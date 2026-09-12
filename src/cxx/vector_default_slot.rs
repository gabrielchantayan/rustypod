//! Indexed vector-element lookup with a lazily initialized fallback slot.
//!
//! The owner has one unexamined target word before its `std::vector` head. The
//! fallback is a separate global word holding the literal `0x08b3_1810`; no
//! concrete type for either value is established by the retailOS callers.

use core::ffi::c_void;

use crate::cxx::templates::{vector_size_elem4_alias_7944, VectorBounds};
use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::{cxa_atexit, ShutdownHandlerFn};

/// The owner shape consumed by [`vector_element_or_default_slot`].
///
/// `elements` is at target offset +4. Named fields preserve that ARM layout
/// while remaining disjoint on 64-bit host fixtures.
#[repr(C)]
pub struct VectorDefaultSlotOwner {
    pub unknown: u32,
    pub elements: VectorBounds,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x04] = [0; core::mem::offset_of!(VectorDefaultSlotOwner, elements)];

/// Fixed value written into the fallback slot, from the literal pool at
/// 0x0829d138.
const DEFAULT_SLOT_VALUE: u32 = 0x08b3_1810;

/// `__dso_handle`, the literal pool word at 0x0829d13c.
const DSO_HANDLE: i32 = 0x089c_a09c;

/// Volatile call bindings preserve the original registration and release calls
/// instead of allowing LLVM to inline the registered shutdown-chain sequence
/// or erase the empty release port.
type CxaAtexit = unsafe extern "C" fn(*mut c_void, ShutdownHandlerFn, i32) -> i32;
type CxaGuardRelease = unsafe extern "C" fn(*mut u32);
static mut VECTOR_DEFAULT_SLOT_CXA_ATEXIT: CxaAtexit = cxa_atexit;
static mut VECTOR_DEFAULT_SLOT_CXA_GUARD_RELEASE: CxaGuardRelease = cxa_guard_release;

#[inline(always)]
unsafe fn vector_default_slot_cxa_atexit() -> CxaAtexit {
    core::ptr::read_volatile(core::ptr::addr_of!(VECTOR_DEFAULT_SLOT_CXA_ATEXIT))
}

#[inline(always)]
unsafe fn vector_default_slot_cxa_guard_release() -> CxaGuardRelease {
    core::ptr::read_volatile(core::ptr::addr_of!(VECTOR_DEFAULT_SLOT_CXA_GUARD_RELEASE))
}

/// Crate-static replacement for the guard at 0x08a0fc68.
///
/// The firmware's .bss is runtime state, so zero is the verified pre-init
/// state rather than a host-mappable image address.
static mut VECTOR_DEFAULT_SLOT_GUARD: u32 = 0;

/// Crate-static replacement for the fallback word at 0x08a0fc6c.
static mut VECTOR_DEFAULT_SLOT: u32 = 0;

/// The `cxa_atexit` handler word in the target's literal pool is 0x083cddb4.
/// It is an instruction within `FUN_083cdd24`, not a function entry: executing
/// it as a handler would write into an unprepared caller frame. The retailOS
/// shutdown chain is not entered on the observed path, so its safe no-op
/// replacement preserves every observable accessor result.
unsafe extern "C" fn vector_default_slot_destructor(_slot: *mut c_void) {}

/// vector_element_or_default_slot — original: `FUN_0829d0c4` @ 0x0829d0c4
/// (128 bytes: 108 bytes of code plus a five-word literal pool; Ghidra reports
/// only the code extent).
///
/// Calls the existing 4-byte vector-size instantiation on `owner + 4`. When
/// `index < size` under the ARM unsigned comparison, it returns the address of
/// that four-byte element. Otherwise, it tests bit 0 of the fallback guard;
/// on first use, it acquires the full guard word, writes `0x08b31810` to the
/// fallback slot, registers that slot with `cxa_atexit`, and releases the
/// guard. It then returns the fallback slot address. A nonzero guard with bit
/// 0 clear reaches `cxa_guard_acquire` and is refused, leaving the slot as-is.
///
/// Raw decoding finds exactly seven direct inbound calls, all unconditional
/// plain `bl` forms (no predicated calls or tail branches): 0x08134390,
/// 0x081343a4, 0x081343b8, 0x08134448, 0x0813453c, 0x081345dc, and
/// 0x08134620. There are no aligned raw-word references to 0x0829d0c4.
///
/// Deliberate deviations: the two fixed .bss words are crate statics on host
/// and target, and the invalid non-entry shutdown-handler word is an inert
/// handler as documented above. Volatile bindings retain the existing
/// `cxa_atexit` and `cxa_guard_release` call boundaries without creating a
/// replaceable dispatch seam; the vector-size and guard-acquire calls remain
/// direct to their existing ports.
///
/// # Safety
///
/// `owner` must point to a readable [`VectorDefaultSlotOwner`]. When `index`
/// is below the vector's unsigned size, `elements.begin` must delimit readable
/// aligned four-byte elements through that index. The function has no NULL
/// guard for `owner` or the vector head.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vector_element_or_default_slot")]
#[inline(never)]
pub unsafe extern "C" fn vector_element_or_default_slot(
    owner: *const VectorDefaultSlotOwner,
    index: u32,
) -> *mut u32 {
    let elements = core::ptr::addr_of!((*owner).elements);
    if (vector_size_elem4_alias_7944(elements) as u32) > index {
        return (*elements).begin.cast::<u32>().add(index as usize);
    }

    let guard = core::ptr::addr_of_mut!(VECTOR_DEFAULT_SLOT_GUARD);
    let slot = core::ptr::addr_of_mut!(VECTOR_DEFAULT_SLOT);
    if core::ptr::read_volatile(guard) & 1 == 0 && cxa_guard_acquire(guard) != 0 {
        core::ptr::write_volatile(slot, DEFAULT_SLOT_VALUE);
        vector_default_slot_cxa_atexit()(slot.cast::<c_void>(), vector_default_slot_destructor, DSO_HANDLE);
        vector_default_slot_cxa_guard_release()(guard);
    }
    slot
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

    static VECTOR_DEFAULT_SLOT_LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn box_alloc(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<ShutdownNode>());
        Box::into_raw(Box::new(ShutdownNode {
            next: ptr::null_mut(),
            arg: ptr::null_mut(),
            handler: vector_default_slot_destructor,
            key: 0,
        })) as *mut u8
    }

    unsafe extern "C" fn box_free(block: *mut u8) {
        drop(Box::from_raw(block.cast::<ShutdownNode>()));
    }

    fn reset() -> MutexGuard<'static, ()> {
        let guard = VECTOR_DEFAULT_SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            VECTOR_DEFAULT_SLOT_GUARD = 0;
            VECTOR_DEFAULT_SLOT = 0;
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
            VECTOR_DEFAULT_SLOT_GUARD = 0;
            VECTOR_DEFAULT_SLOT = 0;
        }
        drop(guard);
    }

    #[test]
    fn returns_an_in_range_four_byte_element_without_initializing_fallback() {
        let guard = reset();
        let mut values = [0x1020_3040u32, 0x5060_7080, 0x90a0_b0c0];
        let owner = VectorDefaultSlotOwner {
            unknown: 0xdead_beef,
            elements: VectorBounds {
                begin: values.as_mut_ptr().cast::<u8>(),
                end: unsafe { values.as_mut_ptr().add(values.len()).cast::<u8>() },
            },
        };

        unsafe {
            assert_eq!(vector_element_or_default_slot(&owner, 2), values.as_mut_ptr().add(2));
            assert_eq!(values, [0x1020_3040, 0x5060_7080, 0x90a0_b0c0]);
            assert_eq!(VECTOR_DEFAULT_SLOT_GUARD, 0);
            assert_eq!(VECTOR_DEFAULT_SLOT, 0);
            assert!(shutdown_chain_head().read().is_null());
        }
        restore(guard);
    }

    #[test]
    fn out_of_range_initializes_and_registers_the_single_fallback_slot() {
        let guard = reset();
        let mut values = [0x1122_3344u32];
        let owner = VectorDefaultSlotOwner {
            unknown: 0,
            elements: VectorBounds {
                begin: values.as_mut_ptr().cast::<u8>(),
                end: unsafe { values.as_mut_ptr().add(1).cast::<u8>() },
            },
        };

        unsafe {
            let slot = vector_element_or_default_slot(&owner, 1);
            assert_eq!(slot, ptr::addr_of_mut!(VECTOR_DEFAULT_SLOT));
            assert_eq!(slot.read(), DEFAULT_SLOT_VALUE);
            assert_eq!(VECTOR_DEFAULT_SLOT_GUARD, 1);
            let registration = shutdown_chain_head().read();
            assert!(!registration.is_null());
            assert_eq!((*registration).arg, slot.cast::<c_void>());
            assert_eq!((*registration).handler as usize, vector_default_slot_destructor as usize);
            assert_eq!((*registration).key, DSO_HANDLE);
            assert!((*registration).next.is_null());

            assert_eq!(vector_element_or_default_slot(&owner, u32::MAX), slot);
            assert!((*registration).next.is_null(), "fallback registers once");
        }
        restore(guard);
    }

    #[test]
    fn bit_zero_clear_nonzero_guard_refuses_fallback_initialization() {
        let guard = reset();
        let owner = VectorDefaultSlotOwner {
            unknown: 0,
            elements: VectorBounds {
                begin: ptr::null_mut(),
                end: ptr::null_mut(),
            },
        };

        unsafe {
            VECTOR_DEFAULT_SLOT_GUARD = 2;
            VECTOR_DEFAULT_SLOT = 0xfeed_face;
            assert_eq!(vector_element_or_default_slot(&owner, 0), ptr::addr_of_mut!(VECTOR_DEFAULT_SLOT));
            assert_eq!(VECTOR_DEFAULT_SLOT_GUARD, 2);
            assert_eq!(VECTOR_DEFAULT_SLOT, 0xfeed_face);
            assert!(shutdown_chain_head().read().is_null());
        }
        restore(guard);
    }
}
