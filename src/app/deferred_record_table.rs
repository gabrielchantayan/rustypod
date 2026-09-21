//! `deferred_record_table_get` — original: `FUN_082a9630` @ **0x082a9630**.
//!
//! Raw ARM establishes a 80-byte instruction extent,
//! `0x082a9630..0x082a9680`; its four-word literal pool occupies
//! `0x082a9680..0x082a9690`, and the next real function begins at
//! `0x082a9690`. The accessor has three plain, unconditional internal `bl`
//! calls (`cxa_guard_acquire`, `cxa_atexit`, and `cxa_guard_release`) and no
//! predicated BL calls. It has three direct plain-BL callers: `FUN_082a7058`,
//! `FUN_082a71d4`, and `FUN_082a7200`.
//!
//! Algorithm: test bit zero of the guard at `0x08a0fc74`. If clear and the
//! complete word is acquired, zero the two-word deferred-record table at
//! `0x08a0fc78`, register it with handler word `0x083abd48`, and release the
//! guard. Every path returns the table address.
//!
//! Deliberate deviations: the handler word has no recovered function identity,
//! so target builds retain it exactly while host builds use an inert handler.
//! Host statics model the fixed guard and target-layout two-word table.

use core::ffi::c_void;

use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::{cxa_atexit, ShutdownHandlerFn};

const FIRMWARE_GUARD: usize = 0x08a0_fc74;
const FIRMWARE_TABLE: usize = 0x08a0_fc78;
const FIRMWARE_HANDLER_WORD: usize = 0x083a_bd48;
const DSO_HANDLE: i32 = 0x089c_a09c;

type CxaAtexit = unsafe extern "C" fn(*mut c_void, ShutdownHandlerFn, i32) -> i32;
type CxaGuardRelease = unsafe extern "C" fn(*mut u32);

/// Volatile bindings retain the retail registration and release call boundaries;
/// the empty release routine is otherwise eliminated by LLVM.
static mut DEFERRED_RECORD_TABLE_CXA_ATEXIT: CxaAtexit = cxa_atexit;
static mut DEFERRED_RECORD_TABLE_CXA_GUARD_RELEASE: CxaGuardRelease = cxa_guard_release;

#[inline(always)]
unsafe fn deferred_record_table_cxa_atexit() -> CxaAtexit {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DEFERRED_RECORD_TABLE_CXA_ATEXIT)) }
}

#[inline(always)]
unsafe fn deferred_record_table_cxa_guard_release() -> CxaGuardRelease {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DEFERRED_RECORD_TABLE_CXA_GUARD_RELEASE)) }
}

#[cfg(not(target_os = "none"))]
static mut DEFERRED_RECORD_TABLE_GUARD: u32 = 0;
#[cfg(not(target_os = "none"))]
static mut DEFERRED_RECORD_TABLE: [u32; 2] = [0; 2];

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn deferred_record_table_guard() -> *mut u32 {
    FIRMWARE_GUARD as *mut u32
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn deferred_record_table_guard() -> *mut u32 {
    core::ptr::addr_of_mut!(DEFERRED_RECORD_TABLE_GUARD)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn deferred_record_table() -> *mut u32 {
    FIRMWARE_TABLE as *mut u32
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn deferred_record_table() -> *mut u32 {
    core::ptr::addr_of_mut!(DEFERRED_RECORD_TABLE).cast::<u32>()
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn deferred_record_table_handler() -> ShutdownHandlerFn {
    unsafe { core::mem::transmute(FIRMWARE_HANDLER_WORD) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_deferred_record_table_handler(_table: *mut c_void) {}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn deferred_record_table_handler() -> ShutdownHandlerFn {
    host_deferred_record_table_handler
}

/// Initializes and returns the fixed two-word deferred-record table.
///
/// # Safety
///
/// On target, the fixed firmware guard and table addresses must remain valid.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn deferred_record_table_get() -> *mut u32 {
    let guard = unsafe { deferred_record_table_guard() };
    let table = unsafe { deferred_record_table() };
    if unsafe { core::ptr::read_volatile(guard) } & 1 == 0 && unsafe { cxa_guard_acquire(guard) } != 0 {
        unsafe {
            table.write(0);
            table.add(1).write(0);
            deferred_record_table_cxa_atexit()(
                table.cast::<c_void>(),
                deferred_record_table_handler(),
                DSO_HANDLE,
            );
            deferred_record_table_cxa_guard_release()(guard);
        }
    }
    table
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

    static DEFERRED_RECORD_TABLE_LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn box_alloc(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<ShutdownNode>());
        Box::into_raw(Box::new(ShutdownNode {
            next: ptr::null_mut(), arg: ptr::null_mut(),
            handler: host_deferred_record_table_handler, key: 0,
        })) as *mut u8
    }

    unsafe extern "C" fn box_free(node: *mut u8) {
        unsafe { drop(Box::from_raw(node.cast::<ShutdownNode>())) };
    }

    fn reset() -> MutexGuard<'static, ()> {
        let lock = DEFERRED_RECORD_TABLE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            DEFERRED_RECORD_TABLE_GUARD = 0;
            DEFERRED_RECORD_TABLE = [0xaaaa_aaaa, 0x5555_5555];
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
            DEFERRED_RECORD_TABLE_GUARD = 0;
        }
        drop(lock);
    }

    #[test]
    fn first_call_zeros_both_words_and_registers_table() {
        let lock = reset();
        unsafe {
            let table = deferred_record_table_get();
            assert_eq!(table, deferred_record_table());
            assert_eq!(table.read(), 0);
            assert_eq!(table.add(1).read(), 0);
            assert_eq!(DEFERRED_RECORD_TABLE_GUARD, 1);
            let registration = *shutdown_chain_head();
            assert!(!registration.is_null());
            assert_eq!((*registration).arg, table.cast::<c_void>());
            assert_eq!((*registration).handler as usize, host_deferred_record_table_handler as usize);
            assert_eq!((*registration).key, DSO_HANDLE);
        }
        restore(lock);
    }

    #[test]
    fn initialized_guard_preserves_table_without_registration() {
        let lock = reset();
        unsafe {
            DEFERRED_RECORD_TABLE_GUARD = 3;
            DEFERRED_RECORD_TABLE = [7, 11];
            let table = deferred_record_table_get();
            assert_eq!([table.read(), table.add(1).read()], [7, 11]);
            assert!(shutdown_chain_head().read().is_null());
        }
        restore(lock);
    }
}
