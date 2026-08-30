//! The app layer's **mutex service** — four status-returning member
//! functions that adapt `kernel/sync_mutex.rs`'s void primitives to the
//! `int method(this, Mutex *)` shape the Silver-era manager classes call.
//!
//! Port:
//! - [`lock_service_lock`] — original: `FUN_08228360` @ 0x08228360
//!   (20 bytes; **39 call sites, all unconditional `bl`**).
//! - [`lock_service_unlock`] — original: `FUN_08228388` @ 0x08228388
//!   (20 bytes; **46 call sites, 45 `bl` + 1 tail `b`**).
//!
//! # The family
//!
//! Four byte-identical-shaped functions sit back to back, in declaration
//! order, each `push {r4, lr}; mov r0, r1; bl <primitive>; mov r0, #0;
//! pop {r4, pc}` — verified by decoding the raw words, and the branch
//! counts by decoding every B/BL word in `osos.dec`:
//!
//! ```text
//! 0x0822834c  create  -> mutex_create @ 0x080744a4    9 bl
//! 0x08228360  lock    -> mutex_lock   @ 0x0807f5c4   39 bl
//! 0x08228374  delete  -> mutex_delete @ 0x0807f650    9 bl
//! 0x08228388  unlock  -> mutex_unlock @ 0x0807f6a0   45 bl + 1 b
//! ```
//!
//! The `push {r4, lr}` is ADS keeping the stack eight-byte aligned; `r4`
//! is never touched. The next function opens at 0x0822839c with the same
//! prologue over a different callee, so 20 bytes is the true extent —
//! Ghidra is right about this one.
//!
//! # Why `this` is dead
//!
//! Every one of these takes the mutex in **r1** and throws **r0** away.
//! The call sites prove r0 is a real `this` and not a spare register: the
//! constructor @ 0x081d9ae8 loads it out of a field —
//!
//! ```text
//! ldr r0, [r4, #0x28c]       @ the service object...
//! add r1, r6, #12            @ ...and the slot's embedded mutex
//! bl  0x0822834c             @ create
//! ...
//! str r8, [r4, #0x28c]       @ the field is only assigned AFTER the loop
//! ```
//!
//! — so the loop hands the adapter a *still-uninitialized* field, 32
//! times, and the firmware is fine because the adapter never reads it.
//! Other sites pass an interior pointer instead (`add r0, r4, #0xccc` @
//! 0x081c89b0) or the word next to the mutex (`ldr r0, [r4, #0xa08]` with
//! `r1 = r4 + 0xa00` @ 0x0820c9cc). One `this`, many unrelated values,
//! never read: a non-virtual member function of a service class that does
//! not need its instance.
//!
//! # The return value is load-bearing
//!
//! `mov r0, #0` is not epilogue noise — callers test it. At 0x0820c9d4:
//!
//! ```text
//! bl  0x08228388
//! cmp r0, #0
//! moveq r0, r6               @ 0 == success
//! ```
//!
//! and at 0x081d9980 the whole call is a tail branch
//! (`pop {r4, r5, r6, lr}; b 0x08228388`), so the adapter's 0 becomes its
//! caller's return value directly. The status is always 0: the kernel
//! primitives are `void`, there is nothing here that can fail.
//!
//! The 46 sites come from six manager classes — 0x081c8494, the
//! 0x081d95xx..0x081d99xx slot table (32 twenty-byte slots each with an
//! embedded mutex at +0x0c), 0x081e36xx..0x081e5cxx, 0x08206xxx and
//! 0x0820cxxx.

use core::ffi::c_void;

use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

/// The status every member of the family returns. The kernel primitives
/// are `void`; nothing here can fail.
pub const LOCK_SERVICE_OK: i32 = 0;

/// lock_service_lock — original: `FUN_08228360` @ 0x08228360 (20 bytes,
/// 0x08228360..0x08228374; **39 call sites, all unconditional `bl`, no
/// predicated forms and no tail `b`** — counted by decoding every branch
/// word in `osos.dec`).
///
/// Acquires `mutex` and reports success:
///
/// ```text
/// push {r4, lr}          @ alignment only; r4 is never touched
/// mov  r0, r1            @ the mutex, from the SECOND argument
/// bl   0x0807f5c4        @ mutex_lock (ported)
/// mov  r0, #0            @ status: callers test this
/// pop  {r4, pc}
/// ```
///
/// `service` is the caller's `this` and is deliberately unused — see the
/// module header for the three different kinds of value the call sites
/// pass in it, including a field that has not been assigned yet.
///
/// The 39 sites sit in the same six manager classes as the unlock
/// adapter's 46 — 0x081c845c, the 0x081d95xx..0x081d99xx slot table
/// (locks the embedded slot mutex at +0x0c), 0x081e35xx..0x081e58xx,
/// 0x08206xxx and 0x0820c9xx..0x0820cexx. No call site tail-branches
/// into the lock adapter, but the zero return is still load-bearing:
/// 0x0820ca68 is followed by `cmp r0, #0` and 0x081e4998 tests the
/// status the same way before deciding an error path.
///
/// # Deviations
///
/// None. `mutex_lock` @ 0x0807f5c4 is ported and called directly.
///
/// # Safety
///
/// `mutex` must point at a live [`Mutex`], as the original requires. A
/// mutex whose semaphore cell is NULL is the "not created yet" state and
/// is a no-op, exactly as in `kernel/sync_mutex.rs`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn lock_service_lock(_service: *mut c_void, mutex: *mut Mutex) -> i32 {
    mutex_lock(mutex);
    LOCK_SERVICE_OK
}

/// lock_service_unlock — original: `FUN_08228388` @ 0x08228388 (20 bytes,
/// 0x08228388..0x0822839c; **46 call sites, 45 `bl` and 1 tail `b`** @
/// 0x081d9980 — counted by decoding every branch word in `osos.dec`).
///
/// Releases `mutex` and reports success:
///
/// ```text
/// push {r4, lr}          @ alignment only; r4 is never touched
/// mov  r0, r1            @ the mutex, from the SECOND argument
/// bl   0x0807f6a0        @ mutex_unlock (ported)
/// mov  r0, #0            @ status: callers test this
/// pop  {r4, pc}
/// ```
///
/// `service` is the caller's `this` and is deliberately unused — see the
/// module header for the three different kinds of value the call sites
/// pass in it, including a field that has not been assigned yet.
///
/// # Deviations
///
/// None. `mutex_unlock` @ 0x0807f6a0 is ported and called directly.
///
/// # Safety
///
/// `mutex` must point at a live [`Mutex`], as the original requires. A
/// mutex whose semaphore cell is NULL is the "not created yet" state and
/// is a no-op, exactly as in `kernel/sync_mutex.rs`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn lock_service_unlock(_service: *mut c_void, mutex: *mut Mutex) -> i32 {
    mutex_unlock(mutex);
    LOCK_SERVICE_OK
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::kernel::sync_mutex::{RomKernelOps, ROM_KERNEL};
    use core::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex as HostMutex;

    /// Serializes the `ROM_KERNEL` save/patch/restore (the
    /// `drivers/display_layer.rs` pattern).
    static ROM_LOCK: HostMutex<()> = HostMutex::new(());

    static SIGNALLED: AtomicU32 = AtomicU32::new(0);
    static LAST_HANDLE: AtomicU32 = AtomicU32::new(0);
    static WAITED: AtomicU32 = AtomicU32::new(0);
    static LAST_WAIT_HANDLE: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn record_signal(handle: u32) {
        SIGNALLED.fetch_add(1, Ordering::SeqCst);
        LAST_HANDLE.store(handle, Ordering::SeqCst);
    }

    unsafe extern "C" fn record_wait(handle: u32) {
        WAITED.fetch_add(1, Ordering::SeqCst);
        LAST_WAIT_HANDLE.store(handle, Ordering::SeqCst);
    }

    /// Runs `body` with a recording `sema_signal` installed, restoring the
    /// table afterwards. The guard is taken once and dropped once, so no
    /// test can re-lock it.
    fn with_recording_kernel(body: impl FnOnce()) {
        let guard = ROM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let saved = unsafe { core::ptr::read(core::ptr::addr_of!(ROM_KERNEL)) };
        let patched = RomKernelOps { sema_signal: record_signal, sema_wait: record_wait, ..saved };
        unsafe { core::ptr::write(core::ptr::addr_of_mut!(ROM_KERNEL), patched) };
        SIGNALLED.store(0, Ordering::SeqCst);
        LAST_HANDLE.store(0, Ordering::SeqCst);
        WAITED.store(0, Ordering::SeqCst);
        LAST_WAIT_HANDLE.store(0, Ordering::SeqCst);

        body();

        unsafe { core::ptr::write(core::ptr::addr_of_mut!(ROM_KERNEL), saved) };
        drop(guard);
    }

    #[test]
    fn lock_takes_the_mutex_from_the_second_argument_and_ignores_this() {
        with_recording_kernel(|| {
            let mut handle: u32 = 0x42;
            let mut mutex = Mutex { sem_cell: &mut handle, unused: 0 };
            // As for unlock: the 32-slot constructor loop hands the
            // adapters a field that has not been assigned yet.
            let bogus_this = 0xdead_beefusize as *mut c_void;

            let status = unsafe { lock_service_lock(bogus_this, &mut mutex) };

            assert_eq!(status, LOCK_SERVICE_OK, "`mov r0, #0`");
            assert_eq!(WAITED.load(Ordering::SeqCst), 1, "r1 reached mutex_lock");
            assert_eq!(LAST_WAIT_HANDLE.load(Ordering::SeqCst), 0x42, "and it was THIS mutex");
        });
    }

    #[test]
    fn lock_accepts_a_null_this() {
        with_recording_kernel(|| {
            let mut handle: u32 = 7;
            let mut mutex = Mutex { sem_cell: &mut handle, unused: 0 };

            let status = unsafe { lock_service_lock(core::ptr::null_mut(), &mut mutex) };

            assert_eq!(status, LOCK_SERVICE_OK);
            assert_eq!(LAST_WAIT_HANDLE.load(Ordering::SeqCst), 7);
        });
    }

    #[test]
    fn lock_on_an_uncreated_mutex_is_a_no_op_that_still_reports_success() {
        // sem_cell NULL is the born state of every slot mutex before the
        // create adapter @ 0x0822834c runs; the status is unconditional.
        with_recording_kernel(|| {
            let mut mutex = Mutex { sem_cell: core::ptr::null_mut(), unused: 0 };

            let status = unsafe { lock_service_lock(core::ptr::null_mut(), &mut mutex) };

            assert_eq!(status, LOCK_SERVICE_OK);
            assert_eq!(WAITED.load(Ordering::SeqCst), 0, "no ROM call");
        });
    }

    #[test]
    fn lock_on_a_zero_handle_cell_is_also_a_no_op() {
        // sem_cell non-NULL with *cell == 0: `mutex_create` allocated the
        // cell but the ROM never filled in a handle; mutex_lock's guard
        // refuses the wait and the adapter still reports success.
        with_recording_kernel(|| {
            let mut handle: u32 = 0;
            let mut mutex = Mutex { sem_cell: &mut handle, unused: 0 };

            let status = unsafe { lock_service_lock(core::ptr::null_mut(), &mut mutex) };

            assert_eq!(status, LOCK_SERVICE_OK);
            assert_eq!(WAITED.load(Ordering::SeqCst), 0, "the zero-handle guard holds");
        });
    }

    #[test]
    fn locking_leaves_the_mutex_object_untouched() {
        // The original writes nothing: `mov r0, r1; bl; mov r0, #0`.
        with_recording_kernel(|| {
            let mut handle: u32 = 3;
            let cell: *mut u32 = &mut handle;
            let mut mutex = Mutex { sem_cell: cell, unused: 0xa5a5_a5a5 };

            unsafe { lock_service_lock(core::ptr::null_mut(), &mut mutex) };

            assert_eq!(mutex.sem_cell, cell, "the cell pointer survives");
            assert_eq!(mutex.unused, 0xa5a5_a5a5, "and so does the padding word");
            assert_eq!(handle, 3, "the handle is waited on, never rewritten");
        });
    }

    #[test]
    fn a_lock_unlock_pair_waits_then_signals_the_same_handle() {
        // The adapters always travel in pairs at the call sites; the same
        // Mutex object must reach the ROM on both legs.
        with_recording_kernel(|| {
            let mut handle: u32 = 0x77;
            let mut mutex = Mutex { sem_cell: &mut handle, unused: 0 };

            assert_eq!(unsafe { lock_service_lock(core::ptr::null_mut(), &mut mutex) }, LOCK_SERVICE_OK);
            assert_eq!(unsafe { lock_service_unlock(core::ptr::null_mut(), &mut mutex) }, LOCK_SERVICE_OK);

            assert_eq!(WAITED.load(Ordering::SeqCst), 1);
            assert_eq!(SIGNALLED.load(Ordering::SeqCst), 1);
            assert_eq!(LAST_WAIT_HANDLE.load(Ordering::SeqCst), 0x77);
            assert_eq!(LAST_HANDLE.load(Ordering::SeqCst), 0x77);
        });
    }

    #[test]
    fn repeated_locks_wait_every_time() {
        // Counting semaphores: the adapter never suppresses a wait.
        with_recording_kernel(|| {
            let mut handle: u32 = 0x13;
            let mut mutex = Mutex { sem_cell: &mut handle, unused: 0 };
            for _ in 0..3 {
                assert_eq!(
                    unsafe { lock_service_lock(core::ptr::null_mut(), &mut mutex) },
                    LOCK_SERVICE_OK
                );
            }
            assert_eq!(WAITED.load(Ordering::SeqCst), 3);
        });
    }

    #[test]
    fn the_mutex_comes_from_the_second_argument_and_the_first_is_ignored() {
        with_recording_kernel(|| {
            let mut handle: u32 = 0x2a;
            let mut mutex = Mutex { sem_cell: &mut handle, unused: 0 };
            // A `this` that is not a valid pointer at all — the 32-slot
            // constructor loop at 0x081d9b08 passes an unassigned field.
            let bogus_this = 0xdead_beefusize as *mut c_void;

            let status = unsafe { lock_service_unlock(bogus_this, &mut mutex) };

            assert_eq!(status, LOCK_SERVICE_OK, "`mov r0, #0`");
            assert_eq!(SIGNALLED.load(Ordering::SeqCst), 1, "r1 reached mutex_unlock");
            assert_eq!(LAST_HANDLE.load(Ordering::SeqCst), 0x2a, "and it was THIS mutex");
        });
    }

    #[test]
    fn a_null_this_is_just_as_fine() {
        with_recording_kernel(|| {
            let mut handle: u32 = 9;
            let mut mutex = Mutex { sem_cell: &mut handle, unused: 0 };

            let status = unsafe { lock_service_unlock(core::ptr::null_mut(), &mut mutex) };

            assert_eq!(status, LOCK_SERVICE_OK);
            assert_eq!(LAST_HANDLE.load(Ordering::SeqCst), 9);
        });
    }

    #[test]
    fn an_uncreated_mutex_is_a_no_op_that_still_reports_success() {
        // sem_cell NULL is the born state of every slot mutex before the
        // create adapter @ 0x0822834c runs.
        with_recording_kernel(|| {
            let mut mutex = Mutex { sem_cell: core::ptr::null_mut(), unused: 0 };

            let status = unsafe { lock_service_unlock(core::ptr::null_mut(), &mut mutex) };

            assert_eq!(status, LOCK_SERVICE_OK, "the status is unconditional");
            assert_eq!(SIGNALLED.load(Ordering::SeqCst), 0, "no ROM call");
        });
    }

    #[test]
    fn a_created_but_undefined_cell_is_also_a_no_op() {
        // sem_cell non-NULL with *cell == 0: `mutex_create` allocated the
        // cell but the ROM never filled in a handle.
        with_recording_kernel(|| {
            let mut handle: u32 = 0;
            let mut mutex = Mutex { sem_cell: &mut handle, unused: 0 };

            let status = unsafe { lock_service_unlock(core::ptr::null_mut(), &mut mutex) };

            assert_eq!(status, LOCK_SERVICE_OK);
            assert_eq!(SIGNALLED.load(Ordering::SeqCst), 0, "the zero-handle guard holds");
        });
    }

    #[test]
    fn unlocking_leaves_the_mutex_object_untouched() {
        // The original writes nothing: `mov r0, r1; bl; mov r0, #0`.
        with_recording_kernel(|| {
            let mut handle: u32 = 5;
            let cell: *mut u32 = &mut handle;
            let mut mutex = Mutex { sem_cell: cell, unused: 0x5a5a_5a5a };

            unsafe { lock_service_unlock(core::ptr::null_mut(), &mut mutex) };

            assert_eq!(mutex.sem_cell, cell, "the cell pointer survives");
            assert_eq!(mutex.unused, 0x5a5a_5a5a, "and so does the padding word");
            assert_eq!(handle, 5, "the handle is signalled, never rewritten");
        });
    }

    #[test]
    fn repeated_unlocks_signal_every_time() {
        // These are RTXC counting semaphores: unlocking an unlocked mutex
        // simply signals again (kernel/sync_mutex.rs).
        with_recording_kernel(|| {
            let mut handle: u32 = 0x11;
            let mut mutex = Mutex { sem_cell: &mut handle, unused: 0 };
            for _ in 0..3 {
                assert_eq!(
                    unsafe { lock_service_unlock(core::ptr::null_mut(), &mut mutex) },
                    LOCK_SERVICE_OK
                );
            }
            assert_eq!(SIGNALLED.load(Ordering::SeqCst), 3);
        });
    }
}
