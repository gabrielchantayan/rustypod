//! `context_handle_process` — original: `FUN_0822af94` @ **0x0822af94**.
//!
//! **88 bytes**, `0x0822af94..0x0822afec`: `pop {r2,r3,r4,r5,r6,pc}` at
//! 0x0822afe8 is followed by the separately linked `FUN_0822afec` entry.
//! Raw ARM decoding finds **5 plain `bl` instructions** in the body (at
//! 0x0822afac, 0x0822afb8, 0x0822afcc, 0x0822afd8, and 0x0822afe0), with
//! zero predicated `bl` instructions. Ghidra's four call-site report refers
//! to inbound callers at 0x081b6be0, 0x081b735c, 0x0820a4b4, and 0x082203e0.
//!
//! Builds a temporary context-selected refcounted handle, copy-assigns it to a
//! second temporary, processes that handle into `output`, then destroys both
//! temporaries in reverse construction order. The two application callees are
//! still unidentified and remain retail-address seams on ARM; host tests use
//! recording seams. Deliberate deviation: the original's stack slots are
//! represented by Rust locals, preserving their target-width handle semantics.

use crate::cxx::handle::{refcounted_ptr_assign_secondary_variant, refcounted_ptr_release_dtor, RefcountedBody};

/// ABI of the unidentified retail helper at 0x0822afec.
pub type ContextHandleConstruct = unsafe extern "C" fn(*mut *mut RefcountedBody, *mut u8);
/// ABI of the unidentified retail helper at 0x0822b8f8.
pub type ContextHandleProcess = unsafe extern "C" fn(*mut u8, *mut *mut RefcountedBody, *mut u8, *mut u8) -> u32;

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn retail_context_handle_construct() -> ContextHandleConstruct {
    core::mem::transmute(0x0822_afecu32 as usize)
}

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn retail_context_handle_process() -> ContextHandleProcess {
    core::mem::transmute(0x0822_b8f8u32 as usize)
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_construct(slot: *mut *mut RefcountedBody, _context: *mut u8) {
    slot.write(core::ptr::null_mut());
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_process(_context: *mut u8, _handle: *mut *mut RefcountedBody, _output: *mut u8, _changed: *mut u8) -> u32 {
    0
}

#[cfg(not(target_arch = "arm"))]
static mut CONTEXT_HANDLE_CONSTRUCT: ContextHandleConstruct = missing_construct;
#[cfg(not(target_arch = "arm"))]
static mut CONTEXT_HANDLE_PROCESS: ContextHandleProcess = missing_process;

#[inline(always)]
unsafe fn context_handle_construct() -> ContextHandleConstruct {
    #[cfg(target_arch = "arm")]
    { retail_context_handle_construct() }
    #[cfg(not(target_arch = "arm"))]
    { core::ptr::addr_of!(CONTEXT_HANDLE_CONSTRUCT).read_volatile() }
}

#[inline(always)]
unsafe fn context_handle_process_seam() -> ContextHandleProcess {
    #[cfg(target_arch = "arm")]
    { retail_context_handle_process() }
    #[cfg(not(target_arch = "arm"))]
    { core::ptr::addr_of!(CONTEXT_HANDLE_PROCESS).read_volatile() }
}

/// Processes the context-selected handle and returns the retail helper status.
///
/// # Safety
/// `context`, `output`, and optional `changed` must meet the respective
/// retail helper contracts. The context constructor must initialize a handle
/// valid for the two subsequent reference-counted destructors. The third and
/// fourth ABI arguments are unused, exactly as in the ARM body.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn context_handle_process(
    context: *mut u8,
    output: *mut u8,
    _unused_2: *mut u8,
    _unused_3: *mut u8,
    changed: *mut u8,
) -> u32 {
    let mut constructed = core::ptr::null_mut();
    context_handle_construct()(&mut constructed, context);
    let mut assigned = core::ptr::null_mut();
    refcounted_ptr_assign_secondary_variant(&mut assigned, &constructed);
    let status = context_handle_process_seam()(context, &mut assigned, output, changed);
    refcounted_ptr_release_dtor(&mut assigned);
    refcounted_ptr_release_dtor(&mut constructed);
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut BODY: RefcountedBody = RefcountedBody { opaque0: 0, refcount: 2, mutex: core::ptr::null_mut() };
    static mut CONSTRUCT_CONTEXT: *mut u8 = core::ptr::null_mut();
    static mut CONSTRUCT_NULL: bool = false;
    static mut PROCESS_ARGS: (*mut u8, *mut *mut RefcountedBody, *mut u8, *mut u8) = (core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut());

    unsafe extern "C" fn construct(slot: *mut *mut RefcountedBody, context: *mut u8) {
        CONSTRUCT_CONTEXT = context;
        if CONSTRUCT_NULL {
            slot.write(core::ptr::null_mut());
        } else {
            BODY.refcount = 2;
            BODY.mutex = core::ptr::null_mut();
            slot.write(core::ptr::addr_of_mut!(BODY));
        }
    }

    unsafe extern "C" fn process(context: *mut u8, handle: *mut *mut RefcountedBody, output: *mut u8, changed: *mut u8) -> u32 {
        PROCESS_ARGS = (context, handle, output, changed);
        if CONSTRUCT_NULL {
            assert!(handle.read().is_null());
        } else {
            assert_eq!(handle.read(), core::ptr::addr_of_mut!(BODY));
        }
        7
    }

    struct Seams(ContextHandleConstruct, ContextHandleProcess);
    impl Drop for Seams {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(CONTEXT_HANDLE_CONSTRUCT).write_volatile(self.0);
                core::ptr::addr_of_mut!(CONTEXT_HANDLE_PROCESS).write_volatile(self.1);
            }
        }
    }

    unsafe fn install() -> Seams {
        let old = (
            core::ptr::addr_of!(CONTEXT_HANDLE_CONSTRUCT).read_volatile(),
            core::ptr::addr_of!(CONTEXT_HANDLE_PROCESS).read_volatile(),
        );
        core::ptr::addr_of_mut!(CONTEXT_HANDLE_CONSTRUCT).write_volatile(construct);
        core::ptr::addr_of_mut!(CONTEXT_HANDLE_PROCESS).write_volatile(process);
        Seams(old.0, old.1)
    }

    #[test]
    fn processes_assigned_handle_then_releases_both_temporaries() {
        let _lock = LOCK.lock();
        let _seams = unsafe { install() };
        let mut context = 0u8;
        let mut output = 0u8;
        let mut request = 0u8;
        let mut changed = 0u8;
        let status = unsafe { context_handle_process(&mut context, &mut output, &mut request, core::ptr::null_mut(), &mut changed) };
        assert_eq!(status, 7);
        unsafe {
            assert_eq!(CONSTRUCT_CONTEXT, &mut context as *mut u8);
            assert_eq!(PROCESS_ARGS, (&mut context as *mut u8, PROCESS_ARGS.1, &mut output as *mut u8, &mut changed as *mut u8));
            assert_eq!(BODY.refcount, 1);
        }
    }

    #[test]
    fn processes_a_null_constructed_handle_without_releasing_a_body() {
        let _lock = LOCK.lock();
        let _seams = unsafe { install() };
        let mut context = 0u8;
        let mut output = 0u8;
        unsafe { CONSTRUCT_NULL = true; }
        let status = unsafe {
            context_handle_process(&mut context, &mut output, core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut())
        };
        unsafe {
            CONSTRUCT_NULL = false;
            assert_eq!(status, 7);
            assert_eq!(PROCESS_ARGS.0, &mut context as *mut u8);
        }
    }
}
