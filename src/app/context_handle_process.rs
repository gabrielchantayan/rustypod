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

use crate::app::mode_selected_handle_construct::mode_selected_handle_construct;
use crate::cxx::handle::{refcounted_ptr_assign_secondary_variant, refcounted_ptr_release_dtor, RefcountedBody};

/// ABI of the unidentified retail helper at 0x0822b8f8.
pub type ContextHandleProcess = unsafe extern "C" fn(*mut u8, *mut *mut RefcountedBody, *mut u8, *mut u8) -> u32;

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn retail_context_handle_process() -> ContextHandleProcess {
    core::mem::transmute(0x0822_b8f8u32 as usize)
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_process(_context: *mut u8, _handle: *mut *mut RefcountedBody, _output: *mut u8, _changed: *mut u8) -> u32 {
    0
}

#[cfg(not(target_arch = "arm"))]
static mut CONTEXT_HANDLE_PROCESS: ContextHandleProcess = missing_process;

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
    mode_selected_handle_construct(&mut constructed, context, _unused_2, _unused_3);
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
    static mut PROCESS_ARGS: (*mut u8, *mut *mut RefcountedBody, *mut u8, *mut u8) = (core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut());

    unsafe extern "C" fn process(context: *mut u8, handle: *mut *mut RefcountedBody, output: *mut u8, changed: *mut u8) -> u32 {
        PROCESS_ARGS = (context, handle, output, changed);
        assert!(handle.read().is_null());
        7
    }

    struct Seams(ContextHandleProcess);
    impl Drop for Seams {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(CONTEXT_HANDLE_PROCESS).write_volatile(self.0) }
        }
    }

    unsafe fn install() -> Seams {
        let old = core::ptr::addr_of!(CONTEXT_HANDLE_PROCESS).read_volatile();
        core::ptr::addr_of_mut!(CONTEXT_HANDLE_PROCESS).write_volatile(process);
        Seams(old)
    }

    #[test]
    fn processes_an_unready_context_with_an_empty_handle() {
        let _lock = LOCK.lock();
        let _seams = unsafe { install() };
        let mut context = [0u64; 0xc0];
        let mut output = 0u8;
        let mut changed = 0u8;
        let status = unsafe {
            context_handle_process(
                context.as_mut_ptr().cast(),
                &mut output,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut changed,
            )
        };
        assert_eq!(status, 7);
        unsafe {
            assert_eq!(PROCESS_ARGS.0, context.as_mut_ptr().cast());
            assert_eq!(PROCESS_ARGS.2, core::ptr::addr_of_mut!(output));
            assert_eq!(PROCESS_ARGS.3, core::ptr::addr_of_mut!(changed));
        }
    }
}
