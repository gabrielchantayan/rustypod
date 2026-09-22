//! `opaque_context_take_mode_one` — original: `FUN_08261ad0` @ **0x08261ad0**
//! (**68 bytes**, `0x08261ad0..0x08261b13`; `push {r4,r5,r6,lr}` through
//! `pop {r4,r5,r6,pc}`; the next separately entered function starts at
//! `0x08261b14`).
//!
//! Full-image A32 decoding finds **3 incoming plain `bl` calls** and **0
//! predicated incoming `bl` calls**. The body makes one unconditional `bl`,
//! to `FUN_08261890` at `0x08261890`, then conditionally tail-branches to the
//! verified but unported body at `0x08261a58`; it contains no predicated `bl`.
//!
//! Algorithm: request one record from the opaque context's `+0x9c` child with
//! mode one and a zero fourth argument. A null result returns `0x27`; otherwise
//! the returned record is forwarded with the original context and output slots
//! to the shared record-processing body. Deliberate deviation: the shared body
//! remains a fixed-address target seam because its identity and its two further
//! unported boundaries are not recovered; host tests install a recording seam.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const RETAIL_OPAQUE_CONTEXT_TAKE_RECORD: usize = 0x0826_1890;
const RETAIL_OPAQUE_CONTEXT_PROCESS_RECORD: usize = 0x0826_1a58;

/// Observed ABI of the opaque context `+0x9c` record-taking boundary.
pub type OpaqueContextTakeRecord = unsafe extern "C" fn(*mut u8, *mut u8, u32, u32) -> *mut u8;
/// Observed ABI of the shared record-processing body at `0x08261a58`.
pub type OpaqueContextProcessRecord = unsafe extern "C" fn(*mut u8, *mut u8, *mut *mut u8, *mut *mut u8) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn take_record(context: *mut u8, child: *mut u8) -> *mut u8 {
    let take: OpaqueContextTakeRecord = core::mem::transmute(RETAIL_OPAQUE_CONTEXT_TAKE_RECORD);
    take(context, child, 1, 0)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn process_record(
    context: *mut u8,
    record: *mut u8,
    payload_out: *mut *mut u8,
    record_out: *mut *mut u8,
) -> u32 {
    let process: OpaqueContextProcessRecord = core::mem::transmute(RETAIL_OPAQUE_CONTEXT_PROCESS_RECORD);
    process(context, record, payload_out, record_out)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_take_record(_context: *mut u8, _child: *mut u8, _mode: u32, _arg: u32) -> *mut u8 {
    core::ptr::null_mut()
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_process_record(
    _context: *mut u8,
    _record: *mut u8,
    _payload_out: *mut *mut u8,
    _record_out: *mut *mut u8,
) -> u32 {
    0
}

/// Host seams for the unported retailOS boundaries.
#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_CONTEXT_TAKE_RECORD: OpaqueContextTakeRecord = missing_take_record;
#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_CONTEXT_PROCESS_RECORD: OpaqueContextProcessRecord = missing_process_record;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn take_record(context: *mut u8, child: *mut u8) -> *mut u8 {
    let take = core::ptr::read_volatile(addr_of!(OPAQUE_CONTEXT_TAKE_RECORD));
    take(context, child, 1, 0)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn process_record(
    context: *mut u8,
    record: *mut u8,
    payload_out: *mut *mut u8,
    record_out: *mut *mut u8,
) -> u32 {
    let process = core::ptr::read_volatile(addr_of!(OPAQUE_CONTEXT_PROCESS_RECORD));
    process(context, record, payload_out, record_out)
}

/// Takes one mode-one record from an opaque context and processes it.
///
/// # Safety
///
/// `context` must address the retail context object, including its `+0x9c`
/// child, and the selected seams must meet their observed ABIs.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_context_take_mode_one(
    context: *mut u8,
    payload_out: *mut *mut u8,
    record_out: *mut *mut u8,
) -> u32 {
    let record = take_record(context, context.add(0x9c));
    if record.is_null() {
        0x27
    } else {
        process_record(context, record, payload_out, record_out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use parking_lot::{Mutex, MutexGuard};

    static SEAM_LOCK: Mutex<()> = Mutex::new(());
    static mut TAKE_CONTEXT: *mut u8 = core::ptr::null_mut();
    static mut TAKE_CHILD: *mut u8 = core::ptr::null_mut();
    static mut TAKE_MODE: u32 = 0;
    static mut TAKE_ARG: u32 = 0;
    static mut PROCESS_ARGS: (*mut u8, *mut u8, *mut *mut u8, *mut *mut u8) = (core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut());
    static mut TAKE_RESULT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn record_take(context: *mut u8, child: *mut u8, mode: u32, arg: u32) -> *mut u8 {
        TAKE_CONTEXT = context;
        TAKE_CHILD = child;
        TAKE_MODE = mode;
        TAKE_ARG = arg;
        TAKE_RESULT
    }

    unsafe extern "C" fn record_process(context: *mut u8, record: *mut u8, payload_out: *mut *mut u8, record_out: *mut *mut u8) -> u32 {
        PROCESS_ARGS = (context, record, payload_out, record_out);
        0x1a
    }

    unsafe fn install_recording_seams() -> (MutexGuard<'static, ()>, OpaqueContextTakeRecord, OpaqueContextProcessRecord) {
        let lock = SEAM_LOCK.lock();
        let take = core::ptr::read_volatile(addr_of!(OPAQUE_CONTEXT_TAKE_RECORD));
        let process = core::ptr::read_volatile(addr_of!(OPAQUE_CONTEXT_PROCESS_RECORD));
        core::ptr::write_volatile(addr_of_mut!(OPAQUE_CONTEXT_TAKE_RECORD), record_take);
        core::ptr::write_volatile(addr_of_mut!(OPAQUE_CONTEXT_PROCESS_RECORD), record_process);
        (lock, take, process)
    }

    unsafe fn restore_seams(take: OpaqueContextTakeRecord, process: OpaqueContextProcessRecord) {
        core::ptr::write_volatile(addr_of_mut!(OPAQUE_CONTEXT_TAKE_RECORD), take);
        core::ptr::write_volatile(addr_of_mut!(OPAQUE_CONTEXT_PROCESS_RECORD), process);
    }

    #[test]
    fn null_record_returns_empty_status_without_processing() {
        unsafe {
            let (_lock, take, process) = install_recording_seams();
            TAKE_RESULT = core::ptr::null_mut();
            PROCESS_ARGS = (core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut());
            let mut context = [0u8; 0x9c];
            assert_eq!(opaque_context_take_mode_one(context.as_mut_ptr(), core::ptr::null_mut(), core::ptr::null_mut()), 0x27);
            assert_eq!(TAKE_CONTEXT, context.as_mut_ptr());
            assert_eq!(TAKE_CHILD, context.as_mut_ptr().add(0x9c));
            assert_eq!((TAKE_MODE, TAKE_ARG), (1, 0));
            assert!(PROCESS_ARGS.0.is_null());
            restore_seams(take, process);
        }
    }

    #[test]
    fn record_forwards_original_arguments_and_status() {
        unsafe {
            let (_lock, take, process) = install_recording_seams();
            let mut context = [0u8; 0x9c];
            let mut payload = core::ptr::null_mut();
            let mut record_out = core::ptr::null_mut();
            TAKE_RESULT = 0x1234usize as *mut u8;
            assert_eq!(opaque_context_take_mode_one(context.as_mut_ptr(), &mut payload, &mut record_out), 0x1a);
            assert_eq!(PROCESS_ARGS, (context.as_mut_ptr(), TAKE_RESULT, &mut payload as *mut *mut u8, &mut record_out as *mut *mut u8));
            restore_seams(take, process);
        }
    }
}
