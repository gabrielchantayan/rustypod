//! `trace_buffer_entry_submit` — original: `FUN_0807c724` @ `0x0807c724`
//! (64 bytes; true extent `0x0807c724..0x0807c764`, followed by the distinct
//! `FUN_0807c764`).
//!
//! Raw A32 words contain two unconditional internal `bl` instructions:
//! `trace_buffer_get` at `0x0814a08c` and the unported trace-buffer entry
//! submitter at `0x0814a1c0`; there are no predicated internal calls.
//! Independent whole-image A32 decoding finds four inbound plain `bl` calls
//! (`0x080c68f4`, `0x0813a6b0`, `0x0813a8e0`, and `0x0813a990`) and zero
//! predicated inbound `bl` calls. The wrapper obtains the lazy trace buffer,
//! then forwards its eight opaque words after that buffer to the submitter.
//!
//! Deliberate deviation: `FUN_0814a1c0` is not yet ported. Device builds call
//! its verified retailOS address; host tests install a volatile seam. Rust's
//! call/return sequence replaces the stock register-save sequence while
//! preserving all nine submitter arguments and its r0 result.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const RETAIL_TRACE_BUFFER_ENTRY_SUBMIT: usize = 0x0814_a1c0;

/// ABI of the unported trace-buffer entry submitter at `0x0814a1c0`.
pub type TraceBufferEntrySubmit = unsafe extern "C" fn(
    u32, u32, u32, u32, u32, u32, u32, u32, u32,
) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_trace_buffer_entry_submit(
    _buffer: u32, _arg1: u32, _arg2: u32, _arg3: u32, _arg4: u32,
    _arg5: u32, _arg6: u32, _arg7: u32, _arg8: u32,
) -> u32 {
    panic!("install trace-buffer entry-submit host seam before calling this wrapper")
}

/// Host seam for the unported trace-buffer entry submitter.
#[cfg(not(target_os = "none"))]
pub static mut TRACE_BUFFER_ENTRY_SUBMIT: TraceBufferEntrySubmit = missing_trace_buffer_entry_submit;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn trace_buffer_entry_submit_retail(
    buffer: u32, arg1: u32, arg2: u32, arg3: u32, arg4: u32,
    arg5: u32, arg6: u32, arg7: u32, arg8: u32,
) -> u32 {
    let submit: TraceBufferEntrySubmit = unsafe { core::mem::transmute(RETAIL_TRACE_BUFFER_ENTRY_SUBMIT) };
    unsafe { submit(buffer, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn trace_buffer_entry_submit_retail(
    buffer: u32, arg1: u32, arg2: u32, arg3: u32, arg4: u32,
    arg5: u32, arg6: u32, arg7: u32, arg8: u32,
) -> u32 {
    unsafe { core::ptr::read_volatile(addr_of!(TRACE_BUFFER_ENTRY_SUBMIT))(buffer, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) }
}

/// Submits an opaque eight-word request through the lazily created trace buffer.
///
/// # Safety
///
/// All words must meet the stock trace-buffer submitter's opaque contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn trace_buffer_entry_submit(
    arg1: u32, arg2: u32, arg3: u32, arg4: u32,
    arg5: u32, arg6: u32, arg7: u32, arg8: u32,
) -> u32 {
    unsafe {
        trace_buffer_entry_submit_retail(
            crate::app::trace_buffer::trace_buffer_get() as u32,
            arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{TraceBufferEntrySubmit, TRACE_BUFFER_ENTRY_SUBMIT, trace_buffer_entry_submit};
    use crate::app::trace_buffer::{TRACE_BUFFER_CACHE, TRACE_STATIC_GUARD};
    extern crate std;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut ARGS: [u32; 9] = [0; 9];
    static mut CALLS: u32 = 0;

    unsafe extern "C" fn recording_submit(
        buffer: u32, arg1: u32, arg2: u32, arg3: u32, arg4: u32,
        arg5: u32, arg6: u32, arg7: u32, arg8: u32,
    ) -> u32 {
        unsafe {
            CALLS += 1;
            ARGS = [buffer, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8];
        }
        0xa5a5_5a5a
    }

    struct Restore {
        submit: TraceBufferEntrySubmit,
        cache: *mut u8,
        guard: u32,
    }

    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                TRACE_BUFFER_ENTRY_SUBMIT = self.submit;
                TRACE_BUFFER_CACHE = self.cache;
                TRACE_STATIC_GUARD = self.guard;
            }
        }
    }

    #[test]
    fn obtains_trace_buffer_and_forwards_all_request_words() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let buffer = 0x1234_5000usize as *mut u8;
        let _restore = unsafe {
            let restore = Restore {
                submit: TRACE_BUFFER_ENTRY_SUBMIT,
                cache: TRACE_BUFFER_CACHE,
                guard: TRACE_STATIC_GUARD,
            };
            TRACE_BUFFER_ENTRY_SUBMIT = recording_submit;
            TRACE_BUFFER_CACHE = buffer;
            TRACE_STATIC_GUARD = 1;
            CALLS = 0;
            ARGS = [0; 9];
            restore
        };

        let result = unsafe {
            trace_buffer_entry_submit(1, 0x8000_0000, 3, 4, 5, 6, 7, u32::MAX)
        };

        assert_eq!(result, 0xa5a5_5a5a);
        assert_eq!(unsafe { CALLS }, 1);
        assert_eq!(unsafe { ARGS }, [buffer as u32, 1, 0x8000_0000, 3, 4, 5, 6, 7, u32::MAX]);
    }
}
