//! `output_buffer_write_dictionary_close` — original: `FUN_08123b00` @ load
//! address **0x08123b00** (52 bytes, `0x08123b00..0x08123b34`; the next real
//! function begins at 0x08123b40 after the `"%s</dict>\n\0"` literal pool).
//!
//! Raw `osos.dec` contains two unconditional direct `bl` instructions
//! (`0x08123b08` to 0x08123a54 and `0x08123b20` to `snprintf` at
//! 0x0802f768), no predicated `bl` instructions, and an unconditional tail
//! `b` at 0x08123b30 to 0x08123c58. The three direct incoming calls are all
//! unconditional `bl` instructions. Ghidra incorrectly merges the tail
//! target's strlen/strncat body into this function.
//!
//! ## Algorithm
//!
//! Writes indentation for `level`, formats `"%s</dict>\n"` into the 512-byte
//! scratch region at state+0x15, then tail-dispatches the generated C string
//! to the output-buffer append helper.
//!
//! ## Deliberate deviations
//!
//! The two unported direct targets remain volatile seams. Target builds bind
//! them to their verified firmware addresses; host tests install deterministic
//! substitutes. This preserves the retail call sequence without assigning an
//! unverified source-level identity to either target.

#[cfg(target_os = "none")]
use core::mem::transmute;

use crate::app::output_buffer_reset::OutputBufferState;
use crate::printf_api::snprintf;

const SCRATCH_OFFSET: usize = 0x15;
const SCRATCH_SIZE: usize = 0x200;
const CLOSE_FORMAT: &[u8] = b"%s</dict>\n\0";

type WriteIndentationFn = unsafe extern "C" fn(*mut OutputBufferState, u32);
type AppendCStringFn = unsafe extern "C" fn(*mut OutputBufferState, *const u8);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_write_indentation(state: *mut OutputBufferState, level: u32) {
    let function: WriteIndentationFn = unsafe { transmute(0x0812_3a54usize) };
    unsafe { function(state, level) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_write_indentation(_state: *mut OutputBufferState, _level: u32) {
    panic!("output_buffer_write_dictionary_close requires firmware helper 0x08123a54")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_append_c_string(state: *mut OutputBufferState, text: *const u8) {
    let function: AppendCStringFn = unsafe { transmute(0x0812_3c58usize) };
    unsafe { function(state, text) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_append_c_string(_state: *mut OutputBufferState, _text: *const u8) {
    panic!("output_buffer_write_dictionary_close requires firmware helper 0x08123c58")
}

/// Active target for the indentation writer at 0x08123a54.
#[cfg(target_os = "none")]
pub static mut OUTPUT_BUFFER_WRITE_INDENTATION: WriteIndentationFn = firmware_write_indentation;
/// See the target definition.
#[cfg(not(target_os = "none"))]
pub static mut OUTPUT_BUFFER_WRITE_INDENTATION: WriteIndentationFn = missing_write_indentation;

/// Active target for the output-buffer C-string appender at 0x08123c58.
#[cfg(target_os = "none")]
pub static mut OUTPUT_BUFFER_APPEND_C_STRING: AppendCStringFn = firmware_append_c_string;
/// See the target definition.
#[cfg(not(target_os = "none"))]
pub static mut OUTPUT_BUFFER_APPEND_C_STRING: AppendCStringFn = missing_append_c_string;

#[inline(always)]
unsafe fn write_indentation() -> WriteIndentationFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OUTPUT_BUFFER_WRITE_INDENTATION)) }
}

#[inline(always)]
unsafe fn append_c_string() -> AppendCStringFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OUTPUT_BUFFER_APPEND_C_STRING)) }
}

/// Emits an indented closing `</dict>` element through an output-buffer state.
///
/// # Safety
///
/// `state` must designate the retail output-buffer layout, including a writable
/// 512-byte scratch region at +0x15. Installed seam functions must accept the
/// same target-width state pointer and C string.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.output_buffer_write_dictionary_close")]
pub unsafe extern "C" fn output_buffer_write_dictionary_close(
    state: *mut OutputBufferState,
    level: u32,
) {
    unsafe {
        write_indentation()(state, level);
        let scratch = (state as *mut u8).add(SCRATCH_OFFSET);
        let indentation = scratch.add(SCRATCH_SIZE);
        let args = [indentation as usize as u32];
        snprintf(
            scratch,
            SCRATCH_SIZE,
            CLOSE_FORMAT.as_ptr(),
            args.as_ptr(),
        );
        append_c_string()(state, scratch);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{
        output_buffer_write_dictionary_close, AppendCStringFn, OutputBufferState, WriteIndentationFn,
        OUTPUT_BUFFER_APPEND_C_STRING, OUTPUT_BUFFER_WRITE_INDENTATION,
    };
    use crate::printf_api::{PrintfEngineFn, VaList, PRINTF_ENGINE};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ffi::c_void;
    use std::sync::{LazyLock, Mutex};

    const FIXTURE_LEN: usize = 0x500;
    static DATA: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::OUTPUT_BUFFER_WRITE_DICTIONARY_CLOSE, FIXTURE_LEN)
            .map(|pointer| pointer as usize)
    });
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut INDENT_LEVEL: u32 = 0;
    static mut APPENDED: [u8; 32] = [0; 32];
    static mut APPEND_STATE: *mut OutputBufferState = core::ptr::null_mut();

    unsafe extern "C" fn write_indentation(state: *mut OutputBufferState, level: u32) {
        unsafe {
            INDENT_LEVEL = level;
            let indentation = (state as *mut u8).add(0x215);
            indentation.write(b' ');
            indentation.add(1).write(b' ');
            indentation.add(2).write(0);
        };
    }

    unsafe extern "C" fn append_c_string(state: *mut OutputBufferState, text: *const u8) {
        unsafe {
            APPEND_STATE = state;
            let mut i = 0;
            while i < APPENDED.len() - 1 && *text.add(i) != 0 {
                APPENDED[i] = *text.add(i);
                i += 1;
            }
            APPENDED[i] = 0;
        }
    }

    unsafe extern "C" fn format_close(
        _format: *const u8,
        putc: unsafe extern "C" fn(u8, *mut c_void),
        context: *mut c_void,
        args: VaList,
    ) -> i32 {
        unsafe {
            let source = *(args as *const u32) as usize as *const u8;
            let mut i = 0;
            while *source.add(i) != 0 {
                putc(*source.add(i), context);
                i += 1;
            }
            for byte in b"</dict>\n" {
                putc(*byte, context);
            }
            i as i32 + 8
        }
    }

    #[test]
    fn forwards_level_formats_close_tag_and_appends_scratch() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            let old_indent: WriteIndentationFn = OUTPUT_BUFFER_WRITE_INDENTATION;
            let old_append: AppendCStringFn = OUTPUT_BUFFER_APPEND_C_STRING;
            let old_engine: PrintfEngineFn = PRINTF_ENGINE;
            OUTPUT_BUFFER_WRITE_INDENTATION = write_indentation;
            OUTPUT_BUFFER_APPEND_C_STRING = append_c_string;
            PRINTF_ENGINE = format_close;
            INDENT_LEVEL = 0;
            APPENDED = [0; 32];
            let Some(data) = *DATA else {
                assert!(note_missing_u32_fixture("app/output_buffer_write_dictionary_close"));
                return;
            };
            let raw = data as *mut u8;
            core::ptr::write_bytes(raw, 0, FIXTURE_LEN);
            let state = raw as *mut OutputBufferState;

            output_buffer_write_dictionary_close(state, 3);

            assert_eq!(INDENT_LEVEL, 3);
            assert_eq!(APPEND_STATE, state);
            assert_eq!(&APPENDED[..11], b"  </dict>\n\0");
            assert_eq!(core::slice::from_raw_parts(raw.add(0x15), 11), b"  </dict>\n\0");
            OUTPUT_BUFFER_WRITE_INDENTATION = old_indent;
            OUTPUT_BUFFER_APPEND_C_STRING = old_append;
            PRINTF_ENGINE = old_engine;
        }
    }
}
