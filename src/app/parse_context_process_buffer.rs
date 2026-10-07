//! `parse_context_process_buffer` — `FUN_08162ac0` @ **0x08162ac0**, 28 bytes.
//!
//! True extent is [0x08162ac0, 0x08162adc), before the context constructor.
//! Whole-image aligned A32 decoding verifies two incoming plain BLs
//! (0x08119e6c, 0x081b1e74), zero incoming predicated BLs, and one outgoing
//! plain BL (zero predicated) to 0x08162820. PUSH / STRD save incoming
//! r2/r3 as stack arguments; MOVs insert mode 1 and option 0, moving the
//! buffer to r3. POP leaves the signed status in r0 unchanged.
//!
//! The stock processor iterates an output collection, decodes the buffer
//! into planar image storage, and converts it for the collection entries.
//! Its exact format is not identified. Keep that processor in retailOS;
//! this port only selects its fixed mode/option. No behavioral deviations.
//! Host builds require an installed processor seam rather than a fallback.

use core::ffi::c_void;

pub type ParseBufferProcessor = unsafe extern "C" fn(
    *mut c_void, u32, u32, *const u8, u32, *mut c_void,
) -> i32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_processor(
    _context: *mut c_void, _mode: u32, _option: u32,
    _buffer: *const u8, _length: u32, _output: *mut c_void,
) -> i32 {
    panic!("install stock buffer processor seam for 0x08162820")
}

#[cfg(not(target_os = "none"))]
pub static mut PARSE_BUFFER_PROCESSOR: ParseBufferProcessor = missing_processor;

/// The arguments must satisfy the stock processor's memory/lifetime contract.
/// In particular, a NULL output returns -6 before accessing other arguments.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn parse_context_process_buffer(
    context: *mut c_void, buffer: *const u8, length: u32, output: *mut c_void,
) -> i32 {
    #[cfg(target_os = "none")]
    let process: ParseBufferProcessor = core::mem::transmute(0x0816_2820usize);
    #[cfg(not(target_os = "none"))]
    let process = core::ptr::addr_of!(PARSE_BUFFER_PROCESSOR).read_volatile();
    process(context, 1, 0, buffer, length, output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    // Reference for the raw processor's NULL-output branch; no decode is modeled.
    unsafe extern "C" fn null_output_reference(
        _context: *mut c_void, _mode: u32, _option: u32,
        _buffer: *const u8, _length: u32, output: *mut c_void,
    ) -> i32 {
        assert!(output.is_null());
        -6
    }

    #[test]
    fn null_output_rejects_without_touching_context_or_buffer() {
        unsafe {
            let previous = PARSE_BUFFER_PROCESSOR;
            PARSE_BUFFER_PROCESSOR = null_output_reference;
            let mut context = [0xdead_beefu32, 0xa5a5_5a5a];
            let buffer = [0x81u8, 0, 0xff, 0x7f];
            for length in [0, 1, 4, 0x8000_0000, u32::MAX] {
                assert_eq!(parse_context_process_buffer(
                    context.as_mut_ptr().cast(), buffer.as_ptr(), length, ptr::null_mut(),
                ), -6);
                assert_eq!(context, [0xdead_beef, 0xa5a5_5a5a]);
                assert_eq!(buffer, [0x81, 0, 0xff, 0x7f]);
            }
            assert_eq!(parse_context_process_buffer(
                ptr::null_mut(), ptr::null(), u32::MAX, ptr::null_mut(),
            ), -6);
            PARSE_BUFFER_PROCESSOR = previous;
        }
    }
}
