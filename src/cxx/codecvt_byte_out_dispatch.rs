//! Byte-stream output conversion virtual dispatcher.
//!
//! Original: `FUN_082a75bc` at load address **0x082a75bc**, true size
//! **76 bytes**, ending at `0x082a7608`, where a separate no-conversion
//! method starts. Whole-image aligned A32 decoding verifies two inbound plain
//! BLs (`0x083d8fa8`, `0x083d9474`), zero predicated BLs, and zero outbound
//! BLs. One indirect call uses synthetic LR and `mov pc,ip`.
//!
//! Loads the receiver's vtable slot +0x0c, forwards receiver, conversion state,
//! input begin/end/next and output begin/end/next, and returns the method's
//! result unchanged. Byte-stream output callers compare the result to 2
//! (conversion error). The concrete virtual target is deliberately unresolved.
//! Raw code, unlike Ghidra's void declaration, preserves the returned r0.
//!
//! Deliberate deviations: a typed Rust call replaces the ARM return trampoline;
//! host vtable cells use pointer-width words at index three, while target cells
//! remain four bytes. No pointer checks or low-bit masking are added: raw code
//! loads the entry directly into PC (ARM-state method ABI).

/// ABI of the byte output conversion method, not a recovered concrete callee.
pub type ByteOutputConversion = unsafe extern "C" fn(
    *mut u8, *mut u32, *const u8, *const u8, *mut *const u8,
    *mut u8, *mut u8, *mut *mut u8,
) -> i32;

/// # Safety
/// The receiver must contain a valid vtable pointer with an ARM-state byte
/// conversion method in word three. All arguments must satisfy that method's
/// unchecked contract; empty ranges are forwarded without dereferencing them.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn codecvt_byte_out_dispatch(
    receiver: *mut u8, state: *mut u32,
    input_begin: *const u8, input_end: *const u8, input_next: *mut *const u8,
    output_begin: *mut u8, output_end: *mut u8, output_next: *mut *mut u8,
) -> i32 {
    let vtable = unsafe { receiver.cast::<*const usize>().read() };
    let entry = unsafe { vtable.add(3).read() };
    let convert: ByteOutputConversion = unsafe { core::mem::transmute(entry) };
    unsafe { convert(receiver, state, input_begin, input_end, input_next,
                     output_begin, output_end, output_next) }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Exact behavior of raw words at 0x082a7608..0x082a761c. This is a
    // fixture, not a claim that every receiver uses that virtual target.
    unsafe extern "C" fn no_conversion_reference(
        _receiver: *mut u8, _state: *mut u32,
        input: *const u8, _input_end: *const u8, input_next: *mut *const u8,
        output: *mut u8, _output_end: *mut u8, output_next: *mut *mut u8,
    ) -> i32 {
        unsafe { input_next.write(input); output_next.write(output); }
        3
    }

    #[test]
    fn no_conversion_preserves_buffers_and_state_for_empty_and_nonempty_ranges() {
        let vtable = [0usize, 0, 0, no_conversion_reference as *const () as usize];
        let mut receiver = vtable.as_ptr();
        let input = [0u8, 0x41, 0x80, 0xff];
        for input_len in 0..=input.len() {
            for capacity in 0..=4 {
                let mut state = 0x7654_3210;
                let mut output = [0xa5u8; 6];
                let begin = unsafe { output.as_mut_ptr().add(1) };
                let mut input_next = core::ptr::null();
                let mut output_next = core::ptr::null_mut();
                let result = unsafe { codecvt_byte_out_dispatch(
                    (&mut receiver as *mut *const usize).cast(), &mut state,
                    input.as_ptr(), input.as_ptr().add(input_len), &mut input_next,
                    begin, begin.add(capacity), &mut output_next,
                ) };
                assert_eq!(result, 3);
                assert_eq!(state, 0x7654_3210);
                assert_eq!(input_next, input.as_ptr());
                assert_eq!(output_next, begin);
                assert_eq!(output, [0xa5; 6]);
                assert_eq!(input, [0, 0x41, 0x80, 0xff]);
            }
        }
    }
}
