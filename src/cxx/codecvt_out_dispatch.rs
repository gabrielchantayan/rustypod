//! Wide-character output conversion virtual dispatcher.
//!
//! Original: `FUN_082a7678` at load address **0x082a7678**, true size
//! **76 bytes**, ending at `0x082a76c4`, where a distinct `push {lr}`
//! conversion implementation begins. Whole-image aligned A32 decoding verifies
//! two inbound plain BLs (`0x083d998c`, `0x083d9c80`), zero predicated BLs,
//! and zero outbound BLs. One indirect call uses synthetic LR and `mov pc,ip`.
//!
//! Loads the receiver's vtable slot +0x0c, forwards receiver, conversion state,
//! input begin/end/next and output begin/end/next, and returns the method's
//! result unchanged. Callers in stream output paths compare the result to 2
//! (conversion error). The concrete virtual target is deliberately unresolved.
//! Raw code, unlike Ghidra's void declaration, preserves the returned r0.
//!
//! Deliberate deviations: a typed Rust call replaces the ARM return trampoline;
//! host vtable cells use pointer-width words at index three, while target cells
//! remain four bytes. No pointer checks or low-bit masking are added: raw code
//! loads the entry directly into PC (ARM-state method ABI).

/// ABI of the output conversion method, not a recovered concrete callee.
pub type OutputConversion = unsafe extern "C" fn(
    *mut u8, *mut u32, *const u16, *const u16, *mut *const u16,
    *mut u8, *mut u8, *mut *mut u8,
) -> i32;

/// # Safety
/// The receiver must contain a valid vtable pointer with an ARM-state output
/// conversion method in word three. All arguments must satisfy that method's
/// unchecked contract; empty ranges are forwarded without dereferencing them.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn codecvt_out_dispatch(
    receiver: *mut u8, state: *mut u32,
    input_begin: *const u16, input_end: *const u16, input_next: *mut *const u16,
    output_begin: *mut u8, output_end: *mut u8, output_next: *mut *mut u8,
) -> i32 {
    let vtable = unsafe { receiver.cast::<*const usize>().read() };
    let entry = unsafe { vtable.add(3).read() };
    let convert: OutputConversion = unsafe { core::mem::transmute(entry) };
    unsafe { convert(receiver, state, input_begin, input_end, input_next,
                     output_begin, output_end, output_next) }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reference behavior from raw words at 0x082a76c4..0x082a7718:
    // initialize next pointers, copy low bytes while both ranges have room,
    // return zero even when output ends before input. This is a fixture, not
    // an assumption that all receivers use that implementation.
    unsafe extern "C" fn narrow_reference(
        _receiver: *mut u8, _state: *mut u32,
        mut input: *const u16, input_end: *const u16, input_next: *mut *const u16,
        mut output: *mut u8, output_end: *mut u8, output_next: *mut *mut u8,
    ) -> i32 {
        unsafe {
            input_next.write(input);
            output_next.write(output);
            while input != input_end && output != output_end {
                output.write(input.read() as u8);
                input = input.add(1);
                output = output.add(1);
                input_next.write(input);
                output_next.write(output);
            }
        }
        0
    }

    #[test]
    fn conversion_respects_both_range_ends_and_preserves_guards_and_state() {
        let vtable = [0usize, 0, 0, narrow_reference as *const () as usize];
        let mut receiver = vtable.as_ptr();
        let input = [0x0041u16, 0x0100, 0xffff, 0x1234];
        for input_len in 0..=input.len() {
            for capacity in 0..=5 {
                let mut state = 0x7654_3210;
                let mut output = [0xa5u8; 7];
                let begin = unsafe { output.as_mut_ptr().add(1) };
                let mut input_next = core::ptr::null();
                let mut output_next = core::ptr::null_mut();
                let result = unsafe { codecvt_out_dispatch(
                    (&mut receiver as *mut *const usize).cast(), &mut state,
                    input.as_ptr(), input.as_ptr().add(input_len), &mut input_next,
                    begin, begin.add(capacity), &mut output_next,
                ) };
                let copied = core::cmp::min(input_len, capacity);
                assert_eq!(result, 0);
                assert_eq!(state, 0x7654_3210);
                assert_eq!(input_next, unsafe { input.as_ptr().add(copied) });
                assert_eq!(output_next, unsafe { begin.add(copied) });
                assert_eq!(output[0], 0xa5);
                for i in 0..copied { assert_eq!(output[i + 1], input[i] as u8); }
                assert!(output[copied + 1..].iter().all(|&byte| byte == 0xa5));
            }
        }
    }
}
