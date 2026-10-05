//! Bounded decimal-digit accumulation — retailOS `FUN_081d6220` at
//! `0x081d6220`, 92 bytes, ending at the next function's push at `0x081d627c`.
//! Whole-image A32 word decoding verifies two plain inbound BL calls at
//! `0x082154b4` and `0x0821a730`, no predicated inbound BL. The body has zero
//! plain or predicated BL and one unconditional indirect BLX at `0x081d623c`.
//!
//! Invoke the input's virtual slot +0x0c, subtract ASCII '0' as a full u32,
//! and accept only digits 0..9 with a post-call count below four. Increment
//! the count before storing accumulator * 10 + digit, wrapping at 32 bits.
//! The receiver argument is unused. No algorithmic deviations; host vtable
//! fields widen with pointer width while retaining the target's word indices.
//! The virtual method's concrete identity is unresolved, not a fixed callee.

/// Input object prefix shared by the target and host fixtures.
#[repr(C)]
pub struct DecimalDigitInput {
    pub vtable: *const DecimalDigitInputVtable,
}

/// Slot +0x0c on ARM; preceding slots have no established identity.
#[repr(C)]
pub struct DecimalDigitInputVtable {
    pub unresolved_slots: [usize; 3],
    pub read_codepoint: unsafe extern "C" fn(*mut DecimalDigitInput) -> u32,
}

/// Accept one digit, returning exactly zero or one.
///
/// # Safety
/// `input` must have a callable slot +0x0c. `count` must be readable after
/// that call; when a digit is accepted it and `accumulator` must be writable,
/// and `accumulator` must be aligned and readable. No null guards are added.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn accumulate_decimal_digit(
    _receiver: *mut u8,
    accumulator: *mut u32,
    input: *mut DecimalDigitInput,
    count: *mut u8,
) -> u32 {
    let vtable = unsafe { (*input).vtable };
    let codepoint = unsafe { ((*vtable).read_codepoint)(input) };
    let digit = codepoint.wrapping_sub(u32::from(b'0'));
    if digit > 9 {
        return 0;
    }
    let used = unsafe { count.read() };
    if used >= 4 {
        return 0;
    }
    unsafe {
        count.write(used + 1);
        let value = accumulator.read();
        accumulator.write(value.wrapping_mul(10).wrapping_add(digit & 0xff));
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Input {
        base: DecimalDigitInput,
        codepoint: u32,
        calls: u32,
    }

    unsafe extern "C" fn read_codepoint(input: *mut DecimalDigitInput) -> u32 {
        let input = unsafe { &mut *input.cast::<Input>() };
        input.calls += 1;
        input.codepoint
    }

    static VTABLE: DecimalDigitInputVtable = DecimalDigitInputVtable {
        unresolved_slots: [0; 3], read_codepoint,
    };

    #[test]
    fn digit_and_count_boundaries_preserve_rejected_state_and_wrap_accepted_values() {
        for codepoint in (0..=256).chain([u32::MAX, 0x1000_0030, 0xffff_ff30]) {
            for initial_count in [0, 1, 3, 4, 5, 255] {
                for initial_value in [0u32, 123, 0x8000_0000, u32::MAX] {
                    let mut input = Input {
                        base: DecimalDigitInput { vtable: &VTABLE }, codepoint, calls: 0,
                    };
                    let mut count = initial_count;
                    let mut value = initial_value;
                    let accepted = (u32::from(b'0')..=u32::from(b'9')).contains(&codepoint)
                        && initial_count < 4;
                    let result = unsafe {
                        accumulate_decimal_digit(core::ptr::null_mut(), &mut value, &mut input.base, &mut count)
                    };
                    assert_eq!(result, u32::from(accepted));
                    assert_eq!(input.calls, 1);
                    assert_eq!(count, initial_count + u8::from(accepted));
                    let expected = if accepted {
                        ((u64::from(initial_value) * 10 + u64::from(codepoint - 48)) & 0xffff_ffff) as u32
                    } else { initial_value };
                    assert_eq!(value, expected);
                }
            }
        }
    }

    #[test]
    fn rejected_codepoint_does_not_read_count_or_accumulator() {
        let mut input = Input {
            base: DecimalDigitInput { vtable: &VTABLE }, codepoint: 47, calls: 0,
        };
        assert_eq!(unsafe {
            accumulate_decimal_digit(core::ptr::null_mut(), core::ptr::null_mut(),
                &mut input.base, core::ptr::null_mut())
        }, 0);
        assert_eq!(input.calls, 1);
    }
}
