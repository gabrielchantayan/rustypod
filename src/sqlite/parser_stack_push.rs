//! SQLite parser value-stack push — `FUN_0839b6e0` @ `0x0839b6e0`.
//!
//! Raw `osos.dec` establishes a 120-byte, 30-instruction body from
//! `0x0839b6e0` through `0x0839b754`; the following bytes are the NUL-terminated
//! `"parser stack overflow"` literal and the next function begins at
//! `0x0839b770`. Decoding all body words finds exactly two unconditional plain
//! `bl` instructions (to `interp_stack_pop_release` @ `0x083998a4` and
//! `sqlite_error_msg` @ `0x083767a0`) and no predicated `bl` instructions.
//!
//! # Algorithm
//!
//! Increment the signed top index in word zero of the parser stack. Indices
//! below 100 receive the token code, parser-state value, and three-word value
//! record in their 20-byte slot. At index 100, restore top to 99, release every
//! live slot, report `"parser stack overflow"` on the Parse context in word two,
//! set its `parseError` byte at target offset `+0x14`, and retain that context pointer.
//!
//! Deliberate deviations: the retail error call has no format substitutions;
//! its unused variadic-register home becomes a null `VaList`. Target pointer
//! fields remain `u32` words, so host tests map the Parse fixture below 4 GiB.

use crate::interp_stack_pop_release::interp_stack_pop_release;
use crate::sqlite::error_msg::{sqlite_error_msg, Parse};

const PARSER_STACK_OVERFLOW: &[u8] = b"parser stack overflow\0";

/// parser_stack_push — original: `FUN_0839b6e0` @ `0x0839b6e0` (120 bytes).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn parser_stack_push(
    stack: *mut u32,
    token: u32,
    parser_state: u32,
    value: *const u32,
) {
    let top = stack.read().wrapping_add(1);
    stack.write(top);
    if (top as i32) >= 100 {
        let parse = stack.add(2).read() as usize as *mut Parse;
        stack.write(top.wrapping_sub(1));
        while (stack.read() as i32) >= 0 {
            interp_stack_pop_release(stack);
        }
        sqlite_error_msg(parse, PARSER_STACK_OVERFLOW.as_ptr(), core::ptr::null());
        parse.cast::<u8>().add(0x14).write(1);
        stack.add(2).write(parse as usize as u32);
        return;
    }

    let slot = stack.add(3 + (top as usize).wrapping_mul(5));
    slot.write(token);
    slot.add(1).write(parser_state);
    slot.add(2).write(value.read());
    slot.add(3).write(value.add(1).read());
    slot.add(4).write(value.add(2).read());
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab, INTERP_OPCODE_RELEASE_TEST_LOCK};
    use crate::util::interp_stack_pop_release::{InterpOpcodeRelease, DEFAULT_INTERP_OPCODE_RELEASE, INTERP_OPCODE_RELEASE};
    use core::ptr;

    static mut RELEASES: u32 = 0;

    unsafe extern "C" fn count_release(_opcode: u32, _payload: *mut u32) -> u32 {
        RELEASES = RELEASES.wrapping_add(1);
        0
    }

    struct ResetRelease;

    impl Drop for ResetRelease {
        fn drop(&mut self) {
            unsafe { ptr::addr_of_mut!(INTERP_OPCODE_RELEASE).write(DEFAULT_INTERP_OPCODE_RELEASE) };
        }
    }

    #[test]
    fn pushes_five_word_slot_at_incremented_top() {
        let mut stack = [0xfeed_beefu32; 3 + 3 * 5];
        stack[0] = 1;
        let value = [0x1111_1111, 0x2222_2222, 0x3333_3333];
        unsafe { parser_stack_push(stack.as_mut_ptr(), 0x44, 0x55, value.as_ptr()) };
        assert_eq!(stack[0], 2);
        assert_eq!(&stack[13..18], &[0x44, 0x55, 0x1111_1111, 0x2222_2222, 0x3333_3333]);
        assert_eq!(stack[3], 0xfeed_beef);
    }

    #[test]
    fn overflow_drains_stack_and_latches_parse_error() {
        let _guard = INTERP_OPCODE_RELEASE_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(parse_memory) = try_map_u32_slab(hints::SQLITE_PARSER_STACK_PUSH, core::mem::size_of::<Parse>()) else {
            return;
        };
        let parse = parse_memory.cast::<Parse>();
        unsafe {
            parse.write(Parse {
                db: ptr::null_mut(), rc: 0, z_err_msg: ptr::null_mut(),
                _gap_0c: [0; 6], check_schema: 0, _gap_13: [0; 45], n_err: 0,
            });
            ptr::addr_of_mut!(INTERP_OPCODE_RELEASE).write(count_release as InterpOpcodeRelease);
            RELEASES = 0;
        }
        let _reset = ResetRelease;
        let mut stack = [0u32; 3 + 100 * 5];
        stack[0] = 99;
        stack[2] = parse as usize as u32;
        for slot in 0..100 {
            stack[3 + slot * 5 + 1] = slot as u32;
        }
        let value = [1, 2, 3];
        unsafe { parser_stack_push(stack.as_mut_ptr(), 9, 8, value.as_ptr()) };
        assert_eq!(stack[0] as i32, -1);
        assert_eq!(stack[2], parse as usize as u32);
        assert_eq!(unsafe { RELEASES }, 100);
        assert_eq!(unsafe { (*parse).n_err }, 1);
        assert_eq!(unsafe { (*parse).rc }, 1);
        assert_eq!(unsafe { parse.cast::<u8>().add(0x14).read() }, 1);
    }
}
