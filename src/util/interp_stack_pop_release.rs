//! Interpreter value-stack pop with payload release — `FUN_083998a4` @
//! `0x083998a4`.
//!
//! Raw `osos.dec` extent is exactly 19 ARM instructions, 76 bytes
//! (`0x083998a4..0x083998ef`); the next independently linked function begins
//! with `push {r4-r11,lr}` at `0x083998f0`. Decoding every ARM `B`/`BL` word
//! in the image finds 4 direct callers, all unconditional plain `bl`
//! (`0x0837f228`, `0x08382748`, `0x0839b69c`, `0x0839b710`); there are no
//! predicated call sites. The body itself contains exactly one `bl`, the
//! unconditional call to the opcode-release dispatcher at `0x08399670`.
//!
//! # Algorithm
//!
//! The retailOS "T" interpreter (`0x0837f110` driver, `__T__ syntax error`
//! reporter) keeps a value stack inside its context: word 0 is the signed
//! top-of-stack index, words 1..3 are header fields, and each 20-byte slot
//! starts at word `3 + top * 5`. Popping reads the slot's word 1, whose low
//! byte is an opcode tag, hands the tag plus a pointer to slot word 2 to the
//! unported opcode-release dispatcher `FUN_08399670` (a jump table over tag
//! ranges `0x9b..0xee` that frees or releases the tagged payload), then
//! decrements the top index and returns the tag byte. An empty stack
//! (negative top) returns 0 without touching memory. Callers use the return
//! only as the tag; one error path drains the stack with
//! `while (ctx.top >= 0) interp_stack_pop_release(ctx)`.
//!
//! The original computes the slot address with wrapping ARM register
//! arithmetic (`ctx + 20 * top + 12`); the port mirrors that with
//! `wrapping_add`/`wrapping_mul` on the word pointer. Deliberate deviation:
//! none on target. Host tests install a release seam in place of the
//! unported dispatcher at `0x08399670`.

use core::ptr::addr_of_mut;

/// ABI of the unported opcode-release dispatcher at `0x08399670`.
pub type InterpOpcodeRelease = unsafe extern "C" fn(opcode: u32, payload: *mut u32) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_interp_opcode_release(opcode: u32, payload: *mut u32) -> u32 {
    let release: InterpOpcodeRelease = unsafe { core::mem::transmute(0x0839_9670usize) };
    unsafe { release(opcode, payload) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_interp_opcode_release(_opcode: u32, _payload: *mut u32) -> u32 {
    panic!("interp_stack_pop_release requires opcode-release dispatcher 0x08399670")
}

#[cfg(target_os = "none")]
pub(crate) const DEFAULT_INTERP_OPCODE_RELEASE: InterpOpcodeRelease = firmware_interp_opcode_release;
#[cfg(not(target_os = "none"))]
pub(crate) const DEFAULT_INTERP_OPCODE_RELEASE: InterpOpcodeRelease = missing_interp_opcode_release;

/// The unported opcode-release dispatcher. Target builds call retailOS
/// directly; host tests replace this callback to observe the pop contract.
pub static mut INTERP_OPCODE_RELEASE: InterpOpcodeRelease = DEFAULT_INTERP_OPCODE_RELEASE;

/// interp_stack_pop_release — original: `FUN_083998a4` @ `0x083998a4`
/// (76 bytes).
///
/// Pops the top 20-byte value slot of the interpreter stack at `stack`:
/// releases the slot payload through the opcode dispatcher keyed by the low
/// byte of slot word 1, decrements the signed top index in word 0, and
/// returns the opcode byte. Returns 0 when the stack is empty (top < 0).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn interp_stack_pop_release(stack: *mut u32) -> u32 {
    let top = unsafe { stack.read() } as i32;
    if top < 0 {
        return 0;
    }
    let slot = stack.wrapping_add(3 + (top as u32 as usize).wrapping_mul(5));
    let opcode = unsafe { slot.add(1).read() } & 0xff;
    let release = unsafe { addr_of_mut!(INTERP_OPCODE_RELEASE).read_volatile() };
    unsafe { release(opcode, slot.add(2)) };
    unsafe { stack.write(top.wrapping_sub(1) as u32) };
    opcode
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::INTERP_OPCODE_RELEASE_TEST_LOCK;
    use core::ptr;
    use std::sync::MutexGuard;
    use std::vec::Vec;

    static mut RELEASE_CALLS: u32 = 0;
    static mut RELEASE_OPCODES: [u32; 8] = [0; 8];
    static mut RELEASE_PAYLOADS: [usize; 8] = [0; 8];

    unsafe extern "C" fn recording_release(opcode: u32, payload: *mut u32) -> u32 {
        unsafe {
            let n = RELEASE_CALLS as usize;
            RELEASE_OPCODES[n] = opcode;
            RELEASE_PAYLOADS[n] = payload as usize;
            RELEASE_CALLS += 1;
        }
        0
    }

    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe { ptr::addr_of_mut!(INTERP_OPCODE_RELEASE).write(DEFAULT_INTERP_OPCODE_RELEASE) };
        }
    }

    fn install_release() -> (MutexGuard<'static, ()>, Reset) {
        let guard = INTERP_OPCODE_RELEASE_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            ptr::addr_of_mut!(INTERP_OPCODE_RELEASE).write(recording_release);
            ptr::addr_of_mut!(RELEASE_CALLS).write(0);
        }
        (guard, Reset)
    }

    fn calls() -> Vec<(u32, usize)> {
        let n = unsafe { RELEASE_CALLS } as usize;
        (0..n)
            .map(|i| unsafe { (RELEASE_OPCODES[i], RELEASE_PAYLOADS[i]) })
            .collect()
    }

    /// Stack image: word 0 top, words 1..3 header, then 5-word slots.
    fn stack_image(slots: &[[u32; 5]], top: i32) -> Vec<u32> {
        let mut image = std::vec![0u32; 3 + slots.len() * 5];
        image[0] = top as u32;
        image[1] = 0x1111_1111;
        image[2] = 0x2222_2222;
        for (i, slot) in slots.iter().enumerate() {
            image[3 + i * 5..8 + i * 5].copy_from_slice(slot);
        }
        image
    }

    #[test]
    fn empty_stack_returns_zero_and_touches_nothing() {
        let (_guard, _reset) = install_release();
        let mut image = stack_image(&[], -1);
        let before = image.clone();
        assert_eq!(interp_stack_pop_release(image.as_mut_ptr()), 0);
        assert_eq!(image, before);
        assert_eq!(unsafe { RELEASE_CALLS }, 0);
    }

    #[test]
    fn pop_reads_tag_releases_payload_and_decrements_top() {
        let (_guard, _reset) = install_release();
        let slots = [[10, 0xdead_be00 | 0xc3, 0xaaaa_0001, 0xaaaa_0002, 0xaaaa_0003]];
        let mut image = stack_image(&slots, 0);
        let base = image.as_mut_ptr() as usize;
        assert_eq!(interp_stack_pop_release(image.as_mut_ptr()), 0xc3);
        assert_eq!(image[0] as i32, -1);
        assert_eq!(calls(), std::vec![(0xc3, base + (3 + 2) * 4)]);
    }

    #[test]
    fn pop_uses_top_index_with_twenty_byte_stride() {
        let (_guard, _reset) = install_release();
        let slots = [
            [0, 0x9b, 1, 2, 3],
            [0, 0x100 | 0xf8, 4, 5, 6],
            [0, 0x55, 7, 8, 9],
        ];
        let mut image = stack_image(&slots, 2);
        let base = image.as_mut_ptr() as usize;
        // top == 2 addresses words 13..18 (word 3 + top * 5).
        assert_eq!(interp_stack_pop_release(image.as_mut_ptr()), 0x55);
        assert_eq!(image[0], 1);
        assert_eq!(calls(), std::vec![(0x55, base + (13 + 2) * 4)]);
        assert_eq!(image[1], 0x1111_1111);
        assert_eq!(image[2], 0x2222_2222);
    }

    #[test]
    fn tag_is_low_byte_of_slot_word_one() {
        let (_guard, _reset) = install_release();
        let slots = [[0, 0xabcd_ef42, 0, 0, 0]];
        let mut image = stack_image(&slots, 0);
        assert_eq!(interp_stack_pop_release(image.as_mut_ptr()), 0x42);
        assert_eq!(calls(), std::vec![(0x42, image.as_mut_ptr() as usize + (3 + 2) * 4)]);
    }

    #[test]
    fn drain_to_empty_matches_caller_loop() {
        let (_guard, _reset) = install_release();
        let slots = [[0, 0xa9, 0, 0, 0], [0, 0xce, 0, 0, 0]];
        let mut image = stack_image(&slots, 1);
        let ptr = image.as_mut_ptr();
        let mut drained = Vec::new();
        while (image[0] as i32) >= 0 {
            drained.push(interp_stack_pop_release(ptr));
        }
        assert_eq!(drained, std::vec![0xce, 0xa9]);
        assert_eq!(image[0] as i32, -1);
        assert_eq!(unsafe { RELEASE_CALLS }, 2);
    }
}
