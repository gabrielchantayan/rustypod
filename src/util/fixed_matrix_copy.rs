//! Q16.16 4x4 matrix copy.

#[cfg(target_os = "none")]
use core::arch::asm;
#[cfg(not(target_os = "none"))]
use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};

use super::fixed_matrix_identity::FixedMatrix4x4;

/// fixed_matrix_copy — original: `FUN_082572c0` @ **0x082572c0** (36 bytes,
/// `0x082572c0..0x082572e4`; the next independently linked function starts at
/// `0x082572e4`). **5 direct inbound `bl` call sites: all plain unconditional;
/// zero predicated forms**, verified by decoding every ARM B/BL immediate in
/// `osos.dec`.
///
/// Copies the sixteen Q16.16 matrix words in ascending order, then copies the
/// identity marker byte at +0x40. Like the raw `ldr`/`str` loop, it requires
/// aligned, valid 0x44-byte source and destination objects and provides no
/// overlap handling or NULL guard.
///
/// Deliberate deviations: target builds use the recovered ARM instruction
/// sequence exactly. Host builds use equivalent volatile accesses because ARM
/// inline assembly cannot execute there.
#[cfg_attr(target_os = "none", link_section = ".text.fixed_matrix_copy")]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fixed_matrix_copy(dst: *mut FixedMatrix4x4, src: *const FixedMatrix4x4) {
    #[cfg(target_os = "none")]
    unsafe {
        asm!(
            "mov r2, #0",
            "2:",
            "ldr r3, [r1, r2, lsl #2]",
            "str r3, [r0, r2, lsl #2]",
            "add r2, r2, #1",
            "cmp r2, #16",
            "blt 2b",
            "ldrb r1, [r1, #64]",
            "strb r1, [r0, #64]",
            inout("r0") dst => _,
            inout("r1") src => _,
            out("r2") _,
            out("r3") _,
            options(nostack),
        );
    }

    #[cfg(not(target_os = "none"))]
    {
        for index in 0..16 {
            write_volatile(
                addr_of_mut!((*dst).elements[index]),
                read_volatile(addr_of!((*src).elements[index])),
            );
        }
        write_volatile(
            addr_of_mut!((*dst).is_identity),
            read_volatile(addr_of!((*src).is_identity)),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_all_words_and_identity_marker() {
        let src = FixedMatrix4x4 {
            elements: [
                0x0102_0304, -1, 0, 1, 0x7fff_ffff, i32::MIN, 6, 7, 8, 9, 10, 11, 12, 13, 14,
                15,
            ],
            is_identity: 0,
        };
        let mut dst = FixedMatrix4x4 {
            elements: [0x55aa_55aa; 16],
            is_identity: 1,
        };

        unsafe { fixed_matrix_copy(&mut dst, &src) };

        assert_eq!(dst.elements, src.elements);
        assert_eq!(dst.is_identity, 0);
    }

    #[test]
    fn copies_set_identity_marker() {
        let src = FixedMatrix4x4 {
            elements: [0; 16],
            is_identity: 1,
        };
        let mut dst = FixedMatrix4x4 {
            elements: [1; 16],
            is_identity: 0,
        };

        unsafe { fixed_matrix_copy(&mut dst, &src) };

        assert_eq!(dst.elements, [0; 16]);
        assert_eq!(dst.is_identity, 1);
    }
}
