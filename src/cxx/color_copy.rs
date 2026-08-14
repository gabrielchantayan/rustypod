//! `color_copy` — original: `FUN_082720e8` @ 0x082720e8 (36 bytes;
//! **46 `bl` (44 unconditional + 2 `blne`) + 2 `b` call sites**,
//! binary-scanned by decoding every B/BL word in osos.dec).
//!
//! The **4-byte colour value's copy**: the assignment/copy-construct
//! member of retailOS's RGBA colour class, four forward `ldrb`/`strb`
//! pairs. Whole function, decoded from the raw words:
//!
//! ```text
//! 082720e8:  e5d12000   ldrb r2, [r1]
//! 082720ec:  e5c02000   strb r2, [r0]
//! 082720f0:  e5d12001   ldrb r2, [r1, #1]
//! 082720f4:  e5c02001   strb r2, [r0, #1]
//! 082720f8:  e5d12002   ldrb r2, [r1, #2]
//! 082720fc:  e5c02002   strb r2, [r0, #2]
//! 08272100:  e5d11003   ldrb r1, [r1, #3]
//! 08272104:  e5c01003   strb r1, [r0, #3]
//! 08272108:  e12fff1e   bx   lr
//! ```
//!
//! Ghidra's 36-byte extent is exact on both sides: 0x082720e4 is the
//! closing `bx lr` of the four-component setter @ 0x082720d0 and
//! 0x0827210c is the `push {lr}` of the 28-byte record copy that
//! follows. No literal pool.
//!
//! # Why the class is a colour
//!
//! The whole translation unit 0x08272018–0x08272108 is one small value
//! type:
//!
//! ```text
//! 0x08272018  pack to a pixel format selected by r0 (0x0565, 0x1444,
//!             0x2565-style codes), masking r1/r2/r3/[sp] with 0xf8 /
//!             0xfc / 0xf0 — RGB565, RGBA4444, RGB555
//! 0x08272090  the RGB565 case on its own: (R & 0xf8) << 8
//!             | (G & 0xfc) << 3 | (B & 0xf8) >> 3
//! 0x082720ac  a byte-identical twin of THIS function (20 `bl` + 2 `b`)
//! 0x082720d0  set from four register/stack components:
//!             strb r1,[r0]; strb r2,[r0,#1]; strb r3,[r0,#2];
//!             strb [sp],[r0,#3]
//! 0x082720e8  THIS PORT — copy the four bytes from another colour
//! ```
//!
//! so the record is four bytes wide, laid out `{R, G, B, A}` in that
//! order. Two independent call-site readings confirm the alpha byte is
//! the last one: 0x080749a8 and 0x080b31f0 build a colour with
//! `mov r3, #0xff` before calling the constructor @ 0x08271de4 and then
//! copy it here, and `cxx::draw_state`'s body initializer @ 0x082630f0
//! defaults the record's foreground colour to `{0, 0, 0, 0xff}` and its
//! background to `{0xff, 0xff, 0xff, 0xff}` — opaque black on opaque
//! white.
//!
//! # Why byte-at-a-time and not a word move
//!
//! Colours are stored unaligned. The draw-state record packs a style
//! byte at +0x10 immediately ahead of two colours at +0x11 and +0x15
//! (see [`crate::cxx::draw_state_color`]), so a 32-bit `ldr`/`str` pair
//! would fault where the original does not. That is the entire reason
//! this helper exists rather than a word assignment, and it is why the
//! two draw-state colour setters @ 0x08263194 and 0x0826319c reach it
//! by `add r0, r0, #0x11` / `#0x15` and a tail `b` — those are the two
//! `b` call sites.
//!
//! # Deviations
//!
//! - The byte moves are `read_volatile`/`write_volatile`, the crate's
//!   standard defence against LLVM's loop-idiom pass rewriting a small
//!   copy into a `memcpy` call (PORTING.md). It also pins the forward,
//!   overlap-propagating order: an overlapping copy observes each store
//!   before the next load, exactly as the original's instruction pairs
//!   do.
//! - Returns nothing. `bx lr` leaves r0 = `dst`, but none of the 46
//!   `bl` sites reads it — every one overwrites r0 in the next
//!   instruction or two, and the two sites that `pop {…, pc}` straight
//!   after the call (0x081ea2ec, 0x081ea170) are void functions whose
//!   caller ignores the value.
//! - No NULL or alignment guard on either pointer, matching the
//!   original.
//! - The byte-identical twin @ 0x082720ac (20 `bl` + 2 `b` sites of its
//!   own) is a second copy ADS emitted in the same translation unit; it
//!   is not ported here. Were it ported, LLVM's MergeFunctions would
//!   fold the two bodies onto one symbol, the
//!   `parse_result_init_alias_3134` situation.

/// Bytes in a colour value: `{R, G, B, A}`, one `ldrb`/`strb` pair each.
pub const COLOR_BYTES: usize = 4;

/// color_copy — original: `FUN_082720e8` @ 0x082720e8 (36 bytes; 46 `bl`
/// + 2 `b` call sites, binary-scanned).
///
/// Copies the four bytes of the colour at `src` to the colour at `dst`,
/// one byte at a time in ascending order. Neither pointer need be
/// aligned — draw-state colours never are — and the ranges may overlap,
/// in which case each store is visible to the following load.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn color_copy(dst: *mut u8, src: *const u8) {
    for i in 0..COLOR_BYTES {
        dst.add(i).write_volatile(src.add(i).read_volatile());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Independent model of the original's four load/store pairs, run
    /// over one buffer so overlap is observable.
    fn reference_forward_copy(bytes: &mut [u8], dst: usize, src: usize) {
        for i in 0..COLOR_BYTES {
            let byte = bytes[src + i];
            bytes[dst + i] = byte;
        }
    }

    #[test]
    fn copies_four_bytes_between_distinct_colours() {
        let source = [0x12, 0x34, 0x56, 0x78u8];
        let mut destination = [0xa5u8; COLOR_BYTES + 1];

        unsafe { color_copy(destination.as_mut_ptr(), source.as_ptr()) };

        assert_eq!(&destination[..COLOR_BYTES], &source);
        assert_eq!(destination[COLOR_BYTES], 0xa5, "nothing past the fourth byte");
    }

    #[test]
    fn every_byte_value_survives_including_nul_and_0xff() {
        // Colour components are opaque data: NUL is not a terminator and
        // 0xff (the draw-state default alpha) is not a sentinel.
        for source in [[0, 0, 0, 0u8], [0xff; 4], [0, 0xff, 0, 0xffu8], [0xff, 0, 0xff, 0]] {
            let mut destination = [0x5au8; COLOR_BYTES];
            unsafe { color_copy(destination.as_mut_ptr(), source.as_ptr()) };
            assert_eq!(destination, source);
        }
    }

    #[test]
    fn works_at_every_alignment_on_both_sides() {
        // The draw-state colours live at +0x11 and +0x15 of the record,
        // so neither pointer is ever word-aligned there.
        let source = [0xde, 0xad, 0xbe, 0xefu8];
        for src_shift in 0..4usize {
            for dst_shift in 0..4usize {
                let mut source_buffer = [0u8; COLOR_BYTES + 4];
                source_buffer[src_shift..src_shift + COLOR_BYTES].copy_from_slice(&source);
                let mut destination = [0u8; COLOR_BYTES + 4];

                unsafe {
                    color_copy(
                        destination.as_mut_ptr().add(dst_shift),
                        source_buffer.as_ptr().add(src_shift),
                    )
                };

                assert_eq!(
                    &destination[dst_shift..dst_shift + COLOR_BYTES],
                    &source,
                    "src_shift {src_shift}, dst_shift {dst_shift}"
                );
            }
        }
    }

    #[test]
    fn overlapping_copies_propagate_forward_like_the_instruction_pairs() {
        // Every overlap of two colours inside one 8-byte buffer.
        for dst in 0..5usize {
            for src in 0..5usize {
                let mut bytes = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17u8];
                let mut expected = bytes;
                reference_forward_copy(&mut expected, dst, src);

                unsafe { color_copy(bytes.as_mut_ptr().add(dst), bytes.as_ptr().add(src)) };

                assert_eq!(bytes, expected, "dst {dst}, src {src}");
            }
        }
    }

    #[test]
    fn a_self_copy_changes_nothing() {
        let mut bytes = [1, 2, 3, 4u8];
        let expected = bytes;
        unsafe { color_copy(bytes.as_mut_ptr(), bytes.as_ptr()) };
        assert_eq!(bytes, expected);
    }
}
