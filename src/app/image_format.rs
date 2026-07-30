//! `image_format_for_kind` — original: `FUN_08105a34` @ 0x08105a34
//! (196 bytes; 6 `bl` + 1 tail `b` call sites, binary-scanned — the
//! scouting note's "8 bl + 2 b" is wrong).
//!
//! A dense ARM jump table that turns an image *kind* into an image
//! *format id*:
//!
//! ```text
//! cmp    r0, #17
//! addls  pc, pc, r0, lsl #2      ; 18-entry jump table
//! b      default                 ; kind > 17
//! ```
//!
//! Each arm loads one constant out of the literal pool at 0x08105af8
//! (kind 3 is the immediate `mov r0, #0x400`, which is why Ghidra shows
//! that one as a literal and the rest as `DAT_` globals) and returns it;
//! kinds 9, 11 and 13 — and anything above 17 — fall through to
//! `mvn r0, #0` = [`IMAGE_FORMAT_NONE`].
//!
//! ## What the ids are
//!
//! The result feeds `FUN_08105b58`, which subtracts 0x3f1 and switches
//! on a 61-entry table (`cmp r6, #0x3c`), builds a 32-byte descriptor on
//! its stack and copies it to the caller's buffer. The constants that
//! descriptor is built from are image geometry: 352, 320, 270, 220, 180,
//! 176, 128, 100, 90, 84, 56, 41, 37 written to +0x00 and +0x04 (often
//! the *same* value to both — square), a fixed 16 at +0x18 (bit depth,
//! i.e. RGB565) and a halfword at +0x1c. `FUN_08079d38` then does
//! `format_descriptor(image_format_for_kind(kind)); return desc[0] *
//! desc[8];` — a byte size. So the 0x3f1..0x42d space is an **image /
//! artwork format** id space, and this table says which format each
//! kind of artwork uses.
//!
//! That reading is an inference from the constants, not from a symbol:
//! nothing in the image names either the kinds or the formats. What
//! would falsify it is `FUN_08105b58`'s descriptor turning out to be
//! something other than geometry — the two square dimensions plus a
//! constant 16 plus a width×height byte count are what make that
//! unlikely.
//!
//! Faithful details:
//! - The bound is `cmp r0, #17` + `addls`, an **unsigned** compare, so
//!   every value above 17 (including anything with the sign bit set)
//!   takes the default arm.
//! - Kinds 0 and 1 share a format, as do 5 and 6; the table below keeps
//!   the duplication rather than collapsing it, because the original's
//!   jump table does.
//!
//! `FUN_08105b28` (ported below as
//! [`image_format_for_kind_kind4_override`]) overrides kind 4 to 0x400
//! and tail-branches here for everything else; `FUN_08105b38` (an
//! argument swap around this function) is left unported.

/// The "no format" answer (`mvn r0, #0`) — kinds 9, 11, 13 and every
/// kind above [`IMAGE_KIND_COUNT`].
pub const IMAGE_FORMAT_NONE: u32 = 0xffff_ffff;

/// Kinds the jump table covers (`cmp r0, #17`, so 0..=17).
pub const IMAGE_KIND_COUNT: u32 = 18;

/// The jump table's answers, kind by kind, read out of the arms and the
/// literal pool at 0x08105af8.
const IMAGE_FORMAT_BY_KIND: [u32; IMAGE_KIND_COUNT as usize] = [
    0x42a,              // 0
    0x42a,              // 1  — shares kind 0's arm
    0x3fd,              // 2
    0x400,              // 3  — `mov r0, #0x400`, not a pool word
    0x428,              // 4
    0x42b,              // 5
    0x42b,              // 6  — shares kind 5's arm
    0x429,              // 7
    0x425,              // 8
    IMAGE_FORMAT_NONE,  // 9
    0x424,              // 10
    IMAGE_FORMAT_NONE,  // 11
    0x40b,              // 12
    IMAGE_FORMAT_NONE,  // 13
    0x41c,              // 14
    0x41f,              // 15
    0x405,              // 16
    0x41e,              // 17
];

/// image_format_for_kind — original: `FUN_08105a34` @ 0x08105a34
/// (196 bytes).
///
/// The image format id for `kind`, or [`IMAGE_FORMAT_NONE`] when the
/// kind has no format.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn image_format_for_kind(kind: u32) -> u32 {
    if kind >= IMAGE_KIND_COUNT {
        return IMAGE_FORMAT_NONE;
    }
    IMAGE_FORMAT_BY_KIND[kind as usize]
}

/// image_format_for_kind_kind4_override — original: `FUN_08105b28` @
/// 0x08105b28 (16 bytes; 5 `bl` call sites, no tail `b`,
/// binary-scanned).
///
/// A four-instruction wrapper around [`image_format_for_kind`]:
///
/// ```text
/// cmp    r0, #4
/// moveq  r0, #0x400
/// bne    0x08105a34    ; tail-branch to image_format_for_kind
/// bx     lr
/// ```
///
/// Kind 4 — which the plain table maps to 0x428 — is answered 0x400
/// (kind 3's format) directly; every other kind tail-branches into the
/// jump table unchanged. All five callers (0x081b725c, 0x0821514c,
/// 0x08215274, 0x08223b98, 0x08223cc0) feed the result straight into
/// the descriptor builder `FUN_08105b58`, so this is the same
/// kind-to-format question asked through a variant table where kind 4
/// shares kind 3's geometry. Why kind 4 is special-cased here but not
/// in the main table is not visible from the image; ported on
/// observable behavior.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn image_format_for_kind_kind4_override(kind: u32) -> u32 {
    if kind == 4 {
        0x400
    } else {
        image_format_for_kind(kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The jump table decoded arm by arm from 0x08105a3c..0x08105a84,
    /// independently of the array the port indexes.
    fn reference(kind: u32) -> u32 {
        match kind {
            0 | 1 => 0x42a,
            2 => 0x3fd,
            3 => 0x400,
            4 => 0x428,
            5 | 6 => 0x42b,
            7 => 0x429,
            8 => 0x425,
            10 => 0x424,
            12 => 0x40b,
            14 => 0x41c,
            15 => 0x41f,
            16 => 0x405,
            17 => 0x41e,
            _ => IMAGE_FORMAT_NONE,
        }
    }

    #[test]
    fn every_kind_matches_the_decoded_jump_table() {
        for kind in 0..IMAGE_KIND_COUNT {
            assert_eq!(image_format_for_kind(kind), reference(kind), "kind {kind}");
        }
    }

    #[test]
    fn the_three_holes_inside_the_table_have_no_format() {
        for kind in [9, 11, 13] {
            assert_eq!(image_format_for_kind(kind), IMAGE_FORMAT_NONE, "kind {kind}");
        }
    }

    #[test]
    fn the_bound_is_unsigned_so_everything_above_seventeen_is_none() {
        assert_eq!(image_format_for_kind(17), 0x41e, "17 is the last covered kind");
        for kind in [18u32, 19, 100, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
            assert_eq!(image_format_for_kind(kind), IMAGE_FORMAT_NONE, "kind {kind:#x}");
        }
    }

    #[test]
    fn the_duplicate_arms_really_are_duplicates() {
        assert_eq!(image_format_for_kind(0), image_format_for_kind(1));
        assert_eq!(image_format_for_kind(5), image_format_for_kind(6));
    }

    #[test]
    fn every_format_lands_inside_the_descriptor_tables_range() {
        // FUN_08105b58 accepts `id - 0x3f1` in 0..=0x3c, so every id
        // this table can return must sit in 0x3f1..=0x42d.
        for kind in 0..IMAGE_KIND_COUNT {
            let format = image_format_for_kind(kind);
            if format == IMAGE_FORMAT_NONE {
                continue;
            }
            assert!((0x3f1..=0x42d).contains(&format), "kind {kind} -> {format:#x}");
        }
    }

    #[test]
    fn kind4_override_answers_0x400_instead_of_0x428() {
        assert_eq!(image_format_for_kind(4), 0x428, "plain table maps kind 4 to 0x428");
        assert_eq!(image_format_for_kind_kind4_override(4), 0x400);
        // 0x400 is kind 3's format: the override makes kind 4 share
        // kind 3's geometry.
        assert_eq!(
            image_format_for_kind_kind4_override(4),
            image_format_for_kind(3),
        );
    }

    #[test]
    fn kind4_override_delegates_every_other_kind_to_the_plain_table() {
        for kind in [0u32, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17] {
            assert_eq!(
                image_format_for_kind_kind4_override(kind),
                image_format_for_kind(kind),
                "kind {kind}"
            );
            assert_eq!(
                image_format_for_kind_kind4_override(kind),
                reference(kind),
                "kind {kind} vs decoded jump table"
            );
        }
        // Out-of-range kinds (unsigned bound) fall through to NONE too.
        for kind in [18u32, 100, 0x8000_0000, u32::MAX] {
            assert_eq!(image_format_for_kind_kind4_override(kind), IMAGE_FORMAT_NONE, "kind {kind:#x}");
        }
        // Only exactly 4 is overridden: neighbours 3 and 5 keep their
        // own formats.
        assert_eq!(image_format_for_kind_kind4_override(3), 0x400);
        assert_eq!(image_format_for_kind_kind4_override(5), 0x42b);
    }
}
