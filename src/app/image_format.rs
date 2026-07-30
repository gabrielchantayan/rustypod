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
//! The result feeds [`image_format_descriptor`] (`FUN_08105b58`, ported
//! below), which subtracts 0x3f1 and switches
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
//! That reading was an inference from the constants, not from a symbol;
//! porting `FUN_08105b58` confirmed it: the descriptor IS geometry —
//! width at +0x00, height at +0x04, height×bytes-per-pixel at +0x08
//! (`FUN_08079d38`'s `desc[0] * desc[8]` byte size falls out as
//! width × that), bit depth at +0x18 and a pixel-format tag halfword at
//! +0x1c (0x565 ≈ RGB565, 0x1888 at 32bpp, 0xc420/0xc422 at 12bpp).
//! Nothing in the image names either the kinds or the formats.
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
//! and tail-branches here for everything else; `FUN_08105b38` (ported
//! below as [`image_format_descriptor_for_kind`]) swaps its arguments,
//! calls this table on the kind and falls through into the descriptor
//! builder `FUN_08105b58` (ported below as
//! [`image_format_descriptor`]).

use crate::libc::memcpy::memcpy;

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

/// Size of the descriptor the builder fills and copies
/// (`mov r2,#0x20; bl 0x08037df8`).
pub const DESCRIPTOR_SIZE: usize = 0x20;

/// First format id the 61-entry jump table covers (`mvn r2,#0x3f0;
/// add r6,r1,r2` → `id - 0x3f1`).
pub const IMAGE_FORMAT_ID_BASE: u32 = 0x3f1;
/// Last covered id (`cmp r6,#0x3c` + `addls`, an unsigned bound, so
/// 0x3f1..=0x42d; anything outside takes the default arm).
pub const IMAGE_FORMAT_ID_LAST: u32 = 0x42d;

// Descriptor field offsets (byte offsets into the 32-byte buffer).
const WIDTH_OFFSET: usize = 0x00;
const HEIGHT_OFFSET: usize = 0x04;
const HEIGHT_BYTES_OFFSET: usize = 0x08;
const AUX_TAG_OFFSET: usize = 0x0c;
const BIT_DEPTH_OFFSET: usize = 0x18;
const PIXEL_FORMAT_OFFSET: usize = 0x1c;

/// Pixel-format tag written to +0x1c by almost every arm
/// (`ldr r1,[0x8105fe4]` = 0x565 — RGB565).
const PIXEL_FORMAT_TAG_RGB565: u16 = 0x565;
/// Tag 0x2565 (`ldr r1,[0x8105ff4]`), the 220×176 and 132×176 variants
/// of the 16bpp formats — plausibly a second 565 flavor; named on the
/// raw value, the image says nothing more.
const PIXEL_FORMAT_TAG_2565: u16 = 0x2565;
/// Tag 0x1888 (`ldr r1,[0x8105ff8]`), used by the one 32bpp format.
const PIXEL_FORMAT_TAG_1888: u16 = 0x1888;
/// Tag 0xc422 (`ldr r1,[0x8105ff0]`), the 480×720/576×720 12bpp pair —
/// a 4:2:2-flavored chroma tag, named on the raw value.
const PIXEL_FORMAT_TAG_C422: u16 = 0xc422;
/// Tag 0xc420 (`ldr r1,[0x8105fec]`), the 480×720 12bpp format — a
/// 4:2:0-flavored chroma tag, named on the raw value.
const PIXEL_FORMAT_TAG_C420: u16 = 0xc420;

/// The geometry one covered format id maps to. `height_bytes` is the
/// +0x08 field: height × bytes-per-pixel in every arm (verified
/// against the bit depth), so `width * height_bytes` is the image
/// buffer's byte size — exactly what `FUN_08079d38` computes as
/// `desc[0] * desc[8]`.
struct DescriptorFields {
    width: u32,
    height: u32,
    height_bytes: u32,
    aux_tag: u16,
    bit_depth: u32,
    pixel_format: u16,
}

impl DescriptorFields {
    const fn new(
        width: u32,
        height: u32,
        height_bytes: u32,
        aux_tag: u16,
        bit_depth: u32,
        pixel_format: u16,
    ) -> Self {
        DescriptorFields { width, height, height_bytes, aux_tag, bit_depth, pixel_format }
    }
}

/// The jump table, decoded arm by arm from 0x08105ba4..0x08105c94
/// (index = `format - 0x3f1`, shared branches collapsed the way the
/// table shares them: 0x403/0x404, 0x3f9/0x40b/0x41a, 0x41f/0x42c).
/// `None` is the default arm at 0x08105cd0 — the table's holes and
/// every out-of-range id.
fn descriptor_fields(format: u32) -> Option<DescriptorFields> {
    let fields = match format {
        0x3f1 => DescriptorFields::new(0x1e, 0x29, 0x54, 0, 16, PIXEL_FORMAT_TAG_RGB565),
        0x3f5 => DescriptorFields::new(0xdc, 0xb0, 0x160, 0x10e, 16, PIXEL_FORMAT_TAG_RGB565),
        0x3f7 => DescriptorFields::new(0x58, 0x82, 0x104, 0, 16, PIXEL_FORMAT_TAG_RGB565),
        0x3f8 => DescriptorFields::new(0x8c, 0x8c, 0x118, 0, 16, PIXEL_FORMAT_TAG_RGB565),
        0x3f9 | 0x40b | 0x41a => {
            DescriptorFields::new(0x38, 0x38, 0x70, 0, 16, PIXEL_FORMAT_TAG_RGB565)
        }
        0x3fb => DescriptorFields::new(0x1e0, 0x2d0, 0x5a0, 0, 16, PIXEL_FORMAT_TAG_C422),
        0x3fc => DescriptorFields::new(0xdc, 0xb0, 0x160, 0x10e, 16, PIXEL_FORMAT_TAG_2565),
        0x3fd => DescriptorFields::new(0x45, 0x5c, 0xb8, 0, 16, PIXEL_FORMAT_TAG_RGB565),
        0x3fe => DescriptorFields::new(0x240, 0x2d0, 0x5a0, 0, 16, PIXEL_FORMAT_TAG_C422),
        0x3ff => DescriptorFields::new(0x84, 0xb0, 0x160, 0, 16, PIXEL_FORMAT_TAG_2565),
        0x400 => DescriptorFields::new(0xf0, 0x140, 0x280, 0, 16, PIXEL_FORMAT_TAG_RGB565),
        0x403 | 0x404 => DescriptorFields::new(0x64, 0x64, 0xc8, 0, 16, PIXEL_FORMAT_TAG_RGB565),
        0x405 => DescriptorFields::new(0xc8, 0xc8, 0x190, 0, 16, PIXEL_FORMAT_TAG_RGB565),
        0x407 => DescriptorFields::new(0x2a, 0x2a, 0x54, 0, 16, PIXEL_FORMAT_TAG_RGB565),
        0x408 => DescriptorFields::new(0x25, 0x29, 0x54, 0, 16, PIXEL_FORMAT_TAG_RGB565),
        0x40c => DescriptorFields::new(0x29, 0x32, 0x64, 0, 16, PIXEL_FORMAT_TAG_RGB565),
        0x41b => DescriptorFields::new(0x5a, 0x5a, 0xb4, 0, 16, PIXEL_FORMAT_TAG_RGB565),
        0x41c => DescriptorFields::new(0xd8, 0x140, 0x280, 0, 16, PIXEL_FORMAT_TAG_RGB565),
        0x41d => DescriptorFields::new(0x6c, 0xb0, 0x160, 0, 16, PIXEL_FORMAT_TAG_RGB565),
        0x41e => DescriptorFields::new(0x9c, 0x140, 0x280, 0, 16, PIXEL_FORMAT_TAG_RGB565),
        0x41f | 0x42c => DescriptorFields::new(0x80, 0x80, 0x100, 0, 16, PIXEL_FORMAT_TAG_RGB565),
        0x424 => DescriptorFields::new(0x140, 0x140, 0x280, 0, 16, PIXEL_FORMAT_TAG_RGB565),
        0x425 => DescriptorFields::new(0x37, 0x37, 0x70, 0, 16, PIXEL_FORMAT_TAG_RGB565),
        0x428 => DescriptorFields::new(0xf0, 0x140, 0x500, 0, 32, PIXEL_FORMAT_TAG_1888),
        0x429 => DescriptorFields::new(0xa0, 0xa0, 0x140, 0, 16, PIXEL_FORMAT_TAG_RGB565),
        0x42a => DescriptorFields::new(0x40, 0x40, 0x80, 0, 16, PIXEL_FORMAT_TAG_RGB565),
        0x42b => DescriptorFields::new(0x1e0, 0x2d0, 0x438, 0, 12, PIXEL_FORMAT_TAG_C420),
        0x42d => DescriptorFields::new(0x8e, 0x8e, 0x11c, 0, 16, PIXEL_FORMAT_TAG_RGB565),
        _ => return None,
    };
    Some(fields)
}

fn put_u32(descriptor: &mut [u8; DESCRIPTOR_SIZE], offset: usize, value: u32) {
    descriptor[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u16(descriptor: &mut [u8; DESCRIPTOR_SIZE], offset: usize, value: u16) {
    descriptor[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

/// image_format_descriptor — original: `FUN_08105b58` @ 0x08105b58
/// (444 bytes of code; the six-word literal pool at 0x08105fe4..
/// 0x08105ff8 Ghidra counts separately. 18 `bl` call sites, no tail
/// `b`, binary-scanned — plus the fall-through tail call from
/// [`image_format_descriptor_for_kind`]).
///
/// The one-step descriptor builder behind every artwork geometry
/// query: the caller passes a 32-byte stack buffer and a format id
/// (0x3f1..=0x42d, usually from [`image_format_for_kind`]) and gets
/// back the image's geometry:
///
/// ```text
/// +0x00 u32  width           +0x10 u32  0 (always)
/// +0x04 u32  height          +0x14 u32  0 (always)
/// +0x08 u32  height_bytes    +0x18 u32  bit depth (16, 32 or 12)
/// +0x0c u16  aux tag         +0x1c u16  pixel-format tag
/// ```
///
/// (`height_bytes` = height × bytes-per-pixel, so `width *
/// height_bytes` is the buffer byte size `FUN_08079d38` computes. The
/// aux tag is 0 everywhere except the 220×176 pair 0x3f5/0x3fc, where
/// it is 0x10e — semantics unknown, ported on observable behavior.)
///
/// Algorithm: zero the two words at +0x10/+0x14, preload the geometry
/// constants shared across arms (0x140, 0x80, 0xdc, 0x54, 0x64, 0xb0,
/// 0x160, 0x160-0x52 = 0x10e) and the 0x565 tag from the literal pool,
/// then `cmp r6,#0x3c; addls pc,pc,r6,lsl#2` — a dense 61-entry jump
/// table on `format - 0x3f1`. Each arm stores its width/height/
/// height_bytes/aux_tag/depth and a tag halfword (0x565 for almost
/// everything; 0x2565, 0xc422, 0xc420, 0x1888 from the pool for the
/// 2565/12bpp/32bpp formats), rejoining through shared store tails at
/// 0x08105e94 / 0x08105f70 / 0x08105fd4 / 0x08105ccc. Finally the
/// 32-byte stack image is copied to the caller's buffer
/// (`bl 0x08037df8`, the ROM memcpy veneer).
///
/// Deliberate deviations:
/// - The original initializes only 26 of the 32 descriptor bytes:
///   +0x0e..+0x0f and +0x1e..+0x1f are never stored, and the default
///   arm (table holes and out-of-range ids) stores nothing but the two
///   zero words — the copy then leaks stack garbage in those bytes.
///   This port zero-fills the whole descriptor instead (strictly
///   safer; a caller reading those bytes sees 0, not stack garbage).
///   Every byte the original does store is reproduced exactly.
/// - The ROM veneer @ 0x08037df8 targets `memcpy`; the ported
///   [`memcpy`](crate::libc::memcpy::memcpy) is called directly, per
///   house pattern.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn image_format_descriptor(descriptor: *mut u8, format: u32) {
    let mut local = [0u8; DESCRIPTOR_SIZE];
    if let Some(fields) = descriptor_fields(format) {
        put_u32(&mut local, WIDTH_OFFSET, fields.width);
        put_u32(&mut local, HEIGHT_OFFSET, fields.height);
        put_u32(&mut local, HEIGHT_BYTES_OFFSET, fields.height_bytes);
        put_u16(&mut local, AUX_TAG_OFFSET, fields.aux_tag);
        put_u32(&mut local, BIT_DEPTH_OFFSET, fields.bit_depth);
        put_u16(&mut local, PIXEL_FORMAT_OFFSET, fields.pixel_format);
    }
    memcpy(descriptor, local.as_ptr(), DESCRIPTOR_SIZE);
}

/// image_format_descriptor_for_kind — original: `FUN_08105b38` @
/// 0x08105b38 (32 bytes; 15 `bl` call sites, no tail `b`,
/// binary-scanned).
///
/// An argument swap around [`image_format_for_kind`] that turns the
/// kind-to-format question into the descriptor question in one call:
///
/// ```text
/// mov    r2, r0            ; keep the caller's descriptor pointer
/// stmdb  sp!, {r4, lr}
/// mov    r0, r1            ; kind into arg0
/// bl     0x08105a34        ; image_format_for_kind(kind)
/// mov    r1, r0            ; format id into arg1
/// ldmia  sp!, {r4, lr}
/// mov    r0, r2            ; descriptor pointer back into arg0
/// mov    r0, r0            ; pad nop — falls through into 0x08105b58
/// ```
///
/// There is no `bx lr`: popping `lr` and falling through into
/// `FUN_08105b58` is a tail call, so the descriptor builder returns
/// straight to this function's caller. Ghidra folds the fall-through
/// into one C function: `FUN_08105b38(out, kind)` =
/// `image_format_descriptor(out, image_format_for_kind(kind))`.
///
/// All 15 callers pass a 32-byte stack buffer and a kind (the
/// `auStack_2bc [32]` pattern in `FUN_081cd1fc` & co.) — this is the
/// one-step "give me the format descriptor for artwork kind N" entry
/// point. Note it consults the *plain* table: kind 4 forwards 0x428
/// here, where [`image_format_for_kind_kind4_override`] would answer
/// 0x400.
///
/// Deliberate deviation: the original's fall-through into
/// `FUN_08105b58` becomes an explicit tail call to
/// [`image_format_descriptor`] (ported above), which LLVM emits as a
/// `b` — the same control-flow shape.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn image_format_descriptor_for_kind(descriptor: *mut u8, kind: u32) {
    image_format_descriptor(descriptor, image_format_for_kind(kind))
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

    // ---- image_format_descriptor (FUN_08105b58) --------------------

    /// Builds the 32-byte descriptor the original would store for one
    /// covered format id, field by field — independent of the port's
    /// own `DescriptorFields` plumbing. `None` models the default arm:
    /// the port's documented deviation zero-fills the whole buffer.
    fn reference_descriptor(
        fields: Option<(u32, u32, u32, u16, u32, u16)>,
    ) -> [u8; DESCRIPTOR_SIZE] {
        let mut desc = [0u8; DESCRIPTOR_SIZE];
        if let Some((width, height, height_bytes, aux_tag, bit_depth, pixel_format)) = fields {
            desc[0x00..0x04].copy_from_slice(&width.to_le_bytes());
            desc[0x04..0x08].copy_from_slice(&height.to_le_bytes());
            desc[0x08..0x0c].copy_from_slice(&height_bytes.to_le_bytes());
            desc[0x0c..0x0e].copy_from_slice(&aux_tag.to_le_bytes());
            desc[0x18..0x1c].copy_from_slice(&bit_depth.to_le_bytes());
            desc[0x1c..0x1e].copy_from_slice(&pixel_format.to_le_bytes());
        }
        desc
    }

    /// The jump table decoded arm by arm from 0x08105ba4..0x08105c94,
    /// written down independently of the port's match: every covered id
    /// in 0x3f1..=0x42d with its (width, height, height_bytes, aux_tag,
    /// bit_depth, pixel_format) tuple.
    const REFERENCE_ARMS: &[(u32, (u32, u32, u32, u16, u32, u16))] = &[
        (0x3f1, (0x1e, 0x29, 0x54, 0, 16, 0x565)),
        (0x3f5, (0xdc, 0xb0, 0x160, 0x10e, 16, 0x565)),
        (0x3f7, (0x58, 0x82, 0x104, 0, 16, 0x565)),
        (0x3f8, (0x8c, 0x8c, 0x118, 0, 16, 0x565)),
        (0x3f9, (0x38, 0x38, 0x70, 0, 16, 0x565)),
        (0x3fb, (0x1e0, 0x2d0, 0x5a0, 0, 16, 0xc422)),
        (0x3fc, (0xdc, 0xb0, 0x160, 0x10e, 16, 0x2565)),
        (0x3fd, (0x45, 0x5c, 0xb8, 0, 16, 0x565)),
        (0x3fe, (0x240, 0x2d0, 0x5a0, 0, 16, 0xc422)),
        (0x3ff, (0x84, 0xb0, 0x160, 0, 16, 0x2565)),
        (0x400, (0xf0, 0x140, 0x280, 0, 16, 0x565)),
        (0x403, (0x64, 0x64, 0xc8, 0, 16, 0x565)),
        (0x404, (0x64, 0x64, 0xc8, 0, 16, 0x565)),
        (0x405, (0xc8, 0xc8, 0x190, 0, 16, 0x565)),
        (0x407, (0x2a, 0x2a, 0x54, 0, 16, 0x565)),
        (0x408, (0x25, 0x29, 0x54, 0, 16, 0x565)),
        (0x40b, (0x38, 0x38, 0x70, 0, 16, 0x565)),
        (0x40c, (0x29, 0x32, 0x64, 0, 16, 0x565)),
        (0x41a, (0x38, 0x38, 0x70, 0, 16, 0x565)),
        (0x41b, (0x5a, 0x5a, 0xb4, 0, 16, 0x565)),
        (0x41c, (0xd8, 0x140, 0x280, 0, 16, 0x565)),
        (0x41d, (0x6c, 0xb0, 0x160, 0, 16, 0x565)),
        (0x41e, (0x9c, 0x140, 0x280, 0, 16, 0x565)),
        (0x41f, (0x80, 0x80, 0x100, 0, 16, 0x565)),
        (0x424, (0x140, 0x140, 0x280, 0, 16, 0x565)),
        (0x425, (0x37, 0x37, 0x70, 0, 16, 0x565)),
        (0x428, (0xf0, 0x140, 0x500, 0, 32, 0x1888)),
        (0x429, (0xa0, 0xa0, 0x140, 0, 16, 0x565)),
        (0x42a, (0x40, 0x40, 0x80, 0, 16, 0x565)),
        (0x42b, (0x1e0, 0x2d0, 0x438, 0, 12, 0xc420)),
        (0x42c, (0x80, 0x80, 0x100, 0, 16, 0x565)),
        (0x42d, (0x8e, 0x8e, 0x11c, 0, 16, 0x565)),
    ];

    fn describe(format: u32) -> [u8; DESCRIPTOR_SIZE] {
        let mut buf = [0xaau8; DESCRIPTOR_SIZE];
        unsafe { image_format_descriptor(buf.as_mut_ptr(), format) };
        buf
    }

    #[test]
    fn every_covered_format_builds_the_decoded_arms_descriptor() {
        for &(format, fields) in REFERENCE_ARMS {
            assert_eq!(describe(format), reference_descriptor(Some(fields)), "format {format:#x}");
        }
    }

    #[test]
    fn every_id_in_the_tables_range_is_covered_or_a_documented_hole() {
        let covered: u32 = REFERENCE_ARMS.len() as u32;
        // 61 table entries - 32 covered = 29 holes, each landing in the
        // default arm. Spot-check holes from across the table.
        assert_eq!(IMAGE_FORMAT_ID_LAST - IMAGE_FORMAT_ID_BASE + 1 - covered, 29);
        for hole in [0x3f2u32, 0x3fa, 0x409, 0x412, 0x417, 0x420, 0x426] {
            assert_eq!(describe(hole), [0u8; DESCRIPTOR_SIZE], "hole {hole:#x}");
        }
    }

    #[test]
    fn out_of_range_ids_take_the_default_arm() {
        // The bound `cmp r6,#0x3c` is unsigned, so ids below 0x3f1 wrap
        // huge and take the default arm too. (All-zero buffer is the
        // port's documented zero-fill deviation.)
        for format in [0u32, 0x3f0, 0x42e, 0x1000, IMAGE_FORMAT_NONE] {
            assert_eq!(describe(format), [0u8; DESCRIPTOR_SIZE], "format {format:#x}");
        }
    }

    #[test]
    fn the_two_reserved_words_are_always_zero() {
        for &(format, _) in REFERENCE_ARMS {
            let desc = describe(format);
            assert_eq!(&desc[0x10..0x18], &[0u8; 8], "format {format:#x}");
        }
    }

    #[test]
    fn height_bytes_times_width_is_the_buffer_byte_size() {
        // FUN_08079d38's `desc[0] * desc[8]`: the +0x08 field is
        // height x bytes-per-pixel, so the product is the byte size.
        // Spot-check the three bit depths: 0x400 (16bpp 240x320),
        // 0x428 (32bpp 240x320), 0x42b (12bpp 480x720).
        assert_eq!(0xf0 * 0x280, 240 * 320 * 2);
        assert_eq!(0xf0 * 0x500, 240 * 320 * 4);
        assert_eq!(0x1e0 * 0x438, 480 * 720 * 12 / 8);
    }

    // ---- image_format_descriptor_for_kind (FUN_08105b38) ------------
    // The tail call now resolves to the ported image_format_descriptor,
    // so these observe the descriptor the forwarded format builds.

    #[test]
    fn every_kind_builds_the_plain_table_formats_descriptor() {
        for kind in 0..IMAGE_KIND_COUNT {
            let mut buf = [0xaau8; DESCRIPTOR_SIZE];
            unsafe { image_format_descriptor_for_kind(buf.as_mut_ptr(), kind) };
            assert_eq!(buf, describe(image_format_for_kind(kind)), "kind {kind}");
            assert_eq!(buf, describe(reference(kind)), "kind {kind} vs decoded jump table");
        }
    }

    #[test]
    fn kind4_uses_the_plain_table_not_the_override() {
        let mut buf = [0u8; DESCRIPTOR_SIZE];
        unsafe { image_format_descriptor_for_kind(buf.as_mut_ptr(), 4) };
        // The swap calls image_format_for_kind, NOT the kind4 override:
        // kind 4 builds 0x428's descriptor (32bpp 240x320), not 0x400's.
        assert_eq!(buf, describe(0x428));
        assert_ne!(buf, describe(0x400));
        assert_eq!(image_format_for_kind_kind4_override(4), 0x400);
    }
}
