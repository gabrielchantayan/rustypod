//! `surface_attach` — original: `FUN_08264518` @ 0x08264518 (56 bytes,
//! 0x08264518..0x08264550; **16 `bl` + 0 predicated `bl` + 2 tail `b` =
//! 18 call sites**, binary-scanned by decoding every ARM B/BL word in
//! osos.dec — exactly the 16 `bl` Ghidra reports, plus the two tail
//! branches @ 0x081b82ec / 0x081b83ac it files separately; zero DATA
//! words in the image hold 0x08264518, so it is never dispatched
//! virtually). Extent confirmed against the next function's entry @
//! 0x08264550 (the sibling setter `str r1,[r0,#28]!; ldm r2,{…}; …`,
//! itself unported), with no trailing literal-pool word.
//!
//! The surface-attaching member of retailOS's scoped 0x44-byte
//! **draw-state record** (cxx/draw_state.rs): binds the record to its
//! draw-target surface descriptor and snapshots the surface's bounds
//! rect as the record's clip rect. Decoded from the raw ARM at
//! 0x08264518:
//!
//! ```text
//! push {r0, r1, r2, r3, r4, r5, r6, lr}  ; 16-byte stack scratch
//! mov  r4, r0              ; this
//! add  r0, r1, #0x98       ; &surface->bounds
//! mov  r5, r1              ; surface
//! ldm  r0, {r1, r2, r3, ip}; copy surface->bounds (4 words)
//! mov  r6, sp
//! mov  r0, sp
//! stm  r6, {r1, r2, r3, ip}; … onto the stack scratch
//! bl   0x0826c2e8          ; rect_move_to_origin(&scratch)
//! add  r0, r4, #0x34       ; &this->clip
//! str  r5, [r4, #0x1c]     ; this->surface = surface
//! ldm  r6, {r1, r2, r3, r4}; reload the origin-moved copy
//! stm  r0, {r1, r2, r3, r4}; this->clip = copy
//! pop  {r0, r1, r2, r3, r4, r5, r6, pc}
//! ```
//!
//! So the semantics are
//!
//! ```text
//! clip = surface->bounds_at_0x98;   // copied, NOT aliased
//! rect_move_to_origin(&clip);       // {0, 0, height, width}
//! this->surface_at_0x1c = surface;  // raw 32-bit word store
//! this->clip_at_0x34    = clip;     // words +0x34..+0x40
//! ```
//!
//! Two behavioural facts the byte order fixes:
//!
//! - **The source rect is never mutated.** `rect_move_to_origin`
//!   rewrites only the stack copy; the surface descriptor's own +0x98
//!   bounds keep their original origin. (Contrast the sibling setter @
//!   0x08264550, which stores a caller-computed rect verbatim with no
//!   origin move.)
//! - The `+0x1c` store is one 32-bit `str` of r1 verbatim — the
//!   surface identity truncates to `u32`, matching every consumer
//!   (`*(this+0x1c) + 4` in the fill/line/text engines).
//!
//! The sole callee, `rect_move_to_origin` @ 0x0826c2e8, is already
//! ported in ui/rect.rs and is called directly — no dispatch seam is
//! needed. The extra r1=surface argument the original passes to it is
//! dead: the callee's decoded body reads only r0.
//!
//! # Deviations
//!
//! - The original returns nothing useful (`pop {…, pc}` restores the
//!   pushed argument spill into r0..r3 — incidentally leaving `this`
//!   in r0, but sampled callers reload r0 or clobber it), so the port
//!   is `void`.
//! - No NULL guard on either argument, matching the original's
//!   unconditional `ldm`/`str`: all 18 call sites are unconditional.
//! - The bounds copy reads and writes aligned `Rect`s (the +0x98 and
//!   +0x34 offsets are word-aligned on a word-aligned base), not
//!   `read_unaligned`: the four-`ldrb`-per-word idiom would be a
//!   pessimization on ARMv5TE.

use crate::cxx::draw_state::DRAW_STATE_SURFACE_OFFSET;
use crate::ui::rect::{rect_move_to_origin, Rect};

/// Byte offset of the record's embedded clip rect (`surface_attach`'s
/// second store destination; the setter 0x08264550 writes the same
/// offset). Ends the record: +0x34 + 0x10 = +0x44 = DRAW_STATE_SIZE.
pub const DRAW_STATE_CLIP_RECT_OFFSET: usize = 0x34;

/// Byte offset of the bounds rect inside a draw-target surface
/// descriptor (`add r0, r1, #0x98`). The default descriptor @
/// 0x08a77c3c carries the default clip rect here (cxx/draw_state.rs).
pub const SURFACE_BOUNDS_RECT_OFFSET: usize = 0x98;

/// surface_attach — original: `FUN_08264518` @ 0x08264518 (56 bytes;
/// 16 `bl` + 2 tail `b` call sites, binary-scanned).
///
/// Stores `surface` into the draw-state record's surface word at
/// `record + 0x1c`, and snapshots the surface's bounds rect at
/// `surface + 0x98` — translated to the origin by
/// [`rect_move_to_origin`] — into the record's clip rect at
/// `record + 0x34`. The surface's own bounds are left untouched.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn surface_attach(record: *mut u8, surface: *const u8) {
    let mut clip = (surface.add(SURFACE_BOUNDS_RECT_OFFSET) as *const Rect).read();
    rect_move_to_origin(&mut clip);
    (record.add(DRAW_STATE_SURFACE_OFFSET) as *mut u32).write(surface as u32);
    (record.add(DRAW_STATE_CLIP_RECT_OFFSET) as *mut Rect).write(clip);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::draw_state::DRAW_STATE_SIZE;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    const GUARD: u8 = 0xa5;
    /// Record plus 0x10 guard bytes, 4-byte aligned so the embedded
    /// `Rect` writes stay aligned (as on the target).
    #[repr(align(4))]
    struct RecordFixture([u8; DRAW_STATE_SIZE + 0x10]);

    fn record_fixture() -> RecordFixture {
        RecordFixture([GUARD; DRAW_STATE_SIZE + 0x10])
    }

    fn record_rect(record: &[u8], offset: usize) -> Rect {
        let words: &[i32] = unsafe {
            core::slice::from_raw_parts(record.as_ptr().add(offset) as *const i32, 4)
        };
        Rect {
            top: words[0],
            left: words[1],
            bottom: words[2],
            right: words[3],
        }
    }

    fn record_surface_word(record: &[u8]) -> u32 {
        unsafe { (record.as_ptr().add(DRAW_STATE_SURFACE_OFFSET) as *const u32).read() }
    }

    /// A surface descriptor fixture mapped below 4 GiB so its identity
    /// round-trips through the record's raw-u32 +0x1c word unchanged.
    struct SurfaceFixture {
        base: *mut u8,
    }

    impl SurfaceFixture {
        /// `bounds` is written at +0x98; every other byte keeps the
        /// guard pattern so overreads are visible.
        fn new(bounds: Rect) -> Option<Self> {
            let base = try_map_u32_slab(hints::SURFACE_ATTACH, 0x1000)?;
            unsafe {
                core::ptr::write_bytes(base, GUARD, 0x1000);
                (base.add(SURFACE_BOUNDS_RECT_OFFSET) as *mut Rect).write(bounds);
            }
            Some(SurfaceFixture { base })
        }

        fn bounds(&self) -> Rect {
            unsafe { (self.base.add(SURFACE_BOUNDS_RECT_OFFSET) as *const Rect).read() }
        }

        fn identity(&self) -> u32 {
            self.base as u32
        }
    }

    #[test]
    fn stores_surface_identity_and_origin_moved_clip() {
        let Some(surface) = SurfaceFixture::new(Rect {
            top: 11,
            left: 22,
            bottom: 111,
            right: 222,
        }) else {
            note_missing_u32_fixture("cxx/draw_state_surface");
            return;
        };
        let mut record = record_fixture();
        unsafe { surface_attach(record.0.as_mut_ptr(), surface.base) };
        assert_eq!(
            record_surface_word(&record.0),
            surface.identity(),
            "+0x1c holds the surface identity as a raw u32 word",
        );        assert_eq!(
            record_rect(&record.0, DRAW_STATE_CLIP_RECT_OFFSET),
            Rect {
                top: 0,
                left: 0,
                bottom: 100, // 111 - 11
                right: 200,  // 222 - 22
            },
            "+0x34 holds the bounds rect moved to the origin",
        );
        // Every byte outside +0x1c..+0x20 and +0x34..+0x44 untouched.
        for (i, &b) in record.0.iter().enumerate() {
            let written =
                (DRAW_STATE_SURFACE_OFFSET..DRAW_STATE_SURFACE_OFFSET + 4).contains(&i)
                    || (DRAW_STATE_CLIP_RECT_OFFSET..DRAW_STATE_CLIP_RECT_OFFSET + 0x10)
                        .contains(&i);
            if !written {
                assert_eq!(b, GUARD, "byte {i:#x} outside the two stores changed");
            }
        }
    }

    #[test]
    fn surface_bounds_are_not_mutated() {
        let bounds = Rect {
            top: -5,
            left: 7,
            bottom: 50,
            right: 70,
        };
        let Some(surface) = SurfaceFixture::new(bounds) else {
            note_missing_u32_fixture("cxx/draw_state_surface");
            return;
        };
        let mut record = record_fixture();
        unsafe { surface_attach(record.0.as_mut_ptr(), surface.base) };
        assert_eq!(
            surface.bounds(),
            bounds,
            "the origin move applies only to the record-local copy",
        );
        assert_eq!(
            record_rect(&record.0, DRAW_STATE_CLIP_RECT_OFFSET),
            Rect {
                top: 0,
                left: 0,
                bottom: 55,
                right: 63,
            },
        );
    }

    #[test]
    fn inverted_bounds_wrap_like_arm_sub() {
        // bottom < top and right < left: rect_move_to_origin subtracts
        // with native ARM wrapping, so a degenerate surface yields
        // wrapped (huge) clip extents rather than a clamped empty rect.
        let Some(surface) = SurfaceFixture::new(Rect {
            top: i32::MIN,
            left: 100,
            bottom: -1,
            right: 50,
        }) else {
            note_missing_u32_fixture("cxx/draw_state_surface");
            return;
        };
        let mut record = record_fixture();
        unsafe { surface_attach(record.0.as_mut_ptr(), surface.base) };
        assert_eq!(
            record_rect(&record.0, DRAW_STATE_CLIP_RECT_OFFSET),
            Rect {
                top: 0,
                left: 0,
                bottom: i32::MAX, // -1 - MIN wraps
                right: -50,       // 50 - 100, no clamp
            },
        );
    }

    #[test]
    fn origin_rect_copies_verbatim() {
        // An already-origin bounds rect is the steady state (the
        // default descriptor's rect): copy must be identity.
        let bounds = Rect {
            top: 0,
            left: 0,
            bottom: 320,
            right: 240,
        };
        let Some(surface) = SurfaceFixture::new(bounds) else {
            note_missing_u32_fixture("cxx/draw_state_surface");
            return;
        };
        let mut record = record_fixture();
        unsafe { surface_attach(record.0.as_mut_ptr(), surface.base) };
        assert_eq!(record_rect(&record.0, DRAW_STATE_CLIP_RECT_OFFSET), bounds);
        assert_eq!(record_surface_word(&record.0), surface.identity());
    }
}
