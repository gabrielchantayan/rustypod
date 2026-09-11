//! plane_cursor_init — original: `FUN_0839bae0` @ 0x0839bae0 (120 bytes
//! exactly; the byte-similar sibling `FUN_0839bb58` — identical except
//! its three `bl`s target the other accessor copy — starts immediately
//! after at 0x0839bb58, so Ghidra's 120-byte extent is exact).
//!
//! 14 `bl` call sites, all unconditional, all inside the fixed-point
//! YCbCr converter `FUN_080c79e8` @ 0x080c79e8 (an unrolled block of
//! 14 calls @ 0x080c7a2c..0x080c7b30, every one with mode = 2) —
//! verified by decoding every ARM B/BL word in osos.dec: no `b` sites,
//! no predicated forms, and the address appears in no data word, so it
//! is never virtually dispatched. The sibling @ 0x0839bb58 has 8 more
//! `bl` sites in the sibling converter @ 0x080c7eb8, also all mode = 2;
//! the even/odd phase modes are dead in osos but are ported faithfully.
//!
//! The original:
//!
//! ```text
//! push  {r4, r5, r6, r7, r8, lr}
//! mov   r5, r1                ; plane
//! mov   r4, r0                ; out
//! add   r0, r5, #16           ; &plane->handle
//! mov   r1, #0
//! mov   r7, r2                ; mode
//! mov   r6, r3                ; index
//! bl    0x83d60dc             ; handle_elem_ptr(slot, 0)
//! str   r0, [r4, #4]          ; out->begin
//! ldr   r0, [r5, #4]          ; plane->count
//! sub   r1, r0, #1
//! add   r0, r5, #16
//! bl    0x83d60dc             ; handle_elem_ptr(slot, count - 1)
//! cmp   r7, #0
//! str   r0, [r4, #8]          ; out->end
//! mov   r0, #2
//! lsleq r1, r6, #1            ; mode 0: index <<= 1
//! beq   store_step2
//! cmp   r7, #1
//! mov   r2, #1
//! movne r1, r6                ; mode >= 2: index as-is
//! strne r2, [r4, #12]         ; mode >= 2: step = 1
//! bne   finish
//! add   r1, r2, r6, lsl #1    ; mode 1: index = 2*index + 1
//! store_step2:
//! str   r0, [r4, #12]         ; modes 0/1: step = 2
//! finish:
//! add   r0, r5, #16
//! bl    0x83d60dc             ; handle_elem_ptr(slot, index)
//! str   r0, [r4]              ; out->cur
//! mov   r0, r4
//! pop   {r4, r5, r6, r7, r8, pc}
//! ```
//!
//! Initializes a 16-byte sampling cursor over a plane of u32 elements
//! held behind a C++ handle (see [`handle_elem_ptr`]):
//!
//! - `begin` (+4) — element 0;
//! - `end`   (+8) — element `count - 1` (wraps to base-1 for count 0);
//! - `cur`   (+0) — element `index`, phase-adjusted by `mode`:
//!   mode 0 selects the EVEN subsampling phase (`2*index`), mode 1 the
//!   ODD phase (`2*index + 1`), any other mode is DIRECT (`index`);
//! - `step`  (+12) — element stride multiplier: 2 for the two
//!   subsampling phases, 1 for direct mode. The converters advance
//!   `cur` by `step` times their row byte-stride per row group, so a
//!   phase cursor walks every other element.
//!
//! The first three words are exactly the `ThreePointers` layout
//! consumed by the already-ported clamp-fetch `three_pointer_select`
//! (util/three_pointer_select.rs, `FUN_083d5eb4`): `cur` is `first`,
//! `begin` is `second`, `end` is `third`, and the fetch clamps `cur`
//! into `[begin, end]` with edge replication. Because `begin` is
//! always element 0 and `index` is unsigned, `cur < begin` can only
//! arise from 32-bit wraparound; the high clamp is the live one.
//!
//! Store order — `begin`, `end`, `step`, `cur` — matches the original
//! exactly, including the `end` store landing between the mode compare
//! and the step store. Deliberate deviation: the original `bl`s the
//! accessor copy @ 0x083d60dc; this port calls the ported
//! [`handle_elem_ptr`] symbol, which both stock copies (0x083d60dc,
//! 0x083d60f0) hook. match.py shows the same structure: two
//! call/store pairs, the three-way mode split, a third call/store,
//! and the construct-and-return-this epilogue.

use crate::cxx::handle::handle_elem_ptr;

/// The 16-byte cursor built by [`plane_cursor_init`]. On the 32-bit
/// target the fields sit at +0/+4/+8/+12; `#[repr(C)]` with named
/// fields keeps the target layout exact and the host fields disjoint.
/// The first three words alias `ThreePointers` (util/three_pointer_select).
#[repr(C)]
pub struct PlaneCursor {
    /// +0: current element pointer, phase-adjusted (`first`).
    pub cur: *mut u32,
    /// +4: element 0 — the clamp low bound (`second`).
    pub begin: *mut u32,
    /// +8: element `count - 1` — the clamp high bound (`third`).
    pub end: *mut u32,
    /// +12: element stride multiplier (2 = subsampling phase, 1 = direct).
    pub step: u32,
}

/// The plane descriptor [`plane_cursor_init`] samples. Only `count`
/// (+4) and `handle` (+16) are read; the other words are opaque to
/// this function (the converter reads +0 itself as a row byte bound).
#[repr(C)]
pub struct PlaneDescriptor {
    /// +0: not read here.
    pub opaque0: u32,
    /// +4: number of u32 elements addressable through the handle.
    pub count: u32,
    /// +8: not read here.
    pub opaque8: u32,
    /// +12: not read here.
    pub opaque12: u32,
    /// +16: handle slot; the cell's first word is the element base.
    pub handle: *const *const u32,
}

/// plane_cursor_init — originals: `FUN_0839bae0` @ 0x0839bae0 (120
/// bytes; 14 unconditional `bl` sites) and byte-similar
/// `FUN_0839bb58` @ 0x0839bb58 (120 bytes; 8 unconditional `bl` sites).
///
/// Fills `out` as described in the module header and returns it — the
/// ADS construct-and-return-this idiom. Mode 0 = even phase
/// (`2*index`, step 2), mode 1 = odd phase (`2*index + 1`, step 2),
/// anything else = direct (`index`, step 1). All index arithmetic is
/// modulo $2^{32}$, as in the original's `lsl #1` / `add`.
///
/// # Safety
/// `out` must be valid for four writable words and `plane` for the
/// `count` and `handle` words, as in the original (no NULL checks).
/// The handle's cell, when non-NULL, must be readable. The returned
/// element pointers are never dereferenced here.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn plane_cursor_init(
    out: *mut PlaneCursor,
    plane: *const PlaneDescriptor,
    mode: u32,
    index: u32,
) -> *mut PlaneCursor {
    let slot = core::ptr::addr_of!((*plane).handle);
    (*out).begin = handle_elem_ptr(slot, 0);
    (*out).end = handle_elem_ptr(slot, (*plane).count.wrapping_sub(1));
    let (index, step) = match mode {
        0 => (index << 1, 2),
        1 => ((index << 1) + 1, 2),
        _ => (index, 1),
    };
    (*out).step = step;
    (*out).cur = handle_elem_ptr(slot, index);
    out
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::util::three_pointer_select::{three_pointer_select, ThreePointers};

    /// A plane of `words` behind a two-level handle, plus the cursor
    /// the init fills.
    struct Fixture {
        words: [u32; 8],
        cell: *const u32,
        plane: PlaneDescriptor,
        cursor: PlaneCursor,
    }

    fn fixture(count: u32) -> Fixture {
        let mut words = [0u32; 8];
        for (i, word) in words.iter_mut().enumerate() {
            *word = 0x1000_0000 + i as u32;
        }
        Fixture {
            words,
            cell: core::ptr::null(),
            plane: PlaneDescriptor {
                opaque0: 0,
                count,
                opaque8: 0,
                opaque12: 0,
                handle: core::ptr::null(),
            },
            cursor: PlaneCursor {
                cur: core::ptr::null_mut(),
                begin: core::ptr::null_mut(),
                end: core::ptr::null_mut(),
                step: 0,
            },
        }
    }

    /// Wire the handle to the word array and run the init.
    fn init(f: &mut Fixture, mode: u32, index: u32) -> *mut PlaneCursor {
        f.cell = f.words.as_ptr();
        f.plane.handle = &f.cell;
        unsafe { plane_cursor_init(&mut f.cursor, &f.plane, mode, index) }
    }

    /// Byte offset of a cursor pointer from the element base.
    fn offset(f: &Fixture, ptr: *mut u32) -> usize {
        (ptr as usize).wrapping_sub(f.words.as_ptr() as usize)
    }

    #[test]
    fn direct_mode_indexes_verbatim_with_unit_step() {
        let mut f = fixture(8);
        let returned = init(&mut f, 2, 3);
        assert_eq!(returned, &mut f.cursor as *mut PlaneCursor, "return-this");
        assert_eq!(offset(&f, f.cursor.begin), 0, "begin = element 0");
        assert_eq!(offset(&f, f.cursor.end), 7 * 4, "end = element count-1");
        assert_eq!(offset(&f, f.cursor.cur), 3 * 4, "cur = element index");
        assert_eq!(f.cursor.step, 1);
    }

    #[test]
    fn even_phase_doubles_the_index_with_step_two() {
        let mut f = fixture(8);
        init(&mut f, 0, 3);
        assert_eq!(offset(&f, f.cursor.cur), 6 * 4);
        assert_eq!(f.cursor.step, 2);
    }

    #[test]
    fn odd_phase_doubles_and_offsets_the_index_with_step_two() {
        let mut f = fixture(8);
        init(&mut f, 1, 3);
        assert_eq!(offset(&f, f.cursor.cur), 7 * 4);
        assert_eq!(f.cursor.step, 2);
    }

    /// Every mode other than 0/1 is direct — the only two osos call
    /// clusters pass 2, but the compare is `!= 1`, not `== 2`.
    #[test]
    fn any_other_mode_is_direct() {
        for mode in [2u32, 3, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff] {
            let mut f = fixture(8);
            init(&mut f, mode, 5);
            assert_eq!(offset(&f, f.cursor.cur), 5 * 4, "mode {mode:#x}");
            assert_eq!(f.cursor.step, 1, "mode {mode:#x}");
        }
    }

    /// `count - 1` underflows: the original's `sub r1, r0, #1` wraps,
    /// so end = element 0xffff_ffff = base - 4 bytes (mod 2^32 on
    /// target; the host offset is the unwrapped 0x3_ffff_fffc).
    #[test]
    fn zero_count_wraps_the_end_index() {
        let mut f = fixture(0);
        init(&mut f, 2, 0);
        assert_eq!(offset(&f, f.cursor.end), 0xffff_ffffusize * 4);
    }

    /// Phase index arithmetic is mod 2^32: `0x8000_0000 << 1` drops
    /// the top bit, matching ARM's `lsl #1`.
    #[test]
    fn phase_index_shift_wraps_at_word_width() {
        let mut f = fixture(8);
        init(&mut f, 0, 0x8000_0000);
        assert_eq!(offset(&f, f.cursor.cur), 0);
        init(&mut f, 1, 0x8000_0000);
        assert_eq!(offset(&f, f.cursor.cur), 4, "2*index + 1 mod 2^32");
        init(&mut f, 1, 0xffff_ffff);
        assert_eq!(offset(&f, f.cursor.cur), 0xffff_ffffusize * 4, "0x1_ffff_ffff mod 2^32");
    }

    /// A NULL handle cell: the accessor's unconditional add turns each
    /// pointer into its byte index — begin = 0, end = (count-1)*4,
    /// cur = phase(index)*4. No dereference happens.
    #[test]
    fn null_cell_yields_bare_byte_offsets() {
        let mut f = fixture(4);
        f.plane.handle = &f.cell; // f.cell stays NULL
        unsafe { plane_cursor_init(&mut f.cursor, &f.plane, 1, 2) };
        assert_eq!(f.cursor.begin as usize, 0);
        assert_eq!(f.cursor.end as usize, 3 * 4);
        assert_eq!(f.cursor.cur as usize, 5 * 4, "odd phase: 2*2 + 1");
        assert_eq!(f.cursor.step, 2);
    }

    /// Parity against an independent reference model of the ARM body
    /// over the mode/index/count corners.
    #[test]
    fn exhaustive_corner_parity() {
        fn reference(mode: u32, index: u32) -> (u32, u32) {
            match mode {
                0 => (index << 1, 2),
                1 => ((index << 1) + 1, 2),
                _ => (index, 1),
            }
        }
        let modes = [0u32, 1, 2, 3, 0x8000_0000, 0xffff_ffff];
        let indices = [0u32, 1, 2, 7, 0x4000_0000, 0x8000_0000, 0xffff_ffff];
        for count in [0u32, 1, 5, 8] {
            for mode in modes {
                for index in indices {
                    let mut f = fixture(count);
                    init(&mut f, mode, index);
                    let (want_index, want_step) = reference(mode, index);
                    assert_eq!(
                        offset(&f, f.cursor.cur),
                        want_index as usize * 4,
                        "count {count} mode {mode:#x} index {index:#x}"
                    );
                    assert_eq!(f.cursor.step, want_step);
                    assert_eq!(offset(&f, f.cursor.begin), 0);
                    assert_eq!(
                        offset(&f, f.cursor.end),
                        count.wrapping_sub(1) as usize * 4
                    );
                }
            }
        }
    }

    /// The produced cursor feeds the already-ported clamp-fetch
    /// (`three_pointer_select`): an in-range `cur` dereferences itself.
    #[test]
    fn cursor_feeds_three_pointer_select_in_range() {
        let mut f = fixture(5);
        init(&mut f, 2, 2);
        let triple = ThreePointers {
            first: f.cursor.cur,
            second: f.cursor.begin,
            third: f.cursor.end,
        };
        assert_eq!(unsafe { three_pointer_select(&triple) }, f.words[2]);
    }

    /// Past `end`, the clamp-fetch returns the last element — the edge
    /// replication the converters rely on when `index` overshoots
    /// `count - 1` (their indices run to `remainder/2 + 6`).
    #[test]
    fn cursor_feeds_three_pointer_select_clamped_high() {
        let mut f = fixture(5);
        init(&mut f, 2, 7);
        let triple = ThreePointers {
            first: f.cursor.cur,
            second: f.cursor.begin,
            third: f.cursor.end,
        };
        assert_eq!(unsafe { three_pointer_select(&triple) }, f.words[4]);
    }
}
