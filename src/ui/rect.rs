//! Ports of the retailOS rectangle primitives — the geometry class the
//! whole drawing/view layer is built on. Two clusters, one type:
//!
//! Queries (`0x082a22a0`..`0x082a23fc`):
//!
//! - `rect_is_empty` — original: `FUN_082a22d8` @ 0x082a22d8 (36 bytes,
//!   21 `bl` call sites).
//! - `rect_is_valid` — original: `FUN_082a22fc` @ 0x082a22fc (36 bytes,
//!   5 `bl` call sites).
//! - `rect_width` — original: `FUN_082a2320` @ 0x082a2320 (16 bytes,
//!   38 `bl` call sites).
//! - `rect_height` — original: `FUN_082a2330` @ 0x082a2330 (16 bytes,
//!   42 `bl` call sites).
//! - `rect_contains` — original: `FUN_082a2340` @ 0x082a2340 (68 bytes,
//!   4 `bl` call sites).
//! - `rect_center` — original: `FUN_082a2384` @ 0x082a2384 (56 bytes,
//!   2 `bl` call sites).
//! - `rect_equals` — original: `FUN_082a23bc` @ 0x082a23bc (64 bytes,
//!   2 `bl` call sites) — C++ `operator==`.
//! - `rect_not_equals` — original: `FUN_082a23fc` @ 0x082a23fc (64
//!   bytes, 8 `bl` call sites) — C++ `operator!=`, a separately emitted
//!   function, not a negation of the above.
//! - `rects_intersect` — original: `FUN_082a22a0` @ 0x082a22a0 (56
//!   bytes, 2 `bl` call sites).
//!
//! Mutators — the whole `0x0826c1c8`..`0x0826c5cc` compilation unit:
//!
//! - `rect_intersect` — original: `FUN_0826c1c8` @ 0x0826c1c8 (132
//!   bytes, 45 `bl` call sites).
//! - `rect_intersect_into` — original: `FUN_0826c24c` @ 0x0826c24c
//!   (156 bytes, 18 `bl` call sites).
//! - `rect_move_to_origin` — original: `FUN_0826c2e8` @ 0x0826c2e8
//!   (48 bytes, 12 `bl` + 1 tail `b` call sites).
//! - `rect_center_vertically_in` — original @ 0x0826c318 (48 bytes,
//!   1 `bl` call site). **Missing from `decomp/functions.csv`** —
//!   Ghidra folded it into its predecessor; the extent comes from the
//!   binary (0x0826c318..0x0826c348, ending in the tail `b` to
//!   `rect_offset`).
//! - `rect_center_horizontally_in` — original @ 0x0826c348 (48 bytes,
//!   1 `bl` call site). Also missing from `functions.csv`.
//! - `rect_set` — original: `FUN_0826c378` @ 0x0826c378 (12 bytes,
//!   20 `bl` call sites).
//! - `rect_inset` — original: `FUN_0826c384` @ 0x0826c384 (84 bytes,
//!   11 `bl` call sites).
//! - `rect_union` — original: `FUN_0826c3d8` @ 0x0826c3d8 (136 bytes,
//!   10 `bl` + 1 tail `b` call sites).
//! - `rect_union_into` — original: `FUN_0826c460` @ 0x0826c460 (148
//!   bytes, 2 `bl` call sites).
//! - `rect_center_in` — original: `FUN_0826c4f4` @ 0x0826c4f4 (92
//!   bytes, 9 `bl` call sites).
//! - `rect_inset_vertical` — original: `FUN_0826c550` @ 0x0826c550
//!   (36 bytes, 2 `bl` call sites).
//! - `rect_offset` — original: `FUN_0826c574` @ 0x0826c574 (52 bytes,
//!   99 `bl` + 11 tail `b` call sites — the hottest of the family).
//! - `rect_clear` — original: `FUN_0826c5a8` @ 0x0826c5a8 (24 bytes,
//!   26 `bl` + 4 tail `b` call sites).
//!
//! One function in the unit is deliberately not given its own Rust
//! symbol: `FUN_0826c5c0` @ 0x0826c5c0 (12 bytes, 1 `bl` call site) is
//! byte-for-byte identical to `rect_set`; a hook for it can point
//! straight at [`rect_set`]. The unit's final word, `FUN_0826c5cc` @
//! 0x0826c5cc, is a lone `bx lr` with no callers at all and is ported
//! as the no-op [`rect_unit_dead_stub`].
//!
//! # Field layout
//!
//! Four 32-bit signed words in **QuickDraw order**: `+0x0` top, `+0x4`
//! left, `+0x8` bottom, `+0xc` right. Recovered from the binary, not
//! assumed:
//!
//! - `0x082a2320` returns `[+0xc] - [+0x4]` and `0x082a2330` returns
//!   `[+0x8] - [+0x0]`. The XRGB8888 -> RGB565 blit loop @ 0x0816d4a0
//!   uses `0x082a2320`'s result as the *pixels per row* (it advances the
//!   source pointer by `result * 4` bytes per row and by 4 bytes per
//!   inner iteration) and `0x082a2330`'s as the *row count*. So
//!   `[+0xc] - [+0x4]` is the width and `[+0x8] - [+0x0]` the height,
//!   which fixes `+0x4`/`+0xc` as the horizontal pair and
//!   `+0x0`/`+0x8` as the vertical pair.
//! - `0x0826c574` adds its first argument to the horizontal pair and its
//!   second to the vertical pair — i.e. `OffsetRect(r, dx, dy)`,
//!   matching QuickDraw's `OffsetRect(r, dh, dv)` argument order.
//! - The screen rectangle appears twice in the image's data as the word
//!   quadruple `{0, 0, 0xf0, 0x140}` (@ 0x0843a1f8, 0x084e05e8) —
//!   bottom = 240, right = 320, the Classic 6G's 320x240 LCD.
//!
//! `rect_center` writes the horizontal midpoint first and the vertical
//! midpoint second, so its output point is `{x, y}` (not QuickDraw's
//! `{v, h}`); [`Point`] reflects that.
//!
//! # Deviations
//!
//! - All comparisons are **signed** (the original uses `movle`/`movgt`/
//!   `strlt`/`strgt`, not the unsigned conditions), and all arithmetic
//!   wraps: the original's bare `sub`/`add` never trap, so coordinate
//!   overflow is reproduced with `wrapping_sub`/`wrapping_add` rather
//!   than panicking in a debug host build.
//! - The predicates return `u32` 0/1 rather than `bool`: ADS returns the
//!   full register and callers such as `rect_intersect` branch on the
//!   whole word.
//! - Every mutator is `void`. Several of them leave *garbage* in r0 —
//!   `rect_intersect`, `rect_intersect_into` and `rect_inset` return
//!   the constant 1 falling out of their closing `rect_is_valid` call
//!   on one path and the destination pointer on the other; `rect_union`
//!   returns a coordinate. No caller can be relying on a value that
//!   differs per path. The rest simply never write r0, which is why
//!   `rect_intersect` and friends can tail-branch to `rect_clear`.
//! - `rects_intersect` drops the original's `rsbs r0, r0, #1` /
//!   `movcc r0, #0` bool-normalisation tail: with `rect_is_empty`
//!   returning 0 or 1 the `cc` case is unreachable, so the pair is just
//!   `1 - empty`.

/// A retailOS rectangle: four signed 32-bit coordinates in QuickDraw
/// order (see the module header). `repr(C)` with `i32` fields lays out
/// identically on the ARMv5TE target and on a 64-bit test host.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rect {
    /// `+0x0` — inclusive top edge (y).
    pub top: i32,
    /// `+0x4` — inclusive left edge (x).
    pub left: i32,
    /// `+0x8` — exclusive bottom edge (y).
    pub bottom: i32,
    /// `+0xc` — exclusive right edge (x).
    pub right: i32,
}

/// The point [`rect_center`] writes: horizontal coordinate first.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Point {
    /// `+0x0` — horizontal coordinate.
    pub x: i32,
    /// `+0x4` — vertical coordinate.
    pub y: i32,
}

/// Midpoint of a coordinate span, with the original's truncate-toward-
/// zero division: `add r3, r3, r3, lsr #31` biases a negative span by
/// one before the arithmetic shift, which is exactly C's `/ 2`.
#[inline(always)]
fn midpoint(low: i32, high: i32) -> i32 {
    low.wrapping_add(high.wrapping_sub(low) / 2)
}

/// rect_is_empty — original: `FUN_082a22d8` @ 0x082a22d8 (36 bytes).
///
/// A rectangle is empty when either span collapses: `right <= left` or
/// `bottom <= top`. Note this is *not* the negation of
/// [`rect_is_valid`] — a zero-width rectangle is both empty and valid.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rect_is_empty(rect: *const Rect) -> u32 {
    let r = &*rect;
    u32::from(r.right <= r.left || r.bottom <= r.top)
}

/// rect_is_valid — original: `FUN_082a22fc` @ 0x082a22fc (36 bytes).
///
/// A rectangle is valid when neither span is inverted: `left <= right`
/// and `top <= bottom`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rect_is_valid(rect: *const Rect) -> u32 {
    let r = &*rect;
    u32::from(r.left <= r.right && r.top <= r.bottom)
}

/// rect_width — original: `FUN_082a2320` @ 0x082a2320 (16 bytes).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rect_width(rect: *const Rect) -> i32 {
    let r = &*rect;
    r.right.wrapping_sub(r.left)
}

/// rect_height — original: `FUN_082a2330` @ 0x082a2330 (16 bytes).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rect_height(rect: *const Rect) -> i32 {
    let r = &*rect;
    r.bottom.wrapping_sub(r.top)
}

/// rect_contains — original: `FUN_082a2340` @ 0x082a2340 (68 bytes).
///
/// Whether `outer` fully covers `inner`, edge for edge. Purely a
/// coordinate comparison: no emptiness test, so an inverted or empty
/// `inner` can still "fit".
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rect_contains(outer: *const Rect, inner: *const Rect) -> u32 {
    let (o, i) = (&*outer, &*inner);
    u32::from(
        i.left >= o.left && i.top >= o.top && i.bottom <= o.bottom && i.right <= o.right,
    )
}

/// rect_center — original: `FUN_082a2384` @ 0x082a2384 (56 bytes).
///
/// Writes the rectangle's midpoint into `out` and returns `out` (the
/// original's closing `mov r0, r1`).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rect_center(rect: *const Rect, out: *mut Point) -> *mut Point {
    let r = &*rect;
    (*out).x = midpoint(r.left, r.right);
    (*out).y = midpoint(r.top, r.bottom);
    out
}

/// rect_equals — original: `FUN_082a23bc` @ 0x082a23bc (64 bytes).
///
/// C++ `operator==`: all four coordinates equal, short-circuiting in
/// field order.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rect_equals(a: *const Rect, b: *const Rect) -> u32 {
    u32::from(*a == *b)
}

/// rect_not_equals — original: `FUN_082a23fc` @ 0x082a23fc (64 bytes).
///
/// C++ `operator!=`, emitted separately from [`rect_equals`] rather
/// than defined in terms of it.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rect_not_equals(a: *const Rect, b: *const Rect) -> u32 {
    u32::from(*a != *b)
}

/// rect_clear — original: `FUN_0826c5a8` @ 0x0826c5a8 (24 bytes).
///
/// Zeroes all four coordinates — the canonical empty rectangle.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rect_clear(rect: *mut Rect) {
    *rect = Rect {
        top: 0,
        left: 0,
        bottom: 0,
        right: 0,
    };
}

/// rect_offset — original: `FUN_0826c574` @ 0x0826c574 (52 bytes).
///
/// Translates the rectangle in place: `dx` moves the horizontal pair,
/// `dy` the vertical pair. QuickDraw's `OffsetRect`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rect_offset(rect: *mut Rect, dx: i32, dy: i32) {
    let r = &mut *rect;
    r.top = r.top.wrapping_add(dy);
    r.left = r.left.wrapping_add(dx);
    r.bottom = r.bottom.wrapping_add(dy);
    r.right = r.right.wrapping_add(dx);
}

/// rect_intersect — original: `FUN_0826c1c8` @ 0x0826c1c8 (132 bytes).
///
/// Clips `dst` to `src` in place. Either operand being empty clears
/// `dst` outright; otherwise the edges are pulled inwards
/// (`max` of the near edges, `min` of the far ones) and the result is
/// cleared if the clip inverted it. A *valid but empty* result — a
/// degenerate zero-width or zero-height overlap — survives unchanged,
/// because the final guard is [`rect_is_valid`], not [`rect_is_empty`].
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rect_intersect(dst: *mut Rect, src: *const Rect) {
    if rect_is_empty(dst) != 0 || rect_is_empty(src) != 0 {
        rect_clear(dst);
        return;
    }
    let s = *src;
    let d = &mut *dst;
    if d.top < s.top {
        d.top = s.top;
    }
    if d.left < s.left {
        d.left = s.left;
    }
    if d.bottom > s.bottom {
        d.bottom = s.bottom;
    }
    if d.right > s.right {
        d.right = s.right;
    }
    if rect_is_valid(dst) == 0 {
        rect_clear(dst);
    }
}

/// rect_intersect_into — original: `FUN_0826c24c` @ 0x0826c24c
/// (156 bytes).
///
/// [`rect_intersect`]'s three-operand form: `out = a ∩ b`, leaving both
/// sources alone. Same rules, including the `rect_is_valid` (not
/// `rect_is_empty`) final guard.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rect_intersect_into(out: *mut Rect, a: *const Rect, b: *const Rect) {
    if rect_is_empty(a) != 0 || rect_is_empty(b) != 0 {
        rect_clear(out);
        return;
    }
    let (x, y) = (*a, *b);
    *out = Rect {
        top: x.top.max(y.top),
        left: x.left.max(y.left),
        bottom: x.bottom.min(y.bottom),
        right: x.right.min(y.right),
    };
    if rect_is_valid(out) == 0 {
        rect_clear(out);
    }
}

/// rect_union — original: `FUN_0826c3d8` @ 0x0826c3d8 (136 bytes).
///
/// Grows `dst` to also cover `src` (the bounding box of the two). An
/// empty `src` leaves `dst` alone and an empty `dst` is overwritten
/// wholesale by `src` — the emptiness tests come first precisely so a
/// zeroed rectangle does not drag the union to the origin.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rect_union(dst: *mut Rect, src: *const Rect) {
    if rect_is_empty(src) != 0 {
        return;
    }
    if rect_is_empty(dst) != 0 {
        *dst = *src;
        return;
    }
    let s = *src;
    let d = &mut *dst;
    d.top = d.top.min(s.top);
    d.left = d.left.min(s.left);
    d.bottom = d.bottom.max(s.bottom);
    d.right = d.right.max(s.right);
}

/// rect_union_into — original: `FUN_0826c460` @ 0x0826c460 (148 bytes).
///
/// [`rect_union`]'s three-operand form: `out = a ∪ b`. An empty operand
/// makes the result a plain copy of the other one — note this differs
/// from the in-place version, which cannot "copy" when `src` is empty.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rect_union_into(out: *mut Rect, a: *const Rect, b: *const Rect) {
    if rect_is_empty(a) != 0 {
        *out = *b;
        return;
    }
    if rect_is_empty(b) != 0 {
        *out = *a;
        return;
    }
    let (x, y) = (*a, *b);
    *out = Rect {
        top: x.top.min(y.top),
        left: x.left.min(y.left),
        bottom: x.bottom.max(y.bottom),
        right: x.right.max(y.right),
    };
}

/// rect_set — original: `FUN_0826c378` @ 0x0826c378 (12 bytes).
///
/// Writes all four coordinates (one `stm`, so in field order). The
/// fifth argument arrives on the stack on the target, matching the
/// original's `ldr ip, [sp]`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rect_set(rect: *mut Rect, top: i32, left: i32, bottom: i32, right: i32) {
    *rect = Rect {
        top,
        left,
        bottom,
        right,
    };
}

/// rect_inset — original: `FUN_0826c384` @ 0x0826c384 (84 bytes).
///
/// QuickDraw's `InsetRect`: shrinks the rectangle by `dx` on each
/// horizontal edge and `dy` on each vertical one (negative values grow
/// it). Over-inserting past the middle inverts the rectangle, and the
/// closing `rect_is_valid` check clears it instead.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rect_inset(rect: *mut Rect, dx: i32, dy: i32) {
    let r = &mut *rect;
    r.top = r.top.wrapping_add(dy);
    r.left = r.left.wrapping_add(dx);
    r.bottom = r.bottom.wrapping_sub(dy);
    r.right = r.right.wrapping_sub(dx);
    if rect_is_valid(rect) == 0 {
        rect_clear(rect);
    }
}

/// rect_inset_vertical — original: `FUN_0826c550` @ 0x0826c550
/// (36 bytes).
///
/// [`rect_inset`]'s vertical-only sibling — `left`/`right` are not read
/// or written. The overshoot guard is open-coded here (`top > bottom`
/// after the inset) rather than routed through `rect_is_valid`, but it
/// still clears all four coordinates.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rect_inset_vertical(rect: *mut Rect, dy: i32) {
    let r = &mut *rect;
    r.top = r.top.wrapping_add(dy);
    r.bottom = r.bottom.wrapping_sub(dy);
    if r.top > r.bottom {
        rect_clear(rect);
    }
}

/// rect_move_to_origin — original: `FUN_0826c2e8` @ 0x0826c2e8
/// (48 bytes).
///
/// Translates the rectangle so its top-left corner sits at (0, 0),
/// keeping its size — the far edges become the height and width. Done
/// by subtraction rather than by calling [`rect_offset`], so it is
/// exact even for coordinates whose negation would overflow.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rect_move_to_origin(rect: *mut Rect) {
    let r = &mut *rect;
    r.bottom = r.bottom.wrapping_sub(r.top);
    r.right = r.right.wrapping_sub(r.left);
    r.top = 0;
    r.left = 0;
}

/// rect_center_in — original: `FUN_0826c4f4` @ 0x0826c4f4 (92 bytes).
///
/// Translates `rect` so it is centred inside `container`, in both axes,
/// without resizing it. Computed as a delta and applied through
/// [`rect_offset`] — the size is preserved exactly even when the
/// rectangle sticks out of the container.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rect_center_in(rect: *mut Rect, container: *const Rect) {
    let (r, c) = (*rect, *container);
    let dx = c.left.wrapping_sub(r.left).wrapping_add(
        rect_width(container).wrapping_sub(rect_width(rect)) / 2,
    );
    let dy = c.top.wrapping_sub(r.top).wrapping_add(
        rect_height(container).wrapping_sub(rect_height(rect)) / 2,
    );
    rect_offset(rect, dx, dy);
}

/// rect_center_vertically_in — original @ 0x0826c318 (48 bytes; absent
/// from `functions.csv`, see the module header).
///
/// [`rect_center_in`] restricted to the vertical axis: the horizontal
/// delta handed to [`rect_offset`] is a hard-coded zero.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rect_center_vertically_in(rect: *mut Rect, container: *const Rect) {
    let dy = (*container).top.wrapping_sub((*rect).top).wrapping_add(
        rect_height(container).wrapping_sub(rect_height(rect)) / 2,
    );
    rect_offset(rect, 0, dy);
}

/// rect_center_horizontally_in — original @ 0x0826c348 (48 bytes;
/// absent from `functions.csv`, see the module header).
///
/// The horizontal twin of [`rect_center_vertically_in`].
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rect_center_horizontally_in(rect: *mut Rect, container: *const Rect) {
    let dx = (*container).left.wrapping_sub((*rect).left).wrapping_add(
        rect_width(container).wrapping_sub(rect_width(rect)) / 2,
    );
    rect_offset(rect, dx, 0);
}

/// rects_intersect — original: `FUN_082a22a0` @ 0x082a22a0 (56 bytes).
///
/// Whether two rectangles overlap, leaving both untouched: intersects a
/// stack copy of `a` with `b` and reports that the result is non-empty.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rects_intersect(a: *const Rect, b: *const Rect) -> u32 {
    let mut clipped = *a;
    rect_intersect(&mut clipped, b);
    1 - rect_is_empty(&clipped)
}

/// rect_unit_dead_stub — original: `FUN_0826c5cc` @ 0x0826c5cc
/// (4 bytes).
///
/// The final word of the rect compilation unit: a lone `bx lr` — takes
/// nothing, reads nothing, writes nothing, returns nothing. Zero `bl`
/// and zero `b` call sites exist anywhere in the image
/// (binary-verified), so this is dead code: almost certainly a
/// linked-out empty virtual or an unreferenced inlined helper the
/// linker never garbage-collected. Ported as an empty body so the
/// address is covered if a hook ever wants it.
///
/// Deviation (codegen only): the `black_box(())` is a zero-instruction
/// compiler barrier that keeps LLVM's identical-function folding from
/// aliasing this symbol onto [`crate::stdio::semihost::nop_stub`],
/// which is the same empty body. The emitted code is still just the
/// crate-wide frame prologue/epilogue plus `bx lr` semantics — a pure
/// no-op either way.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rect_unit_dead_stub() {
    core::hint::black_box(());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Constructor in the *readable* order (x, y, w, h) so the tests say
    /// what they mean; the struct itself keeps the on-device order.
    fn xywh(x: i32, y: i32, w: i32, h: i32) -> Rect {
        Rect {
            top: y,
            left: x,
            bottom: y + h,
            right: x + w,
        }
    }

    fn r(top: i32, left: i32, bottom: i32, right: i32) -> Rect {
        Rect {
            top,
            left,
            bottom,
            right,
        }
    }

    /// Every rectangle the family is exercised against: unit, empty in
    /// each axis, fully inverted, negative-coordinate, and the extremes
    /// that make the coordinate arithmetic wrap.
    fn corpus() -> [Rect; 14] {
        [
            r(0, 0, 0, 0),
            r(0, 0, 1, 1),
            r(0, 0, 240, 320),
            r(10, 20, 10, 40),          // zero height
            r(10, 20, 30, 20),          // zero width
            r(30, 40, 10, 20),          // fully inverted
            r(-5, -5, 5, 5),
            r(-100, -100, -50, -50),
            r(1, 2, 3, 4),
            r(3, 4, 1, 2),
            r(0, 0, i32::MAX, i32::MAX),
            r(i32::MIN, i32::MIN, 0, 0),
            r(i32::MIN, i32::MIN, i32::MAX, i32::MAX),
            r(i32::MAX, i32::MAX, i32::MIN, i32::MIN),
        ]
    }

    #[test]
    fn dead_stub_is_a_callable_no_op() {
        // The whole contract: callable, with no observable effect.
        let rect = r(1, 2, 3, 4);
        unsafe { rect_unit_dead_stub() };
        assert_eq!(rect, r(1, 2, 3, 4));
    }

    #[test]
    fn width_and_height_are_the_horizontal_and_vertical_spans() {
        assert_eq!(unsafe { rect_width(&xywh(20, 10, 300, 200)) }, 300);
        assert_eq!(unsafe { rect_height(&xywh(20, 10, 300, 200)) }, 200);
        // The screen rectangle: 320 wide, 240 tall.
        let screen = r(0, 0, 240, 320);
        assert_eq!(unsafe { rect_width(&screen) }, 320);
        assert_eq!(unsafe { rect_height(&screen) }, 240);
    }

    #[test]
    fn spans_wrap_like_the_original_sub() {
        let wide = r(i32::MIN, i32::MIN, i32::MAX, i32::MAX);
        assert_eq!(unsafe { rect_width(&wide) }, i32::MAX.wrapping_sub(i32::MIN));
        assert_eq!(
            unsafe { rect_height(&wide) },
            i32::MAX.wrapping_sub(i32::MIN)
        );
    }

    #[test]
    fn empty_and_valid_are_independent_predicates() {
        // Zero-width: empty, but not inverted -> also valid.
        let degenerate = r(10, 20, 30, 20);
        assert_eq!(unsafe { rect_is_empty(&degenerate) }, 1);
        assert_eq!(unsafe { rect_is_valid(&degenerate) }, 1);
        // Proper rectangle: neither empty nor invalid.
        let proper = r(0, 0, 240, 320);
        assert_eq!(unsafe { rect_is_empty(&proper) }, 0);
        assert_eq!(unsafe { rect_is_valid(&proper) }, 1);
        // Inverted: empty and invalid.
        let inverted = r(30, 40, 10, 20);
        assert_eq!(unsafe { rect_is_empty(&inverted) }, 1);
        assert_eq!(unsafe { rect_is_valid(&inverted) }, 0);
    }

    #[test]
    fn predicates_match_their_reference_over_the_corpus() {
        for rect in corpus() {
            let empty = u32::from(rect.right <= rect.left || rect.bottom <= rect.top);
            let valid = u32::from(rect.left <= rect.right && rect.top <= rect.bottom);
            assert_eq!(unsafe { rect_is_empty(&rect) }, empty, "{rect:?}");
            assert_eq!(unsafe { rect_is_valid(&rect) }, valid, "{rect:?}");
            // An invalid rectangle is always empty; the converse fails.
            if valid == 0 {
                assert_eq!(empty, 1, "{rect:?}");
            }
        }
    }

    #[test]
    fn contains_is_an_edge_wise_comparison_not_an_area_test() {
        let outer = r(0, 0, 100, 100);
        assert_eq!(unsafe { rect_contains(&outer, &outer) }, 1, "reflexive");
        assert_eq!(unsafe { rect_contains(&outer, &r(10, 10, 90, 90)) }, 1);
        assert_eq!(unsafe { rect_contains(&outer, &r(-1, 10, 90, 90)) }, 0);
        assert_eq!(unsafe { rect_contains(&outer, &r(10, -1, 90, 90)) }, 0);
        assert_eq!(unsafe { rect_contains(&outer, &r(10, 10, 101, 90)) }, 0);
        assert_eq!(unsafe { rect_contains(&outer, &r(10, 10, 90, 101)) }, 0);
        // No emptiness test: an inverted inner still "fits".
        assert_eq!(unsafe { rect_contains(&outer, &r(90, 90, 10, 10)) }, 1);
    }

    #[test]
    fn contains_matches_reference_over_the_corpus() {
        for outer in corpus() {
            for inner in corpus() {
                let want = u32::from(
                    inner.left >= outer.left
                        && inner.top >= outer.top
                        && inner.bottom <= outer.bottom
                        && inner.right <= outer.right,
                );
                assert_eq!(
                    unsafe { rect_contains(&outer, &inner) },
                    want,
                    "{outer:?} {inner:?}"
                );
            }
        }
    }

    #[test]
    fn center_is_the_midpoint_and_returns_its_output() {
        let mut point = Point::default();
        let rect = xywh(20, 10, 300, 200);
        let returned = unsafe { rect_center(&rect, &mut point) };
        assert_eq!(returned, &mut point as *mut Point);
        assert_eq!(point, Point { x: 170, y: 110 });
    }

    #[test]
    fn center_truncates_toward_zero_like_c_division() {
        // Odd spans: the midpoint lands on the near edge's side.
        let mut point = Point::default();
        unsafe { rect_center(&r(0, 0, 3, 5), &mut point) };
        assert_eq!(point, Point { x: 2, y: 1 });
        // Negative spans (inverted rectangle) round toward zero too,
        // which is what `add rN, rN, rN, lsr #31` before `asr #1` buys.
        unsafe { rect_center(&r(0, 0, -3, -5), &mut point) };
        assert_eq!(point, Point { x: -2, y: -1 });
        // Symmetric about the origin.
        unsafe { rect_center(&r(-7, -7, 7, 7), &mut point) };
        assert_eq!(point, Point { x: 0, y: 0 });
    }

    #[test]
    fn center_matches_reference_over_the_corpus() {
        for rect in corpus() {
            let mut point = Point::default();
            unsafe { rect_center(&rect, &mut point) };
            assert_eq!(
                point,
                Point {
                    x: rect.left.wrapping_add(rect.right.wrapping_sub(rect.left) / 2),
                    y: rect.top.wrapping_add(rect.bottom.wrapping_sub(rect.top) / 2),
                },
                "{rect:?}"
            );
        }
    }

    #[test]
    fn equality_operators_are_exact_and_complementary() {
        for a in corpus() {
            for b in corpus() {
                let same = u32::from(
                    a.top == b.top
                        && a.left == b.left
                        && a.bottom == b.bottom
                        && a.right == b.right,
                );
                assert_eq!(unsafe { rect_equals(&a, &b) }, same, "{a:?} {b:?}");
                assert_eq!(unsafe { rect_not_equals(&a, &b) }, 1 - same, "{a:?} {b:?}");
            }
        }
        // One differing field in each position is enough.
        let base = r(1, 2, 3, 4);
        for changed in [r(9, 2, 3, 4), r(1, 9, 3, 4), r(1, 2, 9, 4), r(1, 2, 3, 9)] {
            assert_eq!(unsafe { rect_equals(&base, &changed) }, 0);
            assert_eq!(unsafe { rect_not_equals(&base, &changed) }, 1);
        }
    }

    #[test]
    fn clear_zeroes_every_coordinate() {
        let mut rect = r(-1, -2, -3, -4);
        unsafe { rect_clear(&mut rect) };
        assert_eq!(rect, Rect::default());
        assert_eq!(unsafe { rect_is_empty(&rect) }, 1);
    }

    #[test]
    fn offset_moves_the_horizontal_pair_by_dx_and_the_vertical_by_dy() {
        let mut rect = xywh(20, 10, 300, 200);
        unsafe { rect_offset(&mut rect, 5, -3) };
        assert_eq!(rect, xywh(25, 7, 300, 200));
        // Size is invariant under translation, over the whole corpus.
        for start in corpus() {
            for (dx, dy) in [(0, 0), (7, -9), (-1000, 1000), (i32::MAX, i32::MIN)] {
                let mut moved = start;
                unsafe { rect_offset(&mut moved, dx, dy) };
                assert_eq!(
                    moved,
                    r(
                        start.top.wrapping_add(dy),
                        start.left.wrapping_add(dx),
                        start.bottom.wrapping_add(dy),
                        start.right.wrapping_add(dx),
                    ),
                    "{start:?} {dx} {dy}"
                );
                assert_eq!(unsafe { rect_width(&moved) }, unsafe {
                    rect_width(&start)
                });
                assert_eq!(unsafe { rect_height(&moved) }, unsafe {
                    rect_height(&start)
                });
            }
        }
    }

    #[test]
    fn intersect_clips_to_the_overlap() {
        let mut dst = xywh(0, 0, 100, 100);
        unsafe { rect_intersect(&mut dst, &xywh(50, 50, 100, 100)) };
        assert_eq!(dst, xywh(50, 50, 50, 50));
    }

    #[test]
    fn intersect_clears_when_either_operand_is_empty() {
        let mut dst = xywh(0, 0, 100, 100);
        unsafe { rect_intersect(&mut dst, &r(10, 20, 10, 40)) };
        assert_eq!(dst, Rect::default(), "empty source clears the destination");

        let mut empty = r(10, 20, 10, 40);
        unsafe { rect_intersect(&mut empty, &xywh(0, 0, 100, 100)) };
        assert_eq!(empty, Rect::default(), "empty destination clears too");
    }

    #[test]
    fn intersect_clears_a_disjoint_result() {
        let mut dst = xywh(0, 0, 10, 10);
        unsafe { rect_intersect(&mut dst, &xywh(100, 100, 10, 10)) };
        assert_eq!(dst, Rect::default());
    }

    #[test]
    fn intersect_keeps_a_valid_but_degenerate_overlap() {
        // Edge-to-edge neighbours: the clip is zero-width, still valid,
        // so the original leaves it in place rather than clearing.
        let mut dst = xywh(0, 0, 10, 10);
        unsafe { rect_intersect(&mut dst, &xywh(10, 0, 10, 10)) };
        assert_eq!(dst, r(0, 10, 10, 10));
        assert_eq!(unsafe { rect_is_empty(&dst) }, 1);
        assert_eq!(unsafe { rect_is_valid(&dst) }, 1);
    }

    #[test]
    fn intersect_matches_reference_over_the_corpus() {
        for a in corpus() {
            for b in corpus() {
                let mut got = a;
                unsafe { rect_intersect(&mut got, &b) };

                let mut want = a;
                let a_empty = a.right <= a.left || a.bottom <= a.top;
                let b_empty = b.right <= b.left || b.bottom <= b.top;
                if a_empty || b_empty {
                    want = Rect::default();
                } else {
                    want.top = want.top.max(b.top);
                    want.left = want.left.max(b.left);
                    want.bottom = want.bottom.min(b.bottom);
                    want.right = want.right.min(b.right);
                    if !(want.left <= want.right && want.top <= want.bottom) {
                        want = Rect::default();
                    }
                }
                assert_eq!(got, want, "{a:?} {b:?}");
            }
        }
    }

    #[test]
    fn intersect_is_idempotent_and_never_grows_the_destination() {
        for a in corpus() {
            for b in corpus() {
                let mut once = a;
                unsafe { rect_intersect(&mut once, &b) };
                let mut twice = once;
                unsafe { rect_intersect(&mut twice, &b) };
                if unsafe { rect_is_empty(&once) } == 0 {
                    assert_eq!(twice, once, "{a:?} {b:?}");
                    assert_eq!(unsafe { rect_contains(&a, &once) }, 1, "{a:?} {b:?}");
                    assert_eq!(unsafe { rect_contains(&b, &once) }, 1, "{a:?} {b:?}");
                }
            }
        }
    }

    #[test]
    fn intersect_into_agrees_with_the_in_place_form() {
        for a in corpus() {
            for b in corpus() {
                let mut want = a;
                unsafe { rect_intersect(&mut want, &b) };
                let mut got = r(-7, -7, -7, -7); // pre-dirtied
                unsafe { rect_intersect_into(&mut got, &a, &b) };
                assert_eq!(got, want, "{a:?} {b:?}");
                assert_eq!(a, a, "sources untouched");
            }
        }
    }

    #[test]
    fn union_grows_to_the_bounding_box() {
        let mut dst = xywh(0, 0, 10, 10);
        unsafe { rect_union(&mut dst, &xywh(20, 20, 10, 10)) };
        assert_eq!(dst, xywh(0, 0, 30, 30));
    }

    #[test]
    fn union_treats_empty_operands_as_absent_not_as_the_origin() {
        // An empty source must not drag the union to (0, 0).
        let mut dst = xywh(50, 50, 10, 10);
        unsafe { rect_union(&mut dst, &Rect::default()) };
        assert_eq!(dst, xywh(50, 50, 10, 10));
        // An empty destination is replaced outright, inverted or not.
        let mut empty = r(30, 40, 10, 20);
        unsafe { rect_union(&mut empty, &xywh(50, 50, 10, 10)) };
        assert_eq!(empty, xywh(50, 50, 10, 10));
    }

    #[test]
    fn union_matches_reference_over_the_corpus() {
        for a in corpus() {
            for b in corpus() {
                let mut got = a;
                unsafe { rect_union(&mut got, &b) };
                let want = if unsafe { rect_is_empty(&b) } != 0 {
                    a
                } else if unsafe { rect_is_empty(&a) } != 0 {
                    b
                } else {
                    r(
                        a.top.min(b.top),
                        a.left.min(b.left),
                        a.bottom.max(b.bottom),
                        a.right.max(b.right),
                    )
                };
                assert_eq!(got, want, "{a:?} {b:?}");
                // A non-empty union always contains both non-empty inputs.
                if unsafe { rect_is_empty(&a) } == 0 && unsafe { rect_is_empty(&b) } == 0 {
                    assert_eq!(unsafe { rect_contains(&got, &a) }, 1);
                    assert_eq!(unsafe { rect_contains(&got, &b) }, 1);
                }
            }
        }
    }

    #[test]
    fn union_into_differs_from_in_place_only_by_being_able_to_copy() {
        // Both empty-operand paths of the three-operand form copy.
        let mut out = r(-7, -7, -7, -7);
        unsafe { rect_union_into(&mut out, &Rect::default(), &xywh(5, 5, 2, 2)) };
        assert_eq!(out, xywh(5, 5, 2, 2));
        unsafe { rect_union_into(&mut out, &xywh(5, 5, 2, 2), &Rect::default()) };
        assert_eq!(out, xywh(5, 5, 2, 2));

        for a in corpus() {
            for b in corpus() {
                let mut got = r(-7, -7, -7, -7);
                unsafe { rect_union_into(&mut got, &a, &b) };
                let want = if unsafe { rect_is_empty(&a) } != 0 {
                    b
                } else if unsafe { rect_is_empty(&b) } != 0 {
                    a
                } else {
                    let mut w = a;
                    unsafe { rect_union(&mut w, &b) };
                    w
                };
                assert_eq!(got, want, "{a:?} {b:?}");
            }
        }
    }

    #[test]
    fn set_writes_the_coordinates_in_field_order() {
        let mut rect = r(-1, -2, -3, -4);
        unsafe { rect_set(&mut rect, 1, 2, 3, 4) };
        assert_eq!(rect, r(1, 2, 3, 4));
    }

    #[test]
    fn inset_shrinks_by_dx_horizontally_and_dy_vertically() {
        let mut rect = xywh(0, 0, 100, 100);
        unsafe { rect_inset(&mut rect, 10, 20) };
        assert_eq!(rect, xywh(10, 20, 80, 60));
        // Negative values grow it.
        unsafe { rect_inset(&mut rect, -10, -20) };
        assert_eq!(rect, xywh(0, 0, 100, 100));
    }

    #[test]
    fn inset_past_the_middle_clears_instead_of_inverting() {
        let mut rect = xywh(0, 0, 10, 10);
        unsafe { rect_inset(&mut rect, 6, 0) };
        assert_eq!(rect, Rect::default());
        // A degenerate-but-valid inset survives (exactly halved away).
        let mut exact = xywh(0, 0, 10, 10);
        unsafe { rect_inset(&mut exact, 5, 5) };
        assert_eq!(exact, r(5, 5, 5, 5));
    }

    #[test]
    fn inset_matches_reference_over_the_corpus() {
        for start in corpus() {
            for (dx, dy) in [(0, 0), (1, 1), (-3, 4), (1000, 1000)] {
                let mut got = start;
                unsafe { rect_inset(&mut got, dx, dy) };
                let mut want = r(
                    start.top.wrapping_add(dy),
                    start.left.wrapping_add(dx),
                    start.bottom.wrapping_sub(dy),
                    start.right.wrapping_sub(dx),
                );
                if !(want.left <= want.right && want.top <= want.bottom) {
                    want = Rect::default();
                }
                assert_eq!(got, want, "{start:?} {dx} {dy}");
            }
        }
    }

    #[test]
    fn inset_vertical_leaves_the_horizontal_edges_alone() {
        let mut rect = xywh(7, 0, 100, 100);
        unsafe { rect_inset_vertical(&mut rect, 20) };
        assert_eq!(rect, xywh(7, 20, 100, 60));
        // Overshoot clears everything, horizontal edges included.
        let mut small = xywh(7, 0, 100, 10);
        unsafe { rect_inset_vertical(&mut small, 6) };
        assert_eq!(small, Rect::default());
        // Exactly halved away is `top == bottom`, which survives.
        let mut exact = xywh(7, 0, 100, 10);
        unsafe { rect_inset_vertical(&mut exact, 5) };
        assert_eq!(exact, r(5, 7, 5, 107));
    }

    #[test]
    fn move_to_origin_keeps_the_size_and_zeroes_the_corner() {
        for start in corpus() {
            let (w, h) = unsafe { (rect_width(&start), rect_height(&start)) };
            let mut moved = start;
            unsafe { rect_move_to_origin(&mut moved) };
            assert_eq!(moved.top, 0);
            assert_eq!(moved.left, 0);
            assert_eq!(moved.bottom, h, "{start:?}");
            assert_eq!(moved.right, w, "{start:?}");
        }
    }

    #[test]
    fn center_in_puts_the_rectangle_in_the_middle_of_its_container() {
        let container = xywh(0, 0, 100, 100);
        let mut rect = xywh(0, 0, 20, 40);
        unsafe { rect_center_in(&mut rect, &container) };
        assert_eq!(rect, xywh(40, 30, 20, 40));
        let mut c = Point::default();
        let mut cc = Point::default();
        unsafe {
            rect_center(&rect, &mut c);
            rect_center(&container, &mut cc);
        }
        assert_eq!(c, cc, "centres coincide for even leftovers");
    }

    #[test]
    fn center_in_preserves_size_and_splits_the_axes() {
        for start in corpus() {
            for container in corpus() {
                let (w, h) = unsafe { (rect_width(&start), rect_height(&start)) };

                let mut both = start;
                let mut vertical = start;
                let mut horizontal = start;
                unsafe {
                    rect_center_in(&mut both, &container);
                    rect_center_vertically_in(&mut vertical, &container);
                    rect_center_horizontally_in(&mut horizontal, &container);
                }
                assert_eq!(unsafe { rect_width(&both) }, w, "size preserved");
                assert_eq!(unsafe { rect_height(&both) }, h);

                // The single-axis forms are the two-axis form restricted.
                assert_eq!(vertical.top, both.top, "{start:?} {container:?}");
                assert_eq!(vertical.bottom, both.bottom);
                assert_eq!(vertical.left, start.left, "vertical: x untouched");
                assert_eq!(horizontal.left, both.left, "{start:?} {container:?}");
                assert_eq!(horizontal.right, both.right);
                assert_eq!(horizontal.top, start.top, "horizontal: y untouched");
            }
        }
    }

    #[test]
    fn rects_intersect_reports_overlap_without_touching_its_operands() {
        let a = xywh(0, 0, 100, 100);
        let b = xywh(50, 50, 100, 100);
        assert_eq!(unsafe { rects_intersect(&a, &b) }, 1);
        assert_eq!(a, xywh(0, 0, 100, 100), "operands stay untouched");
        assert_eq!(b, xywh(50, 50, 100, 100));

        // Edge-to-edge neighbours share no area.
        assert_eq!(
            unsafe { rects_intersect(&xywh(0, 0, 10, 10), &xywh(10, 0, 10, 10)) },
            0
        );
        assert_eq!(
            unsafe { rects_intersect(&xywh(0, 0, 10, 10), &xywh(100, 100, 10, 10)) },
            0
        );
    }

    #[test]
    fn rects_intersect_agrees_with_intersect_over_the_corpus() {
        for a in corpus() {
            for b in corpus() {
                let mut clipped = a;
                unsafe { rect_intersect(&mut clipped, &b) };
                assert_eq!(
                    unsafe { rects_intersect(&a, &b) },
                    1 - unsafe { rect_is_empty(&clipped) },
                    "{a:?} {b:?}"
                );
                // Overlap is symmetric even though clipping is not.
                assert_eq!(
                    unsafe { rects_intersect(&a, &b) },
                    unsafe { rects_intersect(&b, &a) },
                    "{a:?} {b:?}"
                );
            }
        }
    }
}
