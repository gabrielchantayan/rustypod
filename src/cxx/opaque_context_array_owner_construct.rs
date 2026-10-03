//! `opaque_context_array_owner_construct` — `FUN_0825788c` @ **0x0825788c**.
//! True extent: 28 bytes to the next function at 0x082578a8 (24 bytes of
//! instructions and the four-byte vtable literal at 0x082578a4). Whole-image
//! A32 decoding finds two inbound plain BLs (0x081d72d4, 0x081d8178), zero
//! predicated BLs; the body contains one plain BL, zero predicated BLs.
//!
//! Stores the retailOS vtable 0x089a758c in the enclosing object's first
//! word, constructs the embedded opaque context array at byte +4 with the
//! incoming signed element count, then subtracts four from the returned
//! member pointer. Callers construct derived owners and replace this vtable.
//! The existing port of 0x08261c48 supplies the member constructor; no new
//! callee seam or recovered class identity is introduced. No deliberate
//! behavioral deviations. Field offsets remain target-sized on host builds.

use super::opaque_context_array_construct::opaque_context_array_construct;

const OWNER_VTABLE: u32 = 0x089a_758c;

/// Constructs an enclosing vtable-bearing opaque context array owner.
///
/// # Safety
/// `this` must be four-byte aligned and point to at least 0x110 writable
/// bytes, with storage satisfying the embedded constructor's callee layouts.
/// The original does not guard NULL or reject negative element counts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_context_array_owner_construct(
    this: *mut u8,
    element_count: i32,
) -> *mut u8 {
    this.cast::<u32>().write(OWNER_VTABLE);
    opaque_context_array_construct(this.add(4), element_count).sub(4)
}
