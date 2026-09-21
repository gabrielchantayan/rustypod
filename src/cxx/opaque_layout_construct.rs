//! `opaque_layout_construct` — original: `FUN_08261da8` @ **0x08261da8**
//! (20 bytes, 0x08261da8..0x08261dbc).
//!
//! Raw words `e92d4010 e1a04000 eb02178e e1a00004 e8bd8010` establish the
//! complete body: preserve `this` in r4, call the 76-byte layout initializer
//! at 0x082e7bf0, then return `this`. The `push {r4,lr}` at 0x08261dbc starts
//! the next separately linked function. Decoding the inbound branch words
//! finds five plain unconditional `bl` call sites (0x081e6b70, 0x0826287c,
//! 0x0839e898, 0x0839ea04, and 0x0839f3e0) and no predicated `bl` call sites.
//!
//! Algorithm: initialize the opaque 40-byte layout record, discard the status,
//! and return the original record pointer. Deliberate deviation: Rust's call
//! may lower differently from the stock direct BL while preserving the
//! initializer's pointer and return-value contract.

use super::opaque_layout_initialize::opaque_layout_initialize;

/// Initializes `layout` through retailOS's 40-byte layout initializer and
/// returns `layout`, including when it is null.
///
/// # Safety
/// `layout` must meet the initializer at 0x082e7bf0's requirements. The stock
/// wrapper does not validate it and still forwards null.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_layout_construct")]
#[inline(never)]
pub unsafe extern "C" fn opaque_layout_construct(layout: *mut u8) -> *mut u8 {
    opaque_layout_initialize(layout.cast());
    layout
}

