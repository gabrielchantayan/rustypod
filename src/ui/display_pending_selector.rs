//! Selector-only deferred display configuration.
//!
//! [`configure_display_pending_selector`] — original: `FUN_0828ccb0` @
//! **0x0828ccb0**. Raw `osos.dec` establishes its true **28-byte** extent:
//! seven ARM instructions at `0x0828ccb0..0x0828cccc`; the separately linked
//! next function begins at `0x0828cccc`. Decoding every ARM `B`/`BL` immediate
//! finds **3 direct callers**, all unconditional `bl` (none predicated):
//! `0x0819981c`, `0x0819a678`, and `0x0819a848`.
//!
//! # Algorithm
//!
//! Passes its display and selector to
//! [`super::display_pending_nibbles::configure_display_pending_nibbles`],
//! retaining all four pending nibbles by supplying the `-1` sentinel.
//!
//! # Deliberate deviations
//!
//! None.

use crate::drivers::display::Display;
use super::display_pending_nibbles::configure_display_pending_nibbles;

/// configure_display_pending_selector — original: `FUN_0828ccb0` @
/// `0x0828ccb0` (28 bytes, `0x0828ccb0..0x0828cccc`; next function
/// `0x0828cccc`). **3 direct unconditional `bl` callers, no predicated
/// calls**, verified by decoding every ARM `B`/`BL` immediate in `osos.dec`.
///
/// Updates only the deferred display selector; all four pending nibble values
/// remain unchanged through the callee's `-1` sentinel semantics.
///
/// # Safety
///
/// `display` must be a live [`Display`] when non-null, as required by the
/// delegated retailOS routine.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn configure_display_pending_selector(display: *mut Display, selector: i32) {
    configure_display_pending_nibbles(display, selector, -1, -1, -1, -1);
}
