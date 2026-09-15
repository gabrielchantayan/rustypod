//! Controller-history selection policy wrappers — originals: `FUN_08292d08`
//! @ `0x08292d08` (20 bytes: 16 bytes of code followed by the 4-byte
//! resource-id literal) and `FUN_08292e58` @ `0x08292e58` (20 bytes).
//!
//! # Verified call sites
//!
//! A raw scan of every ARM `B`/`BL` word in `osos.dec` finds 13 direct `bl`
//! callers of `FUN_08292d08`: 10 unconditional `bl`, two `bleq`, and one
//! `blne`; one further `bne` tail caller exists. The predicated calls are
//! gated by their callers rather than by a NULL guard in this wrapper.
//! `FUN_08292e58` has 25 direct `bl` callers, all unconditional, and no
//! predicated or tail-`b` callers.
//!
//! # Algorithms
//!
//! Both wrappers load private resource `0x0dad073a` and call the ported
//! shared controller-history selection helper. The `with_callback` wrapper
//! passes `1, 0`, causing the helper to install its `CntrlHistoryFn` callback;
//! `without_callback` passes `0, 1` and suppresses that allocation.

/// Private controller resource selected by the stock literal pool.
pub const CONTROLLER_HISTORY_RESOURCE_ID: u32 = 0x0dad_073a;


/// Selects the fixed controller-history resource without installing its
/// history callback.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn controller_history_select_without_callback() {
    crate::app::controller_history_select_core::controller_history_select(
        CONTROLLER_HISTORY_RESOURCE_ID, 0, 1,
    );
}

/// Selects the fixed controller-history resource and installs its callback.
///
/// Original: `FUN_08292d08` at `0x08292d08`, 20 bytes including its literal
/// pool. The 212-byte Ghidra extent incorrectly absorbs following sibling
/// functions.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn controller_history_select_with_callback() {
    crate::app::controller_history_select_core::controller_history_select(
        CONTROLLER_HISTORY_RESOURCE_ID, 1, 0,
    );
}

