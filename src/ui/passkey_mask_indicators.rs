//! `refresh_passkey_mask_indicators` — original: `FUN_0827f098` @ `0x0827f098`
//! (112 instruction bytes plus a 16-byte literal pool; true extent 128 bytes,
//! `0x0827f098..0x0827f118`; the next separately linked function starts at
//! `0x0827f11c`).
//!
//! The raw body reads the view's vtable slot `+0x58` four times and invokes it
//! with the same four-asterisk word (`0x2a2a2a2a`) and selector values
//! `0x5799` through `0x579c` in ascending order. Reloading the slot before each
//! call is observable: a method may replace the view's vtable before the next
//! selector is dispatched.
//!
//! **8 direct call sites**, all unconditional `bl` (no predicated direct
//! calls), verified by decoding every ARM B/BL word in `osos.dec`:
//! `0x0813f860`, `0x0820e880`, `0x0827ebcc`, `0x0827f2a0`, `0x0827f2c4`,
//! `0x0827f97c`, `0x0827fa08`, and `0x0827fa80`. The body itself only uses
//! indirect `blx` dispatches.
//!
//! Deliberate deviation: the concrete vtable slot has no recovered identity,
//! so this port names only its observed mask-indicator dispatch role. Host
//! fixtures use native-width function pointers while the target-layout
//! assertion preserves the ARM `+0x58` slot.

use core::ptr::addr_of;

const MASKED_DIGIT_WORD: u32 = 0x2a2a_2a2a;
const FIRST_MASK_INDICATOR_SELECTOR: u32 = 0x5799;
const MASK_INDICATOR_COUNT: u32 = 4;
const MASK_INDICATOR_VTABLE_WORD: usize = 0x58 / 4;

/// The passkey view as observed by the mask-indicator updater.
#[repr(C)]
pub struct PasskeyMaskIndicatorView {
    /// +0x00: runtime vtable pointer.
    pub vtable: *const PasskeyMaskIndicatorVtable,
}

/// The recovered portion of the passkey view's vtable.
#[repr(C)]
pub struct PasskeyMaskIndicatorVtable {
    /// Slots `+0x00..+0x54`, not decoded by this port.
    pub unresolved_00_54: [usize; MASK_INDICATOR_VTABLE_WORD],
    /// +0x58: accepts `(view, masked_digit_word, indicator_selector)`.
    pub dispatch_mask_indicator: unsafe extern "C" fn(*mut PasskeyMaskIndicatorView, u32, u32),
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x58] = [0; core::mem::offset_of!(PasskeyMaskIndicatorVtable, dispatch_mask_indicator)];

#[inline(always)]
unsafe fn dispatch_mask_indicator(view: *mut PasskeyMaskIndicatorView, selector: u32) {
    // 0827f0a0/0xbc/0xd4/0xec: each call reloads the current vtable.
    let vtable = core::ptr::read_volatile(addr_of!((*view).vtable));
    (vtable.as_ref().unwrap_unchecked().dispatch_mask_indicator)(view, MASKED_DIGIT_WORD, selector);
}

/// Refreshes all four passkey mask indicators through the view's vtable slot
/// `+0x58`. Neither the view nor its vtable is NULL-checked, matching retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn refresh_passkey_mask_indicators(view: *mut PasskeyMaskIndicatorView) {
    dispatch_mask_indicator(view, FIRST_MASK_INDICATOR_SELECTOR);
    dispatch_mask_indicator(view, FIRST_MASK_INDICATOR_SELECTOR + 1);
    dispatch_mask_indicator(view, FIRST_MASK_INDICATOR_SELECTOR + 2);
    dispatch_mask_indicator(view, FIRST_MASK_INDICATOR_SELECTOR + 3);
}

#[cfg(test)]
mod tests {
    use core::ptr::{addr_of, addr_of_mut};

    use parking_lot::Mutex;

    use super::{
        refresh_passkey_mask_indicators, PasskeyMaskIndicatorView, PasskeyMaskIndicatorVtable,
        FIRST_MASK_INDICATOR_SELECTOR, MASKED_DIGIT_WORD, MASK_INDICATOR_VTABLE_WORD,
    };

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALL_COUNT: usize = 0;
    static mut CALLS: [(*mut PasskeyMaskIndicatorView, u32, u32); 4] =
        [(core::ptr::null_mut(), 0, 0); 4];

    unsafe extern "C" fn record_dispatch(
        view: *mut PasskeyMaskIndicatorView,
        masked_digit_word: u32,
        selector: u32,
    ) {
        let index = addr_of!(CALL_COUNT).read();
        addr_of_mut!(CALLS).cast::<(*mut PasskeyMaskIndicatorView, u32, u32)>()
            .add(index)
            .write((view, masked_digit_word, selector));
        addr_of_mut!(CALL_COUNT).write(index + 1);
    }

    unsafe extern "C" fn record_then_replace_vtable(
        view: *mut PasskeyMaskIndicatorView,
        masked_digit_word: u32,
        selector: u32,
    ) {
        record_dispatch(view, masked_digit_word, selector);
        (*view).vtable = &REPLACEMENT_VTABLE;
    }

    static INITIAL_VTABLE: PasskeyMaskIndicatorVtable = PasskeyMaskIndicatorVtable {
        unresolved_00_54: [0; MASK_INDICATOR_VTABLE_WORD],
        dispatch_mask_indicator: record_then_replace_vtable,
    };
    static REPLACEMENT_VTABLE: PasskeyMaskIndicatorVtable = PasskeyMaskIndicatorVtable {
        unresolved_00_54: [0; MASK_INDICATOR_VTABLE_WORD],
        dispatch_mask_indicator: record_dispatch,
    };

    #[test]
    fn dispatches_masked_word_to_each_selector_and_reloads_the_vtable() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            addr_of_mut!(CALL_COUNT).write(0);
            addr_of_mut!(CALLS).write([(core::ptr::null_mut(), 0, 0); 4]);
        }
        let mut view = PasskeyMaskIndicatorView { vtable: &INITIAL_VTABLE };

        unsafe { refresh_passkey_mask_indicators(&mut view) };

        let calls = unsafe { addr_of!(CALLS).read() };
        assert_eq!(unsafe { addr_of!(CALL_COUNT).read() }, 4);
        for (index, (seen_view, word, selector)) in calls.into_iter().enumerate() {
            assert_eq!(seen_view, core::ptr::addr_of_mut!(view));
            assert_eq!(word, MASKED_DIGIT_WORD);
            assert_eq!(selector, FIRST_MASK_INDICATOR_SELECTOR + index as u32);
        }
        assert!(core::ptr::eq(view.vtable, &REPLACEMENT_VTABLE));
    }
}
