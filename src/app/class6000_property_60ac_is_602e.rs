//! `class6000_property_60ac_is_602e` — original: `FUN_08172a0c` @ `0x08172a0c`
//! (44 bytes; eleven ARM instruction words through `0x08172a34`). The next real
//! function begins at `0x08172a38`.
//!
//! Decoding every immediate ARM `B`/`BL` word in `osos.dec` finds three inbound
//! direct call sites, all plain unconditional `bl` at `0x08114808`,
//! `0x08116e14`, and `0x081a74cc`; there are no predicated `bl` call sites.
//! The body has no direct `bl` instruction and one unconditional indirect
//! `blx r3` through vtable slot `+0xdc`.
//!
//! # Algorithm
//!
//! Calls class-0x6000's vtable slot `+0xdc` as `(store, 0x60ac)` and returns
//! whether the result equals `0x602e`. Neither the property nor the virtual
//! method has an established semantic identity, so the symbol retains the
//! verified class, property, and comparison value.
//!
//! # Deliberate deviation
//!
//! Rust expresses the indirect `blx` as a typed call. This preserves the two
//! verified call arguments and boolean result; the stock prologue and epilogue
//! are otherwise not material to the ABI.

/// ARMv5TE vtable word index for byte offset `+0xdc`.
const PROPERTY_60AC_VTABLE_SLOT: usize = 0xdc / 4;
const PROPERTY_KEY_60AC: u32 = 0x60ac;
const PROPERTY_VALUE_602E: u32 = 0x602e;

/// ABI of the unrecovered class-0x6000 vtable slot `+0xdc`.
pub type Class6000Property60ac = unsafe extern "C" fn(*mut u8, u32) -> u32;

/// Returns whether class-0x6000's opaque property `0x60ac` is `0x602e`.
///
/// # Safety
///
/// `store` must designate an object with a readable vtable and a callable
/// slot-`+0xdc` method. RetailOS performs no NULL or bounds checks.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn class6000_property_60ac_is_602e(store: *mut u8) -> bool {
    let vtable = unsafe { (store as *const *const Class6000Property60ac).read() };
    let property = unsafe { vtable.add(PROPERTY_60AC_VTABLE_SLOT).read() };

    unsafe { property(store, PROPERTY_KEY_60AC) == PROPERTY_VALUE_602E }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

    static OBSERVED_STORE: AtomicUsize = AtomicUsize::new(0);
    static OBSERVED_KEY: AtomicU32 = AtomicU32::new(0);
    static PROPERTY_VALUE: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn property_60ac(store: *mut u8, property_key: u32) -> u32 {
        OBSERVED_STORE.store(store as usize, Ordering::Relaxed);
        OBSERVED_KEY.store(property_key, Ordering::Relaxed);
        PROPERTY_VALUE.load(Ordering::Relaxed)
    }

    #[test]
    fn compares_the_virtual_property_value_and_forwards_verified_arguments() {
        let vtable = [property_60ac as Class6000Property60ac; PROPERTY_60AC_VTABLE_SLOT + 1];
        let mut object = vtable.as_ptr();
        let store = core::ptr::addr_of_mut!(object).cast::<u8>();

        PROPERTY_VALUE.store(PROPERTY_VALUE_602E, Ordering::Relaxed);
        assert!(unsafe { class6000_property_60ac_is_602e(store) });
        assert_eq!(OBSERVED_STORE.load(Ordering::Relaxed), store as usize);
        assert_eq!(OBSERVED_KEY.load(Ordering::Relaxed), PROPERTY_KEY_60AC);

        PROPERTY_VALUE.store(PROPERTY_VALUE_602E + 1, Ordering::Relaxed);
        assert!(!unsafe { class6000_property_60ac_is_602e(store) });
    }
}
