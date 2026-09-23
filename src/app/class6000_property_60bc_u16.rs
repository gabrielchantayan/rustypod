//! `class6000_property_60bc_u16` — original: `FUN_08172c44` @ `0x08172c44`
//! (36 bytes; nine ARM instruction words through `0x08172c64`). The next real
//! function begins at `0x08172c68`.
//!
//! Decoding all immediate ARM `B`/`BL` words in `osos.dec` finds three inbound
//! direct call sites, all plain unconditional `bl` at `0x08223010`,
//! `0x08226c90`, and `0x082395ac`; there are no predicated `bl` call sites.
//! The body itself has one indirect `blx r3` through vtable slot `+0xdc`.
//!
//! # Algorithm
//!
//! Dispatches class-0x6000's vtable slot `+0xdc` as
//! `(store, 0x60bc, 0x6000, slot_address)`, then zero-extends its low-sixteen-bit
//! result. The property and virtual method have no established semantic identity,
//! so their verified class and literal identify this port.
//!
//! # Deliberate deviation
//!
//! Rust expresses the indirect `blx` as a typed call. It preserves all four
//! virtual-call arguments and the low-sixteen-bit return value; the stock
//! prologue/epilogue is otherwise not material to the ABI.

/// ARMv5TE vtable word index for byte offset `+0xdc`.
const PROPERTY_60BC_VTABLE_SLOT: usize = 0xdc / 4;
const PROPERTY_KEY_60BC: u32 = 0x60bc;
const CLASS_ID_6000: u32 = 0x6000;

/// ABI of the unrecovered class-0x6000 vtable slot `+0xdc`.
pub type Class6000Property60bc = unsafe extern "C" fn(*mut u8, u32, u32, usize) -> u32;

/// Calls class-0x6000's opaque property `0x60bc` virtual method.
///
/// # Safety
///
/// `store` must designate an object with a readable vtable and a callable
/// slot-`+0xdc` method. RetailOS performs no NULL or bounds checks.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn class6000_property_60bc_u16(store: *mut u8) -> u16 {
    let vtable = unsafe { (store as *const *const Class6000Property60bc).read() };
    let property = unsafe { vtable.add(PROPERTY_60BC_VTABLE_SLOT).read() };

    unsafe { property(store, PROPERTY_KEY_60BC, CLASS_ID_6000, property as usize) as u16 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

    static OBSERVED_KEY: AtomicU32 = AtomicU32::new(0);
    static OBSERVED_CLASS: AtomicU32 = AtomicU32::new(0);
    static OBSERVED_SLOT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn property_60bc(
        _store: *mut u8,
        property_key: u32,
        class_id: u32,
        slot_address: usize,
    ) -> u32 {
        OBSERVED_KEY.store(property_key, Ordering::Relaxed);
        OBSERVED_CLASS.store(class_id, Ordering::Relaxed);
        OBSERVED_SLOT.store(slot_address, Ordering::Relaxed);
        0xa5a5_beef
    }

    #[test]
    fn dispatches_slot_dc_with_verified_arguments_and_u16_result() {
        let vtable = [property_60bc as Class6000Property60bc; PROPERTY_60BC_VTABLE_SLOT + 1];
        let mut object = vtable.as_ptr();
        let result = unsafe { class6000_property_60bc_u16(core::ptr::addr_of_mut!(object).cast()) };

        assert_eq!(result, 0xbeef);
        assert_eq!(OBSERVED_KEY.load(Ordering::Relaxed), PROPERTY_KEY_60BC);
        assert_eq!(OBSERVED_CLASS.load(Ordering::Relaxed), CLASS_ID_6000);
        assert_eq!(
            OBSERVED_SLOT.load(Ordering::Relaxed),
            property_60bc as Class6000Property60bc as usize
        );
    }
}
