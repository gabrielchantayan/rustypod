//! Reset a transient UI-element slot.
//!
//! `ui_element_reset_transient_slot` — original: `FUN_08146600` @
//! **0x08146600**, 72 bytes (`0x08146600..0x08146648`; the separately linked
//! constructor begins at `0x08146648`). Raw whole-image ARM B/BL decoding
//! finds exactly six direct call sites, all unconditional `bl` instructions
//! (`0x08144df8`, `0x08144ee4`, `0x08144ef0`, `0x08144efc`, `0x08144fb0`, and
//! `0x08145024`); there are no predicated calls or tail branches.
//!
//! # Algorithm
//!
//! Address the target-width slot at `element + slot * 4`. If its object handle
//! at `+0x10` is non-NULL, dispatch its vtable method at +0x04, then NULL the
//! handle. Set its state word at `+0x74` to -1 and clear its two byte flags at
//! `+0x88` and `+0x8d`. The concrete element and transient-object types remain
//! opaque; only this strided layout is established by the constructor at
//! `0x08146648` and the six callers.
//!
//! # Deliberate deviation
//!
//! None. The raw body inlines the vtable +0x04 call, so this port does the
//! same rather than adding a dispatch seam. Host fixtures keep the element
//! handle itself target-width (`u32`) and store native-width pointers only
//! inside the fixture object and vtable where the C++ dispatch reads them.

type VtableSlot04Method = unsafe extern "C" fn(object: *mut u8);

/// Resets the transient resource, state, and flags of one opaque UI-element slot.
///
/// # Safety
///
/// `element` must point to writable target-width element storage containing the
/// indexed slot. A non-NULL handle at `element + slot * 4 + 0x10` must name an
/// object accepted by its vtable +0x04 disposal method. The retail body makes
/// no bounds or NULL check for `element` itself.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_element_reset_transient_slot(element: *mut u8, slot: u32) {
    let slot_base = element.add((slot.wrapping_mul(4)) as usize);
    let handle = slot_base.add(0x10).cast::<u32>();

    let object = handle.read() as usize as *mut u8;
    if !object.is_null() {
        let vtable = (object as *const *const u8).read();
        #[cfg(target_os = "none")]
        let dispose = (vtable.cast::<u8>().add(4) as *const VtableSlot04Method).read();
        #[cfg(not(target_os = "none"))]
        let dispose =
            (vtable.cast::<u8>().add(4) as *const VtableSlot04Method).read_unaligned();
        dispose(object);
        handle.write(0);
    }

    slot_base.add(0x74).cast::<u32>().write(u32::MAX);
    element.add(slot.wrapping_add(0x88) as usize).write(0);
    element.add(slot.wrapping_add(0x8d) as usize).write(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut DISPOSE_CALLS: usize = 0;
    static mut DISPOSE_OBJECT: *mut u8 = core::ptr::null_mut();
    static mut HANDLE_AT_DISPOSE: *const u32 = core::ptr::null();

    static mut VTABLE: [u8; 16] = [0; 16];
    unsafe extern "C" fn dispose_object(object: *mut u8) {
        DISPOSE_CALLS += 1;
        DISPOSE_OBJECT = object;
        assert_eq!(HANDLE_AT_DISPOSE.read(), object as usize as u32);
    }

    #[test]
    fn resets_populated_and_empty_target_width_slots() {
        let _guard = TEST_LOCK.lock();
        let Some(element) = try_map_u32_slab(hints::UI_ELEMENT_SLOT_RESET, 0x200) else {
            assert!(note_missing_u32_fixture("ui/element_slot_reset"));
            return;
        };
        unsafe {
            let object = element.add(0x100);
            let vtable = core::ptr::addr_of_mut!(VTABLE).cast::<u8>();
            (vtable.add(4) as *mut unsafe extern "C" fn(*mut u8))
                .write_unaligned(dispose_object);
            object.cast::<*const u8>().write(vtable);

            let populated_slot = element.add(4 + 0x10).cast::<u32>();
            populated_slot.write(object as usize as u32);
            element.add(4 + 0x74).cast::<u32>().write(0x1234_5678);
            element.add(1 + 0x88).write(0xaa);
            element.add(1 + 0x8d).write(0xbb);
            DISPOSE_CALLS = 0;
            DISPOSE_OBJECT = core::ptr::null_mut();
            HANDLE_AT_DISPOSE = populated_slot;

            ui_element_reset_transient_slot(element, 1);

            assert_eq!(DISPOSE_CALLS, 1);
            assert_eq!(DISPOSE_OBJECT, object);
            assert_eq!(populated_slot.read(), 0);
            assert_eq!(element.add(4 + 0x74).cast::<u32>().read(), u32::MAX);
            assert_eq!(element.add(1 + 0x88).read(), 0);
            assert_eq!(element.add(1 + 0x8d).read(), 0);

            let empty_slot = element.add(8 + 0x10).cast::<u32>();
            empty_slot.write(0);
            element.add(8 + 0x74).cast::<u32>().write(0x8765_4321);
            element.add(2 + 0x88).write(0xcc);
            element.add(2 + 0x8d).write(0xdd);
            DISPOSE_CALLS = 0;

            ui_element_reset_transient_slot(element, 2);

            assert_eq!(DISPOSE_CALLS, 0);
            assert_eq!(empty_slot.read(), 0);
            assert_eq!(element.add(8 + 0x74).cast::<u32>().read(), u32::MAX);
            assert_eq!(element.add(2 + 0x88).read(), 0);
            assert_eq!(element.add(2 + 0x8d).read(), 0);
        }
    }
}
