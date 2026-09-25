//! Clone a normalized 'plst' slot source.
//!
//! `clone_plst_slot_source` is `FUN_08047804` @ `0x08047804` (64 bytes).
//! Raw ARM words establish the exact extent: `push {r0-r11,lr}` at
//! `0x08047844` begins the next function. It has three incoming plain `bl`
//! calls (`0x0806d1ec`, `0x0806d294`, and `0x080be2c0`), no predicated calls,
//! and makes three plain `bl` calls.

use crate::ui::clone_slot_source::clone_slot_source;
use crate::ui::plst_selector_normalize::normalize_plst_selector;
use crate::ui::plst_slot_materialize::materialize_plst_slot;

const SLOT_TABLE_OFFSET: usize = 0x3ac;

type NormalizeSelector = unsafe extern "C" fn(*mut u8, *mut u32, *mut u8);
type MaterializeSlot = unsafe extern "C" fn(*mut u8, u32) -> u32;
type CloneSource = unsafe extern "C" fn(*mut u8) -> *mut u8;

#[inline(always)]
unsafe fn clone_plst_slot_source_with(
    element: *mut u8,
    mut selector: u32,
    normalize_selector: NormalizeSelector,
    materialize_slot: MaterializeSlot,
    clone_source: CloneSource,
) -> *mut u8 {
    normalize_selector(element, &mut selector, core::ptr::null_mut());
    if materialize_slot(element, selector) != 0 {
        return core::ptr::null_mut();
    }
    let source = element.add(SLOT_TABLE_OFFSET + selector as usize * 4).cast::<u32>().read()
        as usize as *mut u8;
    clone_source(source)
}

/// clone_plst_slot_source — original: `FUN_08047804` @ `0x08047804` (64 bytes).
///
/// Raw ARM decoded from `work/firmware/osos.dec` covers
/// `0x08047804..0x08047844`; `0x08047844` is the next function's `push`
/// prologue. Decoding every ARM B/BL instruction finds exactly three inbound
/// plain `bl` calls and zero predicated forms; its body makes three plain `bl`
/// calls to `normalize_plst_selector`, `materialize_plst_slot`, and
/// `clone_slot_source`.
///
/// Algorithm: normalize `selector` with a NULL reverse-flag pointer, then
/// materialize its slot. A nonzero materialization status returns NULL.
/// Otherwise clone the source pointer at `element + 0x3ac + selector * 4`.
///
/// Deliberate deviations: Rust represents the ARM stack-local selector and
/// register save/restore with local variables and ABI code. The three verified
/// callees use their existing named Rust ports instead of stock addresses.
///
/// # Safety
///
/// `element` must satisfy the normalizer and materializer contracts. When the
/// materializer succeeds, `element + 0x3ac + selector * 4` must be a readable,
/// aligned target-width pointer field; its non-NULL value must satisfy
/// [`clone_slot_source`]'s contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.clone_plst_slot_source")]
pub unsafe extern "C" fn clone_plst_slot_source(element: *mut u8, selector: u32) -> *mut u8 {
    clone_plst_slot_source_with(
        element,
        selector,
        normalize_plst_selector,
        materialize_plst_slot,
        clone_slot_source,
    )
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use core::ptr;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut NORMALIZED_SELECTOR: u32 = 0;
    static mut MATERIALIZE_STATUS: u32 = 0;
    static mut MATERIALIZE_CALLS: usize = 0;
    static mut CLONED_SOURCE: *mut u8 = ptr::null_mut();
    static mut CLONE_CALLS: usize = 0;
    static mut CLONE_RESULT: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn normalize(_: *mut u8, selector: *mut u32, reverse_flag: *mut u8) {
        assert!(reverse_flag.is_null());
        selector.write(NORMALIZED_SELECTOR);
    }

    unsafe extern "C" fn materialize(_: *mut u8, selector: u32) -> u32 {
        assert_eq!(selector, NORMALIZED_SELECTOR);
        MATERIALIZE_CALLS += 1;
        MATERIALIZE_STATUS
    }

    unsafe extern "C" fn clone(source: *mut u8) -> *mut u8 {
        CLONE_CALLS += 1;
        CLONED_SOURCE = source;
        CLONE_RESULT
    }

    unsafe fn reset() {
        NORMALIZED_SELECTOR = 0;
        MATERIALIZE_STATUS = 0;
        MATERIALIZE_CALLS = 0;
        CLONED_SOURCE = ptr::null_mut();
        CLONE_CALLS = 0;
        CLONE_RESULT = ptr::null_mut();
    }

    fn fixture() -> Option<*mut u8> {
        let element = try_map_u32_slab(hints::PLST_SLOT_SOURCE_CLONE, 0x500)?;
        unsafe { element.write_bytes(0, 0x500) };
        Some(element)
    }

    #[test]
    fn normalizes_materializes_and_clones_the_normalized_slot_source() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(element) = fixture() else { return };
        unsafe {
            reset();
            NORMALIZED_SELECTOR = 2;
            let source = element.add(0x480);
            let clone_result = element.add(0x490);
            element.add(SLOT_TABLE_OFFSET + 2 * 4).cast::<u32>().write(source as u32);
            CLONE_RESULT = clone_result;
            assert_eq!(
                clone_plst_slot_source_with(element, 0x34, normalize, materialize, clone),
                clone_result
            );
            assert_eq!(MATERIALIZE_CALLS, 1);
            assert_eq!(CLONE_CALLS, 1);
            assert_eq!(CLONED_SOURCE, source);
        }
    }

    #[test]
    fn materialization_failure_skips_slot_load_and_clone() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(element) = fixture() else { return };
        unsafe {
            reset();
            NORMALIZED_SELECTOR = 1;
            MATERIALIZE_STATUS = 0xffff_ffce;
            assert!(clone_plst_slot_source_with(element, 1, normalize, materialize, clone).is_null());
            assert_eq!(MATERIALIZE_CALLS, 1);
            assert_eq!(CLONE_CALLS, 0);
        }
    }

    #[test]
    fn successful_materialization_passes_a_null_slot_to_the_clone_callee() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(element) = fixture() else { return };
        unsafe {
            reset();
            NORMALIZED_SELECTOR = 3;
            assert!(clone_plst_slot_source_with(element, 3, normalize, materialize, clone).is_null());
            assert_eq!(MATERIALIZE_CALLS, 1);
            assert_eq!(CLONE_CALLS, 1);
            assert!(CLONED_SOURCE.is_null());
        }
    }
}
