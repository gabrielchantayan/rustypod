//! The 'plst' UI element's indexed secondary-slot item fetch.

use core::ptr;

use crate::ui::plst_class_check::ui_element_is_plst_class;
use crate::ui::plst_slot_item::ui_plst_slot_item_at;

const HEADER_LINK_OFFSET: usize = 0x40;
const HEADER_PRIMARY_COUNT_OFFSET: usize = 0x2c;
const HEADER_SECONDARY_COUNT_OFFSET: usize = 0x2e;
const SECONDARY_SLOT_TABLE_OFFSET: usize = 0x224;
const SLOT_ITEMS_OFFSET: usize = 0x10;

/// Exact ABI of the unported secondary-slot materializer at `0x080dc49c`.
pub type PlstSecondarySlotMaterialize = unsafe extern "C" fn(*mut u8, u32) -> i32;

/// Firmware load address of the secondary-slot materializer.
pub const PLST_SECONDARY_SLOT_MATERIALIZE_ADDRESS: usize = 0x080d_c49c;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_materialize_secondary_slot(element: *mut u8, selector: u32) -> i32 {
    core::mem::transmute::<usize, PlstSecondarySlotMaterialize>(PLST_SECONDARY_SLOT_MATERIALIZE_ADDRESS)(element, selector)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_materialize_secondary_slot(_element: *mut u8, _selector: u32) -> i32 {
    panic!("ui_plst_secondary_slot_item_at requires FUN_080dc49c")
}

/// Dispatch seam for the unported secondary-slot materializer.
#[cfg(target_os = "none")]
pub static mut PLST_SECONDARY_SLOT_MATERIALIZE: PlstSecondarySlotMaterialize = retail_materialize_secondary_slot;

/// Host-test dispatch seam for the unported secondary-slot materializer.
#[cfg(not(target_os = "none"))]
pub static mut PLST_SECONDARY_SLOT_MATERIALIZE: PlstSecondarySlotMaterialize = missing_materialize_secondary_slot;

#[inline(always)]
unsafe fn read_secondary_slot(element: *mut u8, selector: u32) -> *mut u8 {
    element
        .add(SECONDARY_SLOT_TABLE_OFFSET)
        .cast::<u32>()
        .add(selector as usize)
        .read() as usize as *mut u8
}

/// ui_plst_secondary_slot_item_at — original: `FUN_080527d4` @ `0x080527d4` (216 bytes).
///
/// Raw ARM decoded from `work/firmware/osos.dec` occupies
/// `0x080527d4..0x080528ac`; the next `mov r3,r0` at `0x080528ac` starts the
/// following function. The body has four direct, unconditional `bl` calls
/// (class check, primary fetch, selector normalizer, and secondary
/// materializer). Decoding all ARM B/BL words finds three inbound plain `bl`
/// calls and no predicated forms.
///
/// Algorithm: validate the 'plst' class, then dispatch to
/// [`ui_plst_slot_item_at`] when header+0x2c is zero. Otherwise, reject a zero
/// selector or `index >= header+0x2c + header+0x2e`; normalize the selector and
/// low byte of `reverse_flag`, reverse-index when requested, lazily materialize
/// the secondary slot at `element+0x224+selector*4`, and return its
/// `slot+0x10+index*4` word. Materializer status is deliberately discarded.
///
/// Deliberate deviations: the already-ported class check, primary fetch, and
/// selector normalizer are invoked by their Rust symbols. The still-unported
/// `FUN_080dc49c` remains a typed fixed-address seam on firmware and a required
/// host-test seam; its verified cache-population ABI is known, but no broader
/// identity is claimed.
///
/// # Safety
///
/// `element` may be NULL (the class check handles it). A non-NULL element must
/// be a readable 'plst' object with a readable header at +0x40. On the
/// secondary path, its normalized selector must address readable slot-table
/// words at +0x224; a non-NULL slot must be readable through +0x10+index*4+3.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ui_plst_secondary_slot_item_at")]
pub unsafe extern "C" fn ui_plst_secondary_slot_item_at(
    element: *mut u8,
    selector: u32,
    reverse_flag: u32,
    index: u32,
) -> u32 {
    if ui_element_is_plst_class(element) == 0 {
        return 0;
    }
    let header = element.add(HEADER_LINK_OFFSET).cast::<u32>().read() as usize as *const u8;
    let primary_count = u32::from(header.add(HEADER_PRIMARY_COUNT_OFFSET).cast::<u16>().read());
    if primary_count == 0 {
        return ui_plst_slot_item_at(element, selector, reverse_flag, index);
    }
    let secondary_count = u32::from(header.add(HEADER_SECONDARY_COUNT_OFFSET).cast::<u16>().read());
    if selector == 0 || index >= primary_count + secondary_count {
        return 0;
    }
    let mut selector = selector;
    let mut reverse_flag = reverse_flag as u8;
    crate::ui::plst_selector_normalize::normalize_plst_selector(element, &mut selector, &mut reverse_flag);
    let index = if reverse_flag != 0 {
        primary_count + secondary_count - index - 1
    } else {
        index
    };
    let mut slot = read_secondary_slot(element, selector);
    if slot.is_null() {
        let materialize = ptr::read_volatile(ptr::addr_of!(PLST_SECONDARY_SLOT_MATERIALIZE));
        materialize(element, selector);
        slot = read_secondary_slot(element, selector);
        if slot.is_null() {
            return 0;
        }
    }
    slot.add(SLOT_ITEMS_OFFSET).cast::<u32>().add(index as usize).read()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing;
    use parking_lot::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut MATERIALIZE_ELEMENT: *mut u8 = ptr::null_mut();
    static mut MATERIALIZE_SELECTOR: u32 = u32::MAX;
    static mut MATERIALIZE_SLOT: *mut u8 = ptr::null_mut();

    const HEADER_OFF: usize = 0;
    const ELEMENT_OFF: usize = 0x1000;
    const SLOT_OFF: usize = 0x2000;
    const SLAB_BYTES: usize = 0x10000;
    const PLST_TAG: u32 = 0x706c_7374;

    struct MaterializeGuard {
        previous: PlstSecondarySlotMaterialize,
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for MaterializeGuard {
        fn drop(&mut self) {
            unsafe { ptr::addr_of_mut!(PLST_SECONDARY_SLOT_MATERIALIZE).write_volatile(self.previous) }
        }
    }

    unsafe extern "C" fn materialize(element: *mut u8, selector: u32) -> i32 {
        MATERIALIZE_ELEMENT = element;
        MATERIALIZE_SELECTOR = selector;
        element.add(SECONDARY_SLOT_TABLE_OFFSET).cast::<u32>().add(selector as usize).write(MATERIALIZE_SLOT as usize as u32);
        0
    }

    unsafe fn install_materializer(slot: *mut u8) -> MaterializeGuard {
        let lock = TEST_LOCK.lock();
        let previous = ptr::read_volatile(ptr::addr_of!(PLST_SECONDARY_SLOT_MATERIALIZE));
        MATERIALIZE_ELEMENT = ptr::null_mut();
        MATERIALIZE_SELECTOR = u32::MAX;
        MATERIALIZE_SLOT = slot;
        ptr::addr_of_mut!(PLST_SECONDARY_SLOT_MATERIALIZE).write_volatile(materialize);
        MaterializeGuard { previous, _lock: lock }
    }

    unsafe fn fixture() -> Option<*mut u8> {
        testing::try_map_u32_slab(testing::hints::PLST_SECONDARY_SLOT_ITEM, SLAB_BYTES)
    }

    unsafe fn word(base: *mut u8, offset: usize, value: u32) {
        base.add(offset).cast::<u32>().write(value);
    }

    unsafe fn make_element(base: *mut u8, primary_count: u16, secondary_count: u16) -> (*mut u8, *mut u8) {
        let header = base.add(HEADER_OFF);
        let element = base.add(ELEMENT_OFF);
        word(element, 4, PLST_TAG);
        word(element, HEADER_LINK_OFFSET, header as usize as u32);
        header.add(HEADER_PRIMARY_COUNT_OFFSET).cast::<u16>().write(primary_count);
        header.add(HEADER_SECONDARY_COUNT_OFFSET).cast::<u16>().write(secondary_count);
        (element, header)
    }

    #[test]
    fn rejects_wrong_class_zero_selector_and_out_of_range_before_materializing() {
        let Some(base) = (unsafe { fixture() }) else { return };
        let slot = unsafe { base.add(SLOT_OFF) };
        let guard = unsafe { install_materializer(slot) };
        let (element, _) = unsafe { make_element(base, 2, 3) };
        unsafe {
            word(element, 4, 0x7464_6174);
            assert_eq!(ui_plst_secondary_slot_item_at(element, 6, 0, 0), 0);
            word(element, 4, PLST_TAG);
            assert_eq!(ui_plst_secondary_slot_item_at(element, 0, 0, 0), 0);
            assert_eq!(ui_plst_secondary_slot_item_at(element, 6, 0, 5), 0);
            assert!(MATERIALIZE_ELEMENT.is_null());
        }
        drop(guard);
    }

    #[test]
    fn materializes_secondary_slot_and_returns_requested_word() {
        let Some(base) = (unsafe { fixture() }) else { return };
        let slot = unsafe { base.add(SLOT_OFF) };
        let _guard = unsafe { install_materializer(slot) };
        let (element, _) = unsafe { make_element(base, 2, 3) };
        unsafe {
            word(slot, SLOT_ITEMS_OFFSET + 4 * 3, 0xa5a5_5a5a);
            assert_eq!(ui_plst_secondary_slot_item_at(element, 6, 0, 3), 0xa5a5_5a5a);
            assert_eq!(MATERIALIZE_ELEMENT, element);
            assert_eq!(MATERIALIZE_SELECTOR, 6);
        }
    }

    #[test]
    fn delegates_to_primary_slot_fetch_when_primary_count_is_zero() {
        let Some(base) = (unsafe { fixture() }) else { return };
        let (element, _) = unsafe { make_element(base, 0, 2) };
        let slot = unsafe { base.add(SLOT_OFF) };
        unsafe {
            word(element, 0x3ac + 6 * 4, slot as usize as u32);
            word(slot, SLOT_ITEMS_OFFSET + 4, 0x1234_5678);
            assert_eq!(ui_plst_secondary_slot_item_at(element, 6, 0, 1), 0x1234_5678);
        }
    }
}
