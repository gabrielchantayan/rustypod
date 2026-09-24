//! `resource_slot_select_item` — original: `FUN_08066710` @ `0x08066710`.
//!
//! Raw `osos.dec` words establish the exact 44-byte extent
//! `0x08066710..0x0806673c`; the next function starts at `0x0806673c` with
//! `push {r4, lr}`. The body has one plain direct `bl` (`0x08052560`) and no
//! predicated direct `bl` instructions. Whole-image decoding finds three
//! incoming plain `bl` calls and no predicated incoming forms.
//!
//! For a resource slot index in `0..=3`, load its handle from the controller's
//! `+0xf7c` four-word handle table. A null handle leaves the matching `+0xf8c`
//! result word unchanged; otherwise select the requested item from the handle
//! and store that result. Deliberate deviation: host builds use a typed seam
//! for the still-retail item selector; ARM builds call it at `0x08052560`.

#[cfg(not(target_os = "none"))]
const HANDLE_TABLE_OFFSET: usize = 0xf7c;
#[cfg(not(target_os = "none"))]
const RESULT_TABLE_OFFSET: usize = 0xf8c;

type SelectItem = unsafe extern "C" fn(*mut u8, u32) -> *mut u8;

#[cfg(target_os = "none")]
core::arch::global_asm!(
    r#"
    .global resource_slot_select_item
    .type resource_slot_select_item,%function
resource_slot_select_item:
    cmp r1, #3
    stmdb sp!, {{r4, lr}}
    ldmhi sp!, {{r4, pc}}
    add r4, r0, r1, lsl #2
    ldr r0, [r4, #0xf7c]
    cmp r0, #0
    ldmeq sp!, {{r4, pc}}
    mov r1, r2
    bl 0x08052560
    str r0, [r4, #0xf8c]
    ldmia sp!, {{r4, pc}}
    .size resource_slot_select_item, . - resource_slot_select_item
"#
);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_select_item(_handle: *mut u8, _item_index: u32) -> *mut u8 {
    panic!("install resource-slot select-item host seam before calling this port")
}

/// Host replacement for retail item selector `FUN_08052560`.
#[cfg(not(target_os = "none"))]
pub static mut RESOURCE_SLOT_SELECT_ITEM: SelectItem = missing_select_item;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn select_item(handle: *mut u8, item_index: u32) -> *mut u8 {
    unsafe { RESOURCE_SLOT_SELECT_ITEM(handle, item_index) }
}

/// Selects `item_index` from a controller resource handle slot.
///
/// # Safety
/// `controller` must denote the retail controller layout through `+0xf9b`.
#[cfg(not(target_os = "none"))]
#[inline(never)]
pub unsafe extern "C" fn resource_slot_select_item(controller: *mut u8, slot_index: u32, item_index: u32) {
    if slot_index > 3 {
        return;
    }

    unsafe {
        let slot_offset = slot_index as usize * core::mem::size_of::<u32>();
        let handle = (controller.add(HANDLE_TABLE_OFFSET + slot_offset) as *const u32).read_volatile() as *mut u8;
        if handle.is_null() {
            return;
        }
        let item = select_item(handle, item_index);
        (controller.add(RESULT_TABLE_OFFSET + slot_offset) as *mut u32).write_volatile(item as u32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static SEEN_HANDLE: AtomicUsize = AtomicUsize::new(0);
    static SEEN_INDEX: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn select_fixture(handle: *mut u8, item_index: u32) -> *mut u8 {
        CALLS.fetch_add(1, Ordering::SeqCst);
        SEEN_HANDLE.store(handle as usize, Ordering::SeqCst);
        SEEN_INDEX.store(item_index as usize, Ordering::SeqCst);
        0x1234_5678 as *mut u8
    }

    fn reset() {
        CALLS.store(0, Ordering::SeqCst);
        SEEN_HANDLE.store(0, Ordering::SeqCst);
        SEEN_INDEX.store(0, Ordering::SeqCst);
    }

    #[test]
    fn selects_and_stores_the_requested_slot_item() {
        let _lock = TEST_LOCK.lock();
        let mut controller = [0u32; 1000];
        controller[(HANDLE_TABLE_OFFSET / 4) + 3] = 0x1020_3040;
        unsafe { RESOURCE_SLOT_SELECT_ITEM = select_fixture; }
        reset();

        unsafe { resource_slot_select_item(controller.as_mut_ptr() as *mut u8, 3, 17); }

        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(SEEN_HANDLE.load(Ordering::SeqCst), 0x1020_3040);
        assert_eq!(SEEN_INDEX.load(Ordering::SeqCst), 17);
        assert_eq!(controller[(RESULT_TABLE_OFFSET / 4) + 3], 0x1234_5678);
    }

    #[test]
    fn null_handle_and_out_of_range_slot_do_not_write_or_select() {
        let _lock = TEST_LOCK.lock();
        let mut controller = [0u32; 1000];
        controller[RESULT_TABLE_OFFSET / 4] = 0xa5a5_a5a5;
        unsafe { RESOURCE_SLOT_SELECT_ITEM = select_fixture; }
        reset();

        unsafe { resource_slot_select_item(controller.as_mut_ptr() as *mut u8, 0, 1); }
        unsafe { resource_slot_select_item(controller.as_mut_ptr() as *mut u8, 4, 2); }

        assert_eq!(CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(controller[RESULT_TABLE_OFFSET / 4], 0xa5a5_a5a5);
    }
}
