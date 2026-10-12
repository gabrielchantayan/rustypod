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
//! and store that result. Both builds call the canonical Rust
//! `image_library_entry_at` port.

#[cfg(not(target_os = "none"))]
const HANDLE_TABLE_OFFSET: usize = 0xf7c;
#[cfg(not(target_os = "none"))]
const RESULT_TABLE_OFFSET: usize = 0xf8c;

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
    bl image_library_entry_at
    str r0, [r4, #0xf8c]
    ldmia sp!, {{r4, pc}}
    .size resource_slot_select_item, . - resource_slot_select_item
"#
);

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
        let item = crate::app::image_library_entry_at::image_library_entry_at(handle, item_index);
        (controller.add(RESULT_TABLE_OFFSET + slot_offset) as *mut u32).write_volatile(item);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn null_handle_and_out_of_range_slot_leave_results_unchanged() {
        let mut controller = [0u32; 1000];
        controller[RESULT_TABLE_OFFSET / 4] = 0xa5a5_a5a5;
        unsafe { resource_slot_select_item(controller.as_mut_ptr().cast(), 0, 1); }
        unsafe { resource_slot_select_item(controller.as_mut_ptr().cast(), 4, 2); }
        assert_eq!(controller[RESULT_TABLE_OFFSET / 4], 0xa5a5_a5a5);
    }
}
