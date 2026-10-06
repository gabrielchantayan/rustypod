//! Centered grid-slot rendering — `FUN_0816b560` @ `0x0816b560`.
//!
//! Raw extent [0x0816b560, 0x0816b5b4), 84 bytes, ending before the next
//! function's push. Two incoming plain BLs (0x0816b078, 0x0816b9c8), zero
//! predicated incoming BLs; one outgoing plain BL (0x0816b59c), zero
//! predicated outgoing BLs. Snapshot columns (+0xb8), visible rows (+0xbc),
//! allocated rows (+0xc0), and first item (+0xe8). Render columns*allocated
//! rows slots from first item - trunc((allocated-visible)/2), incrementing
//! item and slot together. Arithmetic wraps at 32 bits; the loop uses a
//! signed comparison. No target deviations. The unported slot renderer is
//! called at its verified retail address; hosts must install a renderer.

pub type GridSlotRenderer = unsafe extern "C" fn(*mut i32, i32, i32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_renderer(_grid: *mut i32, _item: i32, _slot: i32) {
    panic!("install grid slot renderer for retail 0x0816b394")
}

#[cfg(not(target_os = "none"))]
pub static mut GRID_SLOT_RENDERER: GridSlotRenderer = missing_renderer;

/// Requires aligned, readable words through +0xe8 and a live grid accepted
/// by the retail slot renderer. Dimensions are snapshotted across callbacks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn grid_render_slots(grid: *mut i32) {
    let columns = grid.add(0xb8 / 4).read();
    let allocated_rows = grid.add(0xc0 / 4).read();
    let count = allocated_rows.wrapping_mul(columns);
    let visible_rows = grid.add(0xbc / 4).read();
    let difference = allocated_rows.wrapping_sub(visible_rows);
    let half = difference.wrapping_add(((difference as u32) >> 31) as i32) >> 1;
    let mut item = grid.add(0xe8 / 4).read().wrapping_sub(half);
    let mut slot = 0i32;
    while slot < count {
        #[cfg(target_os = "none")]
        let render: GridSlotRenderer = core::mem::transmute(0x0816_b394usize);
        #[cfg(not(target_os = "none"))]
        let render = core::ptr::addr_of!(GRID_SLOT_RENDERER).read_volatile();
        render(grid, item, slot);
        slot = slot.wrapping_add(1);
        item = item.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{cell::RefCell, vec::Vec};
    std::thread_local! { static ITEMS: RefCell<Vec<(i32, i32)>> = const { RefCell::new(Vec::new()) }; }

    unsafe extern "C" fn render(grid: *mut i32, item: i32, slot: i32) {
        ITEMS.with(|items| items.borrow_mut().push((item, slot)));
        // A real renderer can mutate the owner; iteration must use snapshots.
        grid.add(0xb8 / 4).write(0);
        grid.add(0xc0 / 4).write(0);
        grid.add(0xe8 / 4).write(999);
    }

    #[test]
    fn signed_dimensions_centering_wrap_and_callback_mutation() {
        let old = unsafe { GRID_SLOT_RENDERER };
        unsafe { GRID_SLOT_RENDERER = render; }
        struct Restore(GridSlotRenderer);
        impl Drop for Restore {
            fn drop(&mut self) { unsafe { GRID_SLOT_RENDERER = self.0; } }
        }
        let _restore = Restore(old);
        for (columns, allocated, visible, first, expected) in [
            (2, 3, 2, 10, std::vec![10, 11, 12, 13, 14, 15]),
            (1, 4, 1, 10, std::vec![9, 10, 11, 12]),
            (1, 2, 5, 10, std::vec![11, 12]),
            (1, 2, 2, i32::MAX, std::vec![i32::MAX, i32::MIN]),
            (0, 3, 1, 10, std::vec![]),
            (1, -2, 0, 10, std::vec![]),
            (i32::MAX, 2, 0, 10, std::vec![]),
            (-1, -2, -2, 10, std::vec![10, 11]),
            (1, 1, i32::MIN, 0, std::vec![1073741823]),
            (1, 1, -1, i32::MIN, std::vec![i32::MAX]),
        ] {
            let mut grid = [0i32; 0xec / 4];
            grid[0xb8 / 4] = columns;
            grid[0xbc / 4] = visible;
            grid[0xc0 / 4] = allocated;
            grid[0xe8 / 4] = first;
            ITEMS.with(|items| items.borrow_mut().clear());
            unsafe { grid_render_slots(grid.as_mut_ptr()); }
            let expected: Vec<_> = expected.into_iter().enumerate().map(|(slot, item)| (item, slot as i32)).collect();
            ITEMS.with(|items| assert_eq!(*items.borrow(), expected));
        }
    }
}
