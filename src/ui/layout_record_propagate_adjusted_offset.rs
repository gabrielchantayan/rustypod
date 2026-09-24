//! Propagate a stock-adjusted coordinate delta between adjacent layout records.
//!
//! `layout_record_propagate_adjusted_offset` — original: `FUN_080d9660` @
//! 0x080d9660 (56 bytes; one plain direct `bl`, no predicated `bl` forms).
//!
//! Raw ARM decoded from `work/firmware/osos.dec` establishes the executable
//! extent `0x080d9660..0x080d9697`: the following `push` at 0x080d9698 starts
//! the next function. It subtracts the previous record's coordinate (+0x4)
//! from the current record's coordinate, passes that delta and both +0xc flag
//! bytes to stock helper 0x080db0d8, then stores previous offset (+0x8) plus
//! the adjusted delta into the current offset. The helper is deliberately an
//! unported call boundary; its exact policy is not assumed here. The Rust port
//! uses `wrapping_add`, matching A32 `add` without a signed-overflow trap.

use core::ptr;

const ADJUST_LAYOUT_DELTA_ADDRESS: usize = 0x080d_b0d8;
const RECORD_COORDINATE_OFFSET: usize = 0x4;
const RECORD_OFFSET_OFFSET: usize = 0x8;
const RECORD_FLAGS_OFFSET: usize = 0xc;

/// ABI of the stock layout-delta adjustment helper at 0x080db0d8.
pub type AdjustLayoutDelta = unsafe extern "C" fn(*mut u8, u32, i32, u32, u32) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_adjust_layout_delta(
    layout: *mut u8,
    selector: u32,
    delta: i32,
    previous_flags: u32,
    current_flags: u32,
) -> i32 {
    let adjust: AdjustLayoutDelta = unsafe { core::mem::transmute(ADJUST_LAYOUT_DELTA_ADDRESS) };
    unsafe { adjust(layout, selector, delta, previous_flags, current_flags) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_adjust_layout_delta(_: *mut u8, _: u32, _: i32, _: u32, _: u32) -> i32 {
    panic!("layout_record_propagate_adjusted_offset requires helper 0x080db0d8")
}

/// External call boundary for the still-stock delta-adjustment policy.
#[derive(Clone, Copy)]
pub struct LayoutRecordOffsetOps {
    pub adjust_delta: AdjustLayoutDelta,
}

pub const DEFAULT_LAYOUT_RECORD_OFFSET_OPS: LayoutRecordOffsetOps = LayoutRecordOffsetOps {
    #[cfg(target_os = "none")]
    adjust_delta: retail_adjust_layout_delta,
    #[cfg(not(target_os = "none"))]
    adjust_delta: missing_adjust_layout_delta,
};

pub static mut LAYOUT_RECORD_OFFSET_OPS: LayoutRecordOffsetOps = DEFAULT_LAYOUT_RECORD_OFFSET_OPS;

#[inline(always)]
fn layout_record_offset_ops() -> LayoutRecordOffsetOps {
    unsafe { ptr::read_volatile(ptr::addr_of!(LAYOUT_RECORD_OFFSET_OPS)) }
}

/// Applies the stock-adjusted coordinate gap to `current`'s offset.
///
/// `previous` and `current` must point to writable retail layout records with
/// words at +0x4/+0x8 and a byte at +0xc.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn layout_record_propagate_adjusted_offset(
    layout: *mut u8,
    selector: u32,
    previous: *mut u8,
    current: *mut u8,
) {
    let previous_coordinate = unsafe { (previous.add(RECORD_COORDINATE_OFFSET) as *const i32).read() };
    let current_coordinate = unsafe { (current.add(RECORD_COORDINATE_OFFSET) as *const i32).read() };
    let previous_flags = unsafe { previous.add(RECORD_FLAGS_OFFSET).read() };
    let current_flags = unsafe { current.add(RECORD_FLAGS_OFFSET).read() };
    let adjusted_delta = unsafe {
        (layout_record_offset_ops().adjust_delta)(
            layout,
            selector,
            current_coordinate.wrapping_sub(previous_coordinate),
            u32::from(previous_flags),
            u32::from(current_flags),
        )
    };
    let previous_offset = unsafe { (previous.add(RECORD_OFFSET_OFFSET) as *const i32).read() };
    unsafe { (current.add(RECORD_OFFSET_OFFSET) as *mut i32).write(previous_offset.wrapping_add(adjusted_delta)) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut SEEN: (*mut u8, u32, i32, u32, u32) = (ptr::null_mut(), 0, 0, 0, 0);

    unsafe extern "C" fn adjust_fixture(
        layout: *mut u8,
        selector: u32,
        delta: i32,
        previous_flags: u32,
        current_flags: u32,
    ) -> i32 {
        unsafe { SEEN = (layout, selector, delta, previous_flags, current_flags) };
        -7
    }

    #[repr(C)]
    struct LayoutRecord {
        unused: u32,
        coordinate: i32,
        offset: i32,
        flags: u8,
        padding: [u8; 3],
    }

    #[test]
    fn passes_byte_flags_and_stores_adjusted_delta_from_previous_offset() {
        let _lock = LOCK.lock();
        unsafe {
            LAYOUT_RECORD_OFFSET_OPS = LayoutRecordOffsetOps { adjust_delta: adjust_fixture };
            SEEN = (ptr::null_mut(), 0, 0, 0, 0);
        }
        let mut layout = [0u8; 1];
        let mut previous = LayoutRecord { unused: 0, coordinate: -20, offset: 100, flags: 0x81, padding: [0; 3] };
        let mut current = LayoutRecord { unused: 0, coordinate: 30, offset: 0, flags: 0xfe, padding: [0; 3] };
        unsafe { layout_record_propagate_adjusted_offset(layout.as_mut_ptr(), 1, (&mut previous as *mut LayoutRecord).cast(), (&mut current as *mut LayoutRecord).cast()) };
        let seen = unsafe { SEEN };
        assert_eq!((seen.0, seen.1, seen.2, seen.3, seen.4), (layout.as_mut_ptr(), 1, 50, 0x81, 0xfe));
        assert_eq!(current.offset, 93);
        unsafe { LAYOUT_RECORD_OFFSET_OPS = DEFAULT_LAYOUT_RECORD_OFFSET_OPS };
    }

    #[test]
    fn preserves_a32_wrapping_offset_addition() {
        let _lock = LOCK.lock();
        unsafe { LAYOUT_RECORD_OFFSET_OPS = LayoutRecordOffsetOps { adjust_delta: adjust_fixture } };
        let mut previous = LayoutRecord { unused: 0, coordinate: i32::MAX, offset: i32::MAX, flags: 0, padding: [0; 3] };
        let mut current = LayoutRecord { unused: 0, coordinate: i32::MIN, offset: 0, flags: 0, padding: [0; 3] };
        unsafe { layout_record_propagate_adjusted_offset(ptr::null_mut(), 0, (&mut previous as *mut LayoutRecord).cast(), (&mut current as *mut LayoutRecord).cast()) };
        assert_eq!(current.offset, i32::MAX - 7);
        unsafe { LAYOUT_RECORD_OFFSET_OPS = DEFAULT_LAYOUT_RECORD_OFFSET_OPS };
    }
}
