//! `record_min_heap_pop_adjust` — original: `FUN_083e7d4c` @ `0x083e7d4c`
//! (48 bytes; `0x083e7d4c..0x083e7d7b`).
//!
//! Raw A32 decoding finds one plain body `bl` (`record_min_heap_sift_down` at
//! `0x083e7f40`) and no predicated body `bl` instructions. The two inbound
//! plain direct-BL callers are `0x083e8220` and `0x083e825c`.
//!
//! Moves the root record to `output`, then sifts `value` down through the
//! `[heap, last)` binary min-heap using its supplied comparator.
//!
//! # Deliberate deviations
//!
//! Rust obtains the record count with typed pointer subtraction rather than
//! the original byte subtraction and `lsr #2`. The unported sift-down helper
//! is a target-address call on firmware and a replaceable host seam for tests.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

type RecordComparator = unsafe extern "C" fn(u32, u32) -> i32;
type RecordMinHeapSiftDown = unsafe extern "C" fn(*mut u32, i32, i32, u32, RecordComparator);

const RETAIL_RECORD_MIN_HEAP_SIFT_DOWN: usize = 0x083e_7f40;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_record_min_heap_sift_down(
    _: *mut u32,
    _: i32,
    _: i32,
    _: u32,
    _: RecordComparator,
) {
    panic!("install record-min-heap sift-down before host use")
}

#[cfg(not(target_os = "none"))]
pub static mut RECORD_MIN_HEAP_POP_ADJUST_OPS: RecordMinHeapPopAdjustOps = RecordMinHeapPopAdjustOps {
    record_min_heap_sift_down: missing_record_min_heap_sift_down,
};

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct RecordMinHeapPopAdjustOps {
    pub record_min_heap_sift_down: RecordMinHeapSiftDown,
}

#[inline(always)]
unsafe fn record_min_heap_sift_down(
    heap: *mut u32,
    record_count: i32,
    value: u32,
    comparator: RecordComparator,
) {
    #[cfg(target_os = "none")]
    {
        let sift_down: RecordMinHeapSiftDown = unsafe { core::mem::transmute(RETAIL_RECORD_MIN_HEAP_SIFT_DOWN) };
        unsafe { sift_down(heap, 0, record_count, value, comparator) };
    }

    #[cfg(not(target_os = "none"))]
    {
        let sift_down = unsafe {
            core::ptr::read_volatile(addr_of!(RECORD_MIN_HEAP_POP_ADJUST_OPS.record_min_heap_sift_down))
        };
        unsafe { sift_down(heap, 0, record_count, value, comparator) };
    }
}

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_min_heap_pop_adjust(
    heap: *mut u32,
    last: *mut u32,
    output: *mut u32,
    value: u32,
    comparator: RecordComparator,
) {
    unsafe { output.write(heap.read()) };
    let record_count = unsafe { last.offset_from(heap) as i32 };
    unsafe { record_min_heap_sift_down(heap, record_count, value, comparator) };
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut CAPTURED: (*mut u32, i32, i32, u32) = (core::ptr::null_mut(), -1, -1, 0);

    unsafe extern "C" fn comparator(left: u32, right: u32) -> i32 {
        left.cmp(&right) as i32
    }

    unsafe extern "C" fn sift_down(
        heap: *mut u32,
        hole_index: i32,
        record_count: i32,
        value: u32,
        _: RecordComparator,
    ) {
        unsafe {
            CAPTURED = (heap, hole_index, record_count, value);
            heap.write(value);
        }
    }

    #[test]
    fn moves_root_to_output_and_adjusts_the_full_range() {
        let _lock = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut heap = [3, 7, 11, 13];
        let mut output = 0;
        unsafe {
            let previous = core::ptr::read_volatile(addr_of!(RECORD_MIN_HEAP_POP_ADJUST_OPS));
            core::ptr::write_volatile(
                addr_of_mut!(RECORD_MIN_HEAP_POP_ADJUST_OPS),
                RecordMinHeapPopAdjustOps { record_min_heap_sift_down: sift_down },
            );
            record_min_heap_pop_adjust(heap.as_mut_ptr(), heap.as_mut_ptr().add(4), &mut output, 19, comparator);
            assert_eq!(output, 3);
            assert_eq!(heap[0], 19);
            assert_eq!(CAPTURED, (heap.as_mut_ptr(), 0, 4, 19));
            core::ptr::write_volatile(addr_of_mut!(RECORD_MIN_HEAP_POP_ADJUST_OPS), previous);
        }
    }

    #[test]
    fn preserves_zero_length_adjustment_for_the_sift_down_helper() {
        let _lock = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut heap = [41];
        let mut output = 0;
        unsafe {
            let previous = core::ptr::read_volatile(addr_of!(RECORD_MIN_HEAP_POP_ADJUST_OPS));
            core::ptr::write_volatile(
                addr_of_mut!(RECORD_MIN_HEAP_POP_ADJUST_OPS),
                RecordMinHeapPopAdjustOps { record_min_heap_sift_down: sift_down },
            );
            record_min_heap_pop_adjust(heap.as_mut_ptr(), heap.as_mut_ptr(), &mut output, 2, comparator);
            assert_eq!(output, 41);
            assert_eq!(CAPTURED, (heap.as_mut_ptr(), 0, 0, 2));
            core::ptr::write_volatile(addr_of_mut!(RECORD_MIN_HEAP_POP_ADJUST_OPS), previous);
        }
    }
}
