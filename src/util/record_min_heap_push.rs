//! `record_min_heap_push` — original: `FUN_083d9e28` @ `0x083d9e28`
//! (108 bytes; `0x083d9e28..0x083d9e93`).
//!
//! Raw A32 decoding finds two plain body `bl` instructions, to the unported
//! vector-growth helper at `0x083e5410` and `record_min_heap_sift_up` at
//! `0x083e7d7c`; it finds no predicated body `bl` instructions. The two inbound
//! plain direct-`bl` callers are `0x082621f0` and `0x08262450`.
//!
//! Appends one target-width record pointer to a three-word vector, growing the
//! storage when full, then restores binary min-heap order by sifting the new
//! final element upward with the comparator word at vector +0x0c.
//!
//! # Deliberate deviations
//!
//! Rust uses word indexing for the target's `lsl #2` offsets. The unported
//! growth helper is a target-address call on firmware and a replaceable host
//! seam; the existing sift-up port is likewise dispatched through a seam here.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

type RecordVectorGrowAndInsert = unsafe extern "C" fn(*mut u32, *mut u32, *const u32);
type RecordMinHeapSiftUp = unsafe extern "C" fn(*mut u32, i32, i32, u32, u32);

const RETAIL_RECORD_VECTOR_GROW_AND_INSERT: usize = 0x083e_5410;
const RETAIL_RECORD_MIN_HEAP_SIFT_UP: usize = 0x083e_7d7c;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_record_vector_grow_and_insert(_: *mut u32, _: *mut u32, _: *const u32) {
    panic!("install record-vector growth helper before host use")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_record_min_heap_sift_up(_: *mut u32, _: i32, _: i32, _: u32, _: u32) {
    panic!("install record-min-heap sift-up before host use")
}

#[cfg(not(target_os = "none"))]
pub static mut RECORD_MIN_HEAP_PUSH_OPS: RecordMinHeapPushOps = RecordMinHeapPushOps {
    record_vector_grow_and_insert: missing_record_vector_grow_and_insert,
    record_min_heap_sift_up: missing_record_min_heap_sift_up,
};

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct RecordMinHeapPushOps {
    pub record_vector_grow_and_insert: RecordVectorGrowAndInsert,
    pub record_min_heap_sift_up: RecordMinHeapSiftUp,
}

#[inline(always)]
unsafe fn record_vector_grow_and_insert(vector: *mut u32, end: *mut u32, value: *const u32) {
    #[cfg(target_os = "none")]
    {
        let helper: RecordVectorGrowAndInsert = unsafe { core::mem::transmute(RETAIL_RECORD_VECTOR_GROW_AND_INSERT) };
        unsafe { helper(vector, end, value) };
    }
    #[cfg(not(target_os = "none"))]
    {
        let helper = unsafe { core::ptr::read_volatile(addr_of!(RECORD_MIN_HEAP_PUSH_OPS.record_vector_grow_and_insert)) };
        unsafe { helper(vector, end, value) };
    }
}

#[inline(always)]
unsafe fn record_min_heap_sift_up(heap: *mut u32, child_index: i32, value: u32, comparator: u32) {
    #[cfg(target_os = "none")]
    {
        let helper: RecordMinHeapSiftUp = unsafe { core::mem::transmute(RETAIL_RECORD_MIN_HEAP_SIFT_UP) };
        unsafe { helper(heap, child_index, 0, value, comparator) };
    }
    #[cfg(not(target_os = "none"))]
    {
        let helper = unsafe { core::ptr::read_volatile(addr_of!(RECORD_MIN_HEAP_PUSH_OPS.record_min_heap_sift_up)) };
        unsafe { helper(heap, child_index, 0, value, comparator) };
    }
}

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_min_heap_push(vector: *mut u32, value: *const u32) {
    let end = unsafe { vector.add(1).read() as usize as *mut u32 };
    let capacity = unsafe { vector.add(2).read() as usize as *mut u32 };
    if end == capacity {
        unsafe { record_vector_grow_and_insert(vector, end, value) };
    } else {
        unsafe { vector.add(1).write(end.add(1) as usize as u32) };
        if !end.is_null() {
            unsafe { end.write(value.read()) };
        }
    }

    let heap = unsafe { vector.read() as usize as *mut u32 };
    let end = unsafe { vector.add(1).read() as usize as *mut u32 };
    if heap != end {
        let value = unsafe { end.sub(1).read() };
        let child_index = unsafe { end.offset_from(heap) as i32 - 1 };
        let comparator = unsafe { vector.add(3).read() };
        unsafe { record_min_heap_sift_up(heap, child_index, value, comparator) };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut GROW_STORAGE: *mut u32 = core::ptr::null_mut();
    static mut GROW_VALUE: u32 = 0;
    static mut SIFT_ARGS: (*mut u32, i32, i32, u32, u32) = (core::ptr::null_mut(), 0, 0, 0, 0);

    unsafe extern "C" fn grow(vector: *mut u32, _: *mut u32, value: *const u32) {
        unsafe {
            GROW_STORAGE.write(value.read());
            vector.write(GROW_STORAGE as usize as u32);
            vector.add(1).write(GROW_STORAGE.add(1) as usize as u32);
            vector.add(2).write(GROW_STORAGE.add(4) as usize as u32);
            GROW_VALUE = value.read();
        }
    }

    unsafe extern "C" fn sift(heap: *mut u32, child: i32, start: i32, value: u32, comparator: u32) {
        unsafe { SIFT_ARGS = (heap, child, start, value, comparator) };
    }

    #[test]
    fn appends_when_capacity_remains_and_grows_at_capacity() {
        let _lock = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(slab) = try_map_u32_slab(hints::RECORD_MIN_HEAP_PUSH, 4096) else {
            assert!(note_missing_u32_fixture("util/record_min_heap_push"));
            return;
        };
        let vector = slab.cast::<u32>();
        let storage = unsafe { vector.add(16) };
        let value = unsafe { vector.add(32) };
        unsafe {
            value.write(0x1122_3344);
            vector.write(storage as usize as u32);
            vector.add(1).write(storage as usize as u32);
            vector.add(2).write(storage.add(4) as usize as u32);
            vector.add(3).write(0xaabb_ccdd);
            GROW_STORAGE = storage.add(8);
            let previous = core::ptr::read_volatile(addr_of!(RECORD_MIN_HEAP_PUSH_OPS));
            core::ptr::write_volatile(addr_of_mut!(RECORD_MIN_HEAP_PUSH_OPS), RecordMinHeapPushOps { record_vector_grow_and_insert: grow, record_min_heap_sift_up: sift });
            record_min_heap_push(vector, value);
            assert_eq!(storage.read(), 0x1122_3344);
            assert_eq!(SIFT_ARGS, (storage, 0, 0, 0x1122_3344, 0xaabb_ccdd));
            vector.add(1).write(storage.add(4) as usize as u32);
            value.write(0x5566_7788);
            record_min_heap_push(vector, value);
            assert_eq!(GROW_VALUE, 0x5566_7788);
            assert_eq!(SIFT_ARGS, (GROW_STORAGE, 0, 0, 0x5566_7788, 0xaabb_ccdd));
            core::ptr::write_volatile(addr_of_mut!(RECORD_MIN_HEAP_PUSH_OPS), previous);
        }
    }
}
