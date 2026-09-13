//! Lazy materialization of one 'plst' element slot.
//!
//! `materialize_plst_slot` is `FUN_080df1b8` @ `0x080df1b8` (212 instruction
//! bytes, followed by its callback literal at `0x080df28c`; the next function
//! begins at `0x080df290`). Decoding every ARM B/BL word in `osos.dec` finds
//! seven incoming direct calls: seven plain `bl`, zero predicated forms, and
//! no tail branches.
//!
//! The element has a 49-word slot table at `+0x3ac`. Slot one is materialized
//! as a 20-byte record `{ unknown, count, byte_len, completed_count, ... }`;
//! a resource callback fills its items and completion count. Other slots first
//! materialize slot one, then clone the element's `+0x3b0` source buffer and
//! hand that clone to an unported population routine.

use crate::app::resource::cache::resource_callback_dispatch;
use crate::heap::veneers::{free_tag4, malloc_tag4};

const SLOT_COUNT: u32 = 49;
const SLOT_TABLE_WORD: usize = 0xeb;
const SLOT_SOURCE_WORD: usize = 0xec;
const HEADER_LINK_WORD: usize = 0x10;
const HEADER_ITEM_COUNT_OFFSET: usize = 0x2e;
const SLOT_RECORD_SIZE: usize = 0x14;
const SLOT_COUNT_WORD: usize = 1;
const SLOT_BYTES_WORD: usize = 2;
const SLOT_COMPLETED_COUNT_WORD: usize = 3;
const BUFFER_SIZE_WORD: usize = 2;
const SLOT_ONE_CALLBACK: usize = 0x080d_9250;
const POPULATE_SLOT_ADDRESS: usize = 0x0809_ef6c;
const INVALID_SELECTOR: u32 = 0xffff_ffce;
const OUT_OF_MEMORY: u32 = 0xffff_ff94;

/// ABI of the unported slot population routine at `0x0809ef6c`.
pub type PlstPopulateSlot = unsafe extern "C" fn(element: *mut u8, slot: *mut u8, selector: u32);
/// ABI of the already ported resource-callback dispatcher.
pub type PlstSlotCallbackDispatch =
    unsafe extern "C" fn(root: *mut u8, callback: usize, context: *mut u8) -> i32;
/// Allocator ABI shared by the MemH/tag-4 buffer family.
pub type PlstSlotAllocate = unsafe extern "C" fn(size: usize) -> *mut u8;
/// Deallocator ABI shared by the MemH/tag-4 buffer family.
pub type PlstSlotFree = unsafe extern "C" fn(ptr: *mut u8);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_populate_slot(element: *mut u8, slot: *mut u8, selector: u32) {
    let populate: PlstPopulateSlot = core::mem::transmute(POPULATE_SLOT_ADDRESS);
    populate(element, slot, selector)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_allocate(size: usize) -> *mut u8 {
    malloc_tag4(size)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_free(ptr: *mut u8) {
    free_tag4(ptr)
}

/// Host defaults preserve the target-width object layout without fabricating
/// heap addresses that cannot round-trip through a slot-table `u32`.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_allocate(_size: usize) -> *mut u8 {
    core::ptr::null_mut()
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_free(_ptr: *mut u8) {}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_populate_slot(_element: *mut u8, _slot: *mut u8, _selector: u32) {
    panic!("materialize_plst_slot requires population routine 0x0809ef6c")
}

/// External boundaries of this one-function port. Target builds use the
/// ported MemH and resource dispatchers plus the remaining stock population
/// routine; host tests install target-width recording fixtures.
#[derive(Clone, Copy)]
pub struct PlstSlotMaterializeOps {
    pub callback_dispatch: PlstSlotCallbackDispatch,
    pub allocate: PlstSlotAllocate,
    pub free: PlstSlotFree,
    pub populate: PlstPopulateSlot,
}

pub const DEFAULT_PLST_SLOT_MATERIALIZE_OPS: PlstSlotMaterializeOps = PlstSlotMaterializeOps {
    callback_dispatch: resource_callback_dispatch,
    #[cfg(target_os = "none")]
    allocate: firmware_allocate,
    #[cfg(not(target_os = "none"))]
    allocate: host_allocate,
    #[cfg(target_os = "none")]
    free: firmware_free,
    #[cfg(not(target_os = "none"))]
    free: host_free,
    #[cfg(target_os = "none")]
    populate: firmware_populate_slot,
    #[cfg(not(target_os = "none"))]
    populate: host_populate_slot,
};

/// Active external boundary. Tests replace it to drive resource completion,
/// allocation failure, and the unported population routine deterministically.
pub static mut PLST_SLOT_MATERIALIZE_OPS: PlstSlotMaterializeOps = DEFAULT_PLST_SLOT_MATERIALIZE_OPS;

#[inline(always)]
fn materialize_ops() -> PlstSlotMaterializeOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(PLST_SLOT_MATERIALIZE_OPS)) }
}

#[inline(always)]
unsafe fn read_target_word(base: *mut u8, word: usize) -> u32 {
    base.cast::<u32>().add(word).read()
}

#[inline(always)]
unsafe fn write_target_word(base: *mut u8, word: usize, value: u32) {
    base.cast::<u32>().add(word).write(value);
}

#[inline(always)]
unsafe fn read_slot(element: *mut u8, selector: u32) -> *mut u8 {
    read_target_word(element, SLOT_TABLE_WORD + selector as usize) as usize as *mut u8
}

#[inline(always)]
unsafe fn write_slot(element: *mut u8, selector: u32, slot: *mut u8) {
    write_target_word(element, SLOT_TABLE_WORD + selector as usize, slot as u32);
}

/// materialize_plst_slot — original: `FUN_080df1b8` @ `0x080df1b8` (212
/// instruction bytes; its `0x080df28c` callback literal makes the complete
/// text/data extent end at `0x080df290`).
///
/// Rejects selectors >=49 with `-50`. A non-NULL cached slot succeeds without
/// invoking any callee. Selector one allocates a 20-byte record, stores the
/// header count and `count * 4`, dispatches callback `0x080d9250` through the
/// element's resource root, and retains the record only when its `+0x0c`
/// completion count equals `+0x04`. Other selectors recursively materialize
/// slot one, clone the non-NULL `+0x3b0` source buffer, call stock
/// `0x0809ef6c(element, clone, selector)`, then cache that clone.
///
/// Incoming calls are all unconditional: raw decoding finds exactly seven
/// plain `bl` calls and no predicated `bl` forms. The function has no NULL or
/// alignment guard for an in-range `element`, just as the retail ARM does.
///
/// Deliberate deviations: `FUN_080d8cac` and `FUN_080da6a0` are folded into
/// their recovered allocation/initialization sequences using the already
/// ported tag-4 allocator. The remaining unported `0x0809ef6c` population
/// routine is an explicit target seam. The source copy is a volatile byte
/// loop rather than the stock generic-copy dispatch; it preserves the copied
/// bytes and avoids an ARM libc memcpy substitution.
///
/// # Safety
///
/// For selectors below 49, `element` must point to a writable object with
/// readable `+0x40`, `+0x3ac..+0x470`, and `+0x3b0` fields. Its header link
/// and source buffer pointers must be valid when their respective paths are
/// reached. The callback and population routine retain the firmware's raw
/// pointer contracts.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.materialize_plst_slot")]
pub unsafe extern "C" fn materialize_plst_slot(element: *mut u8, selector: u32) -> u32 {
    if selector >= SLOT_COUNT {
        return INVALID_SELECTOR;
    }
    if !read_slot(element, selector).is_null() {
        return 0;
    }

    let ops = materialize_ops();
    let slot = if selector == 1 {
        let header = read_target_word(element, HEADER_LINK_WORD) as usize as *mut u8;
        let count = header.add(HEADER_ITEM_COUNT_OFFSET).cast::<u16>().read() as u32;
        let slot = (ops.allocate)(SLOT_RECORD_SIZE);
        if slot.is_null() {
            return OUT_OF_MEMORY;
        }
        write_target_word(slot, SLOT_COMPLETED_COUNT_WORD, 0);
        write_target_word(slot, SLOT_COUNT_WORD, count);
        write_target_word(slot, SLOT_BYTES_WORD, count.wrapping_mul(4));
        let root = read_target_word(element, HEADER_LINK_WORD) as usize as *mut u8;
        let status = (ops.callback_dispatch)(root, SLOT_ONE_CALLBACK, slot);
        if status != 0 || read_target_word(slot, SLOT_COMPLETED_COUNT_WORD) != count {
            (ops.free)(slot);
            return if status != 0 { status as u32 } else { INVALID_SELECTOR };
        }
        slot
    } else {
        let status = materialize_plst_slot(element, 1);
        if status != 0 {
            return status;
        }
        let source = read_target_word(element, SLOT_SOURCE_WORD) as usize as *mut u8;
        if source.is_null() {
            return OUT_OF_MEMORY;
        }
        let byte_len = read_target_word(source, BUFFER_SIZE_WORD);
        let clone = (ops.allocate)(byte_len as usize);
        if clone.is_null() {
            return OUT_OF_MEMORY;
        }
        if byte_len <= i32::MAX as u32 {
            for offset in 0..byte_len as usize {
                clone.add(offset).write_volatile(source.add(offset).read_volatile());
            }
        }
        (ops.populate)(element, clone, selector);
        clone
    };

    write_slot(element, selector, slot);
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    const SLAB_BYTES: usize = 0x8000;
    const HEADER_OFFSET: usize = 0x0000;
    const ELEMENT_OFFSET: usize = 0x1000;
    const RECORD_OFFSET: usize = 0x3000;
    const CLONE_OFFSET: usize = 0x4000;
    const SOURCE_OFFSET: usize = 0x5000;

    static mut ALLOCATIONS: [*mut u8; 2] = [core::ptr::null_mut(); 2];
    static mut ALLOCATION_INDEX: usize = 0;
    static mut FREE_CALLS: u32 = 0;
    static mut LAST_FREED: *mut u8 = core::ptr::null_mut();
    static mut DISPATCH_CALLS: u32 = 0;
    static mut LAST_ROOT: *mut u8 = core::ptr::null_mut();
    static mut LAST_CALLBACK: usize = 0;
    static mut LAST_CONTEXT: *mut u8 = core::ptr::null_mut();
    static mut DISPATCH_STATUS: i32 = 0;
    static mut COMPLETE_SLOT: bool = true;
    static mut POPULATE_CALLS: u32 = 0;
    static mut LAST_POPULATE_SLOT: *mut u8 = core::ptr::null_mut();
    static mut LAST_POPULATE_SELECTOR: u32 = 0;


    unsafe extern "C" fn mock_allocate(_size: usize) -> *mut u8 {
        let result = ALLOCATIONS[ALLOCATION_INDEX];
        ALLOCATION_INDEX += 1;
        result
    }

    unsafe extern "C" fn mock_free(slot: *mut u8) {
        FREE_CALLS += 1;
        LAST_FREED = slot;
    }

    unsafe extern "C" fn mock_dispatch(root: *mut u8, callback: usize, context: *mut u8) -> i32 {
        DISPATCH_CALLS += 1;
        LAST_ROOT = root;
        LAST_CALLBACK = callback;
        LAST_CONTEXT = context;
        if COMPLETE_SLOT {
            let count = read_target_word(context, SLOT_COUNT_WORD);
            write_target_word(context, SLOT_COMPLETED_COUNT_WORD, count);
        }
        DISPATCH_STATUS
    }

    unsafe extern "C" fn mock_populate(_element: *mut u8, slot: *mut u8, selector: u32) {
        POPULATE_CALLS += 1;
        LAST_POPULATE_SLOT = slot;
        LAST_POPULATE_SELECTOR = selector;
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
        previous_ops: PlstSlotMaterializeOps,
        base: *mut u8,
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe { PLST_SLOT_MATERIALIZE_OPS = self.previous_ops }
        }
    }

    fn bench() -> Option<Bench> {
        let lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(base) = try_map_u32_slab(hints::PLST_SLOT_MATERIALIZE, SLAB_BYTES) else {
            assert!(note_missing_u32_fixture("ui::plst_slot_materialize"));
            return None;
        };
        let previous_ops = unsafe { PLST_SLOT_MATERIALIZE_OPS };
        unsafe {
            ALLOCATIONS = [core::ptr::null_mut(); 2];
            ALLOCATION_INDEX = 0;
            FREE_CALLS = 0;
            LAST_FREED = core::ptr::null_mut();
            DISPATCH_CALLS = 0;
            LAST_ROOT = core::ptr::null_mut();
            LAST_CALLBACK = 0;
            LAST_CONTEXT = core::ptr::null_mut();
            DISPATCH_STATUS = 0;
            COMPLETE_SLOT = true;
            POPULATE_CALLS = 0;
            LAST_POPULATE_SLOT = core::ptr::null_mut();
            LAST_POPULATE_SELECTOR = 0;
            PLST_SLOT_MATERIALIZE_OPS = PlstSlotMaterializeOps {
                callback_dispatch: mock_dispatch,
                allocate: mock_allocate,
                free: mock_free,
                populate: mock_populate,
            };
        }
        Some(Bench { _lock: lock, previous_ops, base })
    }

    unsafe fn make_element(base: *mut u8, count: u16) -> *mut u8 {
        core::ptr::write_bytes(base, 0, SLAB_BYTES);
        let header = base.add(HEADER_OFFSET);
        let element = base.add(ELEMENT_OFFSET);
        write_target_word(element, HEADER_LINK_WORD, header as u32);
        header.add(HEADER_ITEM_COUNT_OFFSET).cast::<u16>().write(count);
        element
    }

    #[test]
    fn rejects_out_of_range_before_touching_element_or_ops() {
        let Some(_bench) = bench() else { return };
        assert_eq!(unsafe { materialize_plst_slot(core::ptr::null_mut(), SLOT_COUNT) }, INVALID_SELECTOR);
        assert_eq!(unsafe { (ALLOCATION_INDEX, DISPATCH_CALLS, POPULATE_CALLS) }, (0, 0, 0));
    }

    #[test]
    fn existing_slot_succeeds_without_work() {
        let Some(bench) = bench() else { return };
        unsafe {
            let element = make_element(bench.base, 3);
            write_slot(element, 5, bench.base.add(RECORD_OFFSET));
            assert_eq!(materialize_plst_slot(element, 5), 0);
            assert_eq!((ALLOCATION_INDEX, DISPATCH_CALLS, POPULATE_CALLS), (0, 0, 0));
        }
    }

    #[test]
    fn slot_one_records_count_and_retains_only_completed_callback_result() {
        let Some(bench) = bench() else { return };
        unsafe {
            let element = make_element(bench.base, 3);
            let record = bench.base.add(RECORD_OFFSET);
            record.cast::<u32>().write(0xa5a5_5a5a);
            ALLOCATIONS[0] = record;
            assert_eq!(materialize_plst_slot(element, 1), 0);
            assert_eq!(read_slot(element, 1), record);
            assert_eq!(record.cast::<u32>().read(), 0xa5a5_5a5a);
            assert_eq!(read_target_word(record, SLOT_COUNT_WORD), 3);
            assert_eq!(read_target_word(record, SLOT_BYTES_WORD), 12);
            assert_eq!(read_target_word(record, SLOT_COMPLETED_COUNT_WORD), 3);
            assert_eq!((DISPATCH_CALLS, LAST_ROOT, LAST_CALLBACK, LAST_CONTEXT), (1, bench.base, SLOT_ONE_CALLBACK, record));
            assert_eq!(FREE_CALLS, 0);
        }
    }

    #[test]
    fn slot_one_failure_or_incomplete_result_releases_record() {
        let Some(bench) = bench() else { return };
        unsafe {
            let element = make_element(bench.base, 2);
            let record = bench.base.add(RECORD_OFFSET);
            ALLOCATIONS[0] = record;
            DISPATCH_STATUS = -7;
            assert_eq!(materialize_plst_slot(element, 1), (-7i32) as u32);
            assert!(read_slot(element, 1).is_null());
            assert_eq!((FREE_CALLS, LAST_FREED), (1, record));

            ALLOCATION_INDEX = 0;
            FREE_CALLS = 0;
            DISPATCH_STATUS = 0;
            COMPLETE_SLOT = false;
            assert_eq!(materialize_plst_slot(element, 1), INVALID_SELECTOR);
            assert!(read_slot(element, 1).is_null());
            assert_eq!((FREE_CALLS, LAST_FREED), (1, record));
        }
    }

    #[test]
    fn later_slot_materializes_one_then_clones_and_populates_source() {
        let Some(bench) = bench() else { return };
        unsafe {
            let element = make_element(bench.base, 2);
            let record = bench.base.add(RECORD_OFFSET);
            let clone = bench.base.add(CLONE_OFFSET);
            let source = bench.base.add(SOURCE_OFFSET);
            let bytes = [0x91, 0x82, 0x73, 0x64, 0x55];
            write_target_word(source, BUFFER_SIZE_WORD, bytes.len() as u32);
            for (offset, value) in bytes.iter().enumerate() {
                source.add(offset).write(*value);
            }
            write_target_word(element, SLOT_SOURCE_WORD, source as u32);
            ALLOCATIONS = [record, clone];
            assert_eq!(materialize_plst_slot(element, 7), 0);
            assert_eq!(read_slot(element, 1), record);
            assert_eq!(read_slot(element, 7), clone);
            assert_eq!(unsafe { core::slice::from_raw_parts(clone, bytes.len()) }, bytes);
            assert_eq!((POPULATE_CALLS, LAST_POPULATE_SLOT, LAST_POPULATE_SELECTOR), (1, clone, 7));
        }
    }

    #[test]
    fn allocation_failure_returns_mem_full_without_dispatch() {
        let Some(bench) = bench() else { return };
        unsafe {
            let element = make_element(bench.base, 1);
            assert_eq!(materialize_plst_slot(element, 1), OUT_OF_MEMORY);
            assert_eq!((DISPATCH_CALLS, FREE_CALLS), (0, 0));
        }
    }
}
