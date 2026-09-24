//! `string_map_assign_tree_records` — retailOS `FUN_080e40c8` @ `0x080e40c8`.
//!
//! Raw ARM is exactly 96 bytes, from `push {r3,r4,r5,r6,r7,lr}` through
//! `pop {r3,r4,r5,r6,r7,pc}`; `0x080e4128` starts the next function. Whole-image
//! decoding finds three plain unconditional `bl` calls and no predicated `bl`
//! calls. It walks the red-black tree's leftmost-linked nodes, looks up or
//! creates each node's `+0x14` string-record key in `map`, assigns that record
//! to the returned mapped value, then advances the tree iterator.
//!
//! Deliberate deviation: the three callees remain fixed-address dispatch
//! boundaries on device and replaceable host seams; their names are limited to
//! their independently verified observed ABIs.

#[cfg(not(target_os = "none"))]
use core::ptr;

const TREE_HEADER_OFFSET: usize = 0x10;
const TREE_LEFTMOST_OFFSET: usize = 0x08;
const NODE_RECORD_OFFSET: usize = 0x14;
const RETAIL_STRING_MAP_VALUE_ADDRESS: usize = 0x083d_b32c;
const RETAIL_STRING_RECORD_ASSIGN_ADDRESS: usize = 0x0819_7c68;
const RETAIL_TREE_ITERATOR_ADVANCE_ADDRESS: usize = 0x083b_5b58;

type StringMapValue = unsafe extern "C" fn(*mut u8, *mut u8) -> *mut u8;
type StringRecordAssign = unsafe extern "C" fn(*mut u8, *mut u8) -> *mut u8;
type TreeIteratorAdvance = unsafe extern "C" fn(*mut u32, u32) -> u32;

#[derive(Clone, Copy)]
pub struct StringMapAssignTreeRecordsOps {
    pub map_value: StringMapValue,
    pub assign_record: StringRecordAssign,
    pub advance_iterator: TreeIteratorAdvance,
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn ops() -> StringMapAssignTreeRecordsOps {
    unsafe {
        StringMapAssignTreeRecordsOps {
            map_value: core::mem::transmute(RETAIL_STRING_MAP_VALUE_ADDRESS),
            assign_record: core::mem::transmute(RETAIL_STRING_RECORD_ASSIGN_ADDRESS),
            advance_iterator: core::mem::transmute(RETAIL_TREE_ITERATOR_ADVANCE_ADDRESS),
        }
    }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_map_value(_: *mut u8, _: *mut u8) -> *mut u8 { ptr::null_mut() }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_assign_record(_: *mut u8, _: *mut u8) -> *mut u8 { ptr::null_mut() }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_advance_iterator(_: *mut u32, _: u32) -> u32 { 0 }
#[cfg(not(target_os = "none"))]
const DEFAULT_OPS: StringMapAssignTreeRecordsOps = StringMapAssignTreeRecordsOps {
    map_value: missing_map_value,
    assign_record: missing_assign_record,
    advance_iterator: missing_advance_iterator,
};


#[cfg(not(target_os = "none"))]
pub static mut STRING_MAP_ASSIGN_TREE_RECORDS_OPS: StringMapAssignTreeRecordsOps = DEFAULT_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn ops() -> StringMapAssignTreeRecordsOps {
    unsafe { ptr::read_volatile(ptr::addr_of!(STRING_MAP_ASSIGN_TREE_RECORDS_OPS)) }
}

/// Assigns every string record stored in `tree` into `map`.
///
/// # Safety
/// `tree + 0x10` must contain a valid target-width tree-header pointer, whose
/// `+0x08` word is a valid iterator node or the header sentinel. The selected
/// operation seams must implement the observed retailOS ABIs.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_map_assign_tree_records(tree: *mut u8, map: *mut u8) {
    let header = unsafe { tree.add(TREE_HEADER_OFFSET).cast::<u32>().read() };
    let mut node = unsafe { (header as usize as *const u8).add(TREE_LEFTMOST_OFFSET).cast::<u32>().read() };
    while node != header {
        let record = unsafe { (node as usize as *mut u8).add(NODE_RECORD_OFFSET) };
        let operations = unsafe { ops() };
        let value = unsafe { (operations.map_value)(map, record) };
        unsafe { (operations.assign_record)(value, record) };
        unsafe { (operations.advance_iterator)(&mut node, 0) };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [(u32, u32); 2] = [(0, 0); 2];
    static mut CALL_COUNT: usize = 0;
    static mut ITERATOR_STEPS: [u32; 2] = [0; 2];
    static mut DESTINATION: u8 = 0;

    unsafe extern "C" fn map_value(map: *mut u8, record: *mut u8) -> *mut u8 {
        unsafe { CALLS[CALL_COUNT] = (map as usize as u32, record as usize as u32); CALL_COUNT += 1; ptr::addr_of_mut!(DESTINATION) }
    }
    unsafe extern "C" fn assign_record(value: *mut u8, record: *mut u8) -> *mut u8 {
        unsafe { assert_eq!(value, ptr::addr_of_mut!(DESTINATION)); assert_eq!(record as usize as u32, CALLS[CALL_COUNT - 1].1); }
        value
    }
    unsafe extern "C" fn advance_iterator(node: *mut u32, zero: u32) -> u32 {
        assert_eq!(zero, 0);
        unsafe { *node = ITERATOR_STEPS[CALL_COUNT - 1]; }
        0
    }

    #[test]
    fn assigns_each_node_record_until_the_header_sentinel() {
        let _lock = OPS_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::STRING_MAP_ASSIGN_TREE_RECORDS, 0x1000) else {
            note_missing_u32_fixture("cxx/string_map_assign_tree_records");
            return;
        };
        unsafe {
            ptr::write_bytes(slab, 0, 0x1000);
            let header = slab.add(0x100) as usize as u32;
            let first = slab.add(0x200) as usize as u32;
            let second = slab.add(0x300) as usize as u32;
            slab.add(TREE_HEADER_OFFSET).cast::<u32>().write(header);
            (header as usize as *mut u8).add(TREE_LEFTMOST_OFFSET).cast::<u32>().write(first);
            CALL_COUNT = 0;
            ITERATOR_STEPS = [second, header];
            let saved = STRING_MAP_ASSIGN_TREE_RECORDS_OPS;
            STRING_MAP_ASSIGN_TREE_RECORDS_OPS = StringMapAssignTreeRecordsOps { map_value, assign_record, advance_iterator };
            string_map_assign_tree_records(slab, slab.add(0x400));
            STRING_MAP_ASSIGN_TREE_RECORDS_OPS = saved;
            assert_eq!(CALL_COUNT, 2);
            assert_eq!(CALLS, [(slab.add(0x400) as usize as u32, first + NODE_RECORD_OFFSET as u32), (slab.add(0x400) as usize as u32, second + NODE_RECORD_OFFSET as u32)]);
        }
    }

    #[test]
    fn empty_tree_does_not_dispatch_operations() {
        let _lock = OPS_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::STRING_MAP_ASSIGN_TREE_RECORDS, 0x1000) else {
            note_missing_u32_fixture("cxx/string_map_assign_tree_records");
            return;
        };
        unsafe {
            ptr::write_bytes(slab, 0, 0x1000);
            let header = slab.add(0x100) as usize as u32;
            slab.add(TREE_HEADER_OFFSET).cast::<u32>().write(header);
            (header as usize as *mut u8).add(TREE_LEFTMOST_OFFSET).cast::<u32>().write(header);
            CALL_COUNT = 0;
            string_map_assign_tree_records(slab, slab);
            assert_eq!(CALL_COUNT, 0);
        }
    }
}
