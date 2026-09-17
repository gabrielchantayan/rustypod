//! Sorted pointer-array insertion from retailOS.
//!
//! `FUN_08277654` @ `0x08277654` is **88 bytes**
//! (`0x08277654..0x082776ac`; the next real function starts at
//! `0x082776ac`). Raw ARM decoding verifies four plain inbound `bl` calls
//! (`0x08277888`, `0x0828e188`, `0x0828e388`, `0x0828e588`) and no predicated
//! inbound `bl` calls. Its two internal calls are `array_element_at` and the
//! unresolved array insertion virtual dispatch at `0x08271ad8`.
//!
//! Algorithm: scan the pointer array at `owner + 0x80` for the first record
//! whose signed word at `+0x38` is not less than `record`'s key, then insert
//! `record` at that index. Equal keys therefore insert before existing equal
//! keys.
//!
//! Deliberate deviation: `0x08271ad8` has no established Rust identity, so
//! target builds call its verified ROM address rather than creating a named
//! callee seam. Host tests replace only that dispatch.

use super::array_element_at::{array_element_at, StridedArray};

const ARRAY_OFFSET: usize = 0x80;
const SORT_KEY_OFFSET: usize = 0x38;

type ArrayInsertPointer = unsafe extern "C" fn(*mut StridedArray, i32, *const *mut u8) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn array_insert_pointer_at(array: *mut StridedArray, index: i32, record: *const *mut u8) {
    let insert: ArrayInsertPointer = unsafe { core::mem::transmute(0x0827_1ad8usize) };
    unsafe { insert(array, index, record) };
}

#[cfg(not(target_os = "none"))]
static mut ARRAY_INSERT_POINTER_AT: Option<ArrayInsertPointer> = None;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn array_insert_pointer_at(array: *mut StridedArray, index: i32, record: *const *mut u8) {
    let insert = unsafe { ARRAY_INSERT_POINTER_AT.expect("host array insertion dispatch not installed") };
    unsafe { insert(array, index, record) };
}

/// sorted_pointer_array_insert — original: `FUN_08277654` @ `0x08277654`
/// (88 bytes; 4 plain inbound `bl` call sites, 0 predicated). See the module
/// header for the byte-verified extent, dispatch, and algorithm.
///
/// # Safety
///
/// `owner + 0x80` must be a readable [`StridedArray`] whose elements are
/// readable 32-bit record pointers, and every pointed record plus `record`
/// must have a readable signed word at `+0x38`. Its insertion dispatch must
/// accept a pointer to the local record pointer, as retailOS does.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sorted_pointer_array_insert(owner: *mut u8, record: *mut u8) {
    let array = unsafe { owner.add(ARRAY_OFFSET).cast::<StridedArray>() };
    let count = unsafe { core::ptr::addr_of!((*array).count).read_volatile() };
    let key = unsafe { record.add(SORT_KEY_OFFSET).cast::<i32>().read_volatile() };
    let mut index = 0;

    while index < count {
        let entry_address = unsafe { array_element_at(array, index) };
        let entry = unsafe { (entry_address as usize as *const u32).read_volatile() };
        let entry_key = unsafe {
            (entry as usize as *const u8)
                .add(SORT_KEY_OFFSET)
                .cast::<i32>()
                .read_volatile()
        };
        if entry_key >= key {
            break;
        }
        index += 1;
    }

    unsafe { array_insert_pointer_at(array, index, &record) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    extern crate std;
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    const OWNER: usize = 0x000;
    const ENTRIES: usize = 0x200;
    const RECORDS: usize = 0x400;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SORTED_POINTER_ARRAY_INSERT, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut INSERTED_INDEX: i32 = -1;
    static mut INSERTED_RECORD: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn stride(_: *const StridedArray) -> u32 { 4 }
    static VTABLE: super::super::array_element_at::StridedArrayVtable =
        super::super::array_element_at::StridedArrayVtable {
            unresolved_00_14: [0; 6],
            element_stride: stride,
        };

    unsafe extern "C" fn record_insert(_: *mut StridedArray, index: i32, record: *const *mut u8) -> u32 {
        unsafe {
            INSERTED_INDEX = index;
            INSERTED_RECORD = record.read();
        }
        0
    }

    unsafe fn run(keys: &[i32], candidate_key: i32) -> Option<(i32, u32)> {
        let base = (*FIXTURE)? as *mut u8;
        unsafe {
            base.write_bytes(0, FIXTURE_LEN);
            let array = base.add(OWNER + ARRAY_OFFSET).cast::<StridedArray>();
            array.write(StridedArray {
                vtable: &VTABLE,
                count: keys.len() as i32,
                storage: base.add(ENTRIES) as usize as u32,
            });
            for (index, key) in keys.iter().enumerate() {
                let record = base.add(RECORDS + index * 0x40);
                record.add(SORT_KEY_OFFSET).cast::<i32>().write(*key);
                base.add(ENTRIES).cast::<u32>().add(index).write(record as usize as u32);
            }
            let candidate = base.add(RECORDS + keys.len() * 0x40);
            candidate.add(SORT_KEY_OFFSET).cast::<i32>().write(candidate_key);
            INSERTED_INDEX = -1;
            INSERTED_RECORD = core::ptr::null_mut();
            ARRAY_INSERT_POINTER_AT = Some(record_insert);
            sorted_pointer_array_insert(base.add(OWNER), candidate);
            Some((INSERTED_INDEX, INSERTED_RECORD as usize as u32))
        }
    }

    #[test]
    fn inserts_before_first_equal_or_greater_key() {
        let _guard = TEST_LOCK.lock();
        let Some((index, record)) = (unsafe { run(&[-8, 2, 2, 9], 2) }) else {
            assert!(note_missing_u32_fixture("cxx/sorted_pointer_array_insert"));
            return;
        };
        assert_eq!(index, 1);
        assert_ne!(record, 0);
    }

    #[test]
    fn inserts_at_head_and_tail_for_outside_keys() {
        let _guard = TEST_LOCK.lock();
        assert_eq!(unsafe { run(&[-3, 4], -4) }.map(|result| result.0), Some(0));
        assert_eq!(unsafe { run(&[-3, 4], 5) }.map(|result| result.0), Some(2));
    }

    #[test]
    fn empty_array_inserts_at_zero() {
        let _guard = TEST_LOCK.lock();
        assert_eq!(unsafe { run(&[], i32::MIN) }.map(|result| result.0), Some(0));
    }
}
