//! Insert a statistics-bearing collection into a four-entry history.
//!
//! retailOS `FUN_081d0db0` @ 0x081d0db0; raw extent
//! [0x081d0db0, 0x081d0df8), 72 bytes. The next function loads owner+8
//! and returns. Independent A32 word decoding finds two inbound plain BLs
//! (0x0815e154, 0x081d0f04), no predicated inbound BLs. Outbound calls:
//! one plain BL to collection_value_statistics_refresh, one BLGT to
//! opaque_observable_array_release_erase_at, and one virtual BLX at +0x20.
//! Refresh the supplied collection, insert its pointer by reference at index
//! zero into the owner's array at +4, and release/erase index zero if the
//! signed insertion result exceeds four. Always return one. r2/r3 are not
//! arguments. No target deviations. Host vtable entries use native width;
//! the array offset remains +4, requiring an unaligned host vtable read.

use super::collection_value_statistics_refresh::collection_value_statistics_refresh;
use crate::cxx::observable_array::ObservableArray;
use crate::cxx::opaque_observable_array_release_erase_at::opaque_observable_array_release_erase_at;

type Insert = unsafe extern "C" fn(*mut u8, i32, *mut *mut u32) -> i32;

#[inline(always)]
unsafe fn insert_with(
    owner: *mut u32, value: *mut u32, remove: impl FnOnce(*mut ObservableArray),
) -> u32 {
    collection_value_statistics_refresh(value);
    let mut cell = value;
    let array = owner.cast::<u8>().add(4);
    #[cfg(target_os = "none")]
    let vtable = array.cast::<*const usize>().read();
    #[cfg(not(target_os = "none"))]
    let vtable = array.cast::<*const usize>().read_unaligned();
    let insert: Insert = core::mem::transmute(vtable.add(8).read());
    if insert(array, 0, &mut cell) > 4 {
        remove(array.cast());
    }
    1
}

/// # Safety
/// `value` must satisfy collection_value_statistics_refresh's contract.
/// `owner+4` must be a live observable array with a callable insertion slot
/// at vtable +0x20 and must satisfy release/erase's contract when insertion
/// returns a signed value greater than four. Callbacks must keep it valid.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn collection_history_insert(owner: *mut u32, value: *mut u32) -> u32 {
    insert_with(owner, value, |array| { opaque_observable_array_release_erase_at(array, 0); })
}

#[cfg(test)]
mod tests {
    use super::*;
    unsafe extern "C" fn insert(array: *mut u8, index: i32, cell: *mut *mut u32) -> i32 {
        assert_eq!(index, 0);
        let value = cell.read();
        // A zero-count collection must already have had all statistics reset.
        assert_eq!(core::slice::from_raw_parts(value.add(5), 3), &[0, 0, 0]);
        array.add(12).cast::<u32>().write(1);
        cell.write(core::ptr::null_mut());
        array.add(8).cast::<i32>().read()
    }

    #[test]
    fn refreshes_before_insertion_and_trims_only_above_signed_four() {
        unsafe {
            let mut vtable = [0usize; 9];
            vtable[8] = insert as *const () as usize;
            for result in [i32::MIN, -1, 0, 3, 4, 5, i32::MAX] {
                let mut owner = [0x1357_2468u32; 8];
                let array = owner.as_mut_ptr().cast::<u8>().add(4);
                array.cast::<*const usize>().write_unaligned(vtable.as_ptr());
                array.add(8).cast::<i32>().write(result);
                array.add(12).cast::<u32>().write(0);
                let mut value = [0xa5a5_a5a5u32; 14];
                value[13] = 0;
                let before = value;
                let mut removed = false;
                assert_eq!(insert_with(owner.as_mut_ptr(), value.as_mut_ptr(), |receiver| {
                    assert_eq!(receiver.cast::<u8>(), array);
                    assert_eq!(array.add(12).cast::<u32>().read(), 1);
                    removed = true;
                }), 1);
                assert_eq!(removed, result > 4);
                assert_eq!(owner[0], 0x1357_2468);
                assert_eq!(owner[7], 0x1357_2468);
                for i in (0..5).chain(8..14) { assert_eq!(value[i], before[i]); }
            }
        }
    }
}
