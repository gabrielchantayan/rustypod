//! `dynamic_array_remove` — original: `FUN_080646b8` @ `0x080646b8`
//! (132 bytes; four verified inbound plain `bl` call sites and zero predicated
//! `bl` forms).
//!
//! The next independently entered function starts at `0x0806473c`, establishing
//! the raw extent `0x080646b8..0x0806473c`. The routine rejects a busy array,
//! resolves `u32::MAX` to the current length, clamps a removal that runs past
//! the end, shifts the trailing elements (including the terminal slot), then
//! tail-calls the shared capacity/length adjustment routine at `0x080a6314`.
//! It returns the busy word, zero, or the requested index when the index is
//! beyond the current length.
//! The retail implementation dispatches the shift through an unresolved global
//! mover and tail-branches to `0x080a6314`. Rust uses a volatile overlap-safe
//! byte move and calls that still-unported adjustment boundary; those are
//! deliberate implementation deviations only.

use core::ptr;

const ELEMENT_SIZE_WORD: usize = 1;
const LENGTH_WORD: usize = 2;
const USED_BYTES_WORD: usize = 3;
const CAPACITY_BYTES_WORD: usize = 4;
const BUSY_WORD: usize = 5;

/// Removes `count` elements beginning at `index` from the firmware's dynamic
/// array prefix.
///
/// # Safety
///
/// `array` must point to the seven-word dynamic-array prefix and, when a move
/// is required, its backing storage must contain the terminal element at
/// `length * element_size`. The adjustment boundary at `0x080a6314` owns the
/// backing allocation referenced by word six.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.dynamic_array_remove")]
pub unsafe extern "C" fn dynamic_array_remove(array: *mut u32, mut count: u32, index: u32) -> u32 {
    let busy = array.add(BUSY_WORD).read();
    if busy != 0 {
        return busy;
    }

    let mut resolved_index = index;
    if resolved_index == u32::MAX {
        resolved_index = array.add(LENGTH_WORD).read();
    }
    if resolved_index == 0 {
        return 0;
    }

    let length = array.add(LENGTH_WORD).read();
    if length < resolved_index {
        return resolved_index;
    }
    if resolved_index.wrapping_add(count) > length {
        count = length.wrapping_sub(resolved_index).wrapping_add(1);
    }

    if resolved_index.wrapping_add(count) <= length {
        array.add(BUSY_WORD).write(1);
        let element_size = array.add(ELEMENT_SIZE_WORD).read() as usize;
        let source = dynamic_array_element(array, resolved_index.wrapping_add(count));
        let destination = dynamic_array_element(array, resolved_index);
        let bytes = length
            .wrapping_sub(resolved_index)
            .wrapping_add(1)
            .wrapping_mul(element_size as u32) as usize;
        move_bytes(source, destination, bytes);
        array.add(BUSY_WORD).write(array.add(BUSY_WORD).read().wrapping_sub(1));
    }

    array_resize_fn()(array, count.wrapping_neg() as i32)
}

#[inline(always)]
unsafe fn move_bytes(source: *mut u8, destination: *mut u8, bytes: usize) {
    if (destination as usize) <= (source as usize) {
        for offset in 0..bytes {
            destination.add(offset).write_volatile(source.add(offset).read_volatile());
        }
    } else {
        for offset in (0..bytes).rev() {
            destination.add(offset).write_volatile(source.add(offset).read_volatile());
        }
    }
}

unsafe fn dynamic_array_element(array: *mut u32, index: u32) -> *mut u8 {
    let storage = array.add(6).read() as usize as *mut u8;
    storage.add(index.wrapping_sub(1).wrapping_mul(array.add(ELEMENT_SIZE_WORD).read()) as usize)
}

type ArrayResize = unsafe extern "C" fn(*mut u32, i32) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_array_resize(array: *mut u32, change: i32) -> u32 {
    let function: ArrayResize = core::mem::transmute(0x080a_6314usize);
    function(array, change)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_array_resize(_array: *mut u32, _change: i32) -> u32 {
    panic!("dynamic_array_remove requires capacity adjustment 0x080a6314")
}

#[cfg(target_os = "none")]
static mut ARRAY_RESIZE: ArrayResize = retail_array_resize;
#[cfg(not(target_os = "none"))]
static mut ARRAY_RESIZE: ArrayResize = missing_array_resize;

#[inline(always)]
unsafe fn array_resize_fn() -> ArrayResize {
    ptr::read_volatile(ptr::addr_of!(ARRAY_RESIZE))
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::{dynamic_array_remove, ArrayResize, ARRAY_RESIZE, CAPACITY_BYTES_WORD, LENGTH_WORD, USED_BYTES_WORD};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::{LazyLock, atomic::{AtomicI32, AtomicU32, Ordering}};

    const FIXTURE_LEN: usize = 32;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::DYNAMIC_ARRAY_REMOVE, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());
    static RESIZE_RESULT: AtomicU32 = AtomicU32::new(0);
    static LAST_CHANGE: AtomicI32 = AtomicI32::new(0);

    unsafe extern "C" fn mock_array_resize(array: *mut u32, change: i32) -> u32 {
        LAST_CHANGE.store(change, Ordering::Relaxed);
        let length = array.add(LENGTH_WORD).read().wrapping_add(change as u32);
        let element_size = array.add(1).read();
        array.add(LENGTH_WORD).write(length);
        array.add(USED_BYTES_WORD).write(length.wrapping_mul(element_size));
        RESIZE_RESULT.load(Ordering::Relaxed)
    }

    unsafe fn install_mock() {
        ARRAY_RESIZE = mock_array_resize as ArrayResize;
        RESIZE_RESULT.store(0, Ordering::Relaxed);
        LAST_CHANGE.store(0, Ordering::Relaxed);
    }

    fn fixture() -> Option<*mut u32> {
        (*FIXTURE).map(|pointer| pointer as *mut u32)
    }

    #[test]
    fn removes_middle_range_and_terminal_slot() {
        let _guard = LOCK.lock();
        let Some(storage) = fixture() else {
            assert!(note_missing_u32_fixture("util/dynamic_array_remove"));
            return;
        };
        let mut array = [0u32; 7];
        unsafe {
            storage.copy_from_nonoverlapping([10u32, 20, 30, 40, 0xfeed_face].as_ptr(), 5);
            array[1] = 4;
            array[2] = 4;
            array[3] = 16;
            array[CAPACITY_BYTES_WORD] = 20;
            array[6] = storage as usize as u32;
            install_mock();
            assert_eq!(dynamic_array_remove(array.as_mut_ptr(), 2, 2), 0);
            assert_eq!(core::slice::from_raw_parts(storage, 5), [10, 40, 0xfeed_face, 0, 0xfeed_face]);
        }
        assert_eq!(array[LENGTH_WORD], 2);
        assert_eq!(array[USED_BYTES_WORD], 8);
        assert_eq!(LAST_CHANGE.load(Ordering::Relaxed), -2);
    }

    #[test]
    fn resolves_end_sentinel_and_preserves_busy_or_out_of_range_results() {
        let _guard = LOCK.lock();
        let Some(storage) = fixture() else {
            assert!(note_missing_u32_fixture("util/dynamic_array_remove"));
            return;
        };
        let mut array = [0u32; 7];
        unsafe {
            storage.copy_from_nonoverlapping([1u32, 2, 0x1234_5678].as_ptr(), 3);
            array[1] = 4;
            array[2] = 2;
            array[3] = 8;
            array[6] = storage as usize as u32;
            install_mock();
            assert_eq!(dynamic_array_remove(array.as_mut_ptr(), 1, u32::MAX), 0);
            assert_eq!(core::slice::from_raw_parts(storage, 3), [1, 2, 0x1234_5678]);
        }
        assert_eq!(array[LENGTH_WORD], 1);

        array[5] = 0x55;
        unsafe { assert_eq!(dynamic_array_remove(array.as_mut_ptr(), 1, 1), 0x55) };
        array[5] = 0;
        unsafe { assert_eq!(dynamic_array_remove(array.as_mut_ptr(), 1, 3), 3) };
    }

    #[test]
    fn clamps_past_end_and_returns_resize_error() {
        let _guard = LOCK.lock();
        let Some(storage) = fixture() else {
            assert!(note_missing_u32_fixture("util/dynamic_array_remove"));
            return;
        };
        let mut array = [0u32; 7];
        unsafe {
            storage.copy_from_nonoverlapping([1u32, 2, 3, 0xaaaa_bbbb].as_ptr(), 4);
            array[1] = 4;
            array[2] = 3;
            array[3] = 12;
            array[6] = storage as usize as u32;
            install_mock();
            RESIZE_RESULT.store(0xffff_ff94, Ordering::Relaxed);
            assert_eq!(dynamic_array_remove(array.as_mut_ptr(), 99, 2), 0xffff_ff94);
        }
        assert_eq!(array[LENGTH_WORD], 1);
        assert_eq!(LAST_CHANGE.load(Ordering::Relaxed), -2);
    }
}
