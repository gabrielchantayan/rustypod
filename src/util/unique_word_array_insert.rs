//! `unique_word_array_insert` — original: `FUN_083d5040` @ `0x083d5040`
//! (152 bytes: 38 ARM words; the next distinct function begins at
//! `0x083d50d8`).
//!
//! **Verified call count:** complete raw-image ARM B/BL-immediate decoding
//! finds three inbound direct `bl` callers (0x082c7cd4, 0x082c834c, and
//! 0x0839bdac), all plain unconditional; none are predicated. The body has
//! zero plain outbound `bl` instructions and one predicated `bleq`, to the
//! capacity grow helper at `0x083d50d8`.
//!
//! The six-word header begins `{data, capacity, count, growth_factor, ...}`.
//! It first rejects a word already present anywhere in the capacity-sized
//! backing array. When `count == capacity`, it invokes the growth helper,
//! then finds the first zero word. A free slot other than zero receives the
//! value and increments `count`; slot zero deliberately remains reserved even
//! though its index is returned. It returns the duplicate/missing-slot
//! sentinel `-1` otherwise.
//!
//! Deliberate deviation: the unported grow helper is reached through its
//! verified fixed address on target and a host-test seam off target. Header
//! pointers remain target-width `u32` words, avoiding host-pointer layout
//! widening.

/// ABI of the unported capacity grow helper at `0x083d50d8`.
pub type UniqueWordArrayGrow = unsafe extern "C" fn(*mut u32);

#[cfg(target_os = "none")]
unsafe fn grow(array: *mut u32) {
    let helper: UniqueWordArrayGrow = core::mem::transmute(0x083d_50d8usize);
    helper(array);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_grow(_array: *mut u32) {}

#[cfg(not(target_os = "none"))]
static mut GROW: UniqueWordArrayGrow = missing_grow;

#[cfg(not(target_os = "none"))]
unsafe fn grow(array: *mut u32) {
    GROW(array);
}

/// Inserts a non-duplicate word into the first non-reserved empty slot.
///
/// # Safety
/// `array` must address at least six readable target words, with word zero a
/// valid aligned `u32` data pointer and word one entries readable. If words
/// two and one compare equal, the grow helper must make the updated header and
/// backing array valid before returning. The original performs no NULL,
/// bounds, or overflow checks.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn unique_word_array_insert(array: *mut u32, value: u32) -> i32 {
    let mut index = 0u32;
    let mut capacity = array.add(1).read_volatile();
    let mut data = array.read_volatile() as usize as *mut u32;
    while index < capacity {
        if data.add(index as usize).read_volatile() == value { return -1; }
        index = index.wrapping_add(1);
    }

    if array.add(2).read_volatile() == capacity {
        grow(array);
    }

    capacity = array.add(1).read_volatile();
    data = array.read_volatile() as usize as *mut u32;
    index = 0;
    while index < capacity {
        if data.add(index as usize).read_volatile() == 0 { break; }
        index = index.wrapping_add(1);
    }
    if index == capacity { return -1; }

    if index != 0 {
        array.add(2).write_volatile(array.add(2).read_volatile().wrapping_add(1));
        data.add(index as usize).write_volatile(value);
    }
    index as i32
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr::addr_of_mut;
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::UNIQUE_WORD_ARRAY_INSERT, 0x1000).map(|slab| slab as usize)
    });
    static mut GROW_CALL: *mut u32 = core::ptr::null_mut();
    static mut GROW_REPLACEMENT: *mut u32 = core::ptr::null_mut();

    unsafe extern "C" fn recording_grow(array: *mut u32) {
        GROW_CALL = array;
        if !GROW_REPLACEMENT.is_null() {
            array.write(GROW_REPLACEMENT as u32);
            array.add(1).write(4);
        }
    }

    struct GrowReset(UniqueWordArrayGrow);
    impl Drop for GrowReset {
        fn drop(&mut self) { unsafe { GROW = self.0; } }
    }
    unsafe fn install_recording_grow() -> GrowReset {
        let previous = GROW;
        GROW = recording_grow;
        GrowReset(previous)
    }

    #[test]
    fn rejects_duplicates_and_keeps_the_header_unchanged() {
        let _guard = TEST_LOCK.lock();
        let Some(slab) = *FIXTURE else { note_missing_u32_fixture(module_path!()); return; };
        let data = unsafe { (slab as *mut u32).add(0x40) };
        let _reset = unsafe { install_recording_grow() };
        let mut array = [data as u32, 3, 1, 2, 0, 0];
        unsafe {
            data.copy_from_nonoverlapping([0, 0x1234_5678, 0].as_ptr(), 3);
            GROW_CALL = core::ptr::null_mut();
            assert_eq!(unique_word_array_insert(addr_of_mut!(array).cast(), 0x1234_5678), -1);
            assert_eq!(array, [data as u32, 3, 1, 2, 0, 0]);
            assert_eq!(GROW_CALL, core::ptr::null_mut());
        }
    }

    #[test]
    fn leaves_reserved_zero_slot_empty_but_returns_its_index() {
        let _guard = TEST_LOCK.lock();
        let Some(slab) = *FIXTURE else { note_missing_u32_fixture(module_path!()); return; };
        let data = unsafe { (slab as *mut u32).add(0x80) };
        let mut array = [data as u32, 2, 0, 2, 0, 0];
        unsafe {
            data.copy_from_nonoverlapping([0, 0].as_ptr(), 2);
            assert_eq!(unique_word_array_insert(addr_of_mut!(array).cast(), 0x91), 0);
            assert_eq!(array[2], 0);
            assert_eq!(*data, 0);
        }
    }

    #[test]
    fn grows_then_uses_the_reloaded_data_and_capacity() {
        let _guard = TEST_LOCK.lock();
        let Some(slab) = *FIXTURE else { note_missing_u32_fixture(module_path!()); return; };
        let old_data = unsafe { (slab as *mut u32).add(0xc0) };
        let new_data = unsafe { old_data.add(8) };
        let _reset = unsafe { install_recording_grow() };
        let mut array = [old_data as u32, 2, 2, 2, 0, 0];
        unsafe {
            old_data.copy_from_nonoverlapping([7, 8].as_ptr(), 2);
            new_data.copy_from_nonoverlapping([7, 8, 0, 0].as_ptr(), 4);
            GROW_CALL = core::ptr::null_mut();
            GROW_REPLACEMENT = new_data;
            assert_eq!(unique_word_array_insert(addr_of_mut!(array).cast(), 9), 2);
            GROW_REPLACEMENT = core::ptr::null_mut();
            assert_eq!(GROW_CALL, addr_of_mut!(array).cast());
            assert_eq!(array[1], 4);
            assert_eq!(array[2], 3);
            assert_eq!(*new_data.add(2), 9);
        }
    }
}
