//! Slot-array constructor — `FUN_083d4f78` @ `0x083d4f78`.
//!
//! True extent: 196 bytes, [0x083d4f78, 0x083d503c): 160 instruction
//! bytes followed by a record pointer and 32-byte diagnostic string. The
//! next independent function is `bx lr` at 0x083d503c. Whole-image aligned
//! A32 decoding finds one incoming plain BL (0x081ef148), nine outgoing
//! plain BLs, and zero predicated BLs in either direction.
//!
//! Initialize {storage, capacity, count, options, growth, tracker_label},
//! allocate capacity << 2 bytes and zero them, then load the runtime name
//! from record 0x0897cbd4 + 4. Allocate strlen(name) bytes (NOT length + 1),
//! and strncpy that many bytes from name + (length <= 10 ? 1 : 2). This
//! pads the removed prefix with NUL bytes. Finally invoke the inert tracker
//! diagnostic and return this. No allocation-failure handling exists.
//!
//! Deviations: inline the already-ported record's aligned +4 load; combine
//! three strlen scans of the stable runtime name. The private implementation
//! accepts allocation/name providers for isolated host fixtures; production
//! uses the ported malloc and the real runtime record. Target-width pointer
//! fields stay u32 on hosts, matching existing SlotArray consumers. Volatile
//! memory-helper function pointers prevent LLVM builtin substitution.

use super::slot_array_index_in_bounds::SlotArray;
use super::slot_array_tracker_diagnostic_no_op::slot_array_tracker_diagnostic_no_op;
use crate::libc::{memzero::memzero_aligned, strlen::strlen, strncpy::strncpy};
use crate::runtime::malloc_rt::malloc;

/// Complete six-word container; the existing bounds-check layout is its prefix.
#[repr(C)]
pub struct TrackedSlotArray {
    pub slots: SlotArray,
    pub options: u32,
    pub growth: u32,
    pub tracker_label: u32,
}

const _: [u8; 24] = [0; core::mem::size_of::<TrackedSlotArray>()];
const _: [u8; 20] = [0; core::mem::offset_of!(TrackedSlotArray, tracker_label)];

#[inline(always)]
unsafe fn construct_with(
    this: *mut TrackedSlotArray,
    options: u32,
    capacity: u32,
    growth: u32,
    mut allocate: impl FnMut(usize) -> *mut u8,
    name_source: impl FnOnce() -> *const u8,
) -> *mut TrackedSlotArray {
    this.write(TrackedSlotArray {
        slots: SlotArray { storage: 0, capacity: capacity as i32, count: 0 },
        options, growth, tracker_label: 0,
    });
    let bytes = capacity.wrapping_shl(2) as usize;
    let storage = allocate(bytes);
    (*this).slots.storage = storage as usize as u32;
    let zero = memzero_aligned as unsafe extern "C" fn(*mut u8, usize) -> *mut u8;
    core::ptr::read_volatile(&zero)(storage, bytes);

    let name = name_source();
    let length = strlen(name);
    let label = allocate(length);
    (*this).tracker_label = label as usize as u32;
    let source_offset = if length <= 10 { 1 } else { 2 };
    let copy = strncpy as unsafe extern "C" fn(*mut u8, *const u8, usize) -> *mut u8;
    core::ptr::read_volatile(&copy)(label, name.add(source_offset), length);
    slot_array_tracker_diagnostic_no_op(this.cast());
    this
}

/// Construct an empty pointer-slot array with a retained tracker label.
///
/// # Safety
/// `this` must be aligned and writable for 24 bytes. The runtime tracker
/// record must contain a valid NUL-terminated name. Both allocations must
/// succeed for nonzero sizes and return target-width pointers; neither the
/// original nor this port checks failure. The name must remain stable across
/// allocations, and storage must be word-aligned.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn slot_array_construct(
    this: *mut TrackedSlotArray,
    options: u32,
    capacity: u32,
    growth: u32,
) -> *mut TrackedSlotArray {
    construct_with(this, options, capacity, growth, |size| malloc(size), || {
        (0x0897_cbd8 as *const u32).read() as usize as *const u8
    })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SLOT_ARRAY_CONSTRUCT, 0x1000)
            .map(|pointer| pointer as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn initializes_exact_slot_range_and_shortens_names_at_threshold() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(base) = *FIXTURE else {
            assert!(note_missing_u32_fixture("cxx/slot_array_construct"));
            return;
        };
        unsafe {
            let this = base as *mut TrackedSlotArray;
            let storage = (base + 0x100) as *mut u8;
            let label = (base + 0x200) as *mut u8;
            for capacity in [0u32, 1, 10, 0x4000_0000] {
                for length in [0usize, 1, 2, 10, 11, 32] {
                    let mut name = std::vec![b'X'; length + 1];
                    for index in 0..length { name[index] = b'A' + index as u8 % 26; }
                    name[length] = 0;
                    core::ptr::write_bytes(storage, 0xa5, 64);
                    core::ptr::write_bytes(label, 0xa5, 64);
                    let mut allocations = 0;
                    let returned = construct_with(this, 0x1122_3344, capacity, 0x5566_7788,
                        |size| {
                            allocations += 1;
                            if allocations == 1 {
                                assert_eq!((*this).slots.storage, 0);
                                assert_eq!((*this).slots.capacity, capacity as i32);
                                assert_eq!((*this).slots.count, 0);
                                assert_eq!((*this).options, 0x1122_3344);
                                assert_eq!((*this).growth, 0x5566_7788);
                                assert_eq!((*this).tracker_label, 0);
                                assert_eq!(size, capacity.wrapping_shl(2) as usize);
                                storage
                            } else {
                                assert_eq!(size, length);
                                label
                            }
                        }, || name.as_ptr());
                    assert_eq!(returned, this);
                    assert_eq!((*this).slots.storage, storage as usize as u32);
                    assert_eq!((*this).tracker_label, label as usize as u32);
                    let bytes = capacity.wrapping_shl(2) as usize;
                    for index in 0..64 {
                        assert_eq!(storage.add(index).read(), if index < bytes { 0 } else { 0xa5 });
                    }
                    let offset = if length <= 10 { 1 } else { 2 };
                    for index in 0..64 {
                        let expected = if index >= length { 0xa5 }
                            else if index + offset >= length { 0 }
                            else { name[index + offset] };
                        assert_eq!(label.add(index).read(), expected,
                            "length={length}, index={index}");
                    }
                }
            }
        }
    }
}
