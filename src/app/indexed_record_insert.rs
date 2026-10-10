//! Insert a 20-byte record into an owner's indexed array.
//!
//! retailOS 0x0807f320: 200 bytes, [0x0807f320,0x0807f3e8).
//! Raw A32 scan: one incoming plain BL (0x08059200), one BLNE
//! (0x080595b4); body has four plain BLs and one BLNE.
//! When count equals capacity, allocate (capacity + 3) * 20 zeroed bytes,
//! copy existing records and free the old array before publishing storage.
//! Clamp the unsigned index to count, shift the suffix right with bcopy,
//! copy the new record, then increment count. Allocation failure returns
//! -108 without modifying the owner. Arithmetic wraps at target word width.
//! Deviations: calls established Rust callee ports instead of retail addresses;
//! owner fields remain target-width words on hosts. No new dispatch seam.
//! ARM codegen: 55 versus 50 stock instructions; bcopy inlines into
//! __aeabi_memmove, while allocation, guarded copy, free and IRAM memcpy
//! retain BL relocations. Growth, unsigned clamp, suffix guard and -108
//! failure paths are preserved; match.py prints the expected structural diff.

use crate::heap::veneers::{calloc_tag4, free_tag4};
use crate::libc::bcopy::bcopy;
use crate::libc::bcopy_guarded::bcopy_guarded;
use crate::libc::iram_veneers::iram_memcpy_veneer;

/// # Safety
/// `owner` is an aligned writable object of at least 0x74 bytes, with count
/// at +0x10, capacity at +0x14 and a target-width array pointer at +0x70.
/// Storage holds capacity 20-byte records; `record` is word-aligned and
/// readable for 20 bytes, and remains live through growth and suffix shifting.
/// Counts must describe valid allocations; the old array is tag-4 owned.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn indexed_record_insert(owner: *mut u32, index: u32, record: *const u8) -> i32 {
    if owner.add(4).read() == owner.add(5).read() {
        let bytes = owner.add(5).read().wrapping_add(3).wrapping_mul(20);
        let replacement = calloc_tag4(bytes as usize);
        if replacement.is_null() { return -108; }
        let old = owner.add(28).read() as usize as *mut u8;
        if !old.is_null() {
            bcopy_guarded(old, replacement, owner.add(4).read().wrapping_mul(20) as i32);
            free_tag4(owner.add(28).read() as usize as *mut u8);
        }
        owner.add(28).write(replacement as usize as u32);
        owner.add(5).write(owner.add(5).read().wrapping_add(3));
    }
    let count = owner.add(4).read();
    let index = index.min(count);
    let storage = owner.add(28).read() as usize as *mut u8;
    let slot = storage.wrapping_add(index.wrapping_mul(20) as usize);
    let suffix = count.wrapping_sub(index);
    if suffix != 0 {
        bcopy(slot, slot.wrapping_add(20), suffix.wrapping_mul(20) as usize);
    }
    iram_memcpy_veneer(slot, record, 20);
    owner.add(4).write(owner.add(4).read().wrapping_add(1));
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::{HEAP_OPS, HeapVeneerOps, tests::mock_heap};
    use core::ptr;

    static mut ALLOCATION: *mut u8 = ptr::null_mut();
    static mut REQUEST: (usize, usize) = (0, 0);
    static mut FREED: usize = 0;
    unsafe extern "C" fn allocate(_: *mut HeapDescriptorDescriptor, bytes: usize, tag: usize) -> *mut u8 {
        REQUEST = (bytes, tag);
        let result = ALLOCATION;
        if !result.is_null() { result.write_bytes(0, bytes); }
        result
    }
    unsafe extern "C" fn release(_: *mut HeapDescriptorDescriptor, block: *mut u8, tag: usize) {
        assert_eq!(tag, 4);
        FREED = block as usize;
    }
    struct Restore(HeapVeneerOps);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { ptr::addr_of_mut!(HEAP_OPS).write(self.0); } }
    }

    #[test]
    fn insertion_clamps_shifts_grows_and_preserves_owner_on_failure() {
        let _guard = mock_heap();
        let slab = crate::testing::try_map_u32_slab(
            crate::testing::hints::INDEXED_RECORD_INSERT, 0x1000,
        ).expect("target-width record array fixture");
        unsafe {
            let saved = ptr::addr_of!(HEAP_OPS).read();
            let _restore = Restore(saved);
            HEAP_OPS.alloc_zero = allocate;
            HEAP_OPS.free = release;
            let old = slab.cast::<[u32; 5]>();
            let replacement = slab.add(0x400);
            for count in 0..=3u32 {
                for index in [0, 1, 2, 3, u32::MAX] {
                    for grow in [false, true] {
                        let mut owner = [0xa5a5_a5a5; 29];
                        owner[4] = count;
                        owner[5] = if grow { count } else { count + 1 };
                        owner[28] = if count == 0 && grow { 0 } else { slab as usize as u32 };
                        let before = owner;
                        let mut expected = std::vec::Vec::new();
                        for n in 0..count {
                            let value = [n + 10; 5];
                            old.add(n as usize).write(value);
                            expected.push(value);
                        }
                        old.add(count as usize).write([0xdead_beef; 5]);
                        old.add(count as usize + 1).write([0xdead_beef; 5]);
                        let record = [99u32, 98, 97, 96, 95];
                        expected.insert(index.min(count) as usize, record);
                        ALLOCATION = replacement;
                        REQUEST = (0, 0);
                        FREED = 0;
                        assert_eq!(indexed_record_insert(owner.as_mut_ptr(), index, record.as_ptr().cast()), 0);
                        let result = owner[28] as usize as *const [u32; 5];
                        assert_eq!(core::slice::from_raw_parts(result, expected.len()), expected.as_slice());
                        let mut expected_owner = before;
                        expected_owner[4] = count + 1;
                        if grow {
                            expected_owner[5] = count + 3;
                            expected_owner[28] = replacement as usize as u32;
                            assert_eq!(REQUEST, (((count + 3) * 20) as usize, 4));
                            assert_eq!(FREED, before[28] as usize);
                        } else {
                            assert_eq!(REQUEST, (0, 0));
                            assert_eq!(FREED, 0);
                            assert_eq!(old.add(count as usize + 1).read(), [0xdead_beef; 5]);
                        }
                        assert_eq!(owner, expected_owner);
                    }
                }
            }
            let mut owner = [0x12345678u32; 29];
            owner[4] = 2; owner[5] = 2; owner[28] = slab as usize as u32;
            let before = owner;
            let contents = [42u32; 10];
            ptr::copy_nonoverlapping(contents.as_ptr(), slab.cast(), 10);
            ALLOCATION = ptr::null_mut(); FREED = 0;
            assert_eq!(indexed_record_insert(owner.as_mut_ptr(), 0, ptr::null()), -108);
            assert_eq!(owner, before);
            assert_eq!(core::slice::from_raw_parts(slab.cast::<u32>(), 10), &contents);
            assert_eq!(FREED, 0);
        }
    }
}
