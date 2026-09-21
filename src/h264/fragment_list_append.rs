//! Appends source fragments to a decoder-owned fragment list — original:
//! `FUN_082b516c` @ `0x082b516c`.
//!
//! Raw `osos.dec` establishes the exact 200-byte body
//! `0x082b516c..0x082b5233`; `ldr r0,[r1,#0x10]` at `0x082b5234` starts the
//! next independently linked function. Whole-image A32 decoding finds three
//! inbound plain `bl` calls (0x082b651c, 0x082b68c8, 0x082b6b28), no
//! predicated inbound `bl` calls, and two outbound plain `bl` calls: the
//! fragment-storage reservation helper at 0x082b39f8 and IRAM `__rt_memcpy`
//! through veneer 0x08037db0. The function sums the fragment lengths, records
//! the count in the list header, reserves one contiguous payload range, then
//! appends big-endian payload offsets to the directory while copying each
//! source fragment into that range. It finally updates the list's free-unit
//! and fragment-count halfwords.
//!
//! Deliberate deviations: 0x082b39f8 is unported, so ARM builds invoke its
//! verified four-register ABI directly and host tests install a seam. List
//! pointers and source pointers remain target-width `u32` words, preserving
//! their ARM offsets on 64-bit hosts.

use core::ptr;

const RETAIL_FRAGMENT_STORAGE_RESERVE: usize = 0x082b_39f8;
const HEADER_OFFSET: usize = 8;
const DIRECTORY_OFFSET: usize = 0x0e;
const FREE_UNITS_OFFSET: usize = 0x12;
const FRAGMENT_COUNT_OFFSET: usize = 0x14;
const STORAGE_OFFSET: usize = 0x44;

/// ABI observed at the direct `bl 0x082b39f8`: r2 retains the final source
/// length and r3 retains `fragment_lengths` from this function's entry.
pub type FragmentStorageReserve = unsafe extern "C" fn(*mut u32, u32, u32, *const u16) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_fragment_storage_reserve(
    list: *mut u32,
    total_len: u32,
    last_len: u32,
    fragment_lengths: *const u16,
) -> u32 {
    unsafe {
        core::mem::transmute::<usize, FragmentStorageReserve>(RETAIL_FRAGMENT_STORAGE_RESERVE)(
            list, total_len, last_len, fragment_lengths,
        )
    }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_fragment_storage_reserve(
    _list: *mut u32,
    _total_len: u32,
    _last_len: u32,
    _fragment_lengths: *const u16,
) -> u32 {
    panic!("fragment_list_append requires retail helper 0x082b39f8")
}

#[cfg(target_os = "none")]
pub static mut FRAGMENT_STORAGE_RESERVE: FragmentStorageReserve = retail_fragment_storage_reserve;
#[cfg(not(target_os = "none"))]
pub static mut FRAGMENT_STORAGE_RESERVE: FragmentStorageReserve = missing_fragment_storage_reserve;

#[inline(always)]
fn fragment_storage_reserve() -> FragmentStorageReserve {
    unsafe { ptr::read_volatile(ptr::addr_of!(FRAGMENT_STORAGE_RESERVE)) }
}

/// Appends `fragment_count` byte ranges to `list`'s payload storage.
///
/// `list` must be a valid target-layout list with a u32 storage-base word at
/// `+0x44`; `source_pointers` and `fragment_lengths` contain at least
/// `fragment_count` target pointers and u16 lengths respectively.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn fragment_list_append(
    list: *mut u32,
    fragment_count: u32,
    source_pointers: *const u32,
    fragment_lengths: *const u16,
) {
    let mut total_len = 0u32;
    let mut last_len = 0u32;
    for index in 0..fragment_count as usize {
        last_len = unsafe { fragment_lengths.add(index).read() as u32 };
        total_len = total_len.wrapping_add(last_len);
    }

    let storage = unsafe { list.add(STORAGE_OFFSET / 4).read() as usize as *mut u8 };
    let header = unsafe { storage.add(list.add(HEADER_OFFSET / 4).read() as usize) };
    unsafe {
        header.add(3).write((fragment_count >> 8) as u8);
        header.add(4).write(fragment_count as u8);
    }

    if fragment_count != 0 {
        let mut payload_offset = unsafe {
            fragment_storage_reserve()(list, total_len, last_len, fragment_lengths)
        };
        unsafe {
            let free_units = (list.cast::<u8>().add(FREE_UNITS_OFFSET) as *mut u16).read_unaligned();
            (list.cast::<u8>().add(FREE_UNITS_OFFSET) as *mut u16)
                .write_unaligned(free_units.wrapping_sub((fragment_count as u16).wrapping_mul(2)));
        }
        let mut directory_offset = unsafe {
            (list.cast::<u8>().add(DIRECTORY_OFFSET) as *const u16).read_unaligned() as u32
        };

        for index in 0..fragment_count as usize {
            let len = unsafe { fragment_lengths.add(index).read() as u32 };
            unsafe {
                storage.add(directory_offset as usize).write((payload_offset >> 8) as u8);
                storage.add(directory_offset as usize + 1).write(payload_offset as u8);
                crate::libc::rt_memcpy::__rt_memcpy(
                    storage.add(payload_offset as usize),
                    source_pointers.add(index).read() as usize as *const u8,
                    len as usize,
                );
            }
            directory_offset = directory_offset.wrapping_add(2);
            payload_offset = payload_offset.wrapping_add(len);
        }
    }

    unsafe {
        (list.cast::<u8>().add(FRAGMENT_COUNT_OFFSET) as *mut u16).write_unaligned(fragment_count as u16);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut RESERVE_ARGS: (u32, u32, u32) = (0, 0, 0);
    static mut RESERVE_RESULT: u32 = 0;

    unsafe extern "C" fn reserve(
        list: *mut u32,
        total_len: u32,
        last_len: u32,
        _fragment_lengths: *const u16,
    ) -> u32 {
        unsafe {
            RESERVE_ARGS = (list as usize as u32, total_len, last_len);
            RESERVE_RESULT
        }
    }

    struct Fixture {
        reserve: FragmentStorageReserve,
    }

    impl Fixture {
        unsafe fn install() -> Self {
            let reserve = unsafe { ptr::read_volatile(ptr::addr_of!(FRAGMENT_STORAGE_RESERVE)) };
            unsafe { FRAGMENT_STORAGE_RESERVE = reserve as FragmentStorageReserve; }
            Self { reserve }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe { FRAGMENT_STORAGE_RESERVE = self.reserve; }
        }
    }

    #[test]
    fn records_directory_and_copies_each_fragment() {
        let _lock = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::H264_FRAGMENT_LIST_APPEND, 0x1000) else { return };
        unsafe {
            let list = slab.cast::<u32>();
            let storage = slab.add(0x200);
            let source_a = slab.add(0x300);
            let source_b = slab.add(0x310);
            source_a.copy_from_nonoverlapping([1u8, 2, 3].as_ptr(), 3);
            source_b.copy_from_nonoverlapping([4u8, 5].as_ptr(), 2);
            let sources = slab.add(0x380).cast::<u32>();
            sources.write(source_a as usize as u32);
            sources.add(1).write(source_b as usize as u32);
            let lengths = slab.add(0x390).cast::<u16>();
            lengths.write(3);
            lengths.add(1).write(2);
            list.add(STORAGE_OFFSET / 4).write(storage as usize as u32);
            (list.cast::<u8>().add(HEADER_OFFSET) as *mut u8).write(0x10);
            (list.cast::<u8>().add(DIRECTORY_OFFSET) as *mut u16).write_unaligned(0x40);
            (list.cast::<u8>().add(FREE_UNITS_OFFSET) as *mut u16).write_unaligned(10);
            RESERVE_RESULT = 0x80;
            let fixture = Fixture::install();
            FRAGMENT_STORAGE_RESERVE = reserve;
            fragment_list_append(list, 2, sources, lengths);
            assert_eq!(RESERVE_ARGS, (list as usize as u32, 5, 2));
            assert_eq!((storage.add(0x13).read(), storage.add(0x14).read()), (0, 2));
            assert_eq!((storage.add(0x40).read(), storage.add(0x41).read()), (0, 0x80));
            assert_eq!((storage.add(0x42).read(), storage.add(0x43).read()), (0, 0x83));
            assert_eq!([storage.add(0x80).read(), storage.add(0x81).read(), storage.add(0x82).read(), storage.add(0x83).read(), storage.add(0x84).read()], [1, 2, 3, 4, 5]);
            assert_eq!((list.cast::<u8>().add(FREE_UNITS_OFFSET) as *const u16).read_unaligned(), 6);
            assert_eq!((list.cast::<u8>().add(FRAGMENT_COUNT_OFFSET) as *const u16).read_unaligned(), 2);
            drop(fixture);
        }
    }

    #[test]
    fn zero_fragments_writes_header_and_count_without_reserving() {
        let _lock = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::H264_FRAGMENT_LIST_APPEND_ZERO, 0x1000) else { return };
        unsafe {
            let list = slab.cast::<u32>();
            let storage = slab.add(0x200);
            list.add(STORAGE_OFFSET / 4).write(storage as usize as u32);
            (list.cast::<u8>().add(HEADER_OFFSET) as *mut u8).write(0x20);
            (list.cast::<u8>().add(FREE_UNITS_OFFSET) as *mut u16).write_unaligned(9);
            fragment_list_append(list, 0, ptr::null(), ptr::null());
            assert_eq!((storage.add(0x23).read(), storage.add(0x24).read()), (0, 0));
            assert_eq!((list.cast::<u8>().add(FREE_UNITS_OFFSET) as *const u16).read_unaligned(), 9);
            assert_eq!((list.cast::<u8>().add(FRAGMENT_COUNT_OFFSET) as *const u16).read_unaligned(), 0);
        }
    }
}
