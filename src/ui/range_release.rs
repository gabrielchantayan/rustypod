//! Releases an opaque range operation when its remaining item indices do not
//! overlap an inclusive interval.
//!
//! `range_operation_release_outside_interval` — retailOS `FUN_0821b584` @
//! `0x0821b584`. Raw ARM is exactly 144 bytes (`0x0821b584..0x0821b614`);
//! `0x0821b614` starts the next separately linked function. Decoding every
//! aligned ARM B/BL immediate finds four inbound plain `bl` call sites
//! (`0x0821ab6c`, `0x0821abb8`, `0x0821b3fc`, `0x0821b470`) and no predicated
//! inbound call sites. Its body makes three plain `bl` calls and one
//! predicated fatal `bleq`.
//!
//! It acquires an opaque operation from `owner+4`, resets its cursor to its
//! head, and, when requested, scans remaining item indices. An item inside the
//! inclusive interval retains the operation; otherwise it releases it. A
//! failed acquire returns zero.
//!
//! Deliberate deviations: the three unresolved direct callees retain explicit
//! operation-shaped seam names rather than invented identities. Target builds
//! invoke their verified fixed addresses through `blx`; host tests install
//! recorders. Target pointers remain u32 words, including on 64-bit hosts.

use core::ptr;

const OWNER_OPERATION_SOURCE_WORD: usize = 1;
const OPERATION_HEAD_WORD: usize = 10;
const OPERATION_CURSOR_WORD: usize = 12;
const ITEM_INDEX_WORD_FROM_NEXT_RESULT: usize = 1;

pub type RangeOperationAcquire = unsafe extern "C" fn(u32) -> u32;
pub type RangeOperationNext = unsafe extern "C" fn(u32) -> u32;
pub type RangeOperationRelease = unsafe extern "C" fn(u32);

#[derive(Clone, Copy)]
pub struct RangeReleaseOps {
    pub acquire: RangeOperationAcquire,
    pub next: RangeOperationNext,
    pub release: RangeOperationRelease,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_acquire(source: u32) -> u32 {
    core::mem::transmute::<usize, RangeOperationAcquire>(0x081f_0700)(source)
}
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_next(operation: u32) -> u32 {
    core::mem::transmute::<usize, RangeOperationNext>(0x0811_f244)(operation)
}
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_release(operation: u32) {
    core::mem::transmute::<usize, RangeOperationRelease>(0x0811_f150)(operation)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_acquire(_source: u32) -> u32 { panic!("range_release requires unresolved FUN_081f0700") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_next(_operation: u32) -> u32 { panic!("range_release requires unresolved FUN_0811f244") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release(_operation: u32) { panic!("range_release requires unresolved FUN_0811f150") }

#[cfg(target_os = "none")]
pub const DEFAULT_RANGE_RELEASE_OPS: RangeReleaseOps = RangeReleaseOps { acquire: firmware_acquire, next: firmware_next, release: firmware_release };
#[cfg(not(target_os = "none"))]
pub const DEFAULT_RANGE_RELEASE_OPS: RangeReleaseOps = RangeReleaseOps { acquire: missing_acquire, next: missing_next, release: missing_release };

pub static mut RANGE_RELEASE_OPS: RangeReleaseOps = DEFAULT_RANGE_RELEASE_OPS;

#[inline(always)]
unsafe fn ops() -> RangeReleaseOps {
    ptr::read_volatile(ptr::addr_of!(RANGE_RELEASE_OPS))
}

#[inline(always)]
unsafe fn target_word(address: u32, word: usize) -> u32 {
    ptr::read((address as usize as *const u32).add(word))
}

#[inline(always)]
unsafe fn write_target_word(address: u32, word: usize, value: u32) {
    ptr::write((address as usize as *mut u32).add(word), value)
}

/// Returns one after releasing an acquired operation, zero when acquisition
/// fails or a scanned item lies within `lower..=upper`.
///
/// # Safety
/// `owner` and every nonzero target pointer reached through the chosen seams
/// must address valid aligned target-word layouts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn range_operation_release_outside_interval(
    owner: *const u8,
    _initial_index: u32,
    scan_items: u32,
    lower: i32,
    upper: i32,
) -> u32 {
    if lower == -1 || upper == -1 {
        crate::heap::veneers::heap_panic();
    }

    let operation = (ops().acquire)(target_word(owner as u32, OWNER_OPERATION_SOURCE_WORD));
    if operation == 0 {
        return 0;
    }

    write_target_word(operation, OPERATION_CURSOR_WORD, target_word(target_word(operation, OPERATION_HEAD_WORD), 0));
    if scan_items == 0 {
        loop {
            let item = (ops().next)(operation);
            if item == 0 {
                break;
            }
            let index = target_word(item, ITEM_INDEX_WORD_FROM_NEXT_RESULT) as i32;
            if lower <= index && index <= upper {
                return 0;
            }
        }
    }

    (ops().release)(operation);
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};

    static mut NEXT_ITEMS: [u32; 4] = [0; 4];
    static mut NEXT_COUNT: usize = 0;
    static mut NEXT_INDEX: usize = 0;
    static mut ACQUIRE_SOURCE: u32 = 0;
    static mut RELEASED: u32 = 0;

    unsafe extern "C" fn acquire(source: u32) -> u32 { ACQUIRE_SOURCE = source; source + 0x100 }
    unsafe extern "C" fn next(_operation: u32) -> u32 {
        let item = NEXT_ITEMS[NEXT_INDEX];
        NEXT_INDEX += 1;
        item
    }
    unsafe extern "C" fn release(operation: u32) { RELEASED = operation; }

    struct Reset(RangeReleaseOps);
    impl Drop for Reset { fn drop(&mut self) { unsafe { RANGE_RELEASE_OPS = self.0; } } }

    fn arrange() -> Option<(*mut u8, Reset)> {
        let base = try_map_u32_slab(hints::RANGE_RELEASE, 0x1000)?;
        unsafe {
            let previous = RANGE_RELEASE_OPS;
            RANGE_RELEASE_OPS = RangeReleaseOps { acquire, next, release };
            NEXT_ITEMS = [0; 4]; NEXT_COUNT = 0; NEXT_INDEX = 0; ACQUIRE_SOURCE = 0; RELEASED = 0;
            ptr::write_bytes(base, 0, 0x1000);
            let address = base as usize as u32;
            ptr::write((base as *mut u32).add(1), address + 0x400);
            ptr::write((base.add(0x500) as *mut u32).add(10), address + 0x600);
            ptr::write((base.add(0x600) as *mut u32), address + 0x600);
            Some((base, Reset(previous)))
        }
    }

    #[test]
    fn releases_when_no_scanned_item_is_in_interval() {
        let Some((base, _reset)) = arrange() else { return };
        unsafe {
            let address = base as usize as u32;
            NEXT_ITEMS = [address + 0x700, address + 0x710, 0, 0]; NEXT_COUNT = 2;
            ptr::write((base.add(0x704) as *mut u32), 3);
            ptr::write((base.add(0x714) as *mut u32), 9);
            assert_eq!(range_operation_release_outside_interval(base, 99, 0, 4, 8), 1);
            assert_eq!(ACQUIRE_SOURCE, address + 0x400);
            assert_eq!(RELEASED, address + 0x500);
            assert_eq!(ptr::read((base.add(0x500) as *const u32).add(12)), address + 0x600);
        }
    }

    #[test]
    fn retained_when_an_item_is_on_an_inclusive_boundary() {
        let Some((base, _reset)) = arrange() else { return };
        unsafe {
            let address = base as usize as u32;
            NEXT_ITEMS = [address + 0x700, 0, 0, 0];
            ptr::write(base.add(0x704).cast::<u32>(), 4);
            assert_eq!(range_operation_release_outside_interval(base, 0, 0, 4, 8), 0);
            assert_eq!(RELEASED, 0);
        }
    }

    #[test]
    fn skips_the_scan_when_requested() {
        let Some((base, _reset)) = arrange() else { return };
        unsafe {
            assert_eq!(range_operation_release_outside_interval(base, 0, 1, 4, 8), 1);
            assert_eq!(NEXT_INDEX, 0);
        }
    }
}
