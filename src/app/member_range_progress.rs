//! retailOS `FUN_081f0fb8` @ 0x081f0fb8, 108 bytes (next entry 0x081f1024).
//! Two incoming plain BLs, zero predicated BLs; body: three plain BLs,
//! zero predicated BLs and one virtual BLX. If member +0x48 is absent,
//! return zero. Snapshot the measurement of +0xc4; when +0x30 is zero,
//! clear the range at +0x14 and return one. Otherwise invoke member virtual
//! slot +0x10 with flag one and return whether the new unsigned measurement
//! exceeds the snapshot (wrapping is not progress).
//! Deliberate deviations: unresolved 0x081a8514 retains fixed-address dispatch;
//! 0x083dbc04 uses the existing list_range_clear port. Host injection isolates
//! firmware dependencies, while target pointer fields remain four-byte words.

use crate::cxx::list_range_clear::list_range_clear;

type Measure = unsafe extern "C" fn(*mut u8) -> u32;
type Advance = unsafe fn(*mut u8);
type Clear = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_measure(member: *mut u8) -> u32 {
    let call: Measure = unsafe { core::mem::transmute(0x081a_8514usize) };
    unsafe { call(member) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_measure(_: *mut u8) -> u32 {
    panic!("member_range_progress requires retailOS 0x081a8514")
}

unsafe fn virtual_advance(this: *mut u8) {
    let member = unsafe { this.add(0x48).cast::<u32>().read() } as usize as *mut u32;
    let table = unsafe { member.read() } as usize as *const u32;
    let address = unsafe { table.add(4).read() };
    let call: unsafe extern "C" fn(*mut u32, u32) = unsafe {
        core::mem::transmute(address as usize)
    };
    unsafe { call(member, 1) };
}

unsafe fn progress_with(this: *mut u8, measure: Measure, advance: Advance, clear: Clear) -> u32 {
    if unsafe { this.add(0x48).cast::<u32>().read() } == 0 {
        return 0;
    }
    let before = unsafe { measure(this.add(0xc4)) };
    if unsafe { this.add(0x30).cast::<u32>().read() } == 0 {
        unsafe { clear(this.add(0x14)) };
        return 1;
    }
    unsafe { advance(this) };
    u32::from(unsafe { measure(this.add(0xc4)) } > before)
}

/// Clears an embedded range or requests member progress and compares measurements.
///
/// # Safety
/// `this` must be aligned and readable through +0xc7, with valid embedded
/// range/measurement objects and a target-width member/vtable when selected.
/// Firmware callbacks may mutate those objects; no Rust references may alias them.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn member_range_progress(this: *mut u8) -> u32 {
    unsafe { progress_with(this, retail_measure, virtual_advance, list_range_clear) }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn measure(member: *mut u8) -> u32 {
        unsafe { member.cast::<u32>().read() }
    }
    unsafe fn advance(this: *mut u8) {
        let next = unsafe { this.add(0xc8).cast::<u32>().read() };
        unsafe { this.add(0xc4).cast::<u32>().write(next) };
    }
    unsafe extern "C" fn clear(range: *mut u8) {
        unsafe { range.cast::<u32>().write(0) };
    }
    unsafe extern "C" fn forbidden(_: *mut u8) -> u32 {
        panic!("absent member must not be measured")
    }

    #[test]
    fn absent_member_leaves_range_and_measurement_untouched() {
        let mut object = [0u32; 51];
        object[5] = 17;
        object[49] = 99;
        assert_eq!(unsafe { progress_with(object.as_mut_ptr().cast(), forbidden, advance, clear) }, 0);
        assert_eq!((object[5], object[49]), (17, 99));
    }

    #[test]
    fn disabled_mode_clears_range_even_without_measurement_growth() {
        let mut object = [0u32; 51];
        object[18] = 1;
        object[5] = 17;
        object[49] = u32::MAX;
        assert_eq!(unsafe { progress_with(object.as_mut_ptr().cast(), measure, advance, clear) }, 1);
        assert_eq!((object[5], object[49]), (0, u32::MAX));
    }

    #[test]
    fn active_mode_requires_strict_unsigned_growth_not_wraparound() {
        for (before, after, expected) in [
            (0, 1, 1), (7, 7, 0), (7, 6, 0),
            (0x7fff_ffff, 0x8000_0000, 1), (u32::MAX, 0, 0),
            (0, u32::MAX, 1),
        ] {
            let mut object = [0u32; 51];
            object[18] = 1;
            object[12] = 1;
            object[5] = 17;
            object[49] = before;
            object[50] = after;
            assert_eq!(unsafe { progress_with(object.as_mut_ptr().cast(), measure, advance, clear) }, expected);
            assert_eq!(object[49], after);
            assert_eq!(object[5], 17);
        }
    }
}
