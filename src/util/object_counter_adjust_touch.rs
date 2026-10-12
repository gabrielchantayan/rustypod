//! Object counter adjustment and modification timestamp.
//!
//! Original `FUN_0803c0f0` at **0x0803c0f0**, true size **60 bytes**
//! (`0x0803c0f0..0x0803c12c`, next function begins with push {r4-r6,lr}).
//! Whole-image aligned ARM word decoding finds two plain inbound BLs at
//! 0x08047444 and 0x08048494, zero predicated inbound BLs. The body has one
//! plain BL at 0x0803c120 to the already-ported timestamp wrapper 0x08054fc4,
//! zero predicated BLs. Callers adjust by +1 and -1 before committing.
//!
//! Add a wrapping delta to object word +0x130 for selectors 1 or 0x100,
//! otherwise word +0x12c. OR the first halfword with 0xff00, then store
//! current UTC-corrected Macintosh-epoch seconds at +0x08.
//! Deliberate deviations: none; opaque fields retain verified byte offsets.

use core::ptr;

#[inline(always)]
unsafe fn adjust_with(object: *mut u8, selector: i32, delta: i32, timestamp: unsafe extern "C" fn() -> i32) {
    let offset = if selector == 1 || selector == 0x100 { 0x130 } else { 0x12c };
    let counter = object.add(offset).cast::<u32>();
    ptr::write(counter, ptr::read(counter).wrapping_add(delta as u32));
    let flags = object.cast::<u16>();
    ptr::write(flags, ptr::read(flags) | 0xff00);
    let seconds = timestamp();
    ptr::write(object.add(8).cast::<i32>(), seconds);
}

/// Adjust the selected counter, mark dirty, and timestamp the object.
///
/// Original: 0x0803c0f0, 60 bytes; two plain inbound BLs, no predicated
/// inbound BLs; one plain outgoing BL, no predicated outgoing BLs.
///
/// # Safety
/// `object` must be a writable, four-byte-aligned allocation of at least
/// 0x134 bytes, with initialized flags and counter fields. The current-time
/// subsystem must be initialized as required by the timestamp callee.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_counter_adjust_touch(object: *mut u8, selector: i32, delta: i32) {
    adjust_with(object, selector, delta,
        crate::time::current_mac_epoch_seconds::current_mac_epoch_seconds_with_utc_offset);
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn negative_timestamp() -> i32 { i32::MIN }

    #[test]
    fn selectors_wrapping_and_adjacent_fields() {
        for selector in [1, 0x100, 0, 2, 0x101, -1, i32::MIN, i32::MAX] {
            for (initial, delta) in [(0u32, -1), (u32::MAX, 1), (0x7fff_ffff, 1),
                                     (0x8000_0000, -1), (7, 0), (7, i32::MIN)] {
                for flags in [0u16, 0x005a, 0xa512, 0xffff] {
                    let mut object = [0x7654_3210u32; 0x134 / 4];
                    object[0] = 0xabcdu32 << 16 | flags as u32;
                    object[0x12c / 4] = initial;
                    object[0x130 / 4] = initial;
                    let mut expected = object;
                    let index = if selector == 1 || selector == 0x100 { 0x130 / 4 } else { 0x12c / 4 };
                    expected[index] = initial.wrapping_add(delta as u32);
                    expected[0] |= 0xff00;
                    expected[2] = i32::MIN as u32;
                    unsafe { adjust_with(object.as_mut_ptr().cast(), selector, delta, negative_timestamp); }
                    assert_eq!(object, expected, "selector={selector} delta={delta} flags={flags:#x}");
                }
            }
        }
    }
}
