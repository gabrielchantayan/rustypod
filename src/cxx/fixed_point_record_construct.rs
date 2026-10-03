//! Default construction of a four-word homogeneous fixed-point record.

/// fixed_point_record_construct — original: `FUN_0824c758` @ `0x0824c758`.
/// True extent: 28 bytes (`0x0824c758..0x0824c774`), ending with `bx lr`
/// at 0x0824c770 before the independently linked four-word copy member.
/// Whole-image aligned A32 BL decoding finds two inbound plain calls at
/// 0x0824cc98 and 0x0824cca0, no predicated calls, and no outbound calls.
///
/// Clears words 2, 1, and 0 in that order, then sets word 3 to 0x10000
/// (16.16 fixed-point unity). Returns the original record pointer: retail
/// leaves r0 untouched and its caller uses it to address the next subobject.
/// Deliberate deviations: volatile stores preserve retail write ordering;
/// u32 word offsets preserve the four-byte target layout on host builds.
/// No NULL guard or other semantic deviation.
///
/// # Safety
/// `record` must point to four aligned, writable u32 words.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn fixed_point_record_construct(record: *mut u32) -> *mut u32 {
    record.add(2).write_volatile(0);
    record.add(1).write_volatile(0);
    record.write_volatile(0);
    record.add(3).write_volatile(0x10000);
    record
}

#[cfg(test)]
mod tests {
    use super::fixed_point_record_construct;

    #[test]
    fn replaces_all_fields_without_touching_neighbors_and_returns_record() {
        for fill in [0, u32::MAX, 0xa5a5_5a5a, 0x8000_0000] {
            let mut words = [fill; 6];
            let record = unsafe { words.as_mut_ptr().add(1) };
            assert_eq!(unsafe { fixed_point_record_construct(record) }, record);
            assert_eq!(words, [fill, 0, 0, 0, 0x10000, fill]);
            words[2] = 0x1234_5678;
            words[4] = 0xffff_0000;
            assert_eq!(unsafe { fixed_point_record_construct(record) }, record);
            assert_eq!(words, [fill, 0, 0, 0, 0x10000, fill]);
        }
    }
}
