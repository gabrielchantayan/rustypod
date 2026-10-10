//! Face-backed record data selection. Field roles beyond the selector are
//! intentionally neutral: the raw code establishes copying, not their format.

#[repr(C)]
pub struct FtRecordSource {
    pub reserved: [u32; 5],
    pub metadata: u32,
    pub primary_data: u32,
    pub alternate_data: u32,
}

#[repr(C)]
pub struct FtRecordFace {
    pub reserved: [u32; 103],
    pub metadata_a: u32,
    pub metadata_b: u32,
    pub reserved_tail: [u32; 15],
    pub source: *const FtRecordSource,
}

#[repr(C)]
pub struct FtFaceRecord {
    pub face: *const FtRecordFace,
    pub reserved: [u32; 3],
    pub selected_data: u32,
    pub metadata: u32,
    pub metadata_a: u32,
    pub metadata_b: u32,
}

/// Original FUN_0809cae8, load address 0x0809cae8: 72 instruction bytes
/// through 0x0809cb30. The next function is 0x0809cb5c; the intervening
/// 44 bytes are a filename pointer and assertion string, not instructions.
/// Whole-image ARM-word scan finds two plain incoming BLs (0x08392c38,
/// 0x08392c4c), zero predicated incoming BLs; the body has zero BLs and
/// one BEQ tail call to ft_panic at 0x0804e154.
///
/// Copy face words +0x19c/+0x1a0 and source +0x14 to record +0x18/+0x1c/
/// +0x14, then select source +0x18 for zero selector or +0x1c otherwise
/// into record +0x10. Zero selected data triggers assertion line 48.
/// Deliberate deviations: typed pointer fields widen only on hosts; no
/// invented source-format identity. The assertion preserves the firmware
/// filename address 0x0890de4c. Ghidra's u64 return is spurious; callers
/// ignore the return, and the normal raw path merely leaves r0 unchanged.
///
/// # Safety
/// All three records must be valid and suitably aligned, with the writable
/// record disjoint from its face and source. No null-pointer guards exist.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_face_record_select(
    record: *mut FtFaceRecord, selector: u32,
) -> *mut FtFaceRecord {
    let face = (*record).face;
    let source = (*face).source;
    (*record).metadata_a = (*face).metadata_a;
    (*record).metadata_b = (*face).metadata_b;
    (*record).metadata = (*source).metadata;
    let selected = if selector == 0 { (*source).primary_data } else { (*source).alternate_data };
    (*record).selected_data = selected;
    if selected == 0 {
        crate::ft::trace::ft_panic(
            b"assertion failed on line %d of file %s\n\0".as_ptr(),
            48, 0x0890de4c, source as usize as u32,
        );
    }
    record
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_is_zero_vs_any_nonzero_and_preserves_unrelated_fields() {
        let source = FtRecordSource {
            reserved: [0xabcdef01; 5], metadata: 0xffffffff,
            primary_data: 0x12345678, alternate_data: 0x87654321,
        };
        let face = FtRecordFace {
            reserved: [0; 103], metadata_a: 0x80000000, metadata_b: 0xfeedbeef,
            reserved_tail: [0; 15], source: &source,
        };
        let mut record = FtFaceRecord {
            face: &face, reserved: [7, 8, 9], selected_data: 0,
            metadata: 0, metadata_a: 0, metadata_b: 0,
        };
        for selector in [0, 1, 2, 0x80000000, u32::MAX, 0] {
            let returned = unsafe { ft_face_record_select(&mut record, selector) };
            assert_eq!(returned, &mut record as *mut _);
            assert_eq!(record.selected_data, if selector == 0 { source.primary_data } else { source.alternate_data });
            assert_eq!((record.metadata, record.metadata_a, record.metadata_b),
                       (source.metadata, face.metadata_a, face.metadata_b));
            assert_eq!(record.reserved, [7, 8, 9]);
            assert_eq!(record.face, &face as *const _);
        }
    }

    // The zero-selected-data path diverges through extern-C ft_panic/exit;
    // it cannot be unwound in a host test (same limitation as ft/stream).
}

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::offset_of!(FtRecordFace, metadata_a) == 0x19c);
    assert!(core::mem::offset_of!(FtRecordFace, metadata_b) == 0x1a0);
    assert!(core::mem::offset_of!(FtRecordFace, source) == 0x1e0);
    assert!(core::mem::offset_of!(FtRecordSource, metadata) == 0x14);
    assert!(core::mem::offset_of!(FtRecordSource, primary_data) == 0x18);
    assert!(core::mem::offset_of!(FtRecordSource, alternate_data) == 0x1c);
    assert!(core::mem::offset_of!(FtFaceRecord, selected_data) == 0x10);
    assert!(core::mem::offset_of!(FtFaceRecord, metadata) == 0x14);
    assert!(core::mem::offset_of!(FtFaceRecord, metadata_a) == 0x18);
    assert!(core::mem::offset_of!(FtFaceRecord, metadata_b) == 0x1c);
};
