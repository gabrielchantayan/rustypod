//! Filename-selected record, `FUN_081f3ff4` @ `0x081f3ff4`.
//! Raw extent [0x081f3ff4, 0x081f4058): 100 bytes, followed by an
//! independent push prologue. Verified calls: one plain outbound BL to
//! 0x08091f84, zero predicated outbound BL; zero plain inbound BL and two
//! predicated inbound BLs at 0x081e319c and 0x082060c0.
//!
//! Classify the filename and select one of three 16-byte records. Classifier
//! failure returns one without touching out. Kinds 0..2 store the selected
//! record and return zero; other kinds clear out and return one.
//! Deviations: a byte local replaces the saved incoming r3 stack word, which
//! is not an argument. Structured selection replaces conditional ARM stores.
//! The verified unported classifier uses the existing filename classifier ABI.

use super::stream_create_for_filename::FilenameClassify;

#[cfg(not(target_os = "none"))]
pub static mut RECORD_FILENAME_CLASSIFY: Option<FilenameClassify> = None;

/// Select a record using the resident filename classifier.
///
/// # Safety
/// `filename` must meet the classifier's requirements (including its five-byte
/// suffix read). On classifier success, `out` must be writable. For kinds 0..2,
/// `records` must identify storage containing the corresponding 16-byte record.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn filename_record_select(
    records: *mut u8, filename: *const u8, out: *mut *mut u8,
) -> u32 {
    let mut kind = 0u8;
    #[cfg(target_os = "none")]
    let classify: FilenameClassify = unsafe { core::mem::transmute(0x0809_1f84usize) };
    #[cfg(not(target_os = "none"))]
    let classify = unsafe { RECORD_FILENAME_CLASSIFY.expect("filename classifier not installed") };
    if unsafe { classify(filename, &mut kind) } != 0 { return 1; }
    if kind > 2 {
        unsafe { out.write(core::ptr::null_mut()) };
        return 1;
    }
    unsafe { out.write(records.wrapping_add(kind as usize * 16)) };
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn classify(input: *const u8, kind: *mut u8) -> u32 {
        unsafe { kind.write(input.read()); input.add(1).read() as u32 }
    }

    #[test]
    fn selection_rejection_and_classifier_failure() {
        unsafe {
            RECORD_FILENAME_CLASSIFY = Some(classify);
            let mut storage = [0u32; 12];
            let records = storage.as_mut_ptr().cast::<u8>();
            for kind in 0..=255u8 {
                let input = [kind, 0];
                let mut out = records;
                let status = filename_record_select(records, input.as_ptr(), &mut out);
                if kind <= 2 {
                    assert_eq!(status, 0);
                    assert_eq!(out, records.add(kind as usize * 16));
                } else {
                    assert_eq!(status, 1);
                    assert!(out.is_null());
                }
                for failure in [1, 255] {
                    let input = [kind, failure];
                    let mut out = records;
                    assert_eq!(filename_record_select(records, input.as_ptr(), &mut out), 1);
                    assert_eq!(out, records);
                    assert_eq!(filename_record_select(core::ptr::null_mut(), input.as_ptr(), core::ptr::null_mut()), 1);
                }
            }
            RECORD_FILENAME_CLASSIFY = None;
        }
    }
}
