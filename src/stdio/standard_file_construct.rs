//! standard_file_construct — `FUN_08266c18` @ 0x08266c18.
//! True extent: 88 bytes through 0x08266c70 (72 instruction bytes and
//! four literal words). Raw A32: zero plain BL, one predicated BLEQ to
//! cxx_new_handler_dispatch @ 0x08266abc; two inbound plain BL sites at
//! 0x083d980c and 0x083d9dc8, no predicated inbound BL.
//!
//! Constructs the FILE-pointer member of the standard-stream wrapper:
//! selector 0/1/2 chooses stdin/stdout/stderr; any other selector stores
//! NULL before reporting code 10 with descriptor 0x0897af88. Returns the
//! member address even when the diagnostic returns.
//!
//! Deliberate deviations: reuse stream_file's modeled static FILE objects
//! instead of the firmware's fixed-address objects (0x08b2f820/64/a8).
//! The pointer member is native-width on hosts, four bytes on target.
//! The existing C++ dispatch supplies its documented message-builder seam;
//! unused r2/r3 diagnostic arguments are zero rather than register residue.

use super::stream_file::{AdsFile, stdin_file, stdout_file, stderr_file};
use crate::heap::new_handler::cxx_new_handler_dispatch;

/// Initialize one writable, aligned FILE-pointer member and return it.
///
/// # Safety
/// `slot` must point to a writable FILE-pointer member. Any registered
/// C++ error handler must permit code 10 and the firmware descriptor.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn standard_file_construct(
    slot: *mut *mut AdsFile,
    selector: u32,
) -> *mut *mut AdsFile {
    let file = match selector {
        0 => stdin_file(),
        1 => stdout_file(),
        2 => stderr_file(),
        _ => core::ptr::null_mut(),
    };
    slot.write(file);
    if file.is_null() {
        cxx_new_handler_dispatch(10, 0x0897_af88, 0, 0);
    }
    slot
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_bind_the_existing_standard_stream_objects() {
        for (selector, expected) in [(0, stdin_file()), (1, stdout_file()), (2, stderr_file())] {
            let mut members = [core::ptr::null_mut(), stderr_file(), stdin_file()];
            let slot = core::ptr::addr_of_mut!(members[1]);
            unsafe {
                assert_eq!(standard_file_construct(slot, selector), slot);
            }
            assert_eq!(members, [core::ptr::null_mut(), expected, stdin_file()]);
        }
    }

    #[test]
    fn invalid_selectors_clear_only_the_member_and_return_after_reporting() {
        let _guard = crate::heap::new_handler::tests::LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for selector in [3, 4, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
            let mut members = [stdin_file(), stdout_file(), stderr_file()];
            let slot = core::ptr::addr_of_mut!(members[1]);
            unsafe {
                assert_eq!(standard_file_construct(slot, selector), slot);
            }
            assert_eq!(members, [stdin_file(), core::ptr::null_mut(), stderr_file()]);
        }
    }
}
