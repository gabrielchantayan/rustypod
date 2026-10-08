//! Class check through a target-width handle cell.

/// liti_handle_class_check — original: `FUN_081070a0` @ 0x081070a0.
/// True extent: 8 bytes, ending at the independent constructor at 0x081070a8.
/// Whole-image aligned A32 decoding verifies two plain inbound BLs
/// (0x08143404, 0x08224124), zero predicated inbound BLs, and zero internal BLs.
///
/// Raw words e5900000 eafd42c2 load the handle's first word and tail-branch
/// to 0x08057bb4 (`liti_field_class_check`). Return 1 exactly when that
/// payload is non-NULL and its word-one pointer names a 'liti'-tagged object;
/// return 0 otherwise. Both callers check a locally constructed handle
/// before operating on its payload.
///
/// Deliberate deviations: Rust expresses the tail branch as a returning call
/// to the existing predicate port. All pointer cells retain target u32 width
/// on hosts; no additional NULL guard or new callee seam is introduced.
///
/// # Safety
/// `handle` must be non-NULL, four-byte aligned and readable for one word.
/// Its payload must satisfy `liti_field_class_check`'s safety contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn liti_handle_class_check(handle: *const u32) -> u32 {
    let payload = handle.read() as usize as *const u8;
    crate::app::liti_field_class_check::liti_field_class_check(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_payload_returns_zero_without_reading_adjacent_handle_word() {
        let handle = [0, u32::MAX];
        assert_eq!(unsafe { liti_handle_class_check(handle.as_ptr()) }, 0);
        assert_eq!(handle, [0, u32::MAX]);
    }

    #[test]
    fn follows_target_width_cells_and_rejects_null_or_mismatched_class() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::LITI_HANDLE_CLASS_CHECK, 0x1000,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture("app::liti_handle_class_check"));
            return;
        };
        unsafe {
            let payload = slab.cast::<u32>();
            let target = payload.add(4);
            let handle = [payload as usize as u32, u32::MAX];
            payload.write(0xdead_beef);
            payload.add(1).write(0);
            payload.add(2).write(0xfeed_face);
            assert_eq!(liti_handle_class_check(handle.as_ptr()), 0);
            payload.add(1).write(target as usize as u32);
            for tag in [0, u32::MAX, 0x6974_696d, 0x6974_696c, 0x706c_7374] {
                target.write(tag);
                assert_eq!(liti_handle_class_check(handle.as_ptr()), u32::from(tag == 0x6974_696c));
                assert_eq!(target.read(), tag);
            }
            assert_eq!(payload.read(), 0xdead_beef);
            assert_eq!(payload.add(1).read(), target as usize as u32);
            assert_eq!(payload.add(2).read(), 0xfeed_face);
            assert_eq!(handle, [payload as usize as u32, u32::MAX]);
        }
    }
}
