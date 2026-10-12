use crate::app::liti_class_check::image_library_is_liti_class;

/// image_library_first_container — original: FUN_080522a4 @ 0x080522a4.
/// True size: 24 bytes, ending at the independent entry_match_first prologue
/// at 0x080522bc. Raw-word scan verifies two plain inbound BLs (0x0805e31c,
/// 0x0806410c), zero predicated BLs; the body has one plain predicate BL.
///
/// Raw words: e1a02000 e52de004 eb00165e e1b00000 1592000c e49df004.
/// Preserve the database across image_library_is_liti_class; return its
/// aligned +0x0c word only on success, otherwise return zero. Callers
/// 0x0805e310 and 0x08063e9c walk this list with liti_container_successor.
/// Deliberate deviations: call the existing Rust class predicate instead
/// of stock 0x08057c2c; keep the returned link as a target-width u32 on hosts.
///
/// # Safety
/// A non-NULL database must be word-aligned and readable through +3.
/// If its tag is 'liti', it must also be readable through +0x0f.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.image_library_first_container")]
pub unsafe extern "C" fn image_library_first_container(database: *const u8) -> u32 {
    if unsafe { image_library_is_liti_class(database) } != 0 {
        unsafe { database.cast::<u32>().add(3).read() }
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_database_returns_zero() {
        assert_eq!(unsafe { image_library_first_container(core::ptr::null()) }, 0);
    }

    #[test]
    fn rejected_tag_needs_only_one_word() {
        for tag in [0u32, 0x706c_7374, 0x6974_696d, u32::MAX] {
            assert_eq!(unsafe { image_library_first_container((&tag as *const u32).cast()) }, 0);
        }
    }

    #[test]
    fn returns_exact_fourth_word_including_zero_and_high_bits() {
        for link in [0, 1, 0x0805_0000, 0x8000_0000, u32::MAX] {
            let database = [0x6974_696cu32, 0x1111_1111, 0x2222_2222, link, 0x4444_4444];
            assert_eq!(unsafe { image_library_first_container(database.as_ptr().cast()) }, link);
        }
    }

    #[test]
    fn class_transition_gates_nonzero_link() {
        let mut database = [0u32, 0, 0, 0xdead_beef];
        assert_eq!(unsafe { image_library_first_container(database.as_ptr().cast()) }, 0);
        database[0] = 0x6974_696c;
        assert_eq!(unsafe { image_library_first_container(database.as_ptr().cast()) }, 0xdead_beef);
        database[0] = 0;
        assert_eq!(unsafe { image_library_first_container(database.as_ptr().cast()) }, 0);
    }
}
