//! Platform file directory-entry state.
//!
//! The C++ file object constructed by `FUN_08278dc4` stores its
//! directory-entry index at byte offset `+0x18`; construction initializes
//! that word to `-1`, and the close path restores that sentinel. The file
//! read/write/seek methods use this predicate before dispatching operations
//! on the index.

/// file_has_directory_entry — original: `FUN_082a548c` @ `0x082a548c`
/// (16 bytes; 11 direct C call sites).
///
/// Loads the platform file object's signed directory-entry index at `+0x18`
/// and returns `1` precisely when it is not the closed/unresolved `-1`
/// sentinel, otherwise `0`. The retail ARM body is `ldr; adds #1; movne #1;
/// bx lr`: the flag-setting wrapping addition makes `-1` the only false
/// value. It performs only the load and does not modify the object.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn file_has_directory_entry(file: *const u8) -> i32 {
    const DIRECTORY_ENTRY_INDEX: usize = 0x18;
    i32::from((file.add(DIRECTORY_ENTRY_INDEX) as *const i32).read() != -1)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    const DIRECTORY_ENTRY_INDEX: usize = 0x18;

    #[repr(align(4))]
    struct PlatformFile([u8; 0x20]);

    impl PlatformFile {
        fn with_directory_entry(index: i32) -> Self {
            let mut file = Self([0xa5; 0x20]);
            file.0[DIRECTORY_ENTRY_INDEX..DIRECTORY_ENTRY_INDEX + 4]
                .copy_from_slice(&index.to_ne_bytes());
            file
        }

        fn directory_entry(&self) -> i32 {
            i32::from_ne_bytes(
                self.0[DIRECTORY_ENTRY_INDEX..DIRECTORY_ENTRY_INDEX + 4]
                    .try_into()
                    .unwrap(),
            )
        }

        fn ptr(&self) -> *const u8 {
            self.0.as_ptr()
        }
    }

    #[test]
    fn only_minus_one_is_not_a_directory_entry() {
        for index in [-1, 0, i32::MIN, i32::MAX, -2, 1, 0x1234_5678] {
            let file = PlatformFile::with_directory_entry(index);
            assert_eq!(unsafe { file_has_directory_entry(file.ptr()) }, i32::from(index != -1));
        }
    }

    #[test]
    fn aliases_observe_the_same_index_without_mutating_the_file() {
        let mut file = PlatformFile::with_directory_entry(-1);
        let first_alias = file.0.as_ptr();
        let second_alias = file.0.as_mut_ptr();

        let before_closed_query = file.0;
        assert_eq!(unsafe { file_has_directory_entry(first_alias) }, 0);
        assert_eq!(file.0, before_closed_query, "the predicate is read-only");

        unsafe {
            (second_alias.add(DIRECTORY_ENTRY_INDEX) as *mut i32).write(37);
        }
        let before_open_query = file.0;
        assert_eq!(unsafe { file_has_directory_entry(first_alias) }, 1);
        assert_eq!(file.0, before_open_query, "the predicate is read-only");
        assert_eq!(file.directory_entry(), 37);
    }
}
