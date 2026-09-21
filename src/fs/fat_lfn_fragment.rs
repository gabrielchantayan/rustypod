//! FAT LFN fragment-state update — retailOS `FUN_082dfdc0` at `0x082dfdc0`
//! (48 bytes).
//!
//! Raw `osos.dec` words establish the true extent `0x082dfdc0..0x082dfdef`;
//! `push {r4-r9,sl,lr}` at `0x082dfdf0` starts the next independent function.
//! Whole-image ARM decoding finds two inbound plain `bl` instructions
//! (`0x082e117c`, `0x082e11cc`), one inbound predicated `blne`
//! (`0x082e2858`), and no outbound calls.
//!
//! The leaf increments the fragment count, initializes or replaces the current
//! directory identifier while retaining the replaced identifier, and records
//! the directory-entry index. Deliberate deviation: the retail body is `void`
//! but leaves `r0` unchanged; this port returns `state` explicitly to preserve
//! that observed ABI result.

/// Target-layout state accumulated while scanning FAT long-file-name fragments.
///
/// The untouched word at offset eight remains anonymous because this leaf does
/// not inspect it. All fields are target-width words so their offsets stay
/// correct on hosts with 64-bit pointers.
#[repr(C)]
pub struct FatLfnFragmentState {
    pub fragment_count: u32,
    pub entry_index: u32,
    pub uninspected: u32,
    pub current_directory: u32,
    pub previous_directory: u32,
}

/// Record one long-file-name fragment and return the unchanged state pointer.
///
/// # Safety
///
/// `state` must point to a writable `FatLfnFragmentState`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fat_lfn_fragment_note(
    state: *mut FatLfnFragmentState,
    directory: u32,
    entry_index: u32,
) -> *mut FatLfnFragmentState {
    (*state).fragment_count = (*state).fragment_count.wrapping_add(1);
    let previous_directory = (*state).current_directory;
    if previous_directory == 0 {
        (*state).current_directory = directory;
    }
    if previous_directory != directory {
        (*state).current_directory = directory;
        (*state).previous_directory = previous_directory;
    }
    (*state).entry_index = entry_index;
    state
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    fn state(current_directory: u32) -> FatLfnFragmentState {
        FatLfnFragmentState {
            fragment_count: 0,
            entry_index: 0xaaaa_aaaa,
            uninspected: 0x5555_5555,
            current_directory,
            previous_directory: 0xbbbb_bbbb,
        }
    }

    #[test]
    fn initializes_empty_state_and_preserves_uninspected_word() {
        let mut fragments = state(0);
        let returned = unsafe { fat_lfn_fragment_note(&mut fragments, 7, 11) };
        assert!(core::ptr::eq(returned, &mut fragments));
        assert_eq!(fragments.fragment_count, 1);
        assert_eq!(fragments.entry_index, 11);
        assert_eq!(fragments.current_directory, 7);
        assert_eq!(fragments.previous_directory, 0);
        assert_eq!(fragments.uninspected, 0x5555_5555);
    }

    #[test]
    fn retains_previous_directory_only_when_directory_changes() {
        let mut fragments = state(7);
        unsafe { fat_lfn_fragment_note(&mut fragments, 7, 12) };
        assert_eq!(fragments.previous_directory, 0xbbbb_bbbb);
        unsafe { fat_lfn_fragment_note(&mut fragments, 9, 13) };
        assert_eq!(fragments.fragment_count, 2);
        assert_eq!(fragments.entry_index, 13);
        assert_eq!(fragments.current_directory, 9);
        assert_eq!(fragments.previous_directory, 7);
    }

    #[test]
    fn wraps_fragment_count() {
        let mut fragments = state(3);
        fragments.fragment_count = u32::MAX;
        unsafe { fat_lfn_fragment_note(&mut fragments, 3, 4) };
        assert_eq!(fragments.fragment_count, 0);
    }
}
