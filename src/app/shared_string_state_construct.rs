//! Default construction of an unidentified shared-cell/string state object.
//!
//! Original: `FUN_08215390` @ 0x08215390. True extent: 84 bytes,
//! 80 instruction bytes plus the vtable literal at 0x082153e0; the next
//! real function starts at 0x082153e4. Raw A32 words verify two incoming
//! plain BLs, three outgoing plain BLs, and zero predicated BLs.
//!
//! Installs vtable 0x089931e0, constructs an empty shared-cell handle,
//! clears the +0x0c word, sets +0x10 to -1, default-constructs the string
//! at +0x14, clears +0x1c/+0x20 and the byte at +0x24, and returns this.
//! The +4 word and trailing three bytes remain untouched. Callers allocate
//! 0x28 bytes; the class and remaining field meanings are not established.
//!
//! Deliberate deviations: the final reset helper at 0x08215364 constructs
//! an empty temporary handle, assigns it to the already-empty member, and
//! releases the empty temporary. That provably effect-free sequence is
//! omitted, rather than introducing a second port or firmware seam.
//! `repr(C)` pointer fields widen on hosts; target offsets remain exact.

use crate::cxx::shared_cell::{SharedCell, shared_cell_construct};
use crate::cxx::string_object::{StringObject, string_default_construct};

#[repr(C)]
pub struct SharedStringState {
    pub vtable: u32,
    pub preserved_word: u32,
    pub shared: *mut SharedCell,
    pub cleared_word: u32,
    pub sentinel: u32,
    pub string: StringObject,
    pub trailing_words: [u32; 2],
    pub flag: u8,
    pub preserved_bytes: [u8; 3],
}

/// # Safety
/// `this` must be aligned, non-null writable storage for `SharedStringState`.
/// This is construction, not assignment: existing owned members are not released.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn shared_string_state_construct(
    this: *mut SharedStringState,
) -> *mut SharedStringState {
    core::ptr::addr_of_mut!((*this).vtable).write(0x0899_31e0);
    shared_cell_construct(core::ptr::addr_of_mut!((*this).shared), core::ptr::null_mut());
    core::ptr::addr_of_mut!((*this).cleared_word).write(0);
    core::ptr::addr_of_mut!((*this).sentinel).write(u32::MAX);
    string_default_construct(core::ptr::addr_of_mut!((*this).string));
    core::ptr::addr_of_mut!((*this).trailing_words).write([0; 2]);
    core::ptr::addr_of_mut!((*this).flag).write(0);
    this
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string_object::STRING_OBJECT_VTABLE;

    #[test]
    fn construction_overwrites_owned_members_without_reading_them_and_preserves_holes() {
        for fill in [0u8, 0x5a, 0xff] {
            let mut storage = core::mem::MaybeUninit::<SharedStringState>::uninit();
            let state = storage.as_mut_ptr();
            unsafe {
                state.cast::<u8>().write_bytes(fill, core::mem::size_of::<SharedStringState>());
                assert_eq!(shared_string_state_construct(state), state);
                let state = &*state;
                assert_eq!(state.vtable, 0x0899_31e0);
                assert_eq!(state.preserved_word, u32::from_ne_bytes([fill; 4]));
                assert!(state.shared.is_null());
                assert_eq!(state.cleared_word, 0);
                assert_eq!(state.sentinel, u32::MAX);
                assert_eq!(state.string.vtable, &STRING_OBJECT_VTABLE as *const _);
                assert!(state.string.payload.is_null());
                assert_eq!(state.trailing_words, [0; 2]);
                assert_eq!(state.flag, 0);
                assert_eq!(state.preserved_bytes, [fill; 3]);
            }
        }
    }
}
