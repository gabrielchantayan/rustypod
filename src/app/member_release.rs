//! `member_release_if_present` — original: `thunk_FUN_08214348` @
//! `0x082201f4` (**4 bytes**, one `b 0x0822aa34`). Raw bytes show that
//! veneer tail-branches again to `FUN_08214348` @ `0x08214348`; its 32-byte
//! body reads the owner word at `+0x14` and calls `FUN_081f0530` only when
//! that word is non-NULL. The next separately linked function after the
//! veneer begins at `0x082201f8`.
//!
//! **12 direct `bl` call sites, all unconditional; zero predicated calls**,
//! verified by decoding every ARM B/BL word in `osos.dec`: 0x081426c0,
//! 0x081792d0, 0x081798cc, 0x08179a08, 0x0817a308, 0x0817a850, 0x0817bc94,
//! 0x0817c71c, 0x0817d110, 0x0817d3fc, 0x0817d600, and 0x082a9c80. No image
//! word equals the veneer address, so it is not directly dispatched as data.
//!
//! The member is now known to be the list state accepted by the ported
//! [`crate::cxx::list_cursor_release::list_cursor_release`] operation. The
//! stock destination leaves an otherwise unspecified `r4` in `r0` after the
//! call; every verified caller ignores it, and this veneer remains `void`.

/// Target-sized prefix of an object holding a releasable member at +0x14.
/// Pointer-like target fields remain `u32` so this layout is 24 bytes on
/// both the ARM target and 64-bit test hosts.
#[repr(C)]
pub struct MemberReleaseOwner {
    /// +0x00..+0x10: words untouched by this helper.
    pub unresolved_00: [u32; 5],
    /// +0x14: non-NULL member passed to `list_cursor_release`.
    pub member: u32,
}

const _: () = assert!(core::mem::size_of::<MemberReleaseOwner>() == 0x18);
const _: () = assert!(core::mem::offset_of!(MemberReleaseOwner, member) == 0x14);

/// Releases `owner`'s member word at +0x14 when it is non-NULL.
///
/// # Safety
///
/// `owner` must point to a readable [`MemberReleaseOwner`]. For a nonzero
/// member word, it must designate an object accepted by the release routine;
/// neither the veneer nor its retail tail target guards the owner pointer.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn member_release_if_present(owner: *mut MemberReleaseOwner) {
    let member = (*owner).member;
    if member != 0 {
        crate::cxx::list_cursor_release::list_cursor_release(
            member as usize as *mut crate::cxx::list_cursor_release::ListCursorReleaseState,
        );
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::list_cursor_release::ListCursorReleaseState;
    use crate::testing::{hints, try_map_u32_slab};
    use core::ptr::{addr_of_mut, write};

    #[test]
    fn releases_the_non_null_member_word() {
        let Some(member) = try_map_u32_slab(
            hints::MEMBER_RELEASE_LIST_STATE,
            core::mem::size_of::<ListCursorReleaseState>(),
        ) else {
            return;
        };
        let member = member.cast::<ListCursorReleaseState>();
        unsafe {
            write(member, ListCursorReleaseState {
                unresolved_00: [0; 20],
                mutex_words: [0; 2],
                unresolved_58: [0; 6],
                cursor_clear_suppressed: 1,
                unresolved_71: [0; 3],
            });
        }
        let mut owner = MemberReleaseOwner {
            unresolved_00: [0; 5],
            member: member as usize as u32,
        };

        unsafe { member_release_if_present(addr_of_mut!(owner)) };
    }

    #[test]
    fn leaves_a_null_member_unreleased() {
        let mut owner = MemberReleaseOwner {
            unresolved_00: [0; 5],
            member: 0,
        };

        unsafe { member_release_if_present(addr_of_mut!(owner)) };
    }
}
