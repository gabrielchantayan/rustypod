//! `member_release_if_present` — original conditional tail target:
//! `FUN_08214348` @ `0x08214348` (32 bytes). Its three 4-byte veneers are
//! `thunk_FUN_08214348` @ `0x0820a45c`, `0x082201f4`, and `0x0822aa34`.
//! The assigned `0x0820a45c` veneer is exactly `b 0x0822aa34`; the next
//! separately linked function begins at `0x0820a460`.
//!
//! **`0x0820a45c` has 3 direct `bl` call sites, all unconditional and zero
//! predicated:** `0x0810087c`, `0x081743d0`, and `0x081746bc`, verified by
//! decoding every ARM B/BL immediate in `osos.dec`. Its one tail branch
//! reaches the final veneer, which tail-branches to `FUN_08214348`. That body
//! reads the owner word at `+0x14` and calls `FUN_081f0530` only when it is
//! non-NULL. The outer veneers do not otherwise change arguments or results.
//!
//! The final `0x0822aa34` veneer has 7 direct `bl` call sites, all
//! unconditional, zero predicated, at 0x081b757c, 0x081cc8bc, 0x081cc8f0,
//! 0x081cc9fc, 0x081cce0c, 0x081ccf6c, and 0x08220470. Its inbound
//! plain-B tails are `0x0820a45c` and `0x082201f4`; no aligned image word
//! equals any veneer address, so they are not directly dispatched as data.
//!
//! The member is the list state accepted by the ported
//! [`crate::cxx::list_cursor_release::list_cursor_release`] operation. The
//! stock destination leaves an otherwise unspecified `r4` in `r0` after the
//! call; every verified caller ignores it, and this Rust ABI is `void`.
//! Deliberate deviation: all stock tail branches are flattened into this
//! existing Rust body, avoiding duplicate dispatch seams.

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
                unresolved_00: [0; 12],
                active_cursor: 0,
                range_scale: 0,
                range_start: 0,
                range_end: 0,
                cursor_position: 0,
                cursor_limit: 0,
                unresolved_48: [0; 2],
                mutex_words: [0; 2],
                range_valid: 0,
                cursor_active: 0,
                unresolved_5a: [0; 22],
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
