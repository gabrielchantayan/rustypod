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
//! The member's semantic type is not recoverable from this 4-byte veneer.
//! This port therefore names only the verified operation: release the
//! non-NULL member word at +0x14 through the stock `FUN_081f0530` callee.
//!
//! # Deliberate deviations
//!
//! The two stock tail branches are flattened so the hook has one Rust body.
//! `FUN_081f0530` remains unported and is reached through a volatile seam:
//! target builds call its fixed retailOS address, while host tests install a
//! recorder. The stock destination leaves an otherwise unspecified `r4` in
//! `r0` after a non-NULL release; every verified caller ignores it, and this
//! port exposes the function as `void`.

use core::ptr::addr_of;

const RETAIL_MEMBER_RELEASE_ADDRESS: usize = 0x081f_0530;

/// Target-sized prefix of an object holding a releasable member at +0x14.
/// Pointer-like target fields remain `u32` so this layout is 24 bytes on
/// both the ARM target and 64-bit test hosts.
#[repr(C)]
pub struct MemberReleaseOwner {
    /// +0x00..+0x10: words untouched by this helper.
    pub unresolved_00: [u32; 5],
    /// +0x14: non-NULL member passed to `FUN_081f0530`.
    pub member: u32,
}

const _: () = assert!(core::mem::size_of::<MemberReleaseOwner>() == 0x18);
const _: () = assert!(core::mem::offset_of!(MemberReleaseOwner, member) == 0x14);

/// ABI of the unported member release routine at `0x081f0530`.
pub type MemberRelease = unsafe extern "C" fn(*mut u8);

/// Indirection used only because the retail member release callee is not yet
/// ported.
#[derive(Clone, Copy)]
pub struct MemberReleaseOps {
    pub release: MemberRelease,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_member_release(member: *mut u8) {
    let release: MemberRelease = core::mem::transmute(RETAIL_MEMBER_RELEASE_ADDRESS);
    release(member)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_member_release(_member: *mut u8) {
    panic!("install member-release host operations before releasing a member")
}

#[cfg(target_os = "none")]
pub const DEFAULT_MEMBER_RELEASE_OPS: MemberReleaseOps = MemberReleaseOps {
    release: retail_member_release,
};

#[cfg(not(target_os = "none"))]
pub const DEFAULT_MEMBER_RELEASE_OPS: MemberReleaseOps = MemberReleaseOps {
    release: missing_member_release,
};

/// Active member-release implementation. A volatile load at the call site
/// keeps the target path indirect rather than letting LLVM elide the ROM
/// transfer.
pub static mut MEMBER_RELEASE_OPS: MemberReleaseOps = DEFAULT_MEMBER_RELEASE_OPS;

#[inline(always)]
fn member_release_ops() -> MemberReleaseOps {
    unsafe { core::ptr::read_volatile(addr_of!(MEMBER_RELEASE_OPS)) }
}

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
        (member_release_ops().release)(member as usize as *mut u8);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut RELEASED_MEMBER: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn record_member_release(member: *mut u8) {
        RELEASED_MEMBER = member;
    }

    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(RELEASED_MEMBER).write(core::ptr::null_mut());
            addr_of_mut!(MEMBER_RELEASE_OPS).write(MemberReleaseOps {
                release: record_member_release,
            });
        }
        guard
    }

    fn restore_default(guard: MutexGuard<'static, ()>) {
        unsafe {
            addr_of_mut!(MEMBER_RELEASE_OPS).write(DEFAULT_MEMBER_RELEASE_OPS);
        }
        drop(guard);
    }

    #[test]
    fn releases_the_non_null_member_word() {
        let guard = install_recorder();
        let mut owner = MemberReleaseOwner {
            unresolved_00: [0; 5],
            member: 0x1234_5678,
        };

        unsafe { member_release_if_present(addr_of_mut!(owner)) };

        unsafe {
            assert_eq!(addr_of!(RELEASED_MEMBER).read() as usize, 0x1234_5678);
        }
        restore_default(guard);
    }

    #[test]
    fn leaves_a_null_member_unreleased() {
        let guard = install_recorder();
        let mut owner = MemberReleaseOwner {
            unresolved_00: [0; 5],
            member: 0,
        };

        unsafe { member_release_if_present(addr_of_mut!(owner)) };

        unsafe {
            assert!(addr_of!(RELEASED_MEMBER).read().is_null());
        }
        restore_default(guard);
    }
}
