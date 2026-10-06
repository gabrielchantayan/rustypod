//! `video_engine_upload_and_enable` — `FUN_081675c0` @ 0x081675c0.
//! True extent: 32 bytes, ending at the independent CMP/prologue at 0x081675e0.
//! Whole-image aligned ARM-word scan: two inbound BLs, one plain at
//! 0x0816e450 and one BLNE at 0x0816e600. Body: one plain BL, no predicated
//! BLs, and one plain tail B to 0x0827b9d8.
//!
//! Load the owner's group at +0x128, forward data, square side length and
//! secondary-image flag to resident 0x0827bb8c, reload the owner's group,
//! then enable that group. The resident entry creates/updates primary image
//! status and optionally a secondary image (Ghidra and raw register use agree).
//! Its implementation remains resident: this ports only the assigned wrapper.
//! Deliberate deviations: reuse the Rust group-enable port, express the tail
//! branch as a call, and widen pointers via repr(C) on hosts. No target
//! behavioral deviation; host tests install the resident-call seam.

use super::video_engine::{VideoStatusGroup, video_engine_set_group_enabled};

/// Partial owner layout: the group pointer is at target byte offset 0x128.
#[repr(C)]
pub struct VideoImageOwner {
    pub prefix: [u32; 74],
    pub group: *mut VideoStatusGroup,
}

type UploadGroup = unsafe extern "C" fn(*mut VideoStatusGroup, u32, u32, u32);

#[cfg(not(target_arch = "arm"))]
static mut MOCK_UPLOAD_GROUP: Option<UploadGroup> = None;

/// Host-only seam for the verified, unported resident image upload entry.
#[cfg(not(target_arch = "arm"))]
pub unsafe fn set_mock_upload_group(upload: Option<UploadGroup>) {
    core::ptr::addr_of_mut!(MOCK_UPLOAD_GROUP).write(upload);
}

/// # Safety
/// Owner and its group must be valid for both resident upload and group enable.
/// Data is a target-width image address; the resident routine's image storage,
/// engine globals and callbacks must be valid. Upload may replace owner.group.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn video_engine_upload_and_enable(
    owner: *mut VideoImageOwner, data: u32, side: u32, secondary: u32,
) {
    #[cfg(target_arch = "arm")]
    let upload: UploadGroup = core::mem::transmute(0x0827_bb8cusize);
    #[cfg(not(target_arch = "arm"))]
    let upload = core::ptr::addr_of!(MOCK_UPLOAD_GROUP).read()
        .expect("image upload resident seam must be installed");
    upload(core::ptr::addr_of!((*owner).group).read(), data, side, secondary);
    video_engine_set_group_enabled(core::ptr::addr_of!((*owner).group).read(), 1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::video_engine::{LOCK, set_mock_enable_status};
    use core::ptr::{null_mut, addr_of, addr_of_mut};

    static mut OWNER: *mut VideoImageOwner = null_mut();
    static mut REPLACEMENT: *mut VideoStatusGroup = null_mut();

    unsafe extern "C" fn upload(group: *mut VideoStatusGroup, data: u32, side: u32, secondary: u32) {
        assert_eq!((data, side, secondary), (0x1234_5678, 0x80, 0xffff_ffff));
        // Simulate the resident upload updating image status, then a callback
        // replacing the owner's group. Enabling must use the replacement.
        (*group).primary.add(11).write(0x80);
        (*addr_of!(OWNER).read()).group = addr_of!(REPLACEMENT).read();
    }

    unsafe extern "C" fn enable(status: *mut u8) {
        if status.add(11).read() == 0 { status.add(11).write(1); }
    }

    fn group(primary: *mut u8, secondary: *mut u8) -> VideoStatusGroup {
        VideoStatusGroup {
            prefix: [0; 21], primary, gap_to_secondary: [0; 15], secondary,
            gap_to_tertiary: [0; 15], tertiary: null_mut(), auxiliary: null_mut(),
        }
    }

    #[test]
    fn reloads_replaced_group_and_preserves_already_enabled_status() {
        let _lock = LOCK.lock();
        for replace in [false, true] {
            let mut old_status = [0u8; 16];
            let mut new_status = [0u8; 16];
            let mut optional_status = [0u8; 16];
            optional_status[11] = 0xfe;
            let mut old = group(old_status.as_mut_ptr(), null_mut());
            let mut new = group(new_status.as_mut_ptr(), optional_status.as_mut_ptr());
            let mut owner = VideoImageOwner { prefix: [0xdead_beef; 74], group: &mut old };
            unsafe {
                addr_of_mut!(OWNER).write(&mut owner);
                addr_of_mut!(REPLACEMENT).write(if replace { &mut new } else { &mut old });
                set_mock_upload_group(Some(upload));
                set_mock_enable_status(Some(enable));
                video_engine_upload_and_enable(&mut owner, 0x1234_5678, 0x80, 0xffff_ffff);
                set_mock_enable_status(None);
                set_mock_upload_group(None);
                addr_of_mut!(OWNER).write(null_mut());
                addr_of_mut!(REPLACEMENT).write(null_mut());
            }
            assert_eq!(old_status[11], 0x80);
            assert_eq!(new_status[11], if replace { 1 } else { 0 });
            assert_eq!(optional_status[11], 0xfe);
            assert_eq!(owner.prefix, [0xdead_beef; 74]);
            assert_eq!(&old_status[..11], &[0; 11]);
            assert_eq!(&new_status[12..], &[0; 4]);
        }
    }
}
