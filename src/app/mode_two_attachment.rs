//! `mode_two_attachment` — original: `FUN_0820ba38` @ **`0x0820ba38`**.
//!
//! **56 bytes exactly**, `0x0820ba38..0x0820ba70`: fourteen ARM words end at
//! `pop {r4, r5, pc}`; the next independent function begins at `0x0820ba70`.
//! Raw decoding finds **4 inbound plain `bl` call sites** and no predicated
//! inbound forms; this body makes two unconditional `bl` calls and no
//! predicated calls.
//!
//! # Algorithm
//!
//! Store `mode` at `object + 4`. For mode 2 only, allocate 0x48 bytes with
//! tag-2 `operator_new`, pass the raw allocation and mode 2 to the unported
//! `FUN_08168a8c`, and store its returned target word at `object + 8`. Return
//! one for mode 2; every other mode returns the incoming object address.
//!
//! # Deliberate deviations
//!
//! `FUN_08168a8c` has no recovered identity, so it remains an explicit
//! device-address seam; host tests install that edge. The host seam returns a
//! `u32` target word rather than a native pointer, preserving the retailOS
//! object's 4-byte field layout on 64-bit hosts.

#[cfg(test)]
extern crate std;

use crate::heap::veneers::operator_new;

pub const MODE_TWO_ATTACHMENT_SIZE: usize = 0x48;

/// The observed three-word object prefix. All fields are target words.
#[repr(C)]
pub struct ModeTwoAttachment {
    pub opaque_00: u32,
    pub mode: u32,
    pub attachment: u32,
}

/// ABI of the unported `FUN_08168a8c` constructor.
pub type ModeTwoAttachmentConstruct = unsafe extern "C" fn(*mut u8, u32) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_mode_two_attachment_construct(storage: *mut u8, mode: u32) -> u32 {
    let construct: ModeTwoAttachmentConstruct = unsafe { core::mem::transmute(0x0816_8a8cusize) };
    unsafe { construct(storage, mode) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_mode_two_attachment_construct(_storage: *mut u8, _mode: u32) -> u32 {
    panic!("mode_two_attachment requires constructor 0x08168a8c")
}

#[cfg(target_os = "none")]
pub const DEFAULT_MODE_TWO_ATTACHMENT_CONSTRUCT: ModeTwoAttachmentConstruct = firmware_mode_two_attachment_construct;
#[cfg(not(target_os = "none"))]
pub const DEFAULT_MODE_TWO_ATTACHMENT_CONSTRUCT: ModeTwoAttachmentConstruct = missing_mode_two_attachment_construct;

/// Device-wired constructor seam for the unported direct `bl` target.
pub static mut MODE_TWO_ATTACHMENT_CONSTRUCT: ModeTwoAttachmentConstruct = DEFAULT_MODE_TWO_ATTACHMENT_CONSTRUCT;

/// Writes the mode and attaches the mode-two allocation when requested.
///
/// # Safety
///
/// `object` must point to at least three writable target words. The active
/// constructor must accept the raw allocator result, including NULL.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mode_two_attachment(object: *mut ModeTwoAttachment, mode: u32) -> u32 {
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!((*object).mode), mode) };
    if mode != 2 {
        return object as usize as u32;
    }

    let storage = unsafe { operator_new(MODE_TWO_ATTACHMENT_SIZE) };
    let construct = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(MODE_TWO_ATTACHMENT_CONSTRUCT)) };
    let attachment = unsafe { construct(storage, mode) };
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!((*object).attachment), attachment) };
    1
}

#[cfg(test)]
pub static MODE_TWO_ATTACHMENT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::{alloc_log, mock_heap, set_alloc_ret};

    static mut CONSTRUCT_CALLS: usize = 0;
    static mut CONSTRUCT_STORAGE: *mut u8 = core::ptr::null_mut();
    static mut CONSTRUCT_MODE: u32 = 0;

    unsafe extern "C" fn recording_construct(storage: *mut u8, mode: u32) -> u32 {
        unsafe {
            CONSTRUCT_CALLS += 1;
            CONSTRUCT_STORAGE = storage;
            CONSTRUCT_MODE = mode;
        }
        0x1234_5678
    }

    #[test]
    fn non_two_mode_only_stores_mode_and_returns_object_word() {
        let _attachment = MODE_TWO_ATTACHMENT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _heap = mock_heap();
        let mut object = ModeTwoAttachment { opaque_00: 0xa5a5_a5a5, mode: 0, attachment: 0xfeed_beef };

        let result = unsafe { mode_two_attachment(&mut object, 3) };

        assert_eq!(result, (&mut object as *mut ModeTwoAttachment) as usize as u32);
        assert_eq!(object.mode, 3);
        assert_eq!(object.attachment, 0xfeed_beef);
        assert_eq!(alloc_log(), (0, 0, 0));
    }

    #[test]
    fn mode_two_allocates_constructs_and_stores_returned_word() {
        let _attachment = MODE_TWO_ATTACHMENT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _heap = mock_heap();
        let mut storage = [0u8; MODE_TWO_ATTACHMENT_SIZE];
        let mut object = ModeTwoAttachment { opaque_00: 0, mode: 9, attachment: 0 };
        unsafe {
            MODE_TWO_ATTACHMENT_CONSTRUCT = recording_construct;
            CONSTRUCT_CALLS = 0;
            CONSTRUCT_STORAGE = core::ptr::null_mut();
            CONSTRUCT_MODE = 0;
            set_alloc_ret(storage.as_mut_ptr());
        }

        assert_eq!(unsafe { mode_two_attachment(&mut object, 2) }, 1);
        assert_eq!(object.mode, 2);
        assert_eq!(object.attachment, 0x1234_5678);
        assert_eq!(alloc_log(), (1, MODE_TWO_ATTACHMENT_SIZE, 2));
        unsafe {
            assert_eq!(CONSTRUCT_CALLS, 1);
            assert_eq!(CONSTRUCT_STORAGE, storage.as_mut_ptr());
            assert_eq!(CONSTRUCT_MODE, 2);
            MODE_TWO_ATTACHMENT_CONSTRUCT = DEFAULT_MODE_TWO_ATTACHMENT_CONSTRUCT;
        }
    }

    #[test]
    fn mode_two_passes_null_allocation_to_constructor() {
        let _attachment = MODE_TWO_ATTACHMENT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _heap = mock_heap();
        let mut object = ModeTwoAttachment { opaque_00: 0, mode: 0, attachment: 0 };
        unsafe {
            MODE_TWO_ATTACHMENT_CONSTRUCT = recording_construct;
            CONSTRUCT_CALLS = 0;
            CONSTRUCT_STORAGE = 1usize as *mut u8;
            CONSTRUCT_MODE = 0;
            set_alloc_ret(core::ptr::null_mut());
        }

        assert_eq!(unsafe { mode_two_attachment(&mut object, 2) }, 1);
        assert_eq!(object.attachment, 0x1234_5678);
        assert_eq!(alloc_log(), (1, MODE_TWO_ATTACHMENT_SIZE, 2));
        unsafe {
            assert_eq!(CONSTRUCT_CALLS, 1);
            assert!(CONSTRUCT_STORAGE.is_null());
            assert_eq!(CONSTRUCT_MODE, 2);
            MODE_TWO_ATTACHMENT_CONSTRUCT = DEFAULT_MODE_TWO_ATTACHMENT_CONSTRUCT;
        }
    }
}
