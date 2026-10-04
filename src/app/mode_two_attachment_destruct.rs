//! `mode_two_attachment_destruct` — `FUN_0820ba88` @ `0x0820ba88`.
//!
//! 44 instruction bytes, plus the four-byte vtable literal at `0x0820bab4`:
//! true extent 48 bytes to the independently entered `mov r0, #1; bx lr`
//! at `0x0820bab8`. Raw full-image decoding finds two inbound plain BLs
//! (`0x081fd2f0`, `0x0820ba7c`), zero predicated BLs, and three tail Bs
//! (`0x081f18b8`, `0x08210dc0`, `0x08210f5c`). The body has zero plain or
//! predicated direct BLs and one predicated indirect `blxne`.
//!
//! Install the base vtable word `0x08992240`, then invoke a non-null
//! attachment's virtual slot +0x1c with the attachment as r0. Return the
//! original owner pointer without clearing the attachment or changing mode.
//! The virtual method's identity is unresolved; its name describes only its
//! destructor-context role. Deliberate deviation: host attachment and vtable
//! pointers are widened structurally; ARM retains four-byte slots and fields.

use core::ptr;

pub const MODE_TWO_ATTACHMENT_BASE_VTABLE: u32 = 0x0899_2240;

/// Recovered owner prefix; the ARM attachment field is at +8.
#[repr(C)]
pub struct ModeTwoAttachmentOwner {
    pub vtable: u32,
    pub mode: u32,
    pub attachment: *mut Attachment,
}

#[repr(C)]
pub struct Attachment {
    pub vtable: *const AttachmentVtable,
}

/// The first seven virtual slots are not used here.
#[repr(C)]
pub struct AttachmentVtable {
    pub unresolved_00_18: [usize; 7],
    pub destruct_slot: unsafe extern "C" fn(*mut Attachment),
}

/// # Safety
/// `owner` must be writable. Its non-null attachment must have a readable
/// vtable with a callable +0x1c slot satisfying the retailOS lifetime contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mode_two_attachment_destruct(owner: *mut ModeTwoAttachmentOwner) -> *mut ModeTwoAttachmentOwner {
    unsafe { ptr::write_volatile(ptr::addr_of_mut!((*owner).vtable), MODE_TWO_ATTACHMENT_BASE_VTABLE) };
    let attachment = unsafe { ptr::read_volatile(ptr::addr_of!((*owner).attachment)) };
    if !attachment.is_null() {
        let vtable = unsafe { ptr::read_volatile(ptr::addr_of!((*attachment).vtable)) };
        let destruct = unsafe { ptr::read_volatile(ptr::addr_of!((*vtable).destruct_slot)) };
        unsafe { destruct(attachment) };
    }
    owner
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct ObservedAttachment {
        base: Attachment,
        owner: *mut ModeTwoAttachmentOwner,
        calls: u32,
        clear_owner: bool,
    }

    unsafe extern "C" fn observe_destruct(attachment: *mut Attachment) {
        let observed = unsafe { &mut *attachment.cast::<ObservedAttachment>() };
        let owner = unsafe { &mut *observed.owner };
        assert_eq!(owner.vtable, MODE_TWO_ATTACHMENT_BASE_VTABLE);
        assert_eq!(owner.attachment, attachment);
        assert_eq!(owner.mode, 0xdead_beef);
        observed.calls += 1;
        if observed.clear_owner {
            owner.attachment = ptr::null_mut();
            owner.mode = 7;
            owner.vtable = 0x1234;
        }
    }

    #[test]
    fn null_attachment_resets_only_vtable_and_returns_owner() {
        for mode in [0, 2, u32::MAX] {
            let mut owner = ModeTwoAttachmentOwner { vtable: 0x1234, mode, attachment: ptr::null_mut() };
            let address = ptr::addr_of_mut!(owner);
            assert_eq!(unsafe { mode_two_attachment_destruct(address) }, address);
            assert_eq!(owner.vtable, MODE_TWO_ATTACHMENT_BASE_VTABLE);
            assert_eq!(owner.mode, mode);
            assert!(owner.attachment.is_null());
        }
    }

    #[test]
    fn repeated_dispatch_retains_attachment_and_preserves_callback_mutations() {
        let vtable = AttachmentVtable { unresolved_00_18: [0; 7], destruct_slot: observe_destruct };
        let mut owner = ModeTwoAttachmentOwner { vtable: 0, mode: 0xdead_beef, attachment: ptr::null_mut() };
        let mut attachment = ObservedAttachment {
            base: Attachment { vtable: &vtable }, owner: &mut owner, calls: 0, clear_owner: false,
        };
        owner.attachment = &mut attachment.base;
        let address = ptr::addr_of_mut!(owner);
        for expected in 1..=2 {
            assert_eq!(unsafe { mode_two_attachment_destruct(address) }, address);
            assert_eq!(attachment.calls, expected);
            assert_eq!(owner.attachment, ptr::addr_of_mut!(attachment.base));
            assert_eq!(owner.mode, 0xdead_beef);
        }
        attachment.clear_owner = true;
        assert_eq!(unsafe { mode_two_attachment_destruct(address) }, address);
        assert_eq!(attachment.calls, 3);
        assert!(owner.attachment.is_null());
        assert_eq!(owner.mode, 7);
        assert_eq!(owner.vtable, 0x1234);
        unsafe { mode_two_attachment_destruct(address) };
        assert_eq!(attachment.calls, 3);
        assert_eq!(owner.vtable, MODE_TWO_ATTACHMENT_BASE_VTABLE);
    }
}
