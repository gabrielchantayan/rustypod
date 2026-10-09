//! Guarded 'plst' resource update message.
//!
//! Original: `FUN_080d3570` @ `0x080d3570`, 136 bytes (132 code bytes
//! and message literal at `0x080d35f4`; next function at `0x080d35f8`).
//! Verified calls: inbound 1 plain BL and 1 BLNE; outbound 3 plain BL,
//! no predicated BL.

use core::ptr;
use crate::libc::bzero::bzero;
use super::plst_task_message::{plst_task_message, PlstTaskMessageDispatch};

const FLAGS: usize = 0x1ac;
const UPDATE_ENABLED: usize = 0x1b0;
const UPDATE_PENDING: usize = 0x618;
const UPDATE_MESSAGE: u32 = 0x706c_7375;

pub type PlstResourceRelatedOp = unsafe extern "C" fn(*mut u8, u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_related_operation(resource: *mut u8, selection: u32) {
    let call: PlstResourceRelatedOp = core::mem::transmute(0x080d_f384usize);
    call(resource, selection);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_related_operation(_resource: *mut u8, _selection: u32) {
    panic!("unported retailOS operation at 0x080df384 requires a host seam");
}

/// Verified unported operation and canonical message port; replaceable on hosts.
#[derive(Clone, Copy)]
pub struct PlstResourceUpdateOps {
    pub related: PlstResourceRelatedOp,
    pub message: PlstTaskMessageDispatch,
}

pub const DEFAULT_PLST_RESOURCE_UPDATE_OPS: PlstResourceUpdateOps = PlstResourceUpdateOps {
    related: retail_related_operation,
    message: plst_task_message,
};
pub static mut PLST_RESOURCE_UPDATE_OPS: PlstResourceUpdateOps = DEFAULT_PLST_RESOURCE_UPDATE_OPS;

/// Send the resource's update message after processing related resources.
///
/// Original: `FUN_080d3570` @ `0x080d3570`, true size 136 bytes. Full-image
/// ARM-word decoding finds inbound BL at `0x0806cfec` and BLNE at
/// `0x080df448`; the body has three plain BL and zero predicated BL calls.
/// Always call the verified helper `0x080df384(resource, 0)`. Unless forced,
/// require nonzero byte +0x1b0 and flag bit 1. Mark +0x618 pending before
/// checking guard bit 3. If not guarded, set that bit, zero a 12-byte reply,
/// send `0x706c7375`, clear bit 3 from the current flags, and return reply[0].
/// Rejected or already-guarded updates return zero; message status is ignored.
///
/// Deliberate deviations: the saved r1-r3 stack slots become an aligned
/// three-word reply, since bzero overwrites all of them before dispatch.
/// Incidental restored r1 is not a second return value. The unported helper
/// retains its raw address without an invented identity; host code must
/// replace its seam. Message dispatch uses the canonical Rust port.
///
/// # Safety
/// `resource` must be writable through +0x618 and valid for both operations.
/// Operations must accept a synchronous, aligned 12-byte reply buffer.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn plst_resource_send_update(resource: *mut u8, force: u32) -> u32 {
    let ops = ptr::read_volatile(ptr::addr_of!(PLST_RESOURCE_UPDATE_OPS));
    send_update(resource, force, ops)
}

#[inline(always)]
unsafe fn send_update(resource: *mut u8, force: u32, ops: PlstResourceUpdateOps) -> u32 {
    (ops.related)(resource, 0);
    if force == 0 && (resource.add(UPDATE_ENABLED).read() == 0
        || resource.add(FLAGS).read() & 2 == 0)
    {
        return 0;
    }
    resource.add(UPDATE_PENDING).write(1);
    let flags = resource.add(FLAGS).read();
    if flags & 8 != 0 {
        return 0;
    }
    resource.add(FLAGS).write(flags | 8);
    let mut reply = core::mem::MaybeUninit::<[u32; 3]>::uninit();
    bzero(reply.as_mut_ptr().cast(), 12);
    (ops.message)(resource, UPDATE_MESSAGE, reply.as_mut_ptr().cast());
    resource.add(FLAGS).write(resource.add(FLAGS).read() & !8);
    reply.as_ptr().cast::<u8>().read() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn related(_resource: *mut u8, selection: u32) {
        assert_eq!(selection, 0);
    }
    unsafe extern "C" fn dispatch(resource: *mut u8, message: u32, reply: *mut u8) -> u32 {
        assert_eq!(message, UPDATE_MESSAGE);
        assert_ne!(resource.add(FLAGS).read() & 8, 0);
        assert_eq!(resource.add(UPDATE_PENDING).read(), 1);
        assert_eq!(reply.cast::<[u32; 3]>().read(), [0; 3]);
        // The handler's other flag mutations must survive guard removal.
        resource.add(FLAGS).write(0xed);
        reply.write(0xa5);
        reply.add(1).write(0xfe);
        0xffff_ffce
    }
    unsafe extern "C" fn forbidden(_resource: *mut u8, _message: u32, _reply: *mut u8) -> u32 {
        panic!("rejected update dispatched");
    }
    unsafe extern "C" fn enable(resource: *mut u8, selection: u32) {
        assert_eq!(selection, 0);
        resource.add(UPDATE_ENABLED).write(1);
        resource.add(FLAGS).write(2);
    }

    #[test]
    fn gating_and_reentrancy_preserve_pending_and_flags() {
        for flags in 0..=255u8 {
            for enabled in [0, 1, 255] {
                for force in [0, 1, u32::MAX] {
                    let mut resource = [0u8; UPDATE_PENDING + 1];
                    resource[FLAGS] = flags;
                    resource[UPDATE_ENABLED] = enabled;
                    resource[UPDATE_PENDING] = 0x73;
                    let eligible = force != 0 || (enabled != 0 && flags & 2 != 0);
                    let sends = eligible && flags & 8 == 0;
                    let ops = PlstResourceUpdateOps {
                        related,
                        message: if sends { dispatch } else { forbidden },
                    };
                    let result = unsafe { send_update(resource.as_mut_ptr(), force, ops) };
                    assert_eq!(result, if sends { 0xa5 } else { 0 });
                    assert_eq!(resource[UPDATE_PENDING], if eligible { 1 } else { 0x73 });
                    assert_eq!(resource[FLAGS], if sends { 0xe5 } else { flags });
                }
            }
        }
    }

    unsafe extern "C" fn reject(_resource: *mut u8, _message: u32, _reply: *mut u8) -> u32 {
        0xffff_ffce
    }

    #[test]
    fn rejected_message_returns_zero_reply_and_clears_guard() {
        let mut resource = [0u8; UPDATE_PENDING + 1];
        resource[FLAGS] = 0x41;
        let ops = PlstResourceUpdateOps { related, message: reject };
        assert_eq!(unsafe { send_update(resource.as_mut_ptr(), 1, ops) }, 0);
        assert_eq!(resource[FLAGS], 0x41);
        assert_eq!(resource[UPDATE_PENDING], 1);
    }

    #[test]
    fn helper_changes_are_observed_before_gating() {
        let mut resource = [0u8; UPDATE_PENDING + 1];
        let ops = PlstResourceUpdateOps { related: enable, message: dispatch };
        assert_eq!(unsafe { send_update(resource.as_mut_ptr(), 0, ops) }, 0xa5);
        assert_eq!(resource[FLAGS], 0xe5);
        assert_eq!(resource[UPDATE_PENDING], 1);
    }
}
