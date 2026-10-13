//! Service-25 IRAM gateway: `thunk_EXT_FUN_22004260` @ 0x08037e98.
//!
//! True veneer extent: 8 bytes, `e51ff004 / 22004260`, ending at the next
//! literal veneer at 0x08037ea0. Whole-image aligned ARM decoding finds one
//! plain BL (0x08393acc) and one BLNE (0x08393e90); also a tail B from
//! 0x08056900. The target is the IRAM mirror of 0x08004260, copied by
//! 0x080046e0, not mask ROM. Its 28-byte body ends at 0x0800427c:
//!
//! ```text
//! stmdb sp!, {r0-r4, lr}
//! str   r0, [sp, #8]
//! mov   r0, #25
//! str   r0, [sp]
//! mov   r0, sp
//! bl    0x08003660
//! ldmia sp!, {r0-r4, pc}
//! ```
//!
//! The writable request is `{25, incoming_r1, argument, incoming_r3}`.
//! Return r0 is the post-dispatch selector word, not the argument or word 1.
//! The debug console passes a nonzero task-like identifier only when it
//! differs from the current identifier; the other caller passes zero.
//! The exact service identity remains unestablished, so no task-operation
//! name or validation is invented.
//!
//! Deliberate deviations: use the existing message-dispatch veneer seam
//! instead of the IRAM tail transfer. Saved r4/LR are not service inputs and
//! their two frame words remain unspecified; Rust preserves callee-saved
//! registers through its ABI rather than restoring them from this frame.
//! Incoming r2 is overwritten by the original and is likewise ignored here.

use core::mem::MaybeUninit;
use crate::runtime::message_dispatch_veneer::message_dispatch_veneer;

/// Service-25 request — original load address 0x08037e98 (8-byte veneer),
/// mirror 0x08004260 (28 bytes); one plain and one predicated inbound BL.
/// Dispatches the selector and argument, returning the rewritten first word.
///
/// # Safety
/// The installed dispatcher must honor the service-25 writable frame ABI,
/// without reading the unspecified saved-register trailer as service data.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn gateway_service25_request(
    argument: u32, incoming_r1: u32, _incoming_r2: u32, incoming_r3: u32,
) -> u32 {
    let mut frame = [MaybeUninit::<u32>::uninit(); 6];
    let request = frame.as_mut_ptr().cast::<u32>();
    request.add(1).write(incoming_r1);
    request.add(3).write(incoming_r3);
    request.add(2).write(argument);
    request.write(25);
    message_dispatch_veneer(request);
    request.read()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::message_dispatch_veneer::{
        MessageDispatchVeneerOps, MESSAGE_DISPATCH_VENEER_OPS,
    };
    use crate::runtime::message_dispatch_veneer::tests::DISPATCH_OPS_LOCK;

    struct Restore(MessageDispatchVeneerOps);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { MESSAGE_DISPATCH_VENEER_OPS = self.0; }
        }
    }

    unsafe extern "C" fn rewrite_frame(request: *mut u32) {
        assert_eq!(request.read(), 25);
        assert_eq!(request.add(1).read(), 0x1234_5678);
        assert_eq!(request.add(3).read(), 0x8765_4321);
        let argument = request.add(2).read();
        request.write(argument ^ 0xa5a5_5a5a);
        // Distinct mutations catch returning the wrong saved-register word.
        request.add(1).write(0xdead_beef);
        request.add(2).write(0xfeed_face);
    }

    #[test]
    fn returns_rewritten_selector_for_zero_and_boundary_arguments() {
        let _lock = DISPATCH_OPS_LOCK.lock();
        let _restore = Restore(unsafe { MESSAGE_DISPATCH_VENEER_OPS });
        unsafe {
            MESSAGE_DISPATCH_VENEER_OPS = MessageDispatchVeneerOps { dispatch: rewrite_frame };
            for argument in [0, 1, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
                assert_eq!(
                    gateway_service25_request(argument, 0x1234_5678, !argument, 0x8765_4321),
                    argument ^ 0xa5a5_5a5a,
                );
            }
        }
    }
}
