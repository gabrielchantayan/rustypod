//! Dispatches a temporary kind-0x19 message to a callback context.
//!
//! `kind_0x19_dispatch` — `FUN_081d1f60` @ **0x081d1f60**, **44 bytes**
//! (`0x081d1f60..0x081d1f8c`). Raw ARM ends with a tail branch to
//! `callback_dispatch_release`; the next word is a separate `bx lr` leaf.
//! Binary-wide branch decoding finds **2 unconditional BL callers**
//! (0x0808cd58 and 0x08143b30), **0 predicated BL callers**, and no B callers.
//! The body has two unconditional BL instructions and no predicated BL.
//!
//! Allocate eight bytes in the message-kind arena, construct kind 0x19,
//! then dispatch and release that message with extra=0, returning the
//! dispatch status. No allocation-failure guard exists in the original.
//!
//! Deliberate deviations: none. All three callees are already ported;
//! the dispatcher's existing firmware/host seam remains in its own module.

use crate::app::callback_dispatch_release::callback_dispatch_release;
use crate::app::message_kind::{message_kind_construct, MessageKind, MESSAGE_KIND_SIZE};
use crate::app::message_kind_arena::message_kind_arena_alloc;

macro_rules! kind_0x19_dispatch_body {
    ($context:expr; $alloc:expr, $dispatch:expr) => {{
        let storage = unsafe { $alloc(MESSAGE_KIND_SIZE) }.cast::<MessageKind>();
        let message = unsafe { message_kind_construct(storage, 0x19) };
        unsafe { $dispatch($context, message.cast(), 0) }
    }};
}

/// Constructs, dispatches, and releases a kind-0x19 message.
///
/// # Safety
/// The message-kind arena must be initialized or constructible, and `context`
/// must satisfy `callback_dispatch_release`'s dispatcher requirements.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn kind_0x19_dispatch(context: *mut u8) -> u32 {
    kind_0x19_dispatch_body!(context; message_kind_arena_alloc, callback_dispatch_release)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::callback_dispatch_release::DispatchValue;
    use crate::app::message_kind::MESSAGE_KIND_VTABLE;

    #[test]
    fn reused_envelope_replaces_stale_kind_without_touching_neighbors() {
        // Real constructor on dirty arena-sized storage; a consumer routes by
        // the resulting kind, rather than echoing the wrapper's arguments.
        for stale in [0, 0x18, 0x8000_0019, u32::MAX] {
            let mut words = [0xfeed_cafe, stale, stale, 0xdead_beef];
            let storage = unsafe { words.as_mut_ptr().add(1) };
            let allocate = |size: usize| {
                assert_eq!(size, 8);
                storage.cast::<u8>()
            };
            let consume = |_context: *mut u8, value: *mut DispatchValue, _extra: u32| {
                let message = value.cast::<MessageKind>();
                assert_eq!(unsafe { (*message).base.vtable }, MESSAGE_KIND_VTABLE);
                match unsafe { (*message).kind } {
                    0x19 => 0x8000_0001u32,
                    _ => 0,
                }
            };
            let result = kind_0x19_dispatch_body!(core::ptr::null_mut(); allocate, consume);
            assert_eq!(result, 0x8000_0001);
            assert_eq!(words, [0xfeed_cafe, MESSAGE_KIND_VTABLE, 0x19, 0xdead_beef]);
        }
    }
}
