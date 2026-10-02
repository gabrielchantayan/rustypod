//! `kind_0x1f_message_post` — `FUN_0827e8f4` @ 0x0827e8f4.
//! True extent: 68 bytes, 0x0827e8f4..0x0827e938 (next function's push).
//! Raw A32: three plain outgoing BLs, zero predicated BLs, and one tail B
//! to 0x08110e4c. Whole-image decoding finds two plain incoming BLs,
//! zero predicated incoming BLs, and no incoming tail B.
//!
//! Allocates 28 bytes from the message-kind arena, constructs a kind-0x1f
//! message from five payload arguments, then dispatches with a NULL target
//! and returns the dispatch status. The third payload is truncated to a byte
//! by the existing constructor; its three neighboring bytes remain untouched.
//!
//! Deliberate deviations: no behavioral changes. Reuses the existing retail
//! dispatcher seam; Ghidra incorrectly includes its body in this wrapper.

use crate::app::kind_0x1f_message::{kind_0x1f_message_construct, Kind0x1fMessage, KIND_0X1F_MESSAGE_SIZE};
use crate::app::message_kind_arena::message_kind_arena_pool;
use crate::app::three_word_message_post::message_dispatch;
use crate::heap::fixed_block_pool::fixed_block_pool_alloc;

macro_rules! kind_0x1f_message_post_body {
    ($first:expr, $second:expr, $byte:expr, $fourth:expr, $fifth:expr; $pool:expr, $alloc:expr, $dispatch:expr) => {{
        let storage = unsafe { ($alloc)(($pool)(), KIND_0X1F_MESSAGE_SIZE) }.cast::<Kind0x1fMessage>();
        let message = unsafe {
            kind_0x1f_message_construct(storage, $first, $second, $byte, $fourth, $fifth)
        };
        unsafe { ($dispatch)(message.cast(), core::ptr::null_mut()) }
    }};
}

/// Constructs and dispatches a kind-0x1f message, returning its status.
///
/// # Safety
/// The arena and dispatcher must be initialized. Allocation must return at
/// least 28 writable, word-aligned bytes. RetailOS does not check NULL.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn kind_0x1f_message_post(
    first_payload: u32,
    second_payload: u32,
    byte_payload: u32,
    fourth_payload: u32,
    fifth_payload: u32,
) -> u32 {
    kind_0x1f_message_post_body!(
        first_payload, second_payload, byte_payload, fourth_payload, fifth_payload;
        message_kind_arena_pool, fixed_block_pool_alloc, message_dispatch()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::kind_0x1f_message::KIND_0X1F_MESSAGE_VTABLE;
    use crate::app::message_kind::MessageKind;
    use crate::heap::fixed_block_pool::FixedBlockPool;

    #[test]
    fn dispatch_observes_constructed_message_with_byte_tail_and_guards_preserved() {
        #[repr(C, align(4))]
        struct Storage { before: u32, message: Kind0x1fMessage, after: u32 }
        for payload in [[0; 5], [u32::MAX; 5], [0x10203040, 0x50607080, 0xabcdef00, 0x12345678, 0x87654321]] {
            let mut storage: Storage = unsafe { core::mem::zeroed() };
            storage.before = 0x1234abcd;
            storage.after = 0xabcd1234;
            storage.message.byte_payload_tail = [0x12, 0x34, 0x56];
            let message = core::ptr::addr_of_mut!(storage.message);
            let result = kind_0x1f_message_post_body!(
                payload[0], payload[1], payload[2], payload[3], payload[4];
                || core::ptr::null_mut::<FixedBlockPool>(),
                |_: *mut FixedBlockPool, size: usize| { assert_eq!(size, 28); message.cast::<u8>() },
                |actual: *mut MessageKind, target: *mut u8| {
                    assert!(target.is_null());
                    assert_eq!(actual, message.cast());
                    let actual = &*actual.cast::<Kind0x1fMessage>();
                    assert_eq!(actual.base.base.vtable, KIND_0X1F_MESSAGE_VTABLE);
                    assert_eq!(actual.base.kind, 0x1f);
                    assert_eq!(actual.first_payload, payload[0]);
                    assert_eq!(actual.second_payload, payload[1]);
                    assert_eq!(actual.byte_payload, payload[2] as u8);
                    assert_eq!(actual.byte_payload_tail, [0x12, 0x34, 0x56]);
                    assert_eq!(actual.fourth_payload, payload[3]);
                    assert_eq!(actual.fifth_payload, payload[4]);
                    0xfedcba98u32
                }
            );
            assert_eq!(result, 0xfedcba98);
            assert_eq!(storage.before, 0x1234abcd);
            assert_eq!(storage.after, 0xabcd1234);
        }
    }
}
