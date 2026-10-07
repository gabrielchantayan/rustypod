//! `context_word_message_dispatch` — `FUN_08147108` @ **0x08147108**.
//! True extent: **60 bytes**, 0x08147108..0x08147144 (next ARM prologue).
//! Whole-image aligned raw branch decoding: two plain BL callers at
//! 0x08147078 and 0x081470f8, zero predicated BL callers or B callers.
//! Body: four plain BLs, zero predicated BLs.
//!
//! Allocate a 12-byte envelope from the message arena, read the context's
//! message code at +0xe8, construct an owned four-byte payload from the
//! supplied word, then dispatch and release with extra=0. Callers supply
//! signed direction values -1/+1, but this function preserves all 32 bits.
//! Deliberate deviations: none on target; all four callees are ported.
//! Host tests inject allocation/consumption around the same body and run
//! the real payload constructor to check owned-copy lifetime and bit patterns.

use crate::app::callback_dispatch_release::callback_dispatch_release;
use crate::app::message_arena::message_arena_pool;
use crate::app::queued_message::queued_message_construct;
use crate::heap::fixed_block_pool::fixed_block_pool_alloc;

macro_rules! context_word_message_dispatch_body {
    ($context:expr, $word:expr; $allocate:expr, $construct:expr, $dispatch:expr) => {{
        let context = $context;
        let word: u32 = $word;
        let storage = unsafe { $allocate() };
        let code = unsafe { context.cast::<u32>().add(0xe8 / 4).read() };
        let message = unsafe { $construct(storage, code, core::ptr::addr_of!(word).cast::<u8>(), 4) };
        unsafe { $dispatch(context, message.cast(), 0) };
    }};
}

/// # Safety
/// `context` must be word-aligned and readable through +0xeb, and satisfy
/// the dispatcher requirements. Arena and payload allocations must succeed;
/// the original has no allocation-failure guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn context_word_message_dispatch(context: *mut u8, word: u32) {
    context_word_message_dispatch_body!(context, word;
        || fixed_block_pool_alloc(message_arena_pool(), 12).cast(),
        queued_message_construct, callback_dispatch_release);
}

#[cfg(test)]
mod tests {
    use crate::app::queued_message::{QueuedMessagePayload, queued_message_payload_construct};
    use crate::heap::veneers::tests::{mock_heap, set_alloc_ret};

    #[test]
    fn payload_owns_exact_word_and_preserves_context_boundaries() {
        let _heap = mock_heap();
        for word in [0, 1, u32::MAX, 0x8000_0000, 0x1234_5678] {
            let mut context = [0xfeed_cafeu32; 60];
            context[0xe8 / 4] = 0x8000_0097;
            let before = context;
            let mut copied = [0xa5u8; 12];
            set_alloc_ret(unsafe { copied.as_mut_ptr().add(4) });
            let mut payload = QueuedMessagePayload {
                vtable: 0, message_code: 0, byte_count: 0,
                bytes: core::ptr::null_mut(),
            };
            let storage = core::ptr::addr_of_mut!(payload).cast::<u8>();
            let allocate = || storage;
            let construct = |block, code, source, count| unsafe {
                queued_message_payload_construct(block, code, source, count)
            };
            let consume = |_context: *mut u8, message: *mut u8, _extra: u32| {
                let payload = unsafe { &*message.cast::<QueuedMessagePayload>() };
                assert_eq!(payload.message_code, 0x8000_0097);
                assert_eq!(payload.byte_count, 4);
                assert_eq!(unsafe { core::slice::from_raw_parts(payload.bytes, 4) }, &word.to_le_bytes());
            };
            context_word_message_dispatch_body!(context.as_mut_ptr().cast::<u8>(), word;
                allocate, construct, consume);
            assert_eq!(context, before);
            assert_eq!(&copied[..4], &[0xa5; 4]);
            assert_eq!(&copied[8..], &[0xa5; 4]);
            assert_eq!(&copied[4..8], &word.to_le_bytes());
        }
    }
}
