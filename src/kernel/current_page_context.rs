//! Current-page context selection for the RAM stream buffer.
//!
//! Port: [`current_page_context`] — original: `FUN_0800722c` @ `0x0800722c`
//! (52 bytes; 4 direct `bl` call sites, all unconditional and zero predicated
//! forms, binary-verified by decoding every ARM B/BL word in `osos.dec`).
//!
//! ## Algorithm
//!
//! Gets the event-handler source, dispatches its event-loop callback, and uses
//! the fallback context at `stream_buffer + 0x13c` while that callback is
//! active. Otherwise it derives the producer's 4-KiB page index from words
//! `+0x08 - +0x00` and returns the corresponding context at `+0x34`.
//!
//! ## Deliberate deviations
//!
//! The recovered source-object layout is only modeled through its callback word
//! at +0x20; its callback target remains the existing host/retailOS seam.

use crate::drivers::event_loop_callback::dispatch_event_loop_callback;
use crate::kernel::event_handler_source::event_handler_source;

/// current_page_context — original: `FUN_0800722c` @ `0x0800722c` (52 bytes;
/// 4 direct, unconditional `bl` call sites and no predicated forms).
///
/// # Safety
///
/// `stream_buffer` must be non-null and valid for aligned 32-bit reads through
/// offset +0x13c. Its producer position at +0x08 must lie in the 32-page
/// allocation that begins at +0x00.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn current_page_context(stream_buffer: *const u8) -> u32 {
    let source = event_handler_source();
    if dispatch_event_loop_callback(source) != 0 {
        return stream_buffer.add(0x13c).cast::<u32>().read();
    }

    let buffer_start = stream_buffer.cast::<u32>().read();
    let producer_position = stream_buffer.add(0x08).cast::<u32>().read();
    let page_index = ((producer_position - buffer_start) >> 12) as usize;
    stream_buffer.add(0x34 + page_index * 4).cast::<u32>().read()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::current_page_context;
    use crate::drivers::event_loop_callback::{EventLoopCallbackDispatchOps, DEFAULT_EVENT_LOOP_CALLBACK_DISPATCH_OPS, EVENT_LOOP_CALLBACK_DISPATCH_OPS};
    use core::ptr::addr_of_mut;

    #[repr(align(4))]
    struct StreamBuffer([u8; 0x140]);

    unsafe extern "C" fn active_callback(_callback: u32) -> u32 {
        1
    }

    struct CallbackFixture {
        previous: EventLoopCallbackDispatchOps,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for CallbackFixture {
        fn drop(&mut self) {
            unsafe { addr_of_mut!(EVENT_LOOP_CALLBACK_DISPATCH_OPS).write(self.previous) };
        }
    }

    fn callback_fixture(dispatch: unsafe extern "C" fn(u32) -> u32) -> CallbackFixture {
        let lock = crate::testing::EVENT_LOOP_CALLBACK_DISPATCH_OPS_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let previous = unsafe { EVENT_LOOP_CALLBACK_DISPATCH_OPS };
        unsafe { addr_of_mut!(EVENT_LOOP_CALLBACK_DISPATCH_OPS).write(EventLoopCallbackDispatchOps { dispatch }) };
        CallbackFixture { previous, _lock: lock }
    }

    #[test]
    fn selects_the_producer_page_when_the_callback_is_not_active() {
        let _fixture = callback_fixture(DEFAULT_EVENT_LOOP_CALLBACK_DISPATCH_OPS.dispatch);
        let mut buffer = StreamBuffer([0; 0x140]);
        unsafe {
            buffer.0.as_mut_ptr().cast::<u32>().write(0x1000_0000);
            buffer.0.as_mut_ptr().add(0x08).cast::<u32>().write(0x1000_5000);
            buffer.0.as_mut_ptr().add(0x34 + 5 * 4).cast::<u32>().write(0xface_cafe);
            buffer.0.as_mut_ptr().add(0x13c).cast::<u32>().write(0xdead_beef);
            assert_eq!(current_page_context(buffer.0.as_ptr()), 0xface_cafe);
        }
    }

    #[test]
    fn selects_the_fallback_context_when_the_callback_is_active() {
        let _fixture = callback_fixture(active_callback);
        let mut buffer = StreamBuffer([0; 0x140]);
        unsafe {
            buffer.0.as_mut_ptr().cast::<u32>().write(0x2000_0000);
            buffer.0.as_mut_ptr().add(0x08).cast::<u32>().write(0x2000_3000);
            buffer.0.as_mut_ptr().add(0x34 + 3 * 4).cast::<u32>().write(0x1111_1111);
            buffer.0.as_mut_ptr().add(0x13c).cast::<u32>().write(0x2222_2222);
            assert_eq!(current_page_context(buffer.0.as_ptr()), 0x2222_2222);
        }
    }
}
