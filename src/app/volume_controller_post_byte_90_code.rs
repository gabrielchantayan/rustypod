//! `volume_controller_post_byte_90_code` — original: `FUN_081a5a30` @
//! **0x081a5a30** (40 bytes exactly, 0x081a5a30..0x081a5a58). The next
//! independently linked function opens `push {r4, r5, r6, lr}` at
//! 0x081a5a60; 0x081a5a58 and 0x081a5a5c are sibling event-code wrappers.
//! Raw A32 decoding finds two unconditional direct `bl` calls, no predicated
//! `bl` calls, and one unconditional tail `b` to `event_code_queue_post`.
//! A whole-image decode finds four incoming plain `bl` calls and no predicated
//! forms: 0x0817c618, 0x0817cb78, 0x0821df50, and 0x082a9b7c.
//!
//! ## Algorithm
//!
//! Obtain the volume-controller singleton, load its unsigned byte at +0x90,
//! and post code 4 when it is exactly one; post code 3 for every other byte.
//!
//! ## Deliberate deviation
//!
//! The retail tail branch is a normal Rust call. The byte's domain is not
//! established by its constructor or callers, so the exported name retains
//! the verified offset instead of inventing a status meaning.

use crate::app::event_code_queue::{event_code_queue_post, EventCodeQueue};
use crate::app::singletons::volume_controller_get;
use crate::app::volume_controller_byte_at_90::volume_controller_byte_at_90;

/// Posts 4 if the volume-controller byte at +0x90 equals one, otherwise 3.
///
/// # Safety
///
/// `this` must point to a live [`EventCodeQueue`]. The volume-controller
/// singleton must be constructible and contain readable byte +0x90.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn volume_controller_post_byte_90_code(this: *mut EventCodeQueue) {
    let volume_controller = volume_controller_get();
    let code = if volume_controller_byte_at_90(volume_controller) == 1 { 4 } else { 3 };
    event_code_queue_post(this, code);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::event_code_queue::{EventCodeQueueHooks, EVENT_CODE_QUEUE_HOOKS};
    use crate::app::singletons::{SINGLETON_LOCK, VOLUME_CONTROLLER_INSTANCE};
    use core::sync::atomic::{AtomicU32, Ordering};

    static POSTED_CODE: AtomicU32 = AtomicU32::new(u32::MAX);

    unsafe extern "C" fn record_enqueue(_queue: *mut u8, code: *const u32) {
        POSTED_CODE.store(*code, Ordering::SeqCst);
    }

    #[test]
    fn posts_four_only_for_byte_90_equal_to_one() {
        let _singleton = SINGLETON_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _event_queue = crate::testing::EVENT_CODE_QUEUE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let saved_instance = unsafe { core::ptr::addr_of!(VOLUME_CONTROLLER_INSTANCE).read_volatile() };
        let saved_hooks = unsafe { core::ptr::addr_of!(EVENT_CODE_QUEUE_HOOKS).read_volatile() };
        let mut volume_controller = [0u8; 0x91];
        let mut queue = EventCodeQueue {
            vtable: core::ptr::null(),
            pad_04: 0,
            queue: [0; 10],
            word_30: 0,
            mutex: crate::kernel::sync_mutex::Mutex { sem_cell: core::ptr::null_mut(), unused: 0 },
        };

        unsafe {
            core::ptr::addr_of_mut!(VOLUME_CONTROLLER_INSTANCE).write_volatile(volume_controller.as_mut_ptr());
            core::ptr::addr_of_mut!(EVENT_CODE_QUEUE_HOOKS).write_volatile(EventCodeQueueHooks { enqueue: record_enqueue });
        }
        for (byte, expected_code) in [(0u8, 3u32), (1, 4), (2, 3), (u8::MAX, 3)] {
            volume_controller[0x90] = byte;
            POSTED_CODE.store(u32::MAX, Ordering::SeqCst);

            unsafe { volume_controller_post_byte_90_code(&mut queue) };

            assert_eq!(POSTED_CODE.load(Ordering::SeqCst), expected_code, "byte at +0x90={byte:#04x}");
        }
        unsafe {
            core::ptr::addr_of_mut!(EVENT_CODE_QUEUE_HOOKS).write_volatile(saved_hooks);
            core::ptr::addr_of_mut!(VOLUME_CONTROLLER_INSTANCE).write_volatile(saved_instance);
        }
    }
}
