//! `callback_queue_context_post` — original: `FUN_0814c0b8` @ **0x0814c0b8**
//! (**64 bytes**: 60 instruction bytes followed by the `0x207` literal; **3
//! plain unconditional outbound `bl` calls**, zero predicated `bl` calls).
//!
//! Raw `osos.dec` establishes the extent `0x0814c0b8..0x0814c0f7`; the literal
//! at `0x0814c0f8` is not code and `push {r4-r8,lr}` at `0x0814c0fc` starts the
//! next real function. The function locks the context mutex at `+0x58`, tests
//! whether the lifecycle word at `context[+0x64]+0x30` is zero, and, only when
//! idle, posts kind `0x207` to the shared callback queue with the context as
//! payload. It tail-branches to `mutex_unlock` after restoring its frame.
//!
//! Deliberate deviation: the unported queue-post target `0x081fb41c` retains a
//! raw-address veneer on ARM; host tests install a narrow operations seam.

use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

const CONTEXT_MUTEX_WORD: usize = 0x58 / 4;
const CONTEXT_LIFECYCLE_WORD: usize = 0x64 / 4;
const LIFECYCLE_STATE_WORD: usize = 0x30 / 4;
pub const CALLBACK_QUEUE_CONTEXT_KIND: u32 = 0x207;

pub type CallbackQueuePost = unsafe extern "C" fn(*mut u8, u32, *mut u32);

#[cfg(target_arch = "arm")]
extern "C" {
    fn retail_callback_queue_post(queue: *mut u8, kind: u32, context: *mut u32);
}

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn callback_queue_post(queue: *mut u8, kind: u32, context: *mut u32) {
    retail_callback_queue_post(queue, kind, context);
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_callback_queue_post(_queue: *mut u8, _kind: u32, _context: *mut u32) {}

#[cfg(not(target_arch = "arm"))]
#[derive(Clone, Copy)]
pub struct CallbackQueueContextPostOps {
    pub queue: *mut u8,
    pub post: CallbackQueuePost,
}

#[cfg(not(target_arch = "arm"))]
pub const DEFAULT_CALLBACK_QUEUE_CONTEXT_POST_OPS: CallbackQueueContextPostOps =
    CallbackQueueContextPostOps { queue: core::ptr::null_mut(), post: missing_callback_queue_post };

#[cfg(not(target_arch = "arm"))]
pub static mut CALLBACK_QUEUE_CONTEXT_POST_OPS: CallbackQueueContextPostOps =
    DEFAULT_CALLBACK_QUEUE_CONTEXT_POST_OPS;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn callback_queue_post(queue: *mut u8, kind: u32, context: *mut u32) {
    (core::ptr::read_volatile(core::ptr::addr_of!(CALLBACK_QUEUE_CONTEXT_POST_OPS.post)))(queue, kind, context);
}

/// Posts `context` to the callback queue when its lifecycle state is idle.
///
/// # Safety
/// `context` must reference target-width words through `+0x64`, and that word
/// must be a non-null pointer to target-width words through `+0x30`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn callback_queue_context_post(context: *mut u32) {
    let mutex = context.add(CONTEXT_MUTEX_WORD).cast::<Mutex>();
    mutex_lock(mutex);

    let lifecycle = *context.add(CONTEXT_LIFECYCLE_WORD) as usize as *const u32;
    if *lifecycle.add(LIFECYCLE_STATE_WORD) == 0 {
        #[cfg(target_arch = "arm")]
        let queue = crate::app::callback_queue::callback_queue_instance_get();
        #[cfg(not(target_arch = "arm"))]
        let queue = core::ptr::read_volatile(core::ptr::addr_of!(CALLBACK_QUEUE_CONTEXT_POST_OPS.queue));
        callback_queue_post(queue, CALLBACK_QUEUE_CONTEXT_KIND, context);
    }

    mutex_unlock(mutex);
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
retail_callback_queue_post:
    ldr     pc, [pc, #-4]
    .word   0x081fb41c
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex as HostMutex, MutexGuard};

    static OPS_LOCK: HostMutex<()> = HostMutex::new(());
    static mut POST_CALLS: u32 = 0;
    static mut POST_QUEUE: *mut u8 = core::ptr::null_mut();
    static mut POST_KIND: u32 = 0;
    static mut POST_CONTEXT: *mut u32 = core::ptr::null_mut();

    unsafe extern "C" fn record_post(queue: *mut u8, kind: u32, context: *mut u32) {
        POST_CALLS += 1;
        POST_QUEUE = queue;
        POST_KIND = kind;
        POST_CONTEXT = context;
    }

    fn install_recorder(queue: *mut u8) -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(POST_CALLS).write(0);
            addr_of_mut!(POST_QUEUE).write(core::ptr::null_mut());
            addr_of_mut!(POST_KIND).write(0);
            addr_of_mut!(POST_CONTEXT).write(core::ptr::null_mut());
            addr_of_mut!(CALLBACK_QUEUE_CONTEXT_POST_OPS).write(CallbackQueueContextPostOps { queue, post: record_post });
        }
        guard
    }

    fn restore_default(guard: MutexGuard<'static, ()>) {
        unsafe { addr_of_mut!(CALLBACK_QUEUE_CONTEXT_POST_OPS).write(DEFAULT_CALLBACK_QUEUE_CONTEXT_POST_OPS) };
        drop(guard);
    }

    #[test]
    fn posts_idle_context_with_queue_kind_and_context() {
        let Some(base) = try_map_u32_slab(hints::CALLBACK_QUEUE_CONTEXT_POST, 0x1000) else { return };
        let context = base.cast::<u32>();
        let lifecycle = unsafe { context.add(0x80) };
        let mut queue = [0u8; 4];
        let guard = install_recorder(queue.as_mut_ptr());
        unsafe {
            context.add(CONTEXT_LIFECYCLE_WORD).write(lifecycle as usize as u32);
            lifecycle.add(LIFECYCLE_STATE_WORD).write(0);
            callback_queue_context_post(context);
            assert_eq!(addr_of!(POST_CALLS).read(), 1);
            assert_eq!(addr_of!(POST_QUEUE).read(), queue.as_mut_ptr());
            assert_eq!(addr_of!(POST_KIND).read(), CALLBACK_QUEUE_CONTEXT_KIND);
            assert_eq!(addr_of!(POST_CONTEXT).read(), context);
        }
        restore_default(guard);
    }

    #[test]
    fn does_not_post_non_idle_context() {
        let Some(base) = try_map_u32_slab(hints::CALLBACK_QUEUE_CONTEXT_POST_NON_IDLE, 0x1000) else { return };
        let context = base.cast::<u32>();
        let lifecycle = unsafe { context.add(0x80) };
        let guard = install_recorder(core::ptr::null_mut());
        unsafe {
            context.add(CONTEXT_LIFECYCLE_WORD).write(lifecycle as usize as u32);
            lifecycle.add(LIFECYCLE_STATE_WORD).write(1);
            callback_queue_context_post(context);
            assert_eq!(addr_of!(POST_CALLS).read(), 0);
        }
        restore_default(guard);
    }
}
