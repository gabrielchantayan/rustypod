//! Dispatches idle-context preparation, then registers the context and posts a message.
//!
//! `context_dispatch_and_register_if_idle` — original: `FUN_081f1024` @
//! `0x081f1024` (124 bytes including its trailing literal; executable body is
//! `0x081f1024..0x081f109c`; `push {r4, lr}` at `0x081f10a0` begins the next
//! real function).
//!
//! Raw A32 decoding verifies seven unconditional outgoing `bl` instructions
//! (`0x0807f5c4`, `0x081f08f8`, `0x0807f6a0`, `0x0814b460`, `0x0814b51c`,
//! `0x081f0724`, and `0x0807f6a0`) and no predicated BL forms. The context's
//! lifecycle guard at `+0x50` is acquired first and released on every path.
//! A nonzero byte at `+0x70` only releases that guard and returns zero. When
//! clear, retailOS prepares the context, registers it with the current global
//! registry, and posts message `0x52800004` when registration succeeds.
//!
//! Deliberate deviations: the six unported callees retain only role-based
//! names. Target builds call their verified retailOS addresses; host builds
//! provide narrow callback seams. The target C++ helper at `0x0814b51c`
//! currently always returns one, but the observed zero-result branch is kept.

const LIFECYCLE_GUARD_OFFSET: usize = 0x50;
const IDLE_FLAG_OFFSET: usize = 0x70;
const IDLE_CONTEXT_MESSAGE: u32 = 0x5280_0004;

pub type ContextLifecycleGuard = unsafe extern "C" fn(*mut u8);
pub type IdleContextPrepare = unsafe extern "C" fn(*mut u8);
pub type CurrentRegistry = unsafe extern "C" fn() -> *mut u8;
pub type RegisterContext = unsafe extern "C" fn(*mut u8, *mut u8) -> u32;
pub type IdleContextMessagePost = unsafe extern "C" fn(*mut u8, u32, u32, u32, u32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_lifecycle_guard(_guard: *mut u8) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_prepare(_context: *mut u8) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_current_registry() -> *mut u8 { core::ptr::null_mut() }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_register(_registry: *mut u8, _context: *mut u8) -> u32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_message_post(_context: *mut u8, _message: u32, _first: u32, _second: u32, _priority: u32) {}

/// Host seams for the unported retailOS calls.
#[cfg(not(target_os = "none"))]
pub static mut CONTEXT_LIFECYCLE_LOCK: ContextLifecycleGuard = missing_lifecycle_guard;
#[cfg(not(target_os = "none"))]
pub static mut CONTEXT_LIFECYCLE_UNLOCK: ContextLifecycleGuard = missing_lifecycle_guard;
#[cfg(not(target_os = "none"))]
pub static mut IDLE_CONTEXT_PREPARE: IdleContextPrepare = missing_prepare;
#[cfg(not(target_os = "none"))]
pub static mut CURRENT_CONTEXT_REGISTRY: CurrentRegistry = missing_current_registry;
#[cfg(not(target_os = "none"))]
pub static mut REGISTER_CONTEXT: RegisterContext = missing_register;
#[cfg(not(target_os = "none"))]
pub static mut IDLE_CONTEXT_MESSAGE_POST: IdleContextMessagePost = missing_message_post;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn context_lifecycle_lock() -> ContextLifecycleGuard { core::mem::transmute(0x0807_f5c4usize) }
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn context_lifecycle_unlock() -> ContextLifecycleGuard { core::mem::transmute(0x0807_f6a0usize) }
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn idle_context_prepare() -> IdleContextPrepare { core::mem::transmute(0x081f_08f8usize) }
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn current_context_registry() -> CurrentRegistry { core::mem::transmute(0x0814_b460usize) }
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn register_context() -> RegisterContext { core::mem::transmute(0x0814_b51cusize) }
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn idle_context_message_post() -> IdleContextMessagePost { core::mem::transmute(0x081f_0724usize) }

/// Prepares and registers an idle context, returning whether it posted the idle message.
///
/// `context` must be valid through byte `+0x70`; retailOS performs no null or
/// bounds checks. Every selected callback must satisfy its observed ABI.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.context_dispatch_and_register_if_idle")]
pub unsafe extern "C" fn context_dispatch_and_register_if_idle(context: *mut u8) -> u32 {
    let guard = unsafe { context.add(LIFECYCLE_GUARD_OFFSET) };
    #[cfg(target_os = "none")]
    unsafe { context_lifecycle_lock()(guard) };
    #[cfg(not(target_os = "none"))]
    unsafe { CONTEXT_LIFECYCLE_LOCK(guard) };

    if unsafe { context.add(IDLE_FLAG_OFFSET).read() } != 0 {
        #[cfg(target_os = "none")]
        unsafe { context_lifecycle_unlock()(guard) };
        #[cfg(not(target_os = "none"))]
        unsafe { CONTEXT_LIFECYCLE_UNLOCK(guard) };
        return 0;
    }

    #[cfg(target_os = "none")]
    unsafe { idle_context_prepare()(context) };
    #[cfg(not(target_os = "none"))]
    unsafe { IDLE_CONTEXT_PREPARE(context) };

    #[cfg(target_os = "none")]
    unsafe { context_lifecycle_unlock()(guard) };
    #[cfg(not(target_os = "none"))]
    unsafe { CONTEXT_LIFECYCLE_UNLOCK(guard) };

    #[cfg(target_os = "none")]
    let registry = unsafe { current_context_registry()() };
    #[cfg(not(target_os = "none"))]
    let registry = unsafe { CURRENT_CONTEXT_REGISTRY() };
    #[cfg(target_os = "none")]
    let registered = unsafe { register_context()(registry, context) };
    #[cfg(not(target_os = "none"))]
    let registered = unsafe { REGISTER_CONTEXT(registry, context) };
    if registered == 0 {
        return 0;
    }

    #[cfg(target_os = "none")]
    unsafe { idle_context_message_post()(context, IDLE_CONTEXT_MESSAGE, 0, 0, 1) };
    #[cfg(not(target_os = "none"))]
    unsafe { IDLE_CONTEXT_MESSAGE_POST(context, IDLE_CONTEXT_MESSAGE, 0, 0, 1) };
    1
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static mut TRACE: [u8; 6] = [0; 6];
    static mut REGISTER_ARGS: (usize, usize) = (0, 0);
    static mut POST_ARGS: (usize, u32, u32, u32, u32) = (0, 0, 0, 0, 0);
    static mut REGISTER_RESULT: u32 = 0;

    unsafe extern "C" fn lock(_guard: *mut u8) { unsafe { TRACE[CALLS.fetch_add(1, Ordering::SeqCst)] = 1; } }
    unsafe extern "C" fn unlock(_guard: *mut u8) { unsafe { TRACE[CALLS.fetch_add(1, Ordering::SeqCst)] = 2; } }
    unsafe extern "C" fn prepare(_context: *mut u8) { unsafe { TRACE[CALLS.fetch_add(1, Ordering::SeqCst)] = 3; } }
    unsafe extern "C" fn registry() -> *mut u8 { unsafe { TRACE[CALLS.fetch_add(1, Ordering::SeqCst)] = 4; } 0x1234usize as *mut u8 }
    unsafe extern "C" fn register(registry: *mut u8, context: *mut u8) -> u32 { unsafe { TRACE[CALLS.fetch_add(1, Ordering::SeqCst)] = 5; REGISTER_ARGS = (registry as usize, context as usize); REGISTER_RESULT } }
    unsafe extern "C" fn post(context: *mut u8, message: u32, first: u32, second: u32, priority: u32) { unsafe { TRACE[CALLS.fetch_add(1, Ordering::SeqCst)] = 6; POST_ARGS = (context as usize, message, first, second, priority); } }

    unsafe fn install_seams(result: u32) {
        CALLS.store(0, Ordering::SeqCst);
        TRACE = [0; 6];
        REGISTER_ARGS = (0, 0);
        POST_ARGS = (0, 0, 0, 0, 0);
        REGISTER_RESULT = result;
        CONTEXT_LIFECYCLE_LOCK = lock;
        CONTEXT_LIFECYCLE_UNLOCK = unlock;
        IDLE_CONTEXT_PREPARE = prepare;
        CURRENT_CONTEXT_REGISTRY = registry;
        REGISTER_CONTEXT = register;
        IDLE_CONTEXT_MESSAGE_POST = post;
    }

    #[test]
    fn active_context_only_unlocks() {
        let _guard = TEST_LOCK.lock();
        let mut context = [0u8; 0x71];
        context[IDLE_FLAG_OFFSET] = 1;
        unsafe { install_seams(1); }
        assert_eq!(unsafe { context_dispatch_and_register_if_idle(context.as_mut_ptr()) }, 0);
        assert_eq!(CALLS.load(Ordering::SeqCst), 2);
        assert_eq!(unsafe { &TRACE[..2] }, &[1, 2]);
    }

    #[test]
    fn idle_context_prepares_unlocks_registers_and_posts_on_success() {
        let _guard = TEST_LOCK.lock();
        let mut context = [0u8; 0x71];
        unsafe { install_seams(1); }
        assert_eq!(unsafe { context_dispatch_and_register_if_idle(context.as_mut_ptr()) }, 1);
        assert_eq!(CALLS.load(Ordering::SeqCst), 6);
        assert_eq!(unsafe { &TRACE }, &[1, 3, 2, 4, 5, 6]);
        assert_eq!(unsafe { REGISTER_ARGS }, (0x1234, context.as_ptr() as usize));
        assert_eq!(unsafe { POST_ARGS }, (context.as_ptr() as usize, IDLE_CONTEXT_MESSAGE, 0, 0, 1));
    }

    #[test]
    fn idle_context_does_not_post_when_registration_fails() {
        let _guard = TEST_LOCK.lock();
        let mut context = [0u8; 0x71];
        unsafe { install_seams(0); }
        assert_eq!(unsafe { context_dispatch_and_register_if_idle(context.as_mut_ptr()) }, 0);
        assert_eq!(CALLS.load(Ordering::SeqCst), 5);
        assert_eq!(unsafe { &TRACE[..5] }, &[1, 3, 2, 4, 5]);
    }
}
