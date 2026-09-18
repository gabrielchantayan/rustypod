//! `application_message_post_global` — original: `FUN_081f0724` @
//! **0x081f0724** (**48 bytes exactly**, `0x081f0724..0x081f0753`; the
//! following `push {r4-r10, lr}` at `0x081f0754` begins a sibling).
//!
//! The four Ghidra-resolved callers all use plain `bl`; raw body decoding finds
//! two plain `bl` instructions: global application getter `0x0814b460`, then
//! the unported application-message dispatcher `0x0814b038`. No predicated
//! body call exists.
//!
//! # Algorithm
//!
//! Ignores its first (`owner`) argument, gets the current application object,
//! and calls the dispatcher as `(application, message_code, arg, payload,
//! flags)`. The ARM register moves and stack store preserve all four trailing
//! arguments exactly; the dispatcher's result is deliberately typed away.
//!
//! # Deliberate deviations
//!
//! The getter and dispatcher remain unported, so target builds invoke their
//! verified load addresses and host builds expose volatile replaceable seams.
//! This is the smallest faithful boundary; no identity beyond their recovered
//! application-object/message ABI is claimed.

pub type ApplicationGlobalGet = unsafe extern "C" fn() -> *mut u8;
pub type ApplicationMessageDispatch = unsafe extern "C" fn(*mut u8, u32, u32, *mut u8, u32);

const APPLICATION_GLOBAL_GET_ADDRESS: usize = 0x0814_b460;
const APPLICATION_MESSAGE_DISPATCH_ADDRESS: usize = 0x0814_b038;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_application_global_get() -> *mut u8 {
    unsafe { core::mem::transmute::<usize, ApplicationGlobalGet>(APPLICATION_GLOBAL_GET_ADDRESS)() }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_application_message_dispatch(
    application: *mut u8,
    message_code: u32,
    arg: u32,
    payload: *mut u8,
    flags: u32,
) {
    unsafe {
        core::mem::transmute::<usize, ApplicationMessageDispatch>(APPLICATION_MESSAGE_DISPATCH_ADDRESS)(
            application,
            message_code,
            arg,
            payload,
            flags,
        )
    }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_application_global_get() -> *mut u8 {
    panic!("application_message_post_global requires global getter 0x0814b460")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_application_message_dispatch(
    _application: *mut u8,
    _message_code: u32,
    _arg: u32,
    _payload: *mut u8,
    _flags: u32,
) {
    panic!("application_message_post_global requires dispatcher 0x0814b038")
}

#[cfg(target_os = "none")]
pub static mut APPLICATION_GLOBAL_GET: ApplicationGlobalGet = retail_application_global_get;
#[cfg(not(target_os = "none"))]
pub static mut APPLICATION_GLOBAL_GET: ApplicationGlobalGet = missing_application_global_get;

#[cfg(target_os = "none")]
pub static mut APPLICATION_MESSAGE_DISPATCH: ApplicationMessageDispatch = retail_application_message_dispatch;
#[cfg(not(target_os = "none"))]
pub static mut APPLICATION_MESSAGE_DISPATCH: ApplicationMessageDispatch = missing_application_message_dispatch;

#[inline(always)]
fn application_global_get() -> ApplicationGlobalGet {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(APPLICATION_GLOBAL_GET)) }
}

#[inline(always)]
fn application_message_dispatch() -> ApplicationMessageDispatch {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(APPLICATION_MESSAGE_DISPATCH)) }
}

/// Forwards a message through the current global application object.
///
/// # Safety
///
/// The retail function has no NULL checks: the getter result and all forwarded
/// words must satisfy the unported dispatcher's ABI.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", unsafe(link_section = ".text.application_message_post_global"))]
#[inline(never)]
pub unsafe extern "C" fn application_message_post_global(
    _owner: *mut u8,
    message_code: u32,
    arg: u32,
    payload: *mut u8,
    flags: u32,
) {
    unsafe { application_message_dispatch()(application_global_get()(), message_code, arg, payload, flags) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;
    static APPLICATION: AtomicUsize = AtomicUsize::new(0);
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static ARGS: [AtomicUsize; 5] = [
        AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0),
    ];
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn get_application() -> *mut u8 {
        APPLICATION.load(Ordering::SeqCst) as *mut u8
    }

    unsafe extern "C" fn record_dispatch(application: *mut u8, code: u32, arg: u32, payload: *mut u8, flags: u32) {
        CALLS.fetch_add(1, Ordering::SeqCst);
        for (slot, value) in ARGS.iter().zip([application as usize, code as usize, arg as usize, payload as usize, flags as usize]) {
            slot.store(value, Ordering::SeqCst);
        }
    }

    #[test]
    fn forwards_global_object_and_all_four_message_words() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            APPLICATION_GLOBAL_GET = get_application;
            APPLICATION_MESSAGE_DISPATCH = record_dispatch;
        }
        APPLICATION.store(0x1234_5678, Ordering::SeqCst);
        CALLS.store(0, Ordering::SeqCst);
        unsafe { application_message_post_global(core::ptr::null_mut(), 0xffff_fffe, 0x8000_0001, 0xdead_beef as *mut u8, 0xffff_ffff) };
        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(ARGS[0].load(Ordering::SeqCst), 0x1234_5678);
        assert_eq!(ARGS[1].load(Ordering::SeqCst), 0xffff_fffe);
        assert_eq!(ARGS[2].load(Ordering::SeqCst), 0x8000_0001);
        assert_eq!(ARGS[3].load(Ordering::SeqCst), 0xdead_beef);
        assert_eq!(ARGS[4].load(Ordering::SeqCst), 0xffff_ffff);
    }
}
