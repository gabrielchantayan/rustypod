//! `event_subscription_init` — original: `FUN_0811e978` @ **0x0811e978**.
//!
//! Raw firmware is 44 bytes (`0x0811e978..0x0811e9a4`); `0x0811e9a4` begins
//! the next real function. Decoding every ARM `B`/`BL` word finds five direct
//! inbound calls, all unconditional `bl` (0x08173790, 0x08284af4, 0x08284e90,
//! 0x082858f0, and 0x082859d0), with no predicated calls. The body has one
//! outbound `bl`, to the unported `FUN_0811e84c` at `0x0811e84c`.
//!
//! # Algorithm
//!
//! Clear the event-code word, active byte, rank, and descriptor (`+0x00`, byte
//! `+0x04`, `+0x08`, and `+0x0c`), then initialize its event code through
//! stores the code and derives the two words at `+0x08` and `+0x0c` from the
//! firmware event tables. The constructor returns `this` regardless of the
//! helper's return register.
//!
//! Deliberate deviation: `FUN_0811e84c` is not ported. Target builds call its
//! verified retail address; host tests install a seam and verify the cleared
//! record and forwarded event code.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

/// The target's exact 16-byte event-subscription record layout.
#[repr(C)]
pub struct EventSubscription {
    pub event_code: u32,
    pub active: u8,
    pub reserved_05_to_07: [u8; 3],
    pub event_rank: u32,
    pub event_descriptor: u32,
}

/// ABI of the unported event-code initializer at `0x0811e84c`.
pub type EventSubscriptionSetCode = unsafe extern "C" fn(*mut EventSubscription, u32);

#[cfg(target_os = "none")]
const RETAIL_EVENT_SUBSCRIPTION_SET_CODE: usize = 0x0811_e84c;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn set_event_code(subscription: *mut EventSubscription, event_code: u32) {
    let set_code: EventSubscriptionSetCode = core::mem::transmute(RETAIL_EVENT_SUBSCRIPTION_SET_CODE);
    set_code(subscription, event_code);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_event_subscription_set_code(
    _subscription: *mut EventSubscription,
    _event_code: u32,
) {
    panic!("install event-subscription host operations before calling this constructor")
}

/// Host seam for unported `FUN_0811e84c`.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct EventSubscriptionInitOps {
    pub set_event_code: EventSubscriptionSetCode,
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_EVENT_SUBSCRIPTION_INIT_OPS: EventSubscriptionInitOps = EventSubscriptionInitOps {
    set_event_code: missing_event_subscription_set_code,
};

#[cfg(not(target_os = "none"))]
pub static mut EVENT_SUBSCRIPTION_INIT_OPS: EventSubscriptionInitOps = DEFAULT_EVENT_SUBSCRIPTION_INIT_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn set_event_code(subscription: *mut EventSubscription, event_code: u32) {
    let set_code = core::ptr::read_volatile(addr_of!(EVENT_SUBSCRIPTION_INIT_OPS.set_event_code));
    set_code(subscription, event_code);
}

/// Clears `subscription`, initializes its event code, and returns `subscription`.
///
/// # Safety
///
/// `subscription` must point to a writable target-layout record. The event-code
/// initializer has no NULL guard in retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.event_subscription_init")]
#[inline(never)]
pub unsafe extern "C" fn event_subscription_init(
    subscription: *mut EventSubscription,
    event_code: u32,
) -> *mut EventSubscription {
    subscription.cast::<u32>().write(0);
    subscription.cast::<u8>().add(4).write(0);
    subscription.cast::<u32>().add(2).write(0);
    subscription.cast::<u32>().add(3).write(0);
    set_event_code(subscription, event_code);
    subscription
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut SEEN_SUBSCRIPTION: *mut EventSubscription = core::ptr::null_mut();
    static mut SEEN_EVENT_CODE: u32 = 0;
    static mut RECORD_WAS_CLEARED: bool = false;

    unsafe extern "C" fn record_set_code(subscription: *mut EventSubscription, event_code: u32) {
        SEEN_SUBSCRIPTION = subscription;
        SEEN_EVENT_CODE = event_code;
        RECORD_WAS_CLEARED = (*subscription).event_code == 0
            && (*subscription).active == 0
            && (*subscription).event_rank == 0
            && (*subscription).event_descriptor == 0;
        (*subscription).event_code = event_code;
        (*subscription).event_rank = 0x7fff_ffff;
        (*subscription).event_descriptor = 0xfeed_cafe;
    }

    fn install_recorder() -> std::sync::MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(SEEN_SUBSCRIPTION).write(core::ptr::null_mut());
            addr_of_mut!(SEEN_EVENT_CODE).write(0);
            addr_of_mut!(RECORD_WAS_CLEARED).write(false);
            addr_of_mut!(EVENT_SUBSCRIPTION_INIT_OPS).write(EventSubscriptionInitOps {
                set_event_code: record_set_code,
            });
        }
        guard
    }

    #[test]
    fn clears_targeted_fields_and_preserves_padding_before_initializing_zero_event_code() {
        let _guard = install_recorder();
        let mut subscription = EventSubscription {
            event_code: 0x1111_1111,
            active: 1,
            reserved_05_to_07: [0x22; 3],
            event_rank: 0x3333_3333,
            event_descriptor: 0x4444_4444,
        };

        let returned = unsafe { event_subscription_init(&mut subscription, 0) };

        assert!(core::ptr::eq(returned, &mut subscription));
        unsafe {
            assert!(core::ptr::eq(SEEN_SUBSCRIPTION, &mut subscription));
            assert_eq!(SEEN_EVENT_CODE, 0);
            assert!(RECORD_WAS_CLEARED);
        }
        assert_eq!(subscription.event_code, 0);
        assert_eq!(subscription.event_rank, 0x7fff_ffff);
        assert_eq!(subscription.event_descriptor, 0xfeed_cafe);
        assert_eq!(subscription.reserved_05_to_07, [0x22; 3]);
    }

    #[test]
    fn forwards_nonzero_event_code_after_clearing_targeted_fields() {
        let _guard = install_recorder();
        let mut subscription = EventSubscription {
            event_code: u32::MAX,
            active: u8::MAX,
            reserved_05_to_07: [u8::MAX; 3],
            event_rank: u32::MAX,
            event_descriptor: u32::MAX,
        };

        unsafe { event_subscription_init(&mut subscription, 0xc000_0032) };

        unsafe {
            assert_eq!(SEEN_EVENT_CODE, 0xc000_0032);
            assert!(RECORD_WAS_CLEARED);
        }
        assert_eq!(subscription.reserved_05_to_07, [u8::MAX; 3]);
    }
}
