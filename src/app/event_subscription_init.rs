//! `event_subscription_set_code` — original: `FUN_0811e84c` @ **0x0811e84c**.
//!
//! Raw firmware is 52 bytes (`0x0811e84c..0x0811e880`); `0x0811e880` starts
//! the next real function. Decoding every ARM call word finds four direct,
//! unconditional inbound `bl` calls (at `0x0811e97c`, `0x0811e9a0`,
//! `0x0816f78c`, and `0x082854fc`), no predicated calls, and two unconditional
//! outbound `bl` calls: `FUN_080ffcf0` at `0x080ffcf0` and `FUN_080ffa08` at
//! `0x080ffa08`.
//!
//! # Algorithm
//!
//! If `event_code` is already installed, return without touching the derived
//! fields. Otherwise store it at `+0x00`, then look up and store its event rank
//! at `+0x08` and descriptor at `+0x0c`.
//!
//! Deliberate deviation: neither table-lookup callee has a names.yaml entry or
//! a Rust port. Target builds call their verified retail addresses; host builds
//! use volatile seams so tests can supply their values.
//!
//! `event_subscription_init` — original: `FUN_0811e978` @ **0x0811e978**.
//!
//! Raw firmware is 44 bytes (`0x0811e978..0x0811e9a4`); `0x0811e9a4` begins
//! the next real function. Decoding every ARM `B`/`BL` word finds five direct
//! inbound calls, all unconditional `bl` (0x08173790, 0x08284af4, 0x08284e90,
//! 0x082858f0, and 0x082859d0), with no predicated calls. The body has one
//! outbound `bl`, to `event_subscription_set_code`.
//!
//! # Algorithm
//!
//! Clear the event-code word, active byte, rank, and descriptor (`+0x00`, byte
//! `+0x04`, `+0x08`, and `+0x0c`), then initialize the event code. The
//! constructor returns `this` regardless of the helper's return register.

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

type EventCodeLookup = unsafe extern "C" fn(u32) -> i32;

#[cfg(target_os = "none")]
const RETAIL_EVENT_RANK_LOOKUP: usize = 0x080f_fcf0;
#[cfg(target_os = "none")]
const RETAIL_EVENT_DESCRIPTOR_LOOKUP: usize = 0x080f_fa08;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn lookup_event_rank(event_code: u32) -> i32 {
    let lookup: EventCodeLookup = core::mem::transmute(RETAIL_EVENT_RANK_LOOKUP);
    lookup(event_code)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn lookup_event_descriptor(event_code: u32) -> i32 {
    let lookup: EventCodeLookup = core::mem::transmute(RETAIL_EVENT_DESCRIPTOR_LOOKUP);
    lookup(event_code)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_event_code_lookup(_event_code: u32) -> i32 {
    panic!("install event-subscription host operations before calling this function")
}

/// Host seams for the two unported event-code table lookups.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct EventSubscriptionInitOps {
    pub lookup_event_rank: EventCodeLookup,
    pub lookup_event_descriptor: EventCodeLookup,
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_EVENT_SUBSCRIPTION_INIT_OPS: EventSubscriptionInitOps = EventSubscriptionInitOps {
    lookup_event_rank: missing_event_code_lookup,
    lookup_event_descriptor: missing_event_code_lookup,
};

#[cfg(not(target_os = "none"))]
pub static mut EVENT_SUBSCRIPTION_INIT_OPS: EventSubscriptionInitOps = DEFAULT_EVENT_SUBSCRIPTION_INIT_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn lookup_event_rank(event_code: u32) -> i32 {
    let lookup = core::ptr::read_volatile(addr_of!(EVENT_SUBSCRIPTION_INIT_OPS.lookup_event_rank));
    lookup(event_code)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn lookup_event_descriptor(event_code: u32) -> i32 {
    let lookup = core::ptr::read_volatile(addr_of!(EVENT_SUBSCRIPTION_INIT_OPS.lookup_event_descriptor));
    lookup(event_code)
}

type EventActivityPredicate = unsafe extern "C" fn(u32) -> u32;

#[cfg(target_os = "none")]
const RETAIL_EVENT_ACTIVITY_PREDICATE: usize = 0x080f_fea0;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn event_is_active(event_code: u32) -> u32 {
    let predicate: EventActivityPredicate = core::mem::transmute(RETAIL_EVENT_ACTIVITY_PREDICATE);
    predicate(event_code)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_event_activity_predicate(_event_code: u32) -> u32 {
    panic!("install event-subscription host operations before calling this function")
}

/// Host seam for the unported event-activity predicate at `0x080ffea0`.
#[cfg(not(target_os = "none"))]
pub static mut EVENT_ACTIVITY_PREDICATE: EventActivityPredicate = missing_event_activity_predicate;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn event_is_active(event_code: u32) -> u32 {
    let predicate = core::ptr::read_volatile(core::ptr::addr_of!(EVENT_ACTIVITY_PREDICATE));
    predicate(event_code)
}

/// event_subscription_is_active — original: `FUN_0811e834` @ `0x0811e834`
/// (24 bytes).
///
/// Raw ARM spans `0x0811e834..0x0811e84c`; the next independently entered
/// function begins at `0x0811e84c`. It loads the subscription's event-code
/// word, calls the unported predicate at `0x080ffea0`, then canonicalizes any
/// nonzero result to one. Decoding every ARM B/BL word finds four direct
/// inbound plain `bl` calls at `0x0816f78c`, `0x0816f7b8`, `0x08171b30`, and
/// `0x081734d0`, with no predicated calls; its sole outbound call is a plain
/// `bl` to `0x080ffea0`.
///
/// Deliberate deviation: the predicate has no recovered names.yaml identity,
/// so target builds call its verified retail address and host builds use the
/// volatile seam above. The subscription layout and the wrapper's return
/// canonicalization are otherwise exact.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.event_subscription_is_active")]
#[inline(never)]
pub unsafe extern "C" fn event_subscription_is_active(subscription: *const EventSubscription) -> u32 {
    (event_is_active((*subscription).event_code) != 0) as u32
}


/// Installs `event_code` and derives its rank and descriptor when it changes.
///
/// # Safety
///
/// `subscription` must point to a writable target-layout record. The retail
/// function has no NULL guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.event_subscription_set_code")]
#[inline(never)]
pub unsafe extern "C" fn event_subscription_set_code(
    subscription: *mut EventSubscription,
    event_code: u32,
) {
    if (*subscription).event_code == event_code {
        return;
    }
    (*subscription).event_code = event_code;
    (*subscription).event_rank = lookup_event_rank(event_code) as u32;
    (*subscription).event_descriptor = lookup_event_descriptor((*subscription).event_code) as u32;
}

#[inline(always)]
unsafe fn set_event_code(subscription: *mut EventSubscription, event_code: u32) {
    event_subscription_set_code(subscription, event_code);
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
    use core::ptr::addr_of_mut;
    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut RANK_LOOKUP_CODE: u32 = 0;
    static mut DESCRIPTOR_LOOKUP_CODE: u32 = 0;
    static mut RANK_LOOKUP_COUNT: u32 = 0;
    static mut DESCRIPTOR_LOOKUP_COUNT: u32 = 0;
    static mut ACTIVITY_PREDICATE_CODE: u32 = 0;
    static mut ACTIVITY_PREDICATE_RESULT: u32 = 0;

    unsafe extern "C" fn record_activity_predicate(event_code: u32) -> u32 {
        ACTIVITY_PREDICATE_CODE = event_code;
        ACTIVITY_PREDICATE_RESULT
    }

    fn install_activity_predicate() -> std::sync::MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(ACTIVITY_PREDICATE_CODE).write(0);
            addr_of_mut!(ACTIVITY_PREDICATE_RESULT).write(0);
            addr_of_mut!(EVENT_ACTIVITY_PREDICATE).write(record_activity_predicate);
        }
        guard
    }


    unsafe extern "C" fn record_rank_lookup(event_code: u32) -> i32 {
        RANK_LOOKUP_CODE = event_code;
        RANK_LOOKUP_COUNT += 1;
        -1
    }

    unsafe extern "C" fn record_descriptor_lookup(event_code: u32) -> i32 {
        DESCRIPTOR_LOOKUP_CODE = event_code;
        DESCRIPTOR_LOOKUP_COUNT += 1;
        0x1234_5678
    }

    fn install_recorder() -> std::sync::MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(RANK_LOOKUP_CODE).write(0);
            addr_of_mut!(DESCRIPTOR_LOOKUP_CODE).write(0);
            addr_of_mut!(RANK_LOOKUP_COUNT).write(0);
            addr_of_mut!(DESCRIPTOR_LOOKUP_COUNT).write(0);
            addr_of_mut!(EVENT_SUBSCRIPTION_INIT_OPS).write(EventSubscriptionInitOps {
                lookup_event_rank: record_rank_lookup,
                lookup_event_descriptor: record_descriptor_lookup,
            });
        }
        guard
    }

    #[test]
    fn changed_code_updates_both_derived_fields_from_the_same_code() {
        let _guard = install_recorder();
        let mut subscription = EventSubscription {
            event_code: 0x1111_1111,
            active: 1,
            reserved_05_to_07: [0x22; 3],
            event_rank: 0x3333_3333,
            event_descriptor: 0x4444_4444,
        };

        unsafe { event_subscription_set_code(&mut subscription, 0xc000_0032) };

        assert_eq!(subscription.event_code, 0xc000_0032);
        assert_eq!(subscription.event_rank, u32::MAX);
        assert_eq!(subscription.event_descriptor, 0x1234_5678);
        unsafe {
            assert_eq!(RANK_LOOKUP_CODE, 0xc000_0032);
            assert_eq!(DESCRIPTOR_LOOKUP_CODE, 0xc000_0032);
            assert_eq!(RANK_LOOKUP_COUNT, 1);
            assert_eq!(DESCRIPTOR_LOOKUP_COUNT, 1);
        }
    }

    #[test]
    fn unchanged_code_skips_lookups_and_preserves_derived_fields() {
        let _guard = install_recorder();
        let mut subscription = EventSubscription {
            event_code: 0,
            active: 1,
            reserved_05_to_07: [0x22; 3],
            event_rank: 0x3333_3333,
            event_descriptor: 0x4444_4444,
        };

        unsafe { event_subscription_set_code(&mut subscription, 0) };

        assert_eq!(subscription.event_rank, 0x3333_3333);
        assert_eq!(subscription.event_descriptor, 0x4444_4444);
        unsafe {
            assert_eq!(RANK_LOOKUP_COUNT, 0);
            assert_eq!(DESCRIPTOR_LOOKUP_COUNT, 0);
        }
    }

    #[test]
    fn initializer_preserves_cleared_derived_fields_when_event_code_is_zero() {
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
        assert_eq!(subscription.event_code, 0);
        assert_eq!(subscription.active, 0);
        assert_eq!(subscription.event_rank, 0);
        assert_eq!(subscription.event_descriptor, 0);
        assert_eq!(subscription.reserved_05_to_07, [0x22; 3]);
    }
    #[test]
    fn activity_wrapper_passes_the_event_code_and_canonicalizes_predicate_results() {
        let _guard = install_activity_predicate();
        let subscription = EventSubscription {
            event_code: 0xc000_0032,
            active: 0xa5,
            reserved_05_to_07: [0x5a; 3],
            event_rank: 0x1111_1111,
            event_descriptor: 0x2222_2222,
        };

        unsafe {
            ACTIVITY_PREDICATE_RESULT = 0;
            assert_eq!(event_subscription_is_active(&subscription), 0);
            assert_eq!(ACTIVITY_PREDICATE_CODE, subscription.event_code);

            ACTIVITY_PREDICATE_RESULT = 1;
            assert_eq!(event_subscription_is_active(&subscription), 1);

            ACTIVITY_PREDICATE_RESULT = u32::MAX;
            assert_eq!(event_subscription_is_active(&subscription), 1);
        }
    }

}
