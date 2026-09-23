//! `event_subscription_rtc_sync` — original: `FUN_0816f75c` @ **0x0816f75c**.
//!
//! Raw ARM spans 216 bytes (`0x0816f75c..0x0816f834`); the literal pool begins
//! at `0x0816f834` and `0x0816f844` is the next independently entered function.
//! It has nine unconditional direct `bl` instructions, no predicated direct
//! `bl`, and three indirect `blx` calls through vtable slot `+0x58`.
//!
//! # Algorithm
//!
//! Update the embedded event subscription and RTC configuration from `value`.
//! Schedule the event rank at either zero or 60 seconds according to its active
//! predicate. If either update changed, post three resource messages and root
//! message `0x6000_0004`, then tail-call the unported owner refresh at
//! `0x08065d08`.
//!
//! Deliberate deviations: the unported RTC word setter (`0x08067b20`), scheduler
//! (`0x080dc3e8`), owner refresh (`0x08065d08`), and virtual message slot have
//! no established Rust identities. Target builds call verified retail addresses;
//! host builds inject opaque calls through `EVENT_SUBSCRIPTION_RTC_SYNC_OPS`.

use core::ptr;

const SUBSCRIPTION_WORD: usize = 0x5c / 4;
const RTC_OWNER_WORD: usize = 0xa8 / 4;
const MESSAGE_CATEGORY: u32 = 0x2a2a_2a2a;
const MESSAGE_FIRST: u32 = 0x6094;
const MESSAGE_SECOND: u32 = 0x6095;
const MESSAGE_THIRD: u32 = 0x6096;
const ROOT_MESSAGE: u32 = 0x6000_0004;

type EventSet = unsafe extern "C" fn(*mut u8, u32);
type RtcSet = unsafe extern "C" fn(*mut u8, u32) -> u32;
type EventActive = unsafe extern "C" fn(*const u8) -> u32;
type Schedule = unsafe extern "C" fn(u32, u32);
type Dispatch = unsafe extern "C" fn(*mut u8, u32, u32);
type RootPost = unsafe extern "C" fn(u32);
type OwnerRefresh = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
unsafe fn target_sync(receiver: *mut u8, value: u32) {
    let subscription = ptr::read(receiver.cast::<*const u32>().add(SUBSCRIPTION_WORD)) as usize as *mut u8;
    let owner = ptr::read(receiver.cast::<*const u32>().add(RTC_OWNER_WORD)) as usize as *mut u8;
    let event_set: EventSet = core::mem::transmute(0x0811_e84cusize);
    let word_set: RtcSet = core::mem::transmute(0x0806_7b20usize);
    let configuration_set: RtcSet = core::mem::transmute(0x0806_7af4usize);
    let event_active: EventActive = core::mem::transmute(0x0811_e834usize);
    let schedule: Schedule = core::mem::transmute(0x080d_c3e8usize);
    let dispatch: Dispatch = core::mem::transmute(ptr::read((ptr::read(receiver.cast::<*const u32>()) as *const u32).add(0x58 / 4)) as usize);
    let root_post: RootPost = core::mem::transmute(0x081d_2408usize);
    let owner_refresh: OwnerRefresh = core::mem::transmute(0x0806_5d08usize);
    event_set(subscription, value);
    let first_changed = word_set(owner, value);
    let active = event_active(subscription);
    let second_changed = configuration_set(owner, active);
    let rank = ptr::read(subscription.cast::<u32>().add(2));
    schedule(rank, if event_active(subscription) != 0 { 60 } else { 0 });
    if first_changed != 0 || second_changed != 0 {
        dispatch(receiver, MESSAGE_CATEGORY, MESSAGE_FIRST); dispatch(receiver, MESSAGE_CATEGORY, MESSAGE_SECOND); dispatch(receiver, MESSAGE_CATEGORY, MESSAGE_THIRD); root_post(ROOT_MESSAGE);
    }
    owner_refresh(owner);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_event_set(_: *mut u8, _: u32) { panic!("install event-subscription RTC sync operations") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_rtc_set(_: *mut u8, _: u32) -> u32 { panic!("install event-subscription RTC sync operations") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_active(_: *const u8) -> u32 { panic!("install event-subscription RTC sync operations") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_schedule(_: u32, _: u32) { panic!("install event-subscription RTC sync operations") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_dispatch(_: *mut u8, _: u32, _: u32) { panic!("install event-subscription RTC sync operations") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_root(_: u32) { panic!("install event-subscription RTC sync operations") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_refresh(_: *mut u8) { panic!("install event-subscription RTC sync operations") }

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct EventSubscriptionRtcSyncOps { pub event_set: EventSet, pub word_set: RtcSet, pub event_active: EventActive, pub configuration_set: RtcSet, pub schedule: Schedule, pub dispatch: Dispatch, pub root_post: RootPost, pub owner_refresh: OwnerRefresh }
#[cfg(not(target_os = "none"))]
pub const DEFAULT_EVENT_SUBSCRIPTION_RTC_SYNC_OPS: EventSubscriptionRtcSyncOps = EventSubscriptionRtcSyncOps { event_set: missing_event_set, word_set: missing_rtc_set, event_active: missing_active, configuration_set: missing_rtc_set, schedule: missing_schedule, dispatch: missing_dispatch, root_post: missing_root, owner_refresh: missing_refresh };
#[cfg(not(target_os = "none"))]
pub static mut EVENT_SUBSCRIPTION_RTC_SYNC_OPS: EventSubscriptionRtcSyncOps = DEFAULT_EVENT_SUBSCRIPTION_RTC_SYNC_OPS;

/// Synchronizes the receiver's subscription, RTC configuration, and notifications.
///
/// # Safety
/// `receiver` must designate a target-layout object with readable words at `+0x5c` and `+0xa8`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn event_subscription_rtc_sync(receiver: *mut u8, value: u32) {
    #[cfg(target_os = "none")]
    target_sync(receiver, value);
    #[cfg(not(target_os = "none"))]
    {
        let ops = ptr::read_volatile(ptr::addr_of!(EVENT_SUBSCRIPTION_RTC_SYNC_OPS));
        let subscription = ptr::read(receiver.cast::<*mut u8>().add(SUBSCRIPTION_WORD));
        let owner = ptr::read(receiver.cast::<*mut u8>().add(RTC_OWNER_WORD));
        (ops.event_set)(subscription, value); let first_changed = (ops.word_set)(owner, value);
        let active = (ops.event_active)(subscription); let second_changed = (ops.configuration_set)(owner, active);
        let rank = ptr::read(subscription.cast::<u32>().add(2)); (ops.schedule)(rank, if (ops.event_active)(subscription) != 0 { 60 } else { 0 });
        if first_changed != 0 || second_changed != 0 { (ops.dispatch)(receiver, MESSAGE_CATEGORY, MESSAGE_FIRST); (ops.dispatch)(receiver, MESSAGE_CATEGORY, MESSAGE_SECOND); (ops.dispatch)(receiver, MESSAGE_CATEGORY, MESSAGE_THIRD); (ops.root_post)(ROOT_MESSAGE); }
        (ops.owner_refresh)(owner);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    static mut EVENTS: [u32; 16] = [0; 16]; static mut COUNT: usize = 0;
    unsafe fn record(value: u32) { EVENTS[COUNT] = value; COUNT += 1; }
    unsafe extern "C" fn event_set(_: *mut u8, value: u32) { record(0x1000_0000 | value); }
    unsafe extern "C" fn word_set(_: *mut u8, value: u32) -> u32 { record(0x2000_0000 | value); (value == 7) as u32 }
    unsafe extern "C" fn active(_: *const u8) -> u32 { 1 }
    unsafe extern "C" fn schedule(rank: u32, delay: u32) { record(0x3000_0000 | rank); record(delay); }
    unsafe extern "C" fn dispatch(_: *mut u8, _: u32, resource: u32) { record(resource); }
    unsafe extern "C" fn root(message: u32) { record(message); }
    unsafe extern "C" fn refresh(_: *mut u8) { record(0xdead_beef); }
    #[test]
    fn synchronizes_notifications_and_refreshes_owner_when_the_first_update_changes() { unsafe {
        COUNT = 0; EVENT_SUBSCRIPTION_RTC_SYNC_OPS = EventSubscriptionRtcSyncOps { event_set, word_set, event_active: active, configuration_set: word_set, schedule, dispatch, root_post: root, owner_refresh: refresh };
        let mut subscription = [0u32; 3]; subscription[2] = 9;
        let mut owner = [0usize; 1];
        let mut receiver = [0usize; RTC_OWNER_WORD + 1]; receiver[SUBSCRIPTION_WORD] = subscription.as_mut_ptr() as usize; receiver[RTC_OWNER_WORD] = owner.as_mut_ptr() as usize;
        event_subscription_rtc_sync(receiver.as_mut_ptr().cast(), 7);
        assert_eq!(&EVENTS[..COUNT], &[0x1000_0007, 0x2000_0007, 0x2000_0001, 0x3000_0009, 60, MESSAGE_FIRST, MESSAGE_SECOND, MESSAGE_THIRD, ROOT_MESSAGE, 0xdead_beef]);
    }}
}
