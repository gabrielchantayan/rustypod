//! `event_subscription_utc_refresh` — `FUN_08171ae4` @ 0x08171ae4.
//! True extent: 188 bytes, ending at the next function at 0x08171ba0.
//! Nine outbound plain BL instructions, zero predicated BL instructions.
//! Validate the current calendar, query UTC/DST, store the normalized DST flag,
//! and refresh the subscription only when its full rank or activity differs.
//! Reuse the owner's event code if its rank/activity matches; otherwise resolve
//! a replacement using the signed UTC halfword and signed DST byte.
//! Deviations: omit the null-output query veneer by calling its existing Rust
//! destination directly. Unported activity and code resolver retain verified
//! retail addresses. Host operations isolate calendar and RTC side effects.

use core::ptr;
use super::event_subscription_init::EventSubscription;

/// Only the verified receiver fields; C layout preserves target pointer offsets.
#[repr(C)]
pub struct UtcRefreshReceiver {
    pub prefix: [u8; 0x5c],
    pub subscription: *mut EventSubscription,
    pub middle: [u8; 0xa8 - 0x60],
    pub owner: *mut u8,
}

type Query = unsafe extern "C" fn(*mut i16, *mut u8) -> i32;
type Metadata = unsafe extern "C" fn(*const u8) -> u32;
type Rank = unsafe extern "C" fn(u32) -> i32;
type Active = unsafe extern "C" fn(u32) -> u32;
type Resolve = unsafe extern "C" fn(i32, i32) -> u32;
type Sync = unsafe extern "C" fn(*mut u8, u32);

#[derive(Clone, Copy)]
pub struct UtcRefreshOps {
    pub query: Query, pub metadata: Metadata, pub rank: Rank,
    pub active: Active, pub resolve: Resolve, pub sync: Sync,
}

#[cfg(not(target_os = "none"))]
pub static mut UTC_REFRESH_OPS: Option<UtcRefreshOps> = None;

unsafe fn refresh(receiver: *mut UtcRefreshReceiver, ops: UtcRefreshOps) {
    if (ops.query)(ptr::null_mut(), ptr::null_mut()) == 0 { return; }
    let mut offset = 0i16;
    let mut daylight = 0u8;
    (ops.query)(&mut offset, &mut daylight);
    let subscription = (*receiver).subscription;
    let active = (daylight != 0) as u32;
    (*subscription).active = active as u8;
    if (*subscription).event_rank == offset as i32 as u32
        && ((ops.active)((*subscription).event_code) != 0) as u32 == active {
        return;
    }
    let mut code = (ops.metadata)((*receiver).owner);
    if (ops.rank)(code) != offset as i32 || (ops.active)(code) != active {
        code = (ops.resolve)(offset as i32, daylight as i8 as i32);
    }
    (ops.sync)(receiver.cast(), code);
}

/// Refresh UTC-derived subscription state.
/// # Safety
/// Receiver and subscription must be valid writable C-layout objects; owner
/// must satisfy the metadata accessor and RTC synchronization contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn event_subscription_utc_refresh(receiver: *mut UtcRefreshReceiver) {
    #[cfg(target_os = "none")]
    let ops = UtcRefreshOps {
        query: crate::time::utc_offset::current_utc_offset_query,
        metadata: crate::ft::service::metadata::ft_service_metadata_word_at_b74,
        rank: crate::util::indexed_record_value_lookup::indexed_record_value_lookup,
        active: core::mem::transmute(0x080f_fea0usize),
        resolve: core::mem::transmute(0x080f_fbbcusize),
        sync: super::event_subscription_rtc_sync::event_subscription_rtc_sync,
    };
    #[cfg(not(target_os = "none"))]
    let ops = ptr::read_volatile(ptr::addr_of!(UTC_REFRESH_OPS)).expect("install UTC refresh operations");
    refresh(receiver, ops);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut OFFSET: i16 = 0;
    static mut DST: u8 = 0;
    static mut VALID: i32 = 1;
    static mut OWNER_RANK: i32 = 0;
    static mut ACTIVITY: u32 = 0;
    static mut CALLS: std::vec::Vec<(u32, i32)> = std::vec::Vec::new();
    unsafe extern "C" fn query(offset: *mut i16, dst: *mut u8) -> i32 {
        CALLS.push((1, offset.is_null() as i32));
        if !offset.is_null() { offset.write(OFFSET); dst.write(DST); }
        VALID
    }
    unsafe extern "C" fn metadata(_: *const u8) -> u32 { CALLS.push((2, 0)); 42 }
    unsafe extern "C" fn rank(code: u32) -> i32 { assert_eq!(code, 42); CALLS.push((3, 0)); OWNER_RANK }
    unsafe extern "C" fn active(code: u32) -> u32 { CALLS.push((4, code as i32)); ACTIVITY }
    unsafe extern "C" fn resolve(offset: i32, dst: i32) -> u32 {
        CALLS.push((5, offset)); CALLS.push((6, dst)); 99
    }
    unsafe extern "C" fn sync(_: *mut u8, code: u32) { CALLS.push((7, code as i32)); }
    #[test]
    fn invalid_unchanged_reuse_and_signed_resolution_paths() { unsafe {
        let _guard = LOCK.lock();
        UTC_REFRESH_OPS = Some(UtcRefreshOps { query, metadata, rank, active, resolve, sync });
        let mut subscription = EventSubscription { event_code: 7, active: 9,
            reserved_05_to_07: [0; 3], event_rank: 0, event_descriptor: 0 };
        let mut receiver = UtcRefreshReceiver { prefix: [0; 0x5c], subscription: &mut subscription,
            middle: [0; 0x48], owner: ptr::null_mut() };
        VALID = 0; CALLS.clear();
        event_subscription_utc_refresh(&mut receiver);
        assert_eq!(subscription.active, 9); assert_eq!(CALLS.as_slice(), &[(1, 1)]);
        VALID = 1; OFFSET = -480; DST = 60; ACTIVITY = 8;
        subscription.event_rank = (-480i32) as u32; CALLS.clear();
        event_subscription_utc_refresh(&mut receiver);
        assert_eq!(subscription.active, 1);
        assert_eq!(CALLS.as_slice(), &[(1, 1), (1, 0), (4, 7)]);
        subscription.event_rank = 0; OWNER_RANK = -480; ACTIVITY = 1; CALLS.clear();
        event_subscription_utc_refresh(&mut receiver);
        assert_eq!(CALLS.as_slice(), &[(1, 1), (1, 0), (2, 0), (3, 0), (4, 42), (7, 42)]);
        // Full rank comparison, not narrowed i16; resolver receives signed bytes.
        for (offset, dst) in [(i16::MIN, 128u8), (i16::MAX, 255), (0, 0)] {
            OFFSET = offset; DST = dst; OWNER_RANK = offset as i32 + 1;
            subscription.event_rank = (offset as i32 as u32) ^ 0x10000;
            CALLS.clear(); event_subscription_utc_refresh(&mut receiver);
            assert_eq!(subscription.active, (dst != 0) as u8);
            assert_eq!(CALLS.as_slice(), &[(1, 1), (1, 0), (2, 0), (3, 0),
                (5, offset as i32), (6, dst as i8 as i32), (7, 99)]);
        }
        OFFSET = 0; DST = 0; OWNER_RANK = 0; ACTIVITY = 1;
        subscription.event_rank = 0; CALLS.clear(); event_subscription_utc_refresh(&mut receiver);
        assert_eq!(CALLS.as_slice(), &[(1, 1), (1, 0), (4, 7), (2, 0), (3, 0),
            (4, 42), (5, 0), (6, 0), (7, 99)]);
        UTC_REFRESH_OPS = None;
    }}
}
