//! Collection refresh predicate — `FUN_0812fb64` @ 0x0812fb64.
//!
//! True extent: 140 bytes, 0x0812fb64..0x0812fbf0 (136 instruction bytes
//! and the 0x089caf80 literal). The next function starts with push at
//! 0x0812fbf0. Raw word decoding finds two plain incoming BLs
//! (0x081a6c10, 0x081ca2cc), zero predicated incoming BLs, and two plain
//! outgoing BLs, zero predicated outgoing BLs.
//!
//! Always fetch the demo datetime. Unless the global override byte is set,
//! a nonzero cached day matching its day suppresses refresh. Otherwise count
//! eligible entries, then return one when owner +0x30 and +0x34 differ, or
//! when mode is zero and the eligible count is nonzero. Counts are loaded
//! after traversal, which may change the owner. The global byte's broader
//! identity is unknown; its observed role is only a date-gate override.
//!
//! Deviations: initialize the ten-byte datetime instead of saving unrelated
//! r1-r3 stack contents (the callee overwrites all ten bytes). Target calls
//! use the existing Rust ports directly; host-only operations substitute
//! fixtures and the runtime global byte. No target callee seams are added.

#[cfg(not(target_os = "none"))]
use core::ptr;
use crate::time::datetime::DateTime;

#[cfg(not(target_os = "none"))]
pub struct CollectionRefreshOps {
    pub datetime: unsafe extern "C" fn(*mut DateTime) -> *mut DateTime,
    pub count: unsafe extern "C" fn(*mut u8, *mut u32),
    pub override_byte: *const u8,
}

#[cfg(not(target_os = "none"))]
pub static mut COLLECTION_REFRESH_OPS: CollectionRefreshOps = CollectionRefreshOps {
    datetime: crate::app::demo_mode_datetime::demo_mode_datetime,
    count: crate::app::collection_count_eligible_entries::collection_count_eligible_entries,
    override_byte: ptr::null(),
};

/// # Safety
/// `owner` must contain readable aligned words at +0x30/+0x34 and a byte
/// at +0x3b, plus a valid collection at +0x18 for the eligibility traversal.
/// The demo-mode resource must exist. Host operations must be installed.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn collection_refresh_needed(owner: *mut u8, mode: u32) -> u32 {
    let mut date: DateTime = core::mem::zeroed();
    #[cfg(target_os = "none")]
    crate::app::demo_mode_datetime::demo_mode_datetime(&mut date);
    #[cfg(not(target_os = "none"))]
    let ops = ptr::read(ptr::addr_of!(COLLECTION_REFRESH_OPS));
    #[cfg(not(target_os = "none"))]
    (ops.datetime)(&mut date);
    #[cfg(target_os = "none")]
    let override_byte = (0x089c_af80 as *const u8).read_volatile();
    #[cfg(not(target_os = "none"))]
    let override_byte = ops.override_byte.read_volatile();
    if override_byte == 0 {
        let cached_day = owner.add(0x3b).read();
        if cached_day != 0 && cached_day == date.day { return 0; }
    }
    let mut eligible = 0u32;
    #[cfg(target_os = "none")]
    crate::app::collection_count_eligible_entries::collection_count_eligible_entries(owner, &mut eligible);
    #[cfg(not(target_os = "none"))]
    (ops.count)(owner, &mut eligible);
    u32::from(owner.add(0x30).cast::<u32>().read() != owner.add(0x34).cast::<u32>().read()
        || (mode == 0 && eligible != 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    static mut DAY: u8 = 0;
    static mut ELIGIBLE: u32 = 0;
    static mut OVERRIDE: u8 = 0;
    static mut MUTATE_COUNTS: bool = false;
    static mut EVENTS: u32 = 0;

    unsafe extern "C" fn datetime(out: *mut DateTime) -> *mut DateTime {
        EVENTS = EVENTS * 10 + 1;
        (*out).day = DAY;
        out
    }
    unsafe extern "C" fn count(owner: *mut u8, out: *mut u32) {
        EVENTS = EVENTS * 10 + 2;
        out.write(ELIGIBLE);
        if MUTATE_COUNTS { owner.add(0x34).cast::<u32>().write(99); }
    }

    #[test]
    fn date_gate_and_count_mode_boundaries() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            let saved = ptr::read(ptr::addr_of!(COLLECTION_REFRESH_OPS));
            COLLECTION_REFRESH_OPS = CollectionRefreshOps {
                datetime, count, override_byte: ptr::addr_of!(OVERRIDE),
            };
            for day in [0u8, 1, 255] {
                for cached in [0u8, 1, 255] {
                    for override_byte in [0u8, 1, 255] {
                        for mode in [0u32, 1, u32::MAX] {
                            for eligible in [0u32, 1, u32::MAX] {
                                for unequal in [false, true] {
                                    let mut owner = [0u32; 16];
                                    owner[12] = u32::MAX;
                                    owner[13] = if unequal { 0 } else { u32::MAX };
                                    let bytes = owner.as_mut_ptr().cast::<u8>();
                                    bytes.add(0x3b).write(cached);
                                    DAY = day; OVERRIDE = override_byte; ELIGIBLE = eligible;
                                    MUTATE_COUNTS = false; EVENTS = 0;
                                    let gated = override_byte == 0 && cached != 0 && cached == day;
                                    assert_eq!(collection_refresh_needed(bytes, mode),
                                        u32::from(!gated && (unequal || (mode == 0 && eligible != 0))));
                                    assert_eq!(EVENTS, if gated { 1 } else { 12 });
                                }
                            }
                        }
                    }
                }
            }
            COLLECTION_REFRESH_OPS = saved;
        }
    }

    #[test]
    fn observes_counts_changed_during_eligibility_traversal() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            let saved = ptr::read(ptr::addr_of!(COLLECTION_REFRESH_OPS));
            COLLECTION_REFRESH_OPS = CollectionRefreshOps {
                datetime, count, override_byte: ptr::addr_of!(OVERRIDE),
            };
            let mut owner = [0u32; 16];
            DAY = 1; OVERRIDE = 0; ELIGIBLE = 0; MUTATE_COUNTS = true; EVENTS = 0;
            assert_eq!(collection_refresh_needed(owner.as_mut_ptr().cast(), 1), 1);
            assert_eq!(owner[13], 99);
            assert_eq!(EVENTS, 12);
            COLLECTION_REFRESH_OPS = saved;
        }
    }
}
