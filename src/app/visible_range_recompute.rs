//! `visible_range_recompute` — original: `FUN_081f036c` @ **0x081f036c**.
//!
//! Raw ARM establishes a 144-byte extent, `0x081f036c..0x081f03f8`; the next
//! separately entered function starts with `push {r4-r8,lr}` at `0x081f03fc`.
//! Decoding direct branch-link words finds four inbound plain `bl` calls
//! (`0x081f02e4`, `0x081f077c`, `0x0821ba20`, and `0x0821bb98`), zero
//! predicated inbound forms, and two outbound plain `bl` calls (`0x081f11e0`
//! and `0x081f1114`).
//!
//! # Algorithm
//!
//! Halve the state word at `+0x34`, then derive an inclusive visible range
//! from the attached collection's base (`+0x2b4`) and length (`+0x2b8`). The
//! low bound saturates at zero; a nonzero length clamps the high bound to its
//! final index, while a zero length leaves it zero. With `refresh != 0`, the
//! first pass calls the initial range refresh and latches byte `+0x59`; later
//! passes call the incremental refresh with the old bounds and the incoming
//! fourth argument. New bounds are stored only after that call.
//!
//! # Deliberate deviations
//!
//! The two refresh targets have no recovered identity. Target builds call their
//! verified retailOS addresses; host builds expose volatile replaceable seams.
//! The ABI-visible third argument is unused by the raw body. The fourth is
//! preserved for the incremental target exactly as raw `r3` is.

use core::ptr::{addr_of, read, write};

pub type InitialVisibleRangeRefresh = unsafe extern "C" fn(*mut u8);
pub type IncrementalVisibleRangeRefresh = unsafe extern "C" fn(*mut u8, u32, u32, u32);

const INITIAL_VISIBLE_RANGE_REFRESH_ADDRESS: usize = 0x081f_11e0;
const INCREMENTAL_VISIBLE_RANGE_REFRESH_ADDRESS: usize = 0x081f_1114;
const COLLECTION_OFFSET: usize = 0x30;
const POSITION_OFFSET: usize = 0x34;
const LOW_BOUND_OFFSET: usize = 0x38;
const HIGH_BOUND_OFFSET: usize = 0x3c;
const INITIALIZED_OFFSET: usize = 0x59;
const COLLECTION_BASE_OFFSET: usize = 0x2b4;
const COLLECTION_LENGTH_OFFSET: usize = 0x2b8;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_initial_visible_range_refresh(state: *mut u8) {
    unsafe { core::mem::transmute::<usize, InitialVisibleRangeRefresh>(INITIAL_VISIBLE_RANGE_REFRESH_ADDRESS)(state) }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_incremental_visible_range_refresh(state: *mut u8, low: u32, high: u32, context: u32) {
    unsafe { core::mem::transmute::<usize, IncrementalVisibleRangeRefresh>(INCREMENTAL_VISIBLE_RANGE_REFRESH_ADDRESS)(state, low, high, context) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_initial_visible_range_refresh(_state: *mut u8) {
    panic!("visible_range_recompute requires refresh target 0x081f11e0")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_incremental_visible_range_refresh(_state: *mut u8, _low: u32, _high: u32, _context: u32) {
    panic!("visible_range_recompute requires refresh target 0x081f1114")
}

#[cfg(target_os = "none")]
pub static mut INITIAL_VISIBLE_RANGE_REFRESH: InitialVisibleRangeRefresh = retail_initial_visible_range_refresh;
#[cfg(not(target_os = "none"))]
pub static mut INITIAL_VISIBLE_RANGE_REFRESH: InitialVisibleRangeRefresh = missing_initial_visible_range_refresh;
#[cfg(target_os = "none")]
pub static mut INCREMENTAL_VISIBLE_RANGE_REFRESH: IncrementalVisibleRangeRefresh = retail_incremental_visible_range_refresh;
#[cfg(not(target_os = "none"))]
pub static mut INCREMENTAL_VISIBLE_RANGE_REFRESH: IncrementalVisibleRangeRefresh = missing_incremental_visible_range_refresh;

#[inline(always)]
fn initial_visible_range_refresh() -> InitialVisibleRangeRefresh {
    unsafe { core::ptr::read_volatile(addr_of!(INITIAL_VISIBLE_RANGE_REFRESH)) }
}

#[inline(always)]
fn incremental_visible_range_refresh() -> IncrementalVisibleRangeRefresh {
    unsafe { core::ptr::read_volatile(addr_of!(INCREMENTAL_VISIBLE_RANGE_REFRESH)) }
}

/// Recomputes the attached collection's inclusive visible bounds.
///
/// # Safety
///
/// `state` must be non-NULL, readable through `+0x59`, and writable at `+0x38`,
/// `+0x3c`, and `+0x59`. Its target-width word at `+0x30` is either zero or a
/// readable collection through `+0x2b8`. When `refresh` selects either refresh
/// path, the respective target must satisfy its retailOS ABI.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn visible_range_recompute(state: *mut u8, refresh: u32, _unused: u32, context: u32) {
    let position = unsafe { read(state.add(POSITION_OFFSET).cast::<u32>()) >> 1 };
    let collection = unsafe { read(state.add(COLLECTION_OFFSET).cast::<u32>()) as usize as *const u8 };
    let (low, high) = if collection.is_null() {
        (0, 0)
    } else {
        let base = unsafe { read(collection.add(COLLECTION_BASE_OFFSET).cast::<u32>()) };
        let length = unsafe { read(collection.add(COLLECTION_LENGTH_OFFSET).cast::<u32>()) };
        let low = base.saturating_sub(position);
        let sum = base.wrapping_add(position);
        let high = if sum < length { sum } else if length != 0 { length - 1 } else { 0 };
        (low, high)
    };

    if !collection.is_null() && refresh != 0 {
        if unsafe { read(state.add(INITIALIZED_OFFSET)) } == 0 {
            unsafe { initial_visible_range_refresh()(state) };
            unsafe { write(state.add(INITIALIZED_OFFSET), 1) };
        } else {
            unsafe { incremental_visible_range_refresh()(state, low, high, context) };
        }
    }

    unsafe {
        write(state.add(LOW_BOUND_OFFSET).cast::<u32>(), low);
        write(state.add(HIGH_BOUND_OFFSET).cast::<u32>(), high);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static INITIAL_CALLS: AtomicUsize = AtomicUsize::new(0);
    static INCREMENTAL_CALLS: AtomicUsize = AtomicUsize::new(0);
    static OBSERVED_LOW: AtomicU32 = AtomicU32::new(0);
    static OBSERVED_HIGH: AtomicU32 = AtomicU32::new(0);
    static OBSERVED_CONTEXT: AtomicU32 = AtomicU32::new(0);
    static OBSERVED_OLD_LOW: AtomicU32 = AtomicU32::new(0);
    static OBSERVED_OLD_HIGH: AtomicU32 = AtomicU32::new(0);
    static SLAB: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_initial(state: *mut u8) {
        INITIAL_CALLS.fetch_add(1, Ordering::SeqCst);
        OBSERVED_OLD_LOW.store(unsafe { read(state.add(LOW_BOUND_OFFSET).cast::<u32>()) }, Ordering::SeqCst);
        OBSERVED_OLD_HIGH.store(unsafe { read(state.add(HIGH_BOUND_OFFSET).cast::<u32>()) }, Ordering::SeqCst);
    }

    unsafe extern "C" fn record_incremental(state: *mut u8, low: u32, high: u32, context: u32) {
        INCREMENTAL_CALLS.fetch_add(1, Ordering::SeqCst);
        OBSERVED_LOW.store(low, Ordering::SeqCst);
        OBSERVED_HIGH.store(high, Ordering::SeqCst);
        OBSERVED_CONTEXT.store(context, Ordering::SeqCst);
        OBSERVED_OLD_LOW.store(unsafe { read(state.add(LOW_BOUND_OFFSET).cast::<u32>()) }, Ordering::SeqCst);
        OBSERVED_OLD_HIGH.store(unsafe { read(state.add(HIGH_BOUND_OFFSET).cast::<u32>()) }, Ordering::SeqCst);
    }

    fn fixture(base: u32, length: u32, position: u32) -> Option<(*mut u8, *mut u8)> {
        let slab = match SLAB.load(Ordering::SeqCst) {
            0 => {
                let mapped = crate::testing::try_map_u32_slab(crate::testing::hints::VISIBLE_RANGE_RECOMPUTE, 0x600)?;
                SLAB.store(mapped as usize, Ordering::SeqCst);
                mapped
            }
            address => address as *mut u8,
        };
        unsafe {
            core::ptr::write_bytes(slab, 0, 0x600);
            let state = slab;
            let collection = slab.add(0x100);
            write(state.add(COLLECTION_OFFSET).cast::<u32>(), collection as usize as u32);
            write(state.add(POSITION_OFFSET).cast::<u32>(), position);
            write(collection.add(COLLECTION_BASE_OFFSET).cast::<u32>(), base);
            write(collection.add(COLLECTION_LENGTH_OFFSET).cast::<u32>(), length);
            Some((state, collection))
        }
    }

    #[test]
    fn first_refresh_latches_after_observing_old_bounds() {
        let _guard = TEST_LOCK.lock();
        let Some((state, _)) = fixture(10, 30, 8) else { return };
        unsafe { INITIAL_VISIBLE_RANGE_REFRESH = record_initial; }
        INITIAL_CALLS.store(0, Ordering::SeqCst);
        unsafe {
            write(state.add(LOW_BOUND_OFFSET).cast::<u32>(), 0xaaaa_aaaa);
            write(state.add(HIGH_BOUND_OFFSET).cast::<u32>(), 0xbbbb_bbbb);
            visible_range_recompute(state, 1, 0, 0);
        }
        assert_eq!(INITIAL_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(OBSERVED_OLD_LOW.load(Ordering::SeqCst), 0xaaaa_aaaa);
        assert_eq!(OBSERVED_OLD_HIGH.load(Ordering::SeqCst), 0xbbbb_bbbb);
        assert_eq!(unsafe { read(state.add(INITIALIZED_OFFSET)) }, 1);
        assert_eq!(unsafe { read(state.add(LOW_BOUND_OFFSET).cast::<u32>()) }, 6);
        assert_eq!(unsafe { read(state.add(HIGH_BOUND_OFFSET).cast::<u32>()) }, 14);
    }

    #[test]
    fn incremental_refresh_forwards_context_and_clamps_wrapping_sum() {
        let _guard = TEST_LOCK.lock();
        let Some((state, _)) = fixture(u32::MAX - 2, 7, 8) else { return };
        unsafe {
            INCREMENTAL_VISIBLE_RANGE_REFRESH = record_incremental;
            write(state.add(INITIALIZED_OFFSET), 1);
            write(state.add(LOW_BOUND_OFFSET).cast::<u32>(), 12);
            write(state.add(HIGH_BOUND_OFFSET).cast::<u32>(), 13);
            visible_range_recompute(state, 1, 0, 0xdead_beef);
        }
        assert_eq!(INCREMENTAL_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(OBSERVED_LOW.load(Ordering::SeqCst), u32::MAX - 6);
        assert_eq!(OBSERVED_HIGH.load(Ordering::SeqCst), 1);
        assert_eq!(OBSERVED_CONTEXT.load(Ordering::SeqCst), 0xdead_beef);
        assert_eq!(OBSERVED_OLD_LOW.load(Ordering::SeqCst), 12);
        assert_eq!(OBSERVED_OLD_HIGH.load(Ordering::SeqCst), 13);
    }

    #[test]
    fn empty_collection_refreshes_but_retains_zero_high_bound() {
        let _guard = TEST_LOCK.lock();
        let Some((state, collection)) = fixture(9, 0, 40) else { return };
        unsafe {
            INITIAL_VISIBLE_RANGE_REFRESH = record_initial;
            write(state.add(LOW_BOUND_OFFSET).cast::<u32>(), 99);
            visible_range_recompute(state, 1, 0, 0);
        }
        assert_eq!(unsafe { read(state.add(LOW_BOUND_OFFSET).cast::<u32>()) }, 0);
        assert_eq!(unsafe { read(state.add(HIGH_BOUND_OFFSET).cast::<u32>()) }, 0);
        assert_eq!(unsafe { read(state.add(INITIALIZED_OFFSET)) }, 1);
        unsafe {
            write(state.add(COLLECTION_OFFSET).cast::<u32>(), 0);
            write(state.add(LOW_BOUND_OFFSET).cast::<u32>(), 99);
            write(state.add(HIGH_BOUND_OFFSET).cast::<u32>(), 99);
            visible_range_recompute(state, 1, 0, 0);
        }
        assert_eq!(unsafe { read(state.add(LOW_BOUND_OFFSET).cast::<u32>()) }, 0);
        assert_eq!(unsafe { read(state.add(HIGH_BOUND_OFFSET).cast::<u32>()) }, 0);
        assert_eq!(collection.is_null(), false);
    }
}
