//! Dispatching an owner's initial render state.
//!
//! `coordinate_owner_initial_dispatch` — original: `FUN_0828c80c` @
//! **0x0828c80c** (104 bytes; extent verified through the next distinct
//! `push {r4-r9,lr}` prologue at 0x0828c874). Raw decoding of every aligned
//! ARM `B`/`BL` immediate in `osos.dec` finds exactly four incoming direct
//! plain `bl` calls, at 0x0816d49c, 0x081814fc, 0x08181560, and 0x0818458c;
//! no predicated `bl` calls. Its body contains one plain `bl`, to 0x0828d848.
//!
//! # Algorithm
//!
//! If the owner has a render-context pointer at +0x78 and has not yet
//! dispatched (+0x3e is zero), save the four-word saved render state at
//! +0xb4, replace it with the current four-word state at +0x20, dispatch the
//! owner and current-state address to 0x0828d848, restore the saved state,
//! and mark the owner dispatched. The original returns its two input words
//! unchanged.
//!
//! # Deliberate deviations
//!
//! The callee at 0x0828d848 has no recovered semantic name in `names.yaml`.
//! This port uses a volatile seam named only for its proven owner/current-state
//! dispatch role. Device builds call its verified retail address; host tests
//! install a recording boundary. No other deliberate deviations.

use core::ptr;

/// ABI of unported `FUN_0828d848`: dispatch `owner` using `current_state`.
pub type CoordinateOwnerCurrentStateDispatch = unsafe extern "C" fn(owner: *mut u8, current_state: *mut u8);

#[cfg(target_os = "none")]
const COORDINATE_OWNER_CURRENT_STATE_DISPATCH_ADDRESS: usize = 0x0828_d848;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_current_state_dispatch(owner: *mut u8, current_state: *mut u8) {
    let dispatch: CoordinateOwnerCurrentStateDispatch = unsafe {
        core::mem::transmute(COORDINATE_OWNER_CURRENT_STATE_DISPATCH_ADDRESS)
    };
    unsafe { dispatch(owner, current_state) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_current_state_dispatch(_owner: *mut u8, _current_state: *mut u8) {}

/// The unported current-state dispatcher. Target builds reach 0x0828d848;
/// host tests replace this with a model of the boundary.
#[cfg(target_os = "none")]
pub static mut COORDINATE_OWNER_CURRENT_STATE_DISPATCH: CoordinateOwnerCurrentStateDispatch =
    firmware_current_state_dispatch;
#[cfg(not(target_os = "none"))]
pub static mut COORDINATE_OWNER_CURRENT_STATE_DISPATCH: CoordinateOwnerCurrentStateDispatch =
    missing_current_state_dispatch;

#[inline(always)]
unsafe fn current_state_dispatch() -> CoordinateOwnerCurrentStateDispatch {
    unsafe { ptr::read_volatile(ptr::addr_of!(COORDINATE_OWNER_CURRENT_STATE_DISPATCH)) }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn read_word(owner: *mut u8, offset: usize) -> u32 {
    unsafe { (owner.add(offset) as *const u32).read_volatile() }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn read_word(owner: *mut u8, offset: usize) -> u32 {
    unsafe { (owner.add(offset) as *const u32).read_unaligned() }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn write_word(owner: *mut u8, offset: usize, value: u32) {
    unsafe { (owner.add(offset) as *mut u32).write_volatile(value) };
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn write_word(owner: *mut u8, offset: usize, value: u32) {
    unsafe { (owner.add(offset) as *mut u32).write_unaligned(value) };
}

/// ARM form of [`coordinate_owner_initial_dispatch`].
#[cfg(target_os = "none")]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn coordinate_owner_initial_dispatch(owner: *mut u8, input_word: u32) -> u64 {
    if unsafe { read_word(owner, 0x78) } != 0 && unsafe { owner.add(0x3e).read_volatile() } == 0 {
        let saved = [
            unsafe { read_word(owner, 0xb4) }, unsafe { read_word(owner, 0xb8) },
            unsafe { read_word(owner, 0xbc) }, unsafe { read_word(owner, 0xc0) },
        ];
        unsafe {
            write_word(owner, 0xb4, read_word(owner, 0x20));
            write_word(owner, 0xb8, read_word(owner, 0x24));
            write_word(owner, 0xbc, read_word(owner, 0x28));
            write_word(owner, 0xc0, read_word(owner, 0x2c));
            current_state_dispatch()(owner, owner.add(0x20));
            write_word(owner, 0xb4, saved[0]);
            write_word(owner, 0xb8, saved[1]);
            write_word(owner, 0xbc, saved[2]);
            write_word(owner, 0xc0, saved[3]);
            owner.add(0x3e).write_volatile(1);
        }
    }
    owner as u32 as u64 | (input_word as u64) << 32
}

/// Host form of [`coordinate_owner_initial_dispatch`].
#[cfg(not(target_os = "none"))]
#[inline(never)]
pub unsafe extern "C" fn coordinate_owner_initial_dispatch(owner: *mut u8, input_word: u32) -> u64 {
    if unsafe { read_word(owner, 0x78) } != 0 && unsafe { owner.add(0x3e).read() } == 0 {
        let saved = [
            unsafe { read_word(owner, 0xb4) }, unsafe { read_word(owner, 0xb8) },
            unsafe { read_word(owner, 0xbc) }, unsafe { read_word(owner, 0xc0) },
        ];
        unsafe {
            write_word(owner, 0xb4, read_word(owner, 0x20));
            write_word(owner, 0xb8, read_word(owner, 0x24));
            write_word(owner, 0xbc, read_word(owner, 0x28));
            write_word(owner, 0xc0, read_word(owner, 0x2c));
            current_state_dispatch()(owner, owner.add(0x20));
            write_word(owner, 0xb4, saved[0]);
            write_word(owner, 0xb8, saved[1]);
            write_word(owner, 0xbc, saved[2]);
            write_word(owner, 0xc0, saved[3]);
            owner.add(0x3e).write(1);
        }
    }
    owner as u32 as u64 | (input_word as u64) << 32
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut DISPATCH_COUNT: u32 = 0;
    static mut DISPATCH_OWNER: *mut u8 = ptr::null_mut();
    static mut DISPATCH_STATE: *mut u8 = ptr::null_mut();
    static mut DISPATCHED_WORDS: [u32; 4] = [0; 4];

    unsafe extern "C" fn record_dispatch(owner: *mut u8, state: *mut u8) {
        unsafe {
            DISPATCH_COUNT += 1;
            DISPATCH_OWNER = owner;
            DISPATCH_STATE = state;
            DISPATCHED_WORDS = [
                read_word(owner, 0xb4),
                read_word(owner, 0xb8),
                read_word(owner, 0xbc),
                read_word(owner, 0xc0),
            ];
        }
    }

    fn owner_fixture() -> [u8; 0xc4] {
        let mut owner = [0; 0xc4];
        unsafe {
            write_word(owner.as_mut_ptr(), 0x20, 0x1111_1111);
            write_word(owner.as_mut_ptr(), 0x24, 0x2222_2222);
            write_word(owner.as_mut_ptr(), 0x28, 0x3333_3333);
            write_word(owner.as_mut_ptr(), 0x2c, 0x4444_4444);
            write_word(owner.as_mut_ptr(), 0xb4, 0xaaaa_aaaa);
            write_word(owner.as_mut_ptr(), 0xb8, 0xbbbb_bbbb);
            write_word(owner.as_mut_ptr(), 0xbc, 0xcccc_cccc);
            write_word(owner.as_mut_ptr(), 0xc0, 0xdddd_dddd);
        }
        owner
    }

    #[test]
    fn dispatches_current_state_once_and_restores_saved_state() {
        let _guard = DISPATCH_LOCK.lock();
        let mut owner = owner_fixture();
        unsafe {
            write_word(owner.as_mut_ptr(), 0x78, 1);
            DISPATCH_COUNT = 0;
            DISPATCHED_WORDS = [0; 4];
            COORDINATE_OWNER_CURRENT_STATE_DISPATCH = record_dispatch;
            let returned = coordinate_owner_initial_dispatch(owner.as_mut_ptr(), 0xfeed_beef);
            assert_eq!(returned >> 32, 0xfeed_beef);
            assert_eq!(DISPATCH_COUNT, 1);
            assert_eq!(DISPATCH_OWNER, owner.as_mut_ptr());
            assert_eq!(DISPATCH_STATE, owner.as_mut_ptr().add(0x20));
            assert_eq!(DISPATCHED_WORDS, [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444]);
            assert_eq!(owner[0x3e], 1);
            assert_eq!(read_word(owner.as_mut_ptr(), 0xb4), 0xaaaa_aaaa);
            assert_eq!(read_word(owner.as_mut_ptr(), 0xb8), 0xbbbb_bbbb);
            assert_eq!(read_word(owner.as_mut_ptr(), 0xbc), 0xcccc_cccc);
            assert_eq!(read_word(owner.as_mut_ptr(), 0xc0), 0xdddd_dddd);
            COORDINATE_OWNER_CURRENT_STATE_DISPATCH = missing_current_state_dispatch;
        }
    }

    #[test]
    fn skips_dispatch_without_context_or_after_initial_dispatch() {
        let _guard = DISPATCH_LOCK.lock();
        let mut owner = owner_fixture();
        unsafe {
            DISPATCH_COUNT = 0;
            COORDINATE_OWNER_CURRENT_STATE_DISPATCH = record_dispatch;
            coordinate_owner_initial_dispatch(owner.as_mut_ptr(), 0);
            write_word(owner.as_mut_ptr(), 0x78, 1);
            owner[0x3e] = 1;
            coordinate_owner_initial_dispatch(owner.as_mut_ptr(), 0);
            assert_eq!(DISPATCH_COUNT, 0);
            assert_eq!(owner[0x3e], 1);
            assert_eq!(read_word(owner.as_mut_ptr(), 0xb4), 0xaaaa_aaaa);
            COORDINATE_OWNER_CURRENT_STATE_DISPATCH = missing_current_state_dispatch;
        }
    }
}
