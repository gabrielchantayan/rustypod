//! `buffer_transfer_submit` — original: `FUN_080f80b4` @ `0x080f80b4`
//! (48 bytes).
//!
//! # Verified calls and algorithm
//!
//! Raw ARM words establish the exact extent `0x080f80b4..0x080f80e4`; the
//! next real function begins at `0x080f80e4` with `push {r4,lr}`. The body
//! has zero plain and zero predicated outbound `bl` instructions: it
//! tail-branches to `0x080f7d5c`. Whole-image A32 decoding finds three inbound
//! plain `bl` calls at `0x081f4a54`, `0x081f4aa4`, and `0x081f4b0c`, and zero
//! predicated inbound `bl` forms. Mode `state[0x1e]` selects the ordering of
//! the caller's auxiliary word and `state[0x1c]`; modes other than zero and
//! one return without submitting.
//!
//! # Deliberate deviations
//!
//! The tail target has no recovered semantic identity. Target builds retain
//! its verified address; host builds use a narrow callback seam. Rust returns
//! after that callback rather than tail-branching.

/// ABI of the unported submission target at `0x080f7d5c`.
pub type BufferTransferSubmitTarget = unsafe extern "C" fn(*mut u8, u32, u32, u32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_buffer_transfer_submit_target(
    _state: *mut u8,
    _first: u32,
    _second: u32,
    _length: u32,
) {
}

/// Host seam for the unported retailOS submission target.
#[cfg(not(target_os = "none"))]
pub static mut BUFFER_TRANSFER_SUBMIT_TARGET: BufferTransferSubmitTarget = missing_buffer_transfer_submit_target;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn buffer_transfer_submit_target() -> BufferTransferSubmitTarget {
    core::mem::transmute(0x080f_7d5cusize)
}

/// Submits `length` bytes through the mode-selected transfer state ordering.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn buffer_transfer_submit(state: *mut u8, length: u32, auxiliary: u32) {
    let mode = unsafe { state.add(0x1e).read() };
    let (first, second) = match mode {
        0 => (auxiliary, unsafe { state.add(0x1c).read() } as u32),
        1 => (unsafe { state.add(0x1c).read() } as u32, auxiliary),
        _ => return,
    };

    #[cfg(target_os = "none")]
    unsafe { buffer_transfer_submit_target()(state, first, second, length) };
    #[cfg(not(target_os = "none"))]
    unsafe { BUFFER_TRANSFER_SUBMIT_TARGET(state, first, second, length) };
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut CALLS: [(usize, u32, u32, u32); 2] = [(0, 0, 0, 0); 2];
    static mut CALL_COUNT: usize = 0;

    unsafe extern "C" fn record_submit(state: *mut u8, first: u32, second: u32, length: u32) {
        unsafe {
            CALLS[CALL_COUNT] = (state as usize, first, second, length);
            CALL_COUNT += 1;
        }
    }

    #[test]
    fn mode_selects_submission_order_and_rejects_other_modes() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            CALL_COUNT = 0;
            BUFFER_TRANSFER_SUBMIT_TARGET = record_submit;
        }
        let mut state = [0u8; 0x20];
        state[0x1c] = 0x35;

        state[0x1e] = 0;
        unsafe { buffer_transfer_submit(state.as_mut_ptr(), 0x1000, 0xdead_beef) };
        state[0x1e] = 1;
        unsafe { buffer_transfer_submit(state.as_mut_ptr(), 0x1000, 0xdead_beef) };
        state[0x1e] = 2;
        unsafe { buffer_transfer_submit(state.as_mut_ptr(), 0x1000, 0xdead_beef) };

        unsafe {
            assert_eq!(CALL_COUNT, 2);
            assert_eq!(CALLS[0], (state.as_ptr() as usize, 0xdead_beef, 0x35, 0x1000));
            assert_eq!(CALLS[1], (state.as_ptr() as usize, 0x35, 0xdead_beef, 0x1000));
        }
    }
}
