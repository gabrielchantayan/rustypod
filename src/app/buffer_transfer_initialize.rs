//! `buffer_transfer_initialize` — original: `FUN_080f80e4` @ `0x080f80e4`
//! (76 bytes; Ghidra incorrectly includes the next function's first word).
//!
//! # Verified calls and algorithm
//!
//! Raw ARM words establish one outbound plain `bl` (`0x080f7da8`) and no
//! predicated outbound `bl`; the tail transfer is through the veneer at
//! `0x08038040` to `0x080087e0`. Four inbound direct plain `bl` sites reach
//! this entry; no predicated inbound call has been found. The byte at `state
//! + 0x1e` selects one of two argument orderings for the state initializer:
//! mode zero supplies the caller's auxiliary word first, while mode one
//! supplies the byte at `state + 0x1c` first. Other modes skip initialization.
//! Every mode then tail-enters the notification dispatch with the bytes at
//! `state + 0x1d` and `state + 0x1e`.
//!
//! # Deliberate deviations
//!
//! Neither target has a recovered semantic identity. Target builds call their
//! verified retailOS addresses; host builds provide narrow callback seams.
//! Rust returns normally after the dispatch callback rather than tail-branching.

/// ABI of the unported state initializer at `0x080f7da8`.
pub type BufferTransferInitialize = unsafe extern "C" fn(*mut u8, u32, u32, u32);
/// ABI of the notification dispatch at `0x080087e0`.
pub type BufferTransferNotify = unsafe extern "C" fn(u32, u32) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_buffer_transfer_initialize(
    _state: *mut u8,
    _first: u32,
    _second: u32,
    _length: u32,
) {
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_buffer_transfer_notify(_kind: u32, _mode: u32) -> u32 {
    0
}

/// Host seams for the two unported retailOS targets.
#[cfg(not(target_os = "none"))]
pub static mut BUFFER_TRANSFER_INITIALIZE: BufferTransferInitialize = missing_buffer_transfer_initialize;
#[cfg(not(target_os = "none"))]
pub static mut BUFFER_TRANSFER_NOTIFY: BufferTransferNotify = missing_buffer_transfer_notify;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn buffer_transfer_initialize_target() -> BufferTransferInitialize {
    core::mem::transmute(0x080f_7da8usize)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn buffer_transfer_notify_target() -> BufferTransferNotify {
    core::mem::transmute(0x0800_87e0usize)
}

/// Initializes the transfer state selected by `state[0x1e]`, then notifies its
/// dispatch target with `state[0x1d]` and that selector.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn buffer_transfer_initialize(
    state: *mut u8,
    length: u32,
    auxiliary: u32,
) -> u32 {
    let mode = unsafe { state.add(0x1e).read() } as u32;
    let state_value = unsafe { state.add(0x1c).read() } as u32;

    if mode == 0 || mode == 1 {
        let (first, second) = if mode == 0 {
            (auxiliary, state_value)
        } else {
            (state_value, auxiliary)
        };
        #[cfg(target_os = "none")]
        unsafe { buffer_transfer_initialize_target()(state, first, second, length) };
        #[cfg(not(target_os = "none"))]
        unsafe { BUFFER_TRANSFER_INITIALIZE(state, first, second, length) };
    }

    let kind = unsafe { state.add(0x1d).read() } as u32;
    #[cfg(target_os = "none")]
    return unsafe { buffer_transfer_notify_target()(kind, mode) };
    #[cfg(not(target_os = "none"))]
    unsafe { BUFFER_TRANSFER_NOTIFY(kind, mode) }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    static mut INITIALIZE_CALLS: [(usize, u32, u32, u32); 2] = [(0, 0, 0, 0); 2];
    static mut INITIALIZE_COUNT: usize = 0;
    static mut NOTIFY_ARGS: (u32, u32) = (0, 0);

    unsafe extern "C" fn record_initialize(state: *mut u8, first: u32, second: u32, length: u32) {
        unsafe {
            INITIALIZE_CALLS[INITIALIZE_COUNT] = (state as usize, first, second, length);
            INITIALIZE_COUNT += 1;
        }
    }

    unsafe extern "C" fn record_notify(kind: u32, mode: u32) -> u32 {
        unsafe { NOTIFY_ARGS = (kind, mode) };
        0x6a
    }

    #[test]
    fn mode_selects_initializer_order_and_always_notifies() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            INITIALIZE_COUNT = 0;
            NOTIFY_ARGS = (0, 0);
            BUFFER_TRANSFER_INITIALIZE = record_initialize;
            BUFFER_TRANSFER_NOTIFY = record_notify;
        }
        let mut state = [0u8; 0x20];
        state[0x1c] = 0x35;
        state[0x1d] = 0x47;

        state[0x1e] = 0;
        assert_eq!(unsafe { buffer_transfer_initialize(state.as_mut_ptr(), 0x1000, 0xdead_beef) }, 0x6a);
        state[0x1e] = 1;
        assert_eq!(unsafe { buffer_transfer_initialize(state.as_mut_ptr(), 0x1000, 0xdead_beef) }, 0x6a);
        state[0x1e] = 2;
        assert_eq!(unsafe { buffer_transfer_initialize(state.as_mut_ptr(), 0x1000, 0xdead_beef) }, 0x6a);

        unsafe {
            assert_eq!(INITIALIZE_COUNT, 2);
            assert_eq!(INITIALIZE_CALLS[0], (state.as_ptr() as usize, 0xdead_beef, 0x35, 0x1000));
            assert_eq!(INITIALIZE_CALLS[1], (state.as_ptr() as usize, 0x35, 0xdead_beef, 0x1000));
            assert_eq!(NOTIFY_ARGS, (0x47, 2));
        }
    }
}
