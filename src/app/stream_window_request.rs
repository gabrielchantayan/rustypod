//! `stream_window_request` — original: `FUN_0820a460` @ `0x0820a460`.
//! True extent: **60 bytes**, `0x0820a460..0x0820a49c` (exclusive end);
//! the next function at `0x0820a49c` is a separately linked branch veneer.
//!
//! Raw-image decoding finds two unconditional inbound BL calls, at
//! `0x08100818` and `0x08174554`, and zero predicated calls or inbound B tails.
//! The body has one unconditional BL, at `0x0820a490`, to the already ported
//! `stream_window_dispatch_request` at `0x0822adb0`; no predicated BL occurs.
//! It copies four stack arguments to the outgoing frame, restores the first
//! four register arguments, invokes the dispatcher, and returns its r0 result
//! unchanged. The dispatcher gates the request on interface presence and flag
//! bit 0, normalizes virtual-slot +0x54 success, and saves the requested
//! maximum window length only on success.
//!
//! Deliberate deviations: no behavioral changes. Rust omits the redundant
//! register/stack shuffling. Unlike Ghidra's void prototype, the ABI explicitly
//! preserves the observed u32 return value; both known callers ignore it.

use super::stream_window_dispatch_request::{
    stream_window_dispatch_request, StreamWindowRequestState,
};

/// Submits a stream-window request using the existing dispatcher.
///
/// # Safety
/// `state` and the seven request arguments must satisfy
/// [`stream_window_dispatch_request`]'s safety contract. This wrapper adds no
/// NULL, flag, or argument checks of its own.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stream_window_request(
    state: *mut StreamWindowRequestState,
    request_arg_1: u32,
    maximum_window_length: u32,
    request_arg_3: u32,
    request_arg_4: u32,
    request_arg_5: u32,
    request_arg_6: u32,
    request_arg_7: u32,
) -> u32 {
    stream_window_dispatch_request(
        state, request_arg_1, maximum_window_length, request_arg_3,
        request_arg_4, request_arg_5, request_arg_6, request_arg_7,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::stream_window_dispatch_request::{
        StreamWindowRequestInterface, StreamWindowRequestVtable,
    };

    unsafe extern "C" fn accept_supported_window(
        _interface: *mut StreamWindowRequestInterface,
        request_arg_1: u32,
        maximum_window_length: u32,
        request_arg_3: u32,
        request_arg_4: u32,
        request_arg_5: u32,
        request_arg_6: u32,
        request_arg_7: u32,
    ) -> u32 {
        if request_arg_1 == 0 && maximum_window_length == 7 &&
            request_arg_3 == 0 && request_arg_4 == 0xf0 &&
            request_arg_5 == 8 && request_arg_6 == u32::MAX &&
            request_arg_7 == u32::MAX {
            0x8000_0000
        } else {
            0
        }
    }

    static VTABLE: StreamWindowRequestVtable = StreamWindowRequestVtable {
        unresolved_00_50: [0; 21],
        dispatch_request: accept_supported_window,
    };

    fn state(interface: *mut StreamWindowRequestInterface, flags: u8) -> StreamWindowRequestState {
        StreamWindowRequestState {
            unresolved_00_10: [0; 5],
            request_interface: interface,
            unresolved_18_20: [0; 3],
            request_flags: flags,
            unresolved_25_2b: [0; 7],
            maximum_window_length: 0x1234_5678,
        }
    }

    #[test]
    fn accepted_window_commits_maximum_and_returns_normalized_success() {
        let mut interface = StreamWindowRequestInterface { vtable: &VTABLE };
        let mut state = state(&mut interface, 0x81);
        let result = unsafe {
            stream_window_request(&mut state, 0, 7, 0, 0xf0, 8, u32::MAX, u32::MAX)
        };
        assert_eq!(result, 1);
        assert_eq!(state.maximum_window_length, 7);
    }

    #[test]
    fn refused_window_preserves_previous_maximum() {
        let mut interface = StreamWindowRequestInterface { vtable: &VTABLE };
        let mut state = state(&mut interface, 1);
        let result = unsafe {
            stream_window_request(&mut state, 0, u32::MAX, 0, 0xf0, 8, u32::MAX, u32::MAX)
        };
        assert_eq!(result, 0);
        assert_eq!(state.maximum_window_length, 0x1234_5678);
    }

    #[test]
    fn missing_interface_or_disabled_request_preserves_maximum() {
        for flags in [0, 1, 0xfe, 0xff] {
            let mut state = state(core::ptr::null_mut(), flags);
            assert_eq!(unsafe {
                stream_window_request(&mut state, 0, 7, 0, 0xf0, 8, u32::MAX, u32::MAX)
            }, 0);
            assert_eq!(state.maximum_window_length, 0x1234_5678);
        }
        let mut interface = StreamWindowRequestInterface { vtable: core::ptr::null() };
        let mut state = state(&mut interface, 0xfe);
        assert_eq!(unsafe {
            stream_window_request(&mut state, 0, 7, 0, 0xf0, 8, u32::MAX, u32::MAX)
        }, 0);
        assert_eq!(state.maximum_window_length, 0x1234_5678);
    }
}
