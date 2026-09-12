//! `stream_window_dispatch_request` — original: `FUN_0822adb0` @ `0x0822adb0`
//! (**112 bytes**, `0x0822adb0..0x0822ae1c`; the next separately linked
//! function begins at `0x0822ae20`).
//!
//! The routine only dispatches while `state->request_interface` is non-NULL and
//! `state->request_flags & 1` is set. It forwards all seven request arguments
//! unchanged through interface-vtable slot `+0x54`, normalizes the callback's
//! result to `0` or `1`, and, on success only, saves the second forwarded
//! argument as `state->maximum_window_length`.
//!
//! Decoding every ARM `B`/`BL` immediate in `osos.dec` finds **eight direct
//! inbound `bl` calls**, all unconditional, at `0x081b7dec`, `0x081cc92c`,
//! `0x081cca30`, `0x081cce40`, `0x081ccfa4`, `0x0820a490`, `0x082202e0`, and
//! `0x0822050c`; there are no predicated direct calls, tail branches, or
//! aligned data-word references to this entry. The virtual target has no
//! independently verified identity, so this port deliberately models only its
//! observed vtable slot rather than naming or stubbing a callee. The host's
//! pointer-width layout models those named field roles structurally; target
//! builds retain the exact 32-bit offsets `+0x14`, `+0x24`, and `+0x2c`.
//!
//! Deliberate deviations: none.

/// State fields observed by the request dispatcher.
///
/// On the ARM target, `request_interface`, `request_flags`, and
/// `maximum_window_length` are respectively at `+0x14`, `+0x24`, and `+0x2c`.
/// The naturally widened host pointer intentionally changes only host fixture
/// spacing, never the target layout.
#[repr(C)]
pub struct StreamWindowRequestState {
    pub unresolved_00_10: [u32; 5],
    pub request_interface: *mut StreamWindowRequestInterface,
    pub unresolved_18_20: [u32; 3],
    pub request_flags: u8,
    pub unresolved_25_2b: [u8; 7],
    pub maximum_window_length: u32,
}

/// Interface object whose first word supplies the request-operation vtable.
#[repr(C)]
pub struct StreamWindowRequestInterface {
    pub vtable: *const StreamWindowRequestVtable,
}

/// Recovered portion of the request interface's vtable.
///
/// `dispatch_request` is vtable slot `+0x54` on the 32-bit target. `usize`
/// keeps that slot structurally correct in both target code and widened host
/// fixtures.
#[repr(C)]
pub struct StreamWindowRequestVtable {
    pub unresolved_00_50: [usize; 21],
    pub dispatch_request: unsafe extern "C" fn(
        interface: *mut StreamWindowRequestInterface,
        request_arg_1: u32,
        maximum_window_length: u32,
        request_arg_3: u32,
        request_arg_4: u32,
        request_arg_5: u32,
        request_arg_6: u32,
        request_arg_7: u32,
    ) -> u32,
}

/// Conditionally forwards a stream-window request through its interface.
///
/// # Safety
///
/// `state` must be non-NULL, aligned, and readable through `+0x2c`. When its
/// interface field is non-NULL and flags bit 0 is set, that interface and its
/// vtable slot `+0x54` must be valid for the seven forwarded arguments. The
/// retail function has no state, vtable, or slot NULL guard once dispatch is
/// enabled.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stream_window_dispatch_request(
    state: *mut StreamWindowRequestState,
    request_arg_1: u32,
    maximum_window_length: u32,
    request_arg_3: u32,
    request_arg_4: u32,
    request_arg_5: u32,
    request_arg_6: u32,
    request_arg_7: u32,
) -> u32 {
    let interface = (*state).request_interface;
    if interface.is_null() || (*state).request_flags & 1 == 0 {
        return 0;
    }

    let dispatch = (*(*interface).vtable).dispatch_request;
    let dispatched = dispatch(
        interface,
        request_arg_1,
        maximum_window_length,
        request_arg_3,
        request_arg_4,
        request_arg_5,
        request_arg_6,
        request_arg_7,
    );
    if dispatched == 0 {
        return 0;
    }

    (*state).maximum_window_length = maximum_window_length;
    1
}

#[cfg(test)]
mod tests {
    use super::{
        stream_window_dispatch_request, StreamWindowRequestInterface,
        StreamWindowRequestState, StreamWindowRequestVtable,
    };
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct RecordedCall {
        interface: usize,
        arguments: [u32; 7],
    }

    static mut RECORDED_CALL: Option<RecordedCall> = None;
    static mut CALLBACK_RESULT: u32 = 0;

    unsafe extern "C" fn record_request(
        interface: *mut StreamWindowRequestInterface,
        request_arg_1: u32,
        maximum_window_length: u32,
        request_arg_3: u32,
        request_arg_4: u32,
        request_arg_5: u32,
        request_arg_6: u32,
        request_arg_7: u32,
    ) -> u32 {
        RECORDED_CALL = Some(RecordedCall {
            interface: interface as usize,
            arguments: [
                request_arg_1,
                maximum_window_length,
                request_arg_3,
                request_arg_4,
                request_arg_5,
                request_arg_6,
                request_arg_7,
            ],
        });
        CALLBACK_RESULT
    }

    static VTABLE: StreamWindowRequestVtable = StreamWindowRequestVtable {
        unresolved_00_50: [0; 21],
        dispatch_request: record_request,
    };

    fn state_with(interface: *mut StreamWindowRequestInterface, flags: u8, maximum: u32) -> StreamWindowRequestState {
        StreamWindowRequestState {
            unresolved_00_10: [0; 5],
            request_interface: interface,
            unresolved_18_20: [0; 3],
            request_flags: flags,
            unresolved_25_2b: [0; 7],
            maximum_window_length: maximum,
        }
    }

    #[test]
    fn forwards_all_arguments_and_normalizes_nonzero_result() {
        let _test_guard = TEST_LOCK.lock();
        unsafe {
            RECORDED_CALL = None;
            CALLBACK_RESULT = 0xfeed_beef;
            let mut interface = StreamWindowRequestInterface { vtable: &VTABLE };
            let mut state = state_with(&mut interface, 0x81, 0x1111_1111);

            let result = stream_window_dispatch_request(
                &mut state,
                0x1010_1010,
                0x2020_2020,
                0x3030_3030,
                0x4040_4040,
                0x5050_5050,
                0x6060_6060,
                0x7070_7070,
            );

            assert_eq!(result, 1);
            assert_eq!(state.maximum_window_length, 0x2020_2020);
            assert_eq!(
                RECORDED_CALL,
                Some(RecordedCall {
                    interface: (&mut interface) as *mut StreamWindowRequestInterface as usize,
                    arguments: [
                        0x1010_1010,
                        0x2020_2020,
                        0x3030_3030,
                        0x4040_4040,
                        0x5050_5050,
                        0x6060_6060,
                        0x7070_7070,
                    ],
                })
            );
        }
    }

    #[test]
    fn retains_maximum_when_dispatch_is_refused() {
        let _test_guard = TEST_LOCK.lock();
        unsafe {
            RECORDED_CALL = None;
            CALLBACK_RESULT = 0;
            let mut interface = StreamWindowRequestInterface { vtable: &VTABLE };
            let mut state = state_with(&mut interface, 1, 0x1234_5678);

            assert_eq!(
                stream_window_dispatch_request(&mut state, 1, 9, 3, 5, 7, 11, 13),
                0
            );
            assert_eq!(state.maximum_window_length, 0x1234_5678);
            assert!(RECORDED_CALL.is_some());
        }
    }

    #[test]
    fn skips_dispatch_for_null_interface_or_clear_enable_bit() {
        let _test_guard = TEST_LOCK.lock();
        unsafe {
            RECORDED_CALL = None;
            CALLBACK_RESULT = 1;
            let mut disabled = state_with(core::ptr::null_mut(), 0xff, 31);
            assert_eq!(stream_window_dispatch_request(&mut disabled, 1, 2, 3, 4, 5, 6, 7), 0);
            assert_eq!(disabled.maximum_window_length, 31);
            assert_eq!(RECORDED_CALL, None);

            let mut interface = StreamWindowRequestInterface { vtable: &VTABLE };
            let mut clear_flag = state_with(&mut interface, 0xfe, 37);
            assert_eq!(stream_window_dispatch_request(&mut clear_flag, 1, 2, 3, 4, 5, 6, 7), 0);
            assert_eq!(clear_flag.maximum_window_length, 37);
            assert_eq!(RECORDED_CALL, None);
        }
    }
}
