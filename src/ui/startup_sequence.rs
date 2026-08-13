//! UI startup event sequence.
//!
//! `ui_startup_sequence` — original: `FUN_080056b0` @ `0x080056b0`
//! (32 bytes). Reference:
//! `/home/gabe/Programming/ipod-decomp/decomp/c/000/080056b0_FUN_080056b0.c`;
//! raw ARM is `0x080056b0..0x080056d0`.
//!
//! The stock wrapper calls the `0x080037a0` veneer (whose literal target is
//! the setup block at `0x080ea68c`), then the `0x080037c8` veneer (the
//! `0x080eade0` setup block). It obtains the event-handler source from
//! `FUN_08007470`, dispatches that source with event `1` through
//! `FUN_080076cc`, discards the dispatch result, and returns zero. Its
//! neighboring wrapper at `0x08005690` has the same shape but invokes the
//! preceding setup veneer and dispatches event `0`; this wrapper is therefore
//! the event-one half of the UI startup sequence.

/// Calls outside this one-function port.
///
/// The first two entries retain the original veneer boundaries rather than
/// calling their literal targets directly: those targets are blocks in
/// unported retailOS routines. `event_handler_source` is `FUN_08007470`; its
/// result is passed unchanged in r0 to `dispatch_first_event`, while event 1
/// occupies r1 exactly as at `0x080056c0`.
#[derive(Clone, Copy)]
pub struct UiStartupSequenceOps {
    pub setup_phase_one: unsafe extern "C" fn(),
    pub setup_phase_two: unsafe extern "C" fn(),
    pub event_handler_source: unsafe extern "C" fn() -> *const u8,
    pub dispatch_first_event: unsafe extern "C" fn(source: *const u8, event: u32) -> u32,
}

unsafe extern "C" fn firmware_setup_phase_one() {
    #[cfg(target_os = "none")]
    {
        let setup_phase_one: unsafe extern "C" fn() = core::mem::transmute(0x0800_37a0usize);
        setup_phase_one();
    }
}

unsafe extern "C" fn firmware_setup_phase_two() {
    #[cfg(target_os = "none")]
    {
        let setup_phase_two: unsafe extern "C" fn() = core::mem::transmute(0x0800_37c8usize);
        setup_phase_two();
    }
}

unsafe extern "C" fn firmware_event_handler_source() -> *const u8 {
    #[cfg(target_os = "none")]
    {
        let event_handler_source: unsafe extern "C" fn() -> *const u8 =
            core::mem::transmute(0x0800_7470usize);
        return event_handler_source();
    }

    #[cfg(not(target_os = "none"))]
    {
        core::ptr::null()
    }
}

unsafe extern "C" fn firmware_dispatch_first_event(source: *const u8, event: u32) -> u32 {
    #[cfg(target_os = "none")]
    {
        let dispatch_first_event: unsafe extern "C" fn(*const u8, u32) -> u32 =
            core::mem::transmute(0x0800_76ccusize);
        return dispatch_first_event(source, event);
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = (source, event);
        0
    }
}

/// Unwired target/host ROM-dispatch boundary.
pub const DEFAULT_UI_STARTUP_SEQUENCE_OPS: UiStartupSequenceOps = UiStartupSequenceOps {
    setup_phase_one: firmware_setup_phase_one,
    setup_phase_two: firmware_setup_phase_two,
    event_handler_source: firmware_event_handler_source,
    dispatch_first_event: firmware_dispatch_first_event,
};

/// Active startup boundary. Target builds use the retailOS veneer addresses;
/// direct host tests install a recorder.
pub static mut UI_STARTUP_SEQUENCE_OPS: UiStartupSequenceOps = DEFAULT_UI_STARTUP_SEQUENCE_OPS;

#[inline(always)]
fn startup_ops() -> UiStartupSequenceOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(UI_STARTUP_SEQUENCE_OPS)) }
}

/// ui_startup_sequence — original: `FUN_080056b0` @ `0x080056b0` (32 bytes).
///
/// Runs the two UI setup veneers, retrieves the event-handler source, and
/// dispatches its first handler for event 1. The dispatch return value is dead;
/// this wrapper always returns zero.
///
/// # Deviations
///
/// The two setup veneers, source provider, and dispatch target remain in
/// retailOS. [`UI_STARTUP_SEQUENCE_OPS`] preserves their ABI and strict call
/// order, calling their original load addresses on target and providing a
/// deterministic host seam instead of inventing their implementations.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_startup_sequence() -> u32 {
    let ops = startup_ops();
    unsafe {
        (ops.setup_phase_one)();
        (ops.setup_phase_two)();
        let source = (ops.event_handler_source)();
        (ops.dispatch_first_event)(source, 1);
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Call {
        SetupPhaseOne,
        SetupPhaseTwo,
        EventHandlerSource,
        DispatchFirstEvent { source: usize, event: u32 },
    }

    struct Mock {
        source: usize,
        dispatch_result: u32,
        call_count: usize,
        calls: [Option<Call>; 4],
    }

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static MOCK: Mutex<Mock> = Mutex::new(Mock {
        source: 0,
        dispatch_result: 0,
        call_count: 0,
        calls: [None; 4],
    });

    fn record(call: Call) {
        let mut mock = MOCK.lock().unwrap_or_else(|error| error.into_inner());
        let call_index = mock.call_count;
        mock.calls[call_index] = Some(call);
        mock.call_count = call_index + 1;
    }

    unsafe extern "C" fn mock_setup_phase_one() {
        record(Call::SetupPhaseOne);
    }

    unsafe extern "C" fn mock_setup_phase_two() {
        record(Call::SetupPhaseTwo);
    }

    unsafe extern "C" fn mock_event_handler_source() -> *const u8 {
        record(Call::EventHandlerSource);
        MOCK.lock().unwrap_or_else(|error| error.into_inner()).source as *const u8
    }

    unsafe extern "C" fn mock_dispatch_first_event(source: *const u8, event: u32) -> u32 {
        record(Call::DispatchFirstEvent {
            source: source as usize,
            event,
        });
        MOCK.lock()
            .unwrap_or_else(|error| error.into_inner())
            .dispatch_result
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
        previous: UiStartupSequenceOps,
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe { UI_STARTUP_SEQUENCE_OPS = self.previous };
        }
    }

    fn bench(source: usize, dispatch_result: u32) -> Bench {
        let lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let previous = unsafe { UI_STARTUP_SEQUENCE_OPS };
        *MOCK.lock().unwrap_or_else(|error| error.into_inner()) = Mock {
            source,
            dispatch_result,
            call_count: 0,
            calls: [None; 4],
        };
        unsafe {
            UI_STARTUP_SEQUENCE_OPS = UiStartupSequenceOps {
                setup_phase_one: mock_setup_phase_one,
                setup_phase_two: mock_setup_phase_two,
                event_handler_source: mock_event_handler_source,
                dispatch_first_event: mock_dispatch_first_event,
            };
        }
        Bench {
            _lock: lock,
            previous,
        }
    }

    #[test]
    fn startup_sequence_calls_setup_then_dispatches_event_one_and_returns_zero() {
        const SOURCE: usize = 0x1234_5678;
        let _bench = bench(SOURCE, 0xfeed_face);

        assert_eq!(unsafe { ui_startup_sequence() }, 0);

        let mock = MOCK.lock().unwrap_or_else(|error| error.into_inner());
        assert_eq!(mock.call_count, 4);
        assert_eq!(
            mock.calls,
            [
                Some(Call::SetupPhaseOne),
                Some(Call::SetupPhaseTwo),
                Some(Call::EventHandlerSource),
                Some(Call::DispatchFirstEvent {
                    source: SOURCE,
                    event: 1,
                }),
            ],
            "the raw ARM call order and r0/r1 dispatch ABI are preserved"
        );
    }
}
