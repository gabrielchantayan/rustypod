//! Stream-buffer context initialization wrapper.
//!
//! `stream_buffer_initialize_and_get_page_context` — original:
//! `FUN_08005e5c` @ `0x08005e5c` (28 bytes). Reference:
//! `/home/gabe/Programming/ipod-decomp/decomp/c/000/08005e5c_FUN_08005e5c.c`;
//! raw ARM is `0x08005e5c..0x08005e78`.
//!
//! The wrapper first ensures the retailOS stream buffer is initialized through
//! `FUN_08006e88`, then obtains its current page context through
//! `FUN_0800722c`, stores that word through r2, and returns zero. r0 and r1
//! are preserved only as ABI inputs: the ARM body never reads either.

/// Calls outside this one-function port.
///
/// `initialize_stream_buffer` is `FUN_08006e88`; it lazily constructs the
/// retailOS stream buffer. `current_page_context` is `FUN_0800722c`; it
/// selects the current per-page or fallback context. They remain ROM seams so
/// this wrapper retains their ordering and ABI without claiming to port them.
#[derive(Clone, Copy)]
pub struct StreamBufferContextOps {
    pub initialize_stream_buffer: unsafe extern "C" fn(),
    pub current_page_context: unsafe extern "C" fn() -> u32,
}

unsafe extern "C" fn firmware_initialize_stream_buffer() {
    #[cfg(target_os = "none")]
    {
        let initialize_stream_buffer: unsafe extern "C" fn() =
            core::mem::transmute(0x0800_6e88usize);
        initialize_stream_buffer();
    }
}

unsafe extern "C" fn firmware_current_page_context() -> u32 {
    #[cfg(target_os = "none")]
    {
        let current_page_context: unsafe extern "C" fn() -> u32 =
            core::mem::transmute(0x0800_722cusize);
        return current_page_context();
    }

    #[cfg(not(target_os = "none"))]
    {
        0
    }
}

/// Unwired target/host ROM-dispatch boundary.
pub const DEFAULT_STREAM_BUFFER_CONTEXT_OPS: StreamBufferContextOps = StreamBufferContextOps {
    initialize_stream_buffer: firmware_initialize_stream_buffer,
    current_page_context: firmware_current_page_context,
};

/// Active context boundary. Target builds call retailOS; host tests install a
/// recorder to prove the wrapper's observable sequencing.
pub static mut STREAM_BUFFER_CONTEXT_OPS: StreamBufferContextOps =
    DEFAULT_STREAM_BUFFER_CONTEXT_OPS;

#[inline(always)]
fn stream_buffer_context_ops() -> StreamBufferContextOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(STREAM_BUFFER_CONTEXT_OPS)) }
}

/// stream_buffer_initialize_and_get_page_context — original: `FUN_08005e5c`
/// @ `0x08005e5c` (28 bytes).
///
/// Initializes the shared stream buffer, gets its current page context, stores
/// it to `page_context_out`, and returns zero. The first two ABI words are
/// deliberately unused, exactly as r0 and r1 are in the ARM wrapper.
///
/// # Deviations
///
/// The initialization and context-selection implementations remain in retailOS.
/// [`STREAM_BUFFER_CONTEXT_OPS`] calls their original load addresses on target
/// and supplies a deterministic host seam; it does not alter the wrapper's
/// two calls, output store, or fixed zero return.
///
/// # Safety
///
/// `page_context_out` must be non-null and valid for one aligned `u32` store.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn stream_buffer_initialize_and_get_page_context(
    _unused_first: u32,
    _unused_second: u32,
    page_context_out: *mut u32,
) -> u32 {
    let ops = stream_buffer_context_ops();
    unsafe {
        (ops.initialize_stream_buffer)();
        page_context_out.write((ops.current_page_context)());
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
        Initialize,
        CurrentPageContext,
    }

    struct Mock {
        page_context: u32,
        call_count: usize,
        calls: [Option<Call>; 2],
    }

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static MOCK: Mutex<Mock> = Mutex::new(Mock {
        page_context: 0,
        call_count: 0,
        calls: [None; 2],
    });

    fn record(call: Call) {
        let mut mock = MOCK.lock().unwrap_or_else(|error| error.into_inner());
        let call_index = mock.call_count;
        mock.calls[call_index] = Some(call);
        mock.call_count = call_index + 1;
    }

    unsafe extern "C" fn mock_initialize_stream_buffer() {
        record(Call::Initialize);
    }

    unsafe extern "C" fn mock_current_page_context() -> u32 {
        record(Call::CurrentPageContext);
        MOCK.lock()
            .unwrap_or_else(|error| error.into_inner())
            .page_context
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
        previous: StreamBufferContextOps,
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe { STREAM_BUFFER_CONTEXT_OPS = self.previous };
        }
    }

    fn bench(page_context: u32) -> Bench {
        let lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let previous = unsafe { STREAM_BUFFER_CONTEXT_OPS };
        *MOCK.lock().unwrap_or_else(|error| error.into_inner()) = Mock {
            page_context,
            call_count: 0,
            calls: [None; 2],
        };
        unsafe {
            STREAM_BUFFER_CONTEXT_OPS = StreamBufferContextOps {
                initialize_stream_buffer: mock_initialize_stream_buffer,
                current_page_context: mock_current_page_context,
            };
        }
        Bench {
            _lock: lock,
            previous,
        }
    }

    #[test]
    fn initializes_then_stores_current_page_context_and_returns_zero() {
        let _bench = bench(0xc001_c0de);
        let mut output = 0xdead_beef;

        assert_eq!(
            unsafe {
                stream_buffer_initialize_and_get_page_context(0x1111_1111, 0x2222_2222, &mut output)
            },
            0,
            "the wrapper's result is the fixed zero"
        );
        assert_eq!(output, 0xc001_c0de, "r2 output receives the getter result");

        let mock = MOCK.lock().unwrap_or_else(|error| error.into_inner());
        assert_eq!(mock.call_count, 2);
        assert_eq!(
            mock.calls,
            [Some(Call::Initialize), Some(Call::CurrentPageContext)],
            "initialization precedes page-context lookup"
        );
    }
}
