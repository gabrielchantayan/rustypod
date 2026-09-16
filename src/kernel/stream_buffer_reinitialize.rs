//! Flush-and-reinitialize wrapper for the shared RAM stream buffer.
//!
//! Port: [`stream_buffer_reinitialize`] — original: `FUN_080073b0` @
//! `0x080073b0` (**64 bytes: 60 bytes of code plus its 4-byte literal pool;
//! Ghidra reports 60 bytes, excluding the literal word at `0x080073ec`**.
//! Decoding every ARM B/BL word in `osos.dec` found exactly **5 direct `bl`
//! call sites** (`0x080054e8`, `0x08005534`, `0x08005580`, `0x0800563c`,
//! `0x08007618`), all unconditional with zero predicated forms, plus one
//! tail `b` at `0x08007fc8` from `FUN_08007f88`). The next real function
//! (the stream-buffer constructor `FUN_080073f0`) starts at `0x080073f0`,
//! confirming the literal belongs to this body.
//!
//! ## Algorithm
//!
//! Save all three arguments in callee-saved registers, invoke the two
//! stream flush continuations through the literal veneers at `0x08003848`
//! (-> `0x08201460`) and `0x080038f8` (-> `0x082014c8`, arguments are the
//! first continuation's r0 result and literal 0), clear the stream-buffer
//! page-initialization flag byte at `0x2200aed5`, then tail-call the page
//! initializer `FUN_080072cc` with the original three arguments restored.
//! Clearing `0x2200aed5` re-arms the guard `FUN_080072cc` tests, so the
//! tail call re-runs page setup (zeroing the existing 0x20000-byte
//! allocation and rebuilding page pointers); the initializer's r0 result
//! is forwarded to the caller.
//!
//! ## Deliberate deviations
//!
//! The continuations are entered mid-function and read the object pointer
//! from **callee-saved r4** (`0x08201460`: `mov r0,r4; blx r1`; the shared
//! tail reloads fields from `[r4,#...]`), an ABI Rust cannot express. ARM
//! builds therefore replicate the exact register-level body in assembly,
//! reaching the veneers and the page initializer through absolute
//! literal-loaded `blx`/`bx` because the patch payload links separately
//! from the stock image. Host builds model the two continuations and the
//! page initializer with replaceable inert seams and the `0x2200aed5`
//! flag with private storage.

/// Stream-buffer page-initialization flag at IRAM `0x2200aed5` (the
/// literal at `0x080073ec`).
#[cfg(not(target_arch = "arm"))]
const STREAM_BUFFER_PAGES_READY_ADDRESS: usize = 0x2200_aed5;

/// First stream flush continuation, entered through the literal veneer at
/// `0x08003848` (target `0x08201460`). Receives all three original
/// arguments in r0-r2 and the object in r4; its r0 result feeds the second
/// continuation.
#[cfg(not(target_arch = "arm"))]
pub type StreamBufferFlushEnterFn = unsafe extern "C" fn(
    stream_buffer: *mut u8,
    zero_page_context: u32,
    page_context: u32,
) -> u32;

/// Second stream flush continuation, entered through the literal veneer at
/// `0x080038f8` (target `0x082014c8`). Receives the first continuation's
/// r0 result and a literal 0 in r1.
#[cfg(not(target_arch = "arm"))]
pub type StreamBufferFlushExitFn = unsafe extern "C" fn(state: u32, zero: u32) -> u32;

/// RetailOS page allocation and initialization tail call at `0x080072cc`.
#[cfg(not(target_arch = "arm"))]
pub type StreamBufferPageInitializeFn = unsafe extern "C" fn(
    stream_buffer: *mut u8,
    allocate_if_needed: u32,
    page_context: u32,
) -> u32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn host_stream_buffer_flush_enter(
    _stream_buffer: *mut u8,
    _zero_page_context: u32,
    _page_context: u32,
) -> u32 {
    0
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn host_stream_buffer_flush_exit(_state: u32, _zero: u32) -> u32 {
    0
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn host_stream_buffer_page_initialize(
    _stream_buffer: *mut u8,
    _allocate_if_needed: u32,
    _page_context: u32,
) -> u32 {
    0
}

#[cfg(not(target_arch = "arm"))]
static mut STREAM_BUFFER_FLUSH_ENTER: StreamBufferFlushEnterFn = host_stream_buffer_flush_enter;

#[cfg(not(target_arch = "arm"))]
static mut STREAM_BUFFER_FLUSH_EXIT: StreamBufferFlushExitFn = host_stream_buffer_flush_exit;

#[cfg(not(target_arch = "arm"))]
static mut STREAM_BUFFER_PAGE_INITIALIZE: StreamBufferPageInitializeFn =
    host_stream_buffer_page_initialize;

#[cfg(not(target_arch = "arm"))]
static mut HOST_STREAM_BUFFER_PAGES_READY: u8 = 0;

#[cfg(not(target_arch = "arm"))]
unsafe fn stream_buffer_pages_ready() -> *mut u8 {
    let _ = STREAM_BUFFER_PAGES_READY_ADDRESS;
    core::ptr::addr_of_mut!(HOST_STREAM_BUFFER_PAGES_READY)
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
fn stream_buffer_flush_enter() -> StreamBufferFlushEnterFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(STREAM_BUFFER_FLUSH_ENTER)) }
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
fn stream_buffer_flush_exit() -> StreamBufferFlushExitFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(STREAM_BUFFER_FLUSH_EXIT)) }
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
fn stream_buffer_page_initialize() -> StreamBufferPageInitializeFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(STREAM_BUFFER_PAGE_INITIALIZE)) }
}

/// stream_buffer_reinitialize — original: `FUN_080073b0` @ `0x080073b0`
/// (64 bytes: 60 bytes of code plus a 4-byte literal pool; 5 direct,
/// unconditional `bl` call sites and one tail `b`, binary-verified by
/// decoding every ARM B/BL word in `osos.dec`).
///
/// Runs both stream flush continuations, clears the page-initialization
/// flag byte at `0x2200aed5`, and tail-calls the page initializer with the
/// original arguments, forwarding its result. The host implementation
/// below mirrors that register-level flow through replaceable seams.
#[cfg(not(target_arch = "arm"))]
#[inline(never)]
pub unsafe extern "C" fn stream_buffer_reinitialize(
    stream_buffer: *mut u8,
    zero_page_context: u32,
    page_context: u32,
) -> u32 {
    let state = stream_buffer_flush_enter()(stream_buffer, zero_page_context, page_context);
    stream_buffer_flush_exit()(state, 0);
    core::ptr::write_volatile(stream_buffer_pages_ready(), 0);
    stream_buffer_page_initialize()(stream_buffer, zero_page_context, page_context)
}

// The continuations read the object pointer from callee-saved r4, an ABI
// Rust cannot express, so the ARM body replicates the original register
// flow exactly. The veneers and page initializer are reached through
// absolute literal-loaded register branches because the patch payload
// links separately from the stock image; `blx`/`bx` with an aligned ARM
// target preserve the original `bl`/`b` semantics including lr.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl stream_buffer_reinitialize
    .type stream_buffer_reinitialize, %function
stream_buffer_reinitialize:
    push    {{r4, r5, r6, lr}}
    mov     r6, r2
    mov     r5, r1
    mov     r4, r0
    ldr     r3, =0x08003848
    blx     r3
    mov     r1, #0
    ldr     r3, =0x080038f8
    blx     r3
    ldr     r1, =0x2200aed5
    mov     r0, #0
    strb    r0, [r1]
    mov     r1, r5
    mov     r0, r4
    mov     r2, r6
    pop     {{r4, r5, r6, lr}}
    ldr     r3, =0x080072cc
    bx      r3
    .size stream_buffer_reinitialize, . - stream_buffer_reinitialize
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Step {
        FlushEnter,
        FlushExit,
        PageInitialize,
    }

    #[derive(Clone, Copy)]
    struct Mock {
        sequence: [Option<Step>; 3],
        calls: usize,
        enter_argument: (usize, u32, u32),
        exit_argument: (u32, u32),
        page_initialize_argument: (usize, u32, u32),
        enter_result: u32,
        page_initialize_result: u32,
    }

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static MOCK: Mutex<Mock> = Mutex::new(Mock {
        sequence: [None; 3],
        calls: 0,
        enter_argument: (0, 0, 0),
        exit_argument: (0, 0),
        page_initialize_argument: (0, 0, 0),
        enter_result: 0,
        page_initialize_result: 0,
    });

    struct Fixture {
        _guard: MutexGuard<'static, ()>,
        saved_enter: StreamBufferFlushEnterFn,
        saved_exit: StreamBufferFlushExitFn,
        saved_page_initialize: StreamBufferPageInitializeFn,
        saved_ready: u8,
    }

    impl Fixture {
        fn new(enter_result: u32, page_initialize_result: u32) -> Fixture {
            let guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
            let fixture = unsafe {
                let saved_enter = STREAM_BUFFER_FLUSH_ENTER;
                let saved_exit = STREAM_BUFFER_FLUSH_EXIT;
                let saved_page_initialize = STREAM_BUFFER_PAGE_INITIALIZE;
                let saved_ready = HOST_STREAM_BUFFER_PAGES_READY;
                STREAM_BUFFER_FLUSH_ENTER = recording_flush_enter;
                STREAM_BUFFER_FLUSH_EXIT = recording_flush_exit;
                STREAM_BUFFER_PAGE_INITIALIZE = recording_page_initialize;
                HOST_STREAM_BUFFER_PAGES_READY = 1;
                Fixture {
                    _guard: guard,
                    saved_enter,
                    saved_exit,
                    saved_page_initialize,
                    saved_ready,
                }
            };
            {
                let mut mock = MOCK.lock().unwrap_or_else(|error| error.into_inner());
                mock.sequence = [None; 3];
                mock.calls = 0;
                mock.enter_argument = (0, 0, 0);
                mock.exit_argument = (0, 0);
                mock.page_initialize_argument = (0, 0, 0);
                mock.enter_result = enter_result;
                mock.page_initialize_result = page_initialize_result;
            }
            fixture
        }

        fn mock(&self) -> Mock {
            *MOCK.lock().unwrap_or_else(|error| error.into_inner())
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                STREAM_BUFFER_FLUSH_ENTER = self.saved_enter;
                STREAM_BUFFER_FLUSH_EXIT = self.saved_exit;
                STREAM_BUFFER_PAGE_INITIALIZE = self.saved_page_initialize;
                HOST_STREAM_BUFFER_PAGES_READY = self.saved_ready;
            }
        }
    }

    fn record(step: Step) -> usize {
        let mut mock = MOCK.lock().unwrap_or_else(|error| error.into_inner());
        let index = mock.calls;
        mock.calls += 1;
        if index < mock.sequence.len() {
            mock.sequence[index] = Some(step);
        }
        index
    }

    unsafe extern "C" fn recording_flush_enter(
        stream_buffer: *mut u8,
        zero_page_context: u32,
        page_context: u32,
    ) -> u32 {
        record(Step::FlushEnter);
        let mut mock = MOCK.lock().unwrap_or_else(|error| error.into_inner());
        mock.enter_argument = (stream_buffer as usize, zero_page_context, page_context);
        mock.enter_result
    }

    unsafe extern "C" fn recording_flush_exit(state: u32, zero: u32) -> u32 {
        record(Step::FlushExit);
        let mut mock = MOCK.lock().unwrap_or_else(|error| error.into_inner());
        mock.exit_argument = (state, zero);
        0
    }

    unsafe extern "C" fn recording_page_initialize(
        stream_buffer: *mut u8,
        allocate_if_needed: u32,
        page_context: u32,
    ) -> u32 {
        record(Step::PageInitialize);
        let mut mock = MOCK.lock().unwrap_or_else(|error| error.into_inner());
        mock.page_initialize_argument =
            (stream_buffer as usize, allocate_if_needed, page_context);
        mock.page_initialize_result
    }

    #[test]
    fn reinitialize_runs_continuations_then_clears_flag_then_initializes() {
        let fixture = Fixture::new(0xdead_beef, 0x1234_5678);
        let mut buffer = [0u8; 0x150];
        let result = unsafe {
            stream_buffer_reinitialize(buffer.as_mut_ptr(), 1, 0xa5a5_5a5a)
        };
        let mock = fixture.mock();
        assert_eq!(result, 0x1234_5678, "page initializer result is forwarded");
        assert_eq!(mock.calls, 3);
        assert_eq!(
            mock.sequence,
            [Some(Step::FlushEnter), Some(Step::FlushExit), Some(Step::PageInitialize)],
        );
        assert_eq!(
            mock.enter_argument,
            (buffer.as_mut_ptr() as usize, 1, 0xa5a5_5a5a),
            "all three original arguments reach the first continuation",
        );
        assert_eq!(
            mock.exit_argument,
            (0xdead_beef, 0),
            "second continuation gets the first result and a literal zero",
        );
        assert_eq!(
            mock.page_initialize_argument,
            (buffer.as_mut_ptr() as usize, 1, 0xa5a5_5a5a),
            "tail call receives the original arguments unchanged",
        );
        assert_eq!(unsafe { HOST_STREAM_BUFFER_PAGES_READY }, 0);
    }

    #[test]
    fn reinitialize_forwards_zero_and_pointer_arguments() {
        let fixture = Fixture::new(0, 0);
        let result = unsafe { stream_buffer_reinitialize(core::ptr::null_mut(), 0, 0) };
        let mock = fixture.mock();
        assert_eq!(result, 0);
        assert_eq!(mock.enter_argument, (0, 0, 0));
        assert_eq!(mock.exit_argument, (0, 0));
        assert_eq!(mock.page_initialize_argument, (0, 0, 0));
        assert_eq!(unsafe { HOST_STREAM_BUFFER_PAGES_READY }, 0);
    }
}
