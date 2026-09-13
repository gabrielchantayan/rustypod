//! dispatch_stream_to_sink — original: `FUN_082794b8` @ `0x082794b8` (20
//! bytes: five ARM words; next function starts at `0x082794cc`).
//!
//! **Verified call count:** six direct `bl` call sites, all unconditional
//! (`0x0827a2fc`, `0x0827a448`, `0x0827aa0c`, `0x0827ab44`, `0x0827ac78`, and
//! `0x0827adb0`); a full binary scan found no predicated calls.
//!
//! ```text
//! ldr r1, [r0, #4]     ; stream = context->stream
//! ldr r0, [r0, #16]    ; sink = context->sink
//! ldr r2, [r0]         ; vtable = sink->vtable
//! ldr r2, [r2]         ; dispatch = vtable->slot_0
//! bx  r2               ; dispatch(sink, stream), preserving its r0 result
//! ```
//!
//! Dispatches the context's stream through the nested sink's first vtable
//! slot. The image does not establish the concrete sink type or the callee's
//! identity, so this port names only the observed dispatch role. The original
//! performs no NULL checks.
//!
//! Deliberate deviation: Rust expresses the terminal `bx` as a normal call
//! while preserving its return value. On the 64-bit host the vtable is widened
//! structurally so function pointers are not truncated; the target layout is
//! the physical 32-bit ARM layout.

use core::ptr::addr_of;

/// Context consumed by [`dispatch_stream_to_sink`].
///
/// On the target, `stream` and `sink` occupy words `+0x04` and `+0x10`.
#[repr(C)]
pub struct StreamSinkDispatchContext {
    /// +0x00: not read by this wrapper.
    pub unresolved_00: u32,
    /// +0x04 on ARM: forwarded unchanged to the sink method.
    pub stream: *mut u8,
    /// +0x08: not read by this wrapper.
    pub unresolved_08: u32,
    /// +0x0c: not read by this wrapper.
    pub unresolved_0c: u32,
    /// +0x10 on ARM: object whose vtable slot zero is dispatched.
    pub sink: *mut StreamSink,
}

/// Object whose first word points to the stream sink's vtable.
#[repr(C)]
pub struct StreamSink {
    #[cfg(target_os = "none")]
    pub vtable: *const u32,
    #[cfg(not(target_os = "none"))]
    pub vtable: *const StreamSinkVtable,
}

/// Host representation of the sink's recovered first virtual slot.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct StreamSinkVtable {
    /// +0x00 on ARM: receives `(sink, stream)` and returns its status in r0.
    pub dispatch_stream: unsafe extern "C" fn(*mut StreamSink, *mut u8) -> u32,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 4] = [0; core::mem::offset_of!(StreamSinkDispatchContext, stream)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 16] = [0; core::mem::offset_of!(StreamSinkDispatchContext, sink)];

/// Dispatches `context.stream` through `context.sink`'s vtable slot zero.
///
/// `context` must reference a readable context with a non-NULL sink. Its sink
/// must have a readable vtable and a callable first entry; like retailOS, this
/// function does not validate any of these preconditions. The sink method's
/// `u32` return value is propagated unchanged.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn dispatch_stream_to_sink(context: *mut StreamSinkDispatchContext) -> u32 {
    #[cfg(target_os = "none")]
    {
        let stream = addr_of!((*context).stream).read_volatile();
        let sink = addr_of!((*context).sink).read_volatile();
        let vtable = addr_of!((*sink).vtable).read_volatile();
        let dispatch_address = vtable.read_volatile();
        let dispatch: unsafe extern "C" fn(*mut StreamSink, *mut u8) -> u32 =
            core::mem::transmute(dispatch_address as usize);
        dispatch(sink, stream)
    }

    #[cfg(not(target_os = "none"))]
    {
        let stream = addr_of!((*context).stream).read_volatile();
        let sink = addr_of!((*context).sink).read_volatile();
        let vtable = addr_of!((*sink).vtable).read_volatile();
        ((*vtable).dispatch_stream)(sink, stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use core::ptr::{addr_of_mut, null_mut};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut SEEN_SINK: *mut StreamSink = null_mut();
    static mut SEEN_STREAM: *mut u8 = null_mut();

    unsafe extern "C" fn recording_dispatch(sink: *mut StreamSink, stream: *mut u8) -> u32 {
        SEEN_SINK = sink;
        SEEN_STREAM = stream;
        0x91e2_0047
    }

    static VTABLE: StreamSinkVtable = StreamSinkVtable {
        dispatch_stream: recording_dispatch,
    };

    fn reset() {
        unsafe {
            SEEN_SINK = null_mut();
            SEEN_STREAM = null_mut();
        }
    }

    #[test]
    fn forwards_the_nested_sink_and_stream_and_preserves_its_status() {
        let _guard = TEST_LOCK.lock();
        reset();
        let mut stream = [0x5au8; 7];
        let mut sink = StreamSink { vtable: &VTABLE };
        let mut context = StreamSinkDispatchContext {
            unresolved_00: 0x1111_2222,
            stream: stream.as_mut_ptr(),
            unresolved_08: 0x3333_4444,
            unresolved_0c: 0x5555_6666,
            sink: addr_of_mut!(sink),
        };

        let status = unsafe { dispatch_stream_to_sink(addr_of_mut!(context)) };

        assert_eq!(status, 0x91e2_0047);
        unsafe {
            assert_eq!(SEEN_SINK, addr_of_mut!(sink));
            assert_eq!(SEEN_STREAM, stream.as_mut_ptr());
        }
    }

    #[test]
    fn forwards_a_null_stream_without_adding_a_guard() {
        let _guard = TEST_LOCK.lock();
        reset();
        let mut sink = StreamSink { vtable: &VTABLE };
        let mut context = StreamSinkDispatchContext {
            unresolved_00: 0xffff_ffff,
            stream: null_mut(),
            unresolved_08: 0,
            unresolved_0c: 0xffff_ffff,
            sink: addr_of_mut!(sink),
        };

        let status = unsafe { dispatch_stream_to_sink(addr_of_mut!(context)) };

        assert_eq!(status, 0x91e2_0047);
        unsafe {
            assert_eq!(SEEN_SINK, addr_of_mut!(sink));
            assert!(SEEN_STREAM.is_null());
        }
    }
}
