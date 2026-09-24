//! `dispatch_optional_codec` — original: `FUN_080621b4` @ `0x080621b4` (52
//! bytes; true extent `0x080621b4..0x080621e8`, followed by the distinct
//! getter wrapper at `0x080621e8`).
//!
//! **Verified call count:** one plain unconditional `bl` inside the body
//! (`0x080621c0` to the unported context getter at `0x0806212c`); no
//! predicated `bl` forms. Raw ARM words establish the four conditional moves,
//! the conditional stack restore, and `bxne r2`; inbound scanning finds two
//! plain calls and one predicated `blgt` call.
//!
//! The function obtains an optional, lazily initialized dispatch context and,
//! when its word at `+0x10` is nonzero, calls that callback with the caller's
//! buffer and length. A missing context or callback returns `-1`; otherwise
//! the callback's `r0` result is returned unchanged. The getter's concrete
//! identity is not established, so it remains a literal veneer to retailOS.
//!
//! Deliberate deviation: the terminal ARM `bx` is a normal Rust call. Host
//! contexts widen the callback field so native function pointers are not
//! truncated; the target representation remains a five-word ARM record.

use core::ptr::addr_of;

/// Callback installed at word `+0x10` of the optional dispatch context.
pub type CodecDispatch = unsafe extern "C" fn(*mut u8, u32) -> i32;

/// Context returned by the unported getter at `0x0806212c`.
#[repr(C)]
pub struct OptionalCodecDispatchContext {
    /// Words `+0x00..+0x0c`, not read by this wrapper.
    #[cfg(target_os = "none")]
    pub unresolved: [u32; 4],
    /// Word `+0x10` on ARM: callback address.
    #[cfg(target_os = "none")]
    pub dispatch: u32,
    /// Host representation preserving the observed five-word ordering.
    #[cfg(not(target_os = "none"))]
    pub unresolved: [usize; 4],
    /// Host-native form of the callback at ARM word `+0x10`.
    #[cfg(not(target_os = "none"))]
    pub dispatch: Option<CodecDispatch>,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 16] = [0; core::mem::offset_of!(OptionalCodecDispatchContext, dispatch)];

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_optional_codec_context() -> *mut OptionalCodecDispatchContext {
    core::ptr::null_mut()
}

/// Host seam for the unported optional-context getter at `0x0806212c`.
#[cfg(not(target_arch = "arm"))]
pub static mut OPTIONAL_CODEC_CONTEXT_GET: unsafe extern "C" fn() -> *mut OptionalCodecDispatchContext =
    missing_optional_codec_context;

#[cfg(target_arch = "arm")]
extern "C" {
    fn get_optional_codec_context() -> *mut OptionalCodecDispatchContext;
}

/// Obtains the optional context and dispatches `buffer` and `length` through
/// its callback at word `+0x10`, or returns `-1` when either is absent.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn dispatch_optional_codec(buffer: *mut u8, length: u32) -> i32 {
    #[cfg(target_arch = "arm")]
    let context = unsafe { get_optional_codec_context() };
    #[cfg(not(target_arch = "arm"))]
    let context = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OPTIONAL_CODEC_CONTEXT_GET))() };

    if context.is_null() {
        return -1;
    }

    #[cfg(target_os = "none")]
    {
        let dispatch_address = unsafe { addr_of!((*context).dispatch).read_volatile() };
        if dispatch_address == 0 {
            return -1;
        }
        let dispatch: CodecDispatch = unsafe { core::mem::transmute(dispatch_address as usize) };
        unsafe { dispatch(buffer, length) }
    }

    #[cfg(not(target_os = "none"))]
    {
        match unsafe { addr_of!((*context).dispatch).read_volatile() } {
            Some(dispatch) => unsafe { dispatch(buffer, length) },
            None => -1,
        }
    }
}

// The patch payload is not within an ARM `bl` range of retailOS. This veneer
// preserves lr and returns the getter's r0 result unchanged.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
get_optional_codec_context:
    ldr     pc, 1f
1:  .word   0x0806212c
"#
);

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::{addr_of_mut, null_mut};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CONTEXT: *mut OptionalCodecDispatchContext = null_mut();
    static mut SEEN: (*mut u8, u32) = (null_mut(), 0);

    unsafe extern "C" fn context_getter() -> *mut OptionalCodecDispatchContext {
        unsafe { CONTEXT }
    }

    unsafe extern "C" fn recording_dispatch(buffer: *mut u8, length: u32) -> i32 {
        unsafe { SEEN = (buffer, length) };
        -73
    }

    struct GetterRestore(unsafe extern "C" fn() -> *mut OptionalCodecDispatchContext);

    impl Drop for GetterRestore {
        fn drop(&mut self) {
            unsafe { OPTIONAL_CODEC_CONTEXT_GET = self.0 };
        }
    }

    #[test]
    fn dispatches_buffer_and_length_and_preserves_callback_result() {
        let _lock = TEST_LOCK.lock();
        let _restore = unsafe {
            let previous = OPTIONAL_CODEC_CONTEXT_GET;
            OPTIONAL_CODEC_CONTEXT_GET = context_getter;
            GetterRestore(previous)
        };
        let mut context = OptionalCodecDispatchContext {
            unresolved: [0; 4],
            dispatch: Some(recording_dispatch),
        };
        let mut buffer = [0u8; 3];
        unsafe {
            CONTEXT = addr_of_mut!(context);
            SEEN = (null_mut(), 0);
        }

        let result = unsafe { dispatch_optional_codec(buffer.as_mut_ptr(), 3) };

        assert_eq!(result, -73);
        assert_eq!(unsafe { SEEN }, (buffer.as_mut_ptr(), 3));
    }

    #[test]
    fn returns_negative_one_without_context_or_callback() {
        let _lock = TEST_LOCK.lock();
        let _restore = unsafe {
            let previous = OPTIONAL_CODEC_CONTEXT_GET;
            OPTIONAL_CODEC_CONTEXT_GET = context_getter;
            GetterRestore(previous)
        };
        unsafe { CONTEXT = null_mut() };
        assert_eq!(unsafe { dispatch_optional_codec(null_mut(), 0) }, -1);

        let mut context = OptionalCodecDispatchContext {
            unresolved: [usize::MAX; 4],
            dispatch: None,
        };
        unsafe { CONTEXT = addr_of_mut!(context) };
        assert_eq!(unsafe { dispatch_optional_codec(null_mut(), u32::MAX) }, -1);
    }
}
