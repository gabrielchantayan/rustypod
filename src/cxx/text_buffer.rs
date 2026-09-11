//! `text_buffer_construct_with_capacity` — original: `FUN_08186380` @
//! 0x08186380 (60 bytes).
//!
//! ## Extent and call count, binary-verified
//!
//! Raw `osos.dec` begins with `push {r4,r5,r6,lr}` at 0x08186380, reaches
//! `pop {r4,r5,r6,pc}` at 0x081863b8, then has the literal-pool word at
//! 0x081863bc. The next separately linked function starts at 0x081863c0,
//! making the true extent 56 code bytes plus 4 literal bytes. Decoding every
//! ARM B/BL word in the image finds 10 direct `bl` call sites, all
//! unconditional (zero predicated calls): 0x080abfc4, 0x080ac000,
//! 0x080be7c8, 0x081318a0, 0x0813283c, 0x0815f364, 0x0815f604,
//! 0x0818cac8, 0x08210054, and 0x0822348c.
//!
//! ## Algorithm
//!
//! Construct the two-word base string object, replace its first word with the
//! literal at 0x081863bc, clear the capacity word at +8, then reserve the
//! requested capacity only when it is nonzero. The base constructor's return
//! is used for every following access and is returned to the caller.
//!
//! The literal is 0x089896bc. Its static-image bytes are the NUL-terminated
//! string `4TC_VolumeLimitLockScreenE`, not a decodable vtable. Its runtime
//! role is unresolved, so it is modeled strictly as a type marker rather than
//! as an invented virtual table.
//!
//! ## Deliberate deviations
//!
//! The literal is a ROM pointer, which host processes cannot dereference, so
//! the port stores [`TEXT_BUFFER_TYPE_MARKER`] instead. The reserve helper
//! `FUN_08186344` has no separate port: its fully decoded behavior is the
//! wired [`DEFAULT_TEXT_BUFFER_OPS`] boundary, including its call to the
//! already ported `realloc_wrapper` @ 0x080edbf0. Tests substitute that
//! boundary to observe the constructor's conditional dispatch and ordering.

use crate::cxx::string_object::{string_default_construct, StringObject};
use crate::heap::veneers::realloc_wrapper;

/// The original literal-pool value at 0x081863bc.
pub const TEXT_BUFFER_TYPE_MARKER_ADDRESS: usize = 0x0898_96bc;

/// A host-safe model of the NUL-terminated static text at
/// [`TEXT_BUFFER_TYPE_MARKER_ADDRESS`].
pub static TEXT_BUFFER_TYPE_MARKER: [u8; 27] = *b"4TC_VolumeLimitLockScreenE\0";

/// A base string object with its requested buffer capacity at +8 on ARM.
///
/// The leading two fields deliberately match [`StringObject`]'s two words so
/// the base constructor can operate on this object. `repr(C)` preserves the
/// three-word target layout while retaining a sound wider-pointer host model.
#[repr(C)]
pub struct TextBuffer {
    /// +0x00 — after construction, the 0x081863bc marker literal.
    pub type_marker: *const u8,
    /// +0x04 — the reallocatable NUL-terminated text storage.
    pub text: *mut u8,
    /// +0x08 — allocated text capacity, updated only after successful reserve.
    pub capacity: u32,
}

/// The unported reserve helper at 0x08186344.
#[derive(Clone, Copy)]
pub struct TextBufferOps {
    pub reserve: unsafe extern "C" fn(buffer: *mut TextBuffer, minimum_capacity: u32),
}

/// Exact model of the direct callee `FUN_08186344`.
///
/// It returns when the existing capacity is enough and text is non-NULL.
/// Otherwise it calls `FUN_082761d4`, whose fully decoded body reallocates the
/// text with `(tag = 0x34, copy_on_move = 1)`, stores the result even when it
/// is NULL, initializes newly allocated text when the old pointer was 0 or 1,
/// and reports success through the non-NULL result. This helper then records
/// `minimum_capacity` only on that success path.
unsafe extern "C" fn reserve_text_buffer(buffer: *mut TextBuffer, minimum_capacity: u32) {
    let buffer = &mut *buffer;
    if minimum_capacity <= buffer.capacity && !buffer.text.is_null() {
        return;
    }

    let previous_text = buffer.text;
    let text = realloc_wrapper(previous_text, minimum_capacity as usize, 0x34, 1);
    buffer.text = text;
    if !text.is_null() {
        if previous_text as usize <= 1 {
            *text = 0;
        }
        buffer.capacity = minimum_capacity;
    }
}

/// Wired model for the one unported direct callee.
pub const DEFAULT_TEXT_BUFFER_OPS: TextBufferOps = TextBufferOps {
    reserve: reserve_text_buffer,
};

/// Active reserve boundary. A later port of 0x08186344 replaces this default
/// without changing the constructor.
pub static mut TEXT_BUFFER_OPS: TextBufferOps = DEFAULT_TEXT_BUFFER_OPS;

#[inline(always)]
unsafe fn reserve_op() -> unsafe extern "C" fn(*mut TextBuffer, u32) {
    core::ptr::read_volatile(core::ptr::addr_of!(TEXT_BUFFER_OPS.reserve))
}

/// text_buffer_construct_with_capacity — original: `FUN_08186380` @
/// 0x08186380 (60 bytes; 10 unconditional `bl` call sites, binary-scanned).
///
/// Initializes `buffer` as a two-word [`StringObject`], overwrites its first
/// word with the 0x081863bc type-marker literal, clears capacity, then calls
/// the reserve helper only when `minimum_capacity != 0`. The base constructor
/// return drives the subsequent stores and the returned value; no pointer is
/// NULL-guarded, matching the firmware.
///
/// # Safety
///
/// `buffer` must be writable `TextBuffer` storage. A nonzero capacity invokes
/// the active [`TEXT_BUFFER_OPS`] reserve implementation, which may reallocate
/// and therefore has the additional storage requirements of that boundary.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn text_buffer_construct_with_capacity(
    buffer: *mut TextBuffer,
    minimum_capacity: u32,
) -> *mut TextBuffer {
    let initialized = string_default_construct(buffer.cast::<StringObject>()).cast::<TextBuffer>();
    (*initialized).type_marker = TEXT_BUFFER_TYPE_MARKER.as_ptr();
    (*initialized).capacity = 0;
    if minimum_capacity != 0 {
        reserve_op()(initialized, minimum_capacity);
    }
    initialized
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::mem::MaybeUninit;
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut LAST_CALL: Option<(*mut TextBuffer, u32, *const u8, *mut u8, u32)> = None;
    static mut RESERVED_TEXT: [u8; 1] = [0];

    struct OpsRestore;

    impl Drop for OpsRestore {
        fn drop(&mut self) {
            unsafe { TEXT_BUFFER_OPS = DEFAULT_TEXT_BUFFER_OPS }
        }
    }

    unsafe extern "C" fn recording_reserve(buffer: *mut TextBuffer, minimum_capacity: u32) {
        LAST_CALL = Some((
            buffer,
            minimum_capacity,
            (*buffer).type_marker,
            (*buffer).text,
            (*buffer).capacity,
        ));
        (*buffer).text = core::ptr::addr_of_mut!(RESERVED_TEXT).cast::<u8>();
        (*buffer).capacity = minimum_capacity;
    }

    #[test]
    fn zero_capacity_initializes_without_reserving() {
        let _lock = OPS_LOCK.lock();
        unsafe {
            TEXT_BUFFER_OPS = DEFAULT_TEXT_BUFFER_OPS;
            LAST_CALL = None;
            let mut storage = MaybeUninit::<TextBuffer>::uninit();
            let buffer = text_buffer_construct_with_capacity(storage.as_mut_ptr(), 0);

            assert_eq!(buffer, storage.as_mut_ptr());
            assert_eq!((*buffer).type_marker, TEXT_BUFFER_TYPE_MARKER.as_ptr());
            assert!((*buffer).text.is_null());
            assert_eq!((*buffer).capacity, 0);
            assert_eq!(LAST_CALL, None);
        }
    }

    #[test]
    fn nonzero_capacity_reserves_after_initializing_fields() {
        let _lock = OPS_LOCK.lock();
        let _restore = OpsRestore;
        unsafe {
            TEXT_BUFFER_OPS = TextBufferOps { reserve: recording_reserve };
            LAST_CALL = None;
            let mut storage = MaybeUninit::<TextBuffer>::uninit();
            let buffer = text_buffer_construct_with_capacity(storage.as_mut_ptr(), 0x200);

            assert_eq!(buffer, storage.as_mut_ptr());
            assert_eq!(
                LAST_CALL,
                Some((
                    buffer,
                    0x200,
                    TEXT_BUFFER_TYPE_MARKER.as_ptr(),
                    core::ptr::null_mut(),
                    0,
                )),
            );
            assert_eq!((*buffer).text, core::ptr::addr_of_mut!(RESERVED_TEXT).cast::<u8>());
            assert_eq!((*buffer).capacity, 0x200);
        }
    }
}
