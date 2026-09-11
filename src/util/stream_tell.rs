//! Stream-position query through vtable slot +0x1c — `stream_tell` @
//! 0x0805e6d0.
//!
//! Original: `FUN_0805e6d0` @ 0x0805e6d0 (28 bytes; raw ARM shows the next
//! sibling starts with `cmp r0, #0` at 0x0805e6ec, confirming Ghidra's
//! extent). Decoding every ARM B/BL word in osos.dec finds 10 direct call
//! sites: 10 unconditional `bl`, zero predicated `bl`, and zero plain
//! branches. The wrapper alone checks a NULL handle; its callers rely on
//! that rather than gating their calls.
//!
//! Algorithm (raw ARM): if the handle is NULL, return -5. Otherwise load
//! `object = *handle`, load its vtable, and tail-dispatch slot +0x1c as
//! `tell(object)`, returning that slot's value unchanged. A non-NULL handle
//! whose object pointer or vtable is NULL is dereferenced, just as in the
//! original. Deliberate deviation: the target's 32-bit slot layout is modeled
//! by the named `StreamVtable` fields, which naturally widen on 64-bit hosts.

use super::stream_seek::{StreamObject, STREAM_HANDLE_ERROR};

/// stream_tell — original: `FUN_0805e6d0` @ 0x0805e6d0 (28 bytes; 10
/// unpredicated `bl` call sites, verified by decoding every B/BL word in
/// osos.dec).
///
/// Returns the current position of the stream behind `stream` by tail-calling
/// vtable slot +0x1c. Returns -5 only when `stream` itself is NULL; otherwise
/// the slot's i32 value is returned unchanged.
///
/// # Safety
///
/// A non-NULL `stream` must point to a readable object pointer, and that
/// object must carry a readable vtable with a valid tell slot. The original
/// has no guard on those dereferences, and neither does this port.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.stream_tell")]
pub unsafe extern "C" fn stream_tell(stream: *const *mut StreamObject) -> i32 {
    if stream.is_null() {
        return STREAM_HANDLE_ERROR;
    }
    let object = unsafe { *stream };
    let vtable = unsafe { (*object).vtable };
    unsafe { ((*vtable).tell)(object) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::util::stream_seek::StreamVtable;

    // The recorder is process-global because the vtable slot is a plain
    // `extern "C"` function pointer, exactly like the original's; these
    // tests serialize updates and dispatches through it.
    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    static mut CALLS: u32 = 0;
    static mut SEEN_THIS: usize = 0;
    static mut RESULT: i32 = 0;

    unsafe extern "C" fn unused_seek(_this: *mut StreamObject, _position: i64) -> i32 {
        0
    }

    unsafe extern "C" fn recording_tell(this: *mut StreamObject) -> i32 {
        unsafe {
            CALLS += 1;
            SEEN_THIS = this as usize;
            core::ptr::addr_of!(RESULT).read()
        }
    }

    static TELL_VTABLE: StreamVtable = StreamVtable {
        slots_00_0c: [0; 4],
        read_10: 0,
        seek: unused_seek,
        opaque_18: 0,
        tell: recording_tell,
    };

    fn fixture(result: i32) -> (parking_lot::MutexGuard<'static, ()>, StreamObject) {
        let lock = TEST_LOCK.lock();
        unsafe {
            core::ptr::addr_of_mut!(CALLS).write(0);
            core::ptr::addr_of_mut!(SEEN_THIS).write(0);
            core::ptr::addr_of_mut!(RESULT).write(result);
        }
        (lock, StreamObject { vtable: &TELL_VTABLE })
    }

    #[test]
    fn null_handle_returns_minus_five_without_dispatching() {
        let (_lock, _object) = fixture(0);

        assert_eq!(unsafe { stream_tell(core::ptr::null()) }, -5);
        assert_eq!(unsafe { core::ptr::addr_of!(CALLS).read() }, 0);
    }

    #[test]
    fn slot_seven_receives_the_object_pointer() {
        let (_lock, mut object) = fixture(0x1234_5678);
        let handle: *mut StreamObject = &mut object;

        assert_eq!(unsafe { stream_tell(&handle) }, 0x1234_5678);
        assert_eq!(unsafe { core::ptr::addr_of!(CALLS).read() }, 1);
        assert_eq!(
            unsafe { core::ptr::addr_of!(SEEN_THIS).read() },
            handle as usize,
            "r0 at the bxne is *handle, the stream object"
        );
    }

    #[test]
    fn slot_result_is_not_normalized() {
        for result in [0, 1, -5, i32::MIN, i32::MAX] {
            let (_lock, mut object) = fixture(result);
            let handle: *mut StreamObject = &mut object;

            assert_eq!(unsafe { stream_tell(&handle) }, result, "result {result}");
            assert_eq!(unsafe { core::ptr::addr_of!(CALLS).read() }, 1);
        }
    }

    #[test]
    fn tell_slot_is_at_target_offset() {
        assert_eq!(
            core::mem::offset_of!(StreamVtable, tell),
            7 * core::mem::size_of::<usize>(),
            "structural slot position after slots +0x00..+0x18"
        );
        #[cfg(target_pointer_width = "32")]
        assert_eq!(core::mem::offset_of!(StreamVtable, tell), 0x1c);
    }
}
