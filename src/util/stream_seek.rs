//! Absolute stream seek through vtable slot +0x14 — `stream_seek` @
//! 0x0805e79c.
//!
//! Original: `FUN_0805e79c` @ 0x0805e79c (64 bytes; extent verified from
//! the raw words in osos.dec — the next function opens with
//! `push {r4-r8, lr}` at 0x0805e7dc, exactly where this function's
//! `pop {ip, pc}` lands, so Ghidra's 64-byte size is correct). 15 `bl`
//! call sites, all unpredicated and zero predicated forms, counted by
//! decoding every B/BL word in osos.dec; the wrapper's own NULL guard on
//! the handle is the only guard, so callers never check first.
//!
//! Algorithm (raw ARM):
//!
//! ```text
//! 0805e79c  cmp  r0, #0           @ handle == NULL?
//! 0805e7a0  push {r3, lr}
//! 0805e7a4  beq  0x0805e7d4       @   -> return -5
//! 0805e7a8  mov  r3, #0
//! 0805e7ac  str  r3, [sp]         @ dead store: the slot is only
//!                                 @ re-popped into ip at the tail
//! 0805e7b0  ldr  r0, [r0]         @ object = *handle
//! 0805e7b4  mov  r2, r1           @ \
//! 0805e7b8  asr  ip, r1, #31      @  } r2:r3 = (s64)offset
//! 0805e7bc  ldr  r1, [r0]         @ vtable = *object      |
//! 0805e7c0  mov  r3, ip           @ /
//! 0805e7c4  ldr  r1, [r1, #0x14]  @ slot +0x14
//! 0805e7c8  blx  r1               @ seek(object, position)
//! 0805e7cc  cmp  r0, #0
//! 0805e7d0  beq  0x0805e7d8       @ status == 0 -> return 0
//! 0805e7d4  mvn  r0, #4           @ r0 = -5
//! 0805e7d8  pop  {ip, pc}
//! ```
//!
//! `stream` is a handle: a pointer to the stream object pointer. The ported
//! `stream_read_core` @ 0x0805e754 dispatches slot +0x10, while this wrapper
//! dispatches slot +0x14 and the tell wrapper @ 0x0805e6d0 dispatches slot
//! +0x1c; all use the same double-dereference convention.
//! The offset arrives as a 32-bit word and is sign-extended
//! into the r2:r3 pair, so the slot receives an absolute signed 64-bit
//! position; r1 at the `blx` is leftover scratch (the loaded slot pointer
//! itself), never a real argument. Callers in the 0x080570cc-0x08057874
//! record-walking cluster seek with `stream_tell(stream) + delta`
//! idioms, and `FUN_080a69cc` rewinds with `stream_seek(stream, 0)`.
//!
//! Result normalization: 0 when the slot reports success, -5
//! (0xfffffffb) when the handle is NULL or the slot returns any nonzero
//! status — the underlying status is discarded, exactly like the -5 the
//! tell wrapper returns for a NULL handle.
//!
//! Deliberate deviations: the dead `str r3, [sp]` is not reproduced (it
//! only re-materializes as the discarded ip at `pop {ip, pc}`). Host
//! pointers are wider than the target's 32-bit vtable words, so the
//! modeled vtable widens structurally on 64-bit hosts while the filler
//! keeps slot +0x14 at its target byte offset on device. The slot target
//! is runtime vtable data and is dispatched through the object's own
//! vtable, so no dispatch seam is needed (the `app/class_8900.rs`
//! precedent).

/// The result returned by these stream-handle wrappers for a NULL handle
/// (the original's `mvn r0, #4`).
pub const STREAM_HANDLE_ERROR: i32 = -5;

/// A stream object, as seen through the read, seek, and tell wrappers: only
/// its vtable word is decoded.
#[repr(C)]
pub struct StreamObject {
    /// +0x00: the stream's vtable.
    pub vtable: *const StreamVtable,
}

/// The stream vtable, modeled down to the slots the seek and tell wrappers
/// dispatch.
///
/// Named fields preserve the target's 32-bit slot layout without literal
/// byte offsets; each word widens naturally on a 64-bit host.
#[repr(C)]
pub struct StreamVtable {
    /// Slots +0x00..+0x0c, not dispatched by this wrapper.
    pub slots_00_0c: [usize; 4],
    /// Slot +0x10: stream read, `(this, buf, len, mode) -> raw result`.
    pub read_10: unsafe extern "C" fn(
        this: *mut StreamObject,
        buf: *mut u8,
        len: u32,
        mode: u32,
    ) -> i32,
    /// Slot +0x14: absolute seek, `(this, position) -> status`,
    /// status 0 on success. `position` rides in r2:r3 on the target,
    /// matching this `i64` parameter's AAPCS placement.
    pub seek: unsafe extern "C" fn(this: *mut StreamObject, position: i64) -> i32,
    /// Slot +0x18, not dispatched by either wrapper.
    pub opaque_18: usize,
    /// Slot +0x1c: current absolute position, `(this) -> position`.
    pub tell: unsafe extern "C" fn(this: *mut StreamObject) -> i32,
}

/// stream_seek — original: `FUN_0805e79c` @ 0x0805e79c (64 bytes;
/// 15 `bl` call sites, all unpredicated, counted by decoding every B/BL
/// word in osos.dec).
///
/// Seeks the stream behind `stream` (a pointer to the object pointer) to
/// the absolute position `offset`, sign-extended to 64 bits, through
/// vtable slot +0x14. Returns 0 on success and -5 when `stream` is NULL
/// or the slot returns a nonzero status.
///
/// # Safety
///
/// A non-NULL `stream` must point to a readable object pointer, and the
/// object must carry a readable vtable with a valid slot +0x14 entry;
/// the original has no guard on either dereference, and neither does
/// this port.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.stream_seek")]
pub unsafe extern "C" fn stream_seek(stream: *const *mut StreamObject, offset: i32) -> i32 {
    if stream.is_null() {
        return STREAM_HANDLE_ERROR;
    }
    let object = unsafe { *stream };
    let vtable = unsafe { (*object).vtable };
    let status = unsafe { ((*vtable).seek)(object, i64::from(offset)) };
    if status == 0 {
        0
    } else {
        STREAM_HANDLE_ERROR
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    // The recorder is process-global because the vtable slot is a plain
    // `extern "C"` function pointer, exactly like the original's; the
    // tests in this module run under one lock.
    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    static mut CALLS: u32 = 0;
    static mut SEEN_THIS: usize = 0;
    static mut SEEN_POSITION: i64 = 0;
    static mut STATUS: i32 = 0;

    unsafe extern "C" fn recording_seek(this: *mut StreamObject, position: i64) -> i32 {
        unsafe {
            CALLS += 1;
            SEEN_THIS = this as usize;
            SEEN_POSITION = position;
            core::ptr::addr_of!(STATUS).read()
        }
    }

    unsafe extern "C" fn unused_read(
        _this: *mut StreamObject,
        _buf: *mut u8,
        _len: u32,
        _mode: u32,
    ) -> i32 {
        0
    }

    unsafe extern "C" fn unused_tell(_this: *mut StreamObject) -> i32 {
        0
    }

    static SEEK_VTABLE: StreamVtable = StreamVtable {
        slots_00_0c: [0; 4],
        read_10: unused_read,
        seek: recording_seek,
        opaque_18: 0,
        tell: unused_tell,
    };

    fn fixture(status: i32) -> (parking_lot::MutexGuard<'static, ()>, StreamObject) {
        let lock = TEST_LOCK.lock();
        unsafe {
            core::ptr::addr_of_mut!(CALLS).write(0);
            core::ptr::addr_of_mut!(SEEN_THIS).write(0);
            core::ptr::addr_of_mut!(SEEN_POSITION).write(0);
            core::ptr::addr_of_mut!(STATUS).write(status);
        }
        (lock, StreamObject { vtable: &SEEK_VTABLE })
    }

    #[test]
    fn null_handle_returns_minus_five_without_dispatching() {
        let (_lock, _object) = fixture(0);
        let result = unsafe { stream_seek(core::ptr::null(), 0) };
        assert_eq!(result, -5);
        assert_eq!(unsafe { core::ptr::addr_of!(CALLS).read() }, 0);
    }

    #[test]
    fn successful_seek_returns_zero_and_passes_object_and_position() {
        let (_lock, mut object) = fixture(0);
        let handle: *mut StreamObject = &mut object;

        let result = unsafe { stream_seek(&handle, 4096) };

        assert_eq!(result, 0);
        assert_eq!(unsafe { core::ptr::addr_of!(CALLS).read() }, 1);
        assert_eq!(
            unsafe { core::ptr::addr_of!(SEEN_THIS).read() },
            handle as usize,
            "r0 at the blx is *handle, the stream object"
        );
        assert_eq!(unsafe { core::ptr::addr_of!(SEEN_POSITION).read() }, 4096);
    }

    #[test]
    fn offset_is_sign_extended_to_64_bits() {
        let (_lock, mut object) = fixture(0);
        let handle: *mut StreamObject = &mut object;

        let result = unsafe { stream_seek(&handle, -8) };
        assert_eq!(result, 0);
        assert_eq!(
            unsafe { core::ptr::addr_of!(SEEN_POSITION).read() },
            -8i64,
            "the original's asr #31 splats the sign into the high word"
        );

        let result = unsafe { stream_seek(&handle, i32::MIN) };
        assert_eq!(result, 0);
        assert_eq!(
            unsafe { core::ptr::addr_of!(SEEN_POSITION).read() },
            i64::from(i32::MIN)
        );
    }

    #[test]
    fn any_nonzero_slot_status_becomes_minus_five() {
        for status in [1, -3, i32::MAX, i32::MIN] {
            let (_lock, mut object) = fixture(status);
            let handle: *mut StreamObject = &mut object;

            let result = unsafe { stream_seek(&handle, 0) };

            assert_eq!(result, -5, "status {status} is collapsed to -5");
            assert_eq!(unsafe { core::ptr::addr_of!(CALLS).read() }, 1);
        }
    }

    #[test]
    fn slot_five_is_dispatched_at_target_byte_offset() {
        assert_eq!(
            core::mem::offset_of!(StreamVtable, seek),
            4 * core::mem::size_of::<usize>() + core::mem::size_of::<usize>(),
            "structural slot position after slots +0x00..+0x10"
        );
        #[cfg(target_pointer_width = "32")]
        assert_eq!(core::mem::offset_of!(StreamVtable, seek), 0x14);
    }
}
