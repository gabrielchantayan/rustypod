//! Output-stream sentry preflight.
//!
//! `FUN_083d8468` @ 0x083d8468, 176 bytes through exclusive end
//! 0x083d8518 (next PUSH); executable code ends at 0x083d850c, followed
//! by three literals. Raw whole-image decoding finds one inbound plain BL
//! at 0x083d8400, no predicated inbound BLs; body: three plain BLs, one
//! BLNE, and one indirect BLX through stream-buffer vtable byte slot +0x10.
//!
//! Flush the tied stream when present. When C/C++ stream synchronization is
//! enabled, flush the primary FILE for the active object, otherwise the
//! secondary FILE for an object recognized by 0x083d6ec4. Reload the adjusted
//! object's buffer after these calls; if its mode bit 0 is set, call virtual
//! slot +0x10 with an eight-byte result area, offset zero and direction two.
//! Return the original receiver. The virtual result is intentionally ignored.
//!
//! Deviations: incidental saved r1/r2/r3 values are not part of the pointer
//! return ABI; host builds substitute the firmware-only preflight dependencies
//! and use native-width virtual slots, retaining target-width object words.

#[cfg(target_os = "none")]
unsafe fn tied_flush(stream: *mut u32) {
    super::ostream_flush::ostream_flush(stream.cast());
}
#[cfg(target_os = "none")]
unsafe fn synchronized() -> bool { (0x08a0fbc8 as *const u8).read_volatile() != 0 }
#[cfg(target_os = "none")]
unsafe fn primary(stream: *mut u32) -> bool {
    super::object_matches_active_context::object_matches_active_context(stream)
}
#[cfg(target_os = "none")]
unsafe fn secondary(stream: *mut u32) -> bool {
    super::secondary_standard_stream_subobject::secondary_standard_stream_subobject(stream.cast()) != 0
}
#[cfg(target_os = "none")]
unsafe fn flush(file: usize) {
    crate::stdio::stdio_init::fflush(file as *mut _);
}

#[cfg(not(target_os = "none"))]
pub(crate) struct HostOps {
    pub(crate) tied: unsafe fn(*mut u32),
    pub(crate) enabled: unsafe fn() -> bool,
    pub(crate) primary: unsafe fn(*mut u32) -> bool,
    pub(crate) secondary: unsafe fn(*mut u32) -> bool,
    pub(crate) flush: unsafe fn(usize),
}
#[cfg(not(target_os = "none"))]
pub(crate) static mut HOST_OPS: HostOps = HostOps {
    tied: |_| panic!("firmware tied-stream flush unavailable"),
    enabled: || panic!("firmware stream synchronization unavailable"),
    primary: |_| panic!("firmware active context unavailable"),
    secondary: |_| panic!("firmware secondary context unavailable"),
    flush: |_| panic!("firmware FILE unavailable"),
};
#[cfg(not(target_os = "none"))]
unsafe fn tied_flush(stream: *mut u32) { (HOST_OPS.tied)(stream); }
#[cfg(not(target_os = "none"))]
unsafe fn synchronized() -> bool { (HOST_OPS.enabled)() }
#[cfg(not(target_os = "none"))]
unsafe fn primary(stream: *mut u32) -> bool { (HOST_OPS.primary)(stream) }
#[cfg(not(target_os = "none"))]
unsafe fn secondary(stream: *mut u32) -> bool { (HOST_OPS.secondary)(stream) }
#[cfg(not(target_os = "none"))]
unsafe fn flush(file: usize) { (HOST_OPS.flush)(file); }

unsafe fn owner(stream: *mut u32) -> *mut u32 {
    let adjustment = (stream.read() as usize as *const i32).sub(3).read();
    stream.cast::<u8>().wrapping_offset(adjustment as isize).cast()
}

/// # Safety
/// The receiver and adjusted basic_ios must be valid aligned target-layout
/// objects, including the vtable's signed adjustment at -12. Nonzero tied
/// streams, buffers, and virtual callbacks must be valid firmware objects.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ostream_prepare_output(stream: *mut u32) -> *mut u32 {
    let tied = owner(stream).add(14).read();
    if tied != 0 { tied_flush(tied as usize as *mut u32); }
    if synchronized() {
        if primary(stream) { flush(0x08b2f864); }
        else if secondary(stream) { flush(0x08b2f8a8); }
    }
    let buffer = owner(stream).add(13).read() as usize as *mut u32;
    if !buffer.is_null() && buffer.add(1).read() & 1 != 0 {
        type Seek = unsafe extern "C" fn(*mut [u32; 2], *mut u32, i32, u32);
        let table = buffer.read() as usize as *const Seek;
        let mut result = core::mem::MaybeUninit::<[u32; 2]>::uninit();
        table.add(4).read()(result.as_mut_ptr(), buffer, 0, 2);
    }
    stream
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering::SeqCst};
    static MODE: AtomicU32 = AtomicU32::new(0);
    unsafe fn enabled() -> bool { MODE.load(SeqCst) & 1 != 0 }
    unsafe fn active(_: *mut u32) -> bool { MODE.load(SeqCst) & 2 != 0 }
    unsafe fn other(_: *mut u32) -> bool {
        assert_eq!(MODE.load(SeqCst) & 2, 0, "primary must short-circuit");
        MODE.load(SeqCst) & 4 != 0
    }
    unsafe fn sync(file: usize) {
        let receiver = FIXTURE as *mut u32;
        owner(receiver).add(12).write(file as u32);
    }
    static mut FIXTURE: usize = 0;
    unsafe fn tied(stream: *mut u32) {
        // The tied flush replaces the original buffer, proving the reload.
        let receiver = FIXTURE as *mut u32;
        assert_eq!(stream, receiver.add(40));
        owner(receiver).add(13).write(receiver.add(48) as usize as u32);
    }
    unsafe extern "C" fn seek(result: *mut [u32; 2], buffer: *mut u32, offset: i32, direction: u32) {
        assert_eq!((offset, direction), (0, 2));
        buffer.add(2).write(buffer.add(2).read() + 1);
        result.write([0xffffffff, 0xffffffff]);
    }
    #[test]
    fn synchronization_priority_optional_buffer_and_tied_replacement() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::OSTREAM_PREPARE_OUTPUT, 4096,
        ) else { return; };
        unsafe {
            let saved = core::ptr::read(core::ptr::addr_of!(HOST_OPS));
            HOST_OPS = HostOps { tied, enabled, primary: active, secondary: other, flush: sync };
            let receiver = slab.add(128).cast::<u32>();
            FIXTURE = receiver as usize;
            let prefix = slab.cast::<i32>();
            prefix.write(16); // positive basic_ios adjustment
            receiver.write(prefix.add(3) as usize as u32);
            let fields = receiver.add(4);
            let table = slab.add(512).cast::<unsafe extern "C" fn(*mut [u32; 2], *mut u32, i32, u32)>();
            table.add(4).write(seek);
            for mode in 0..8 {
                MODE.store(mode, SeqCst);
                for flags in [0, 1, 2, 0x80000001] {
                    for has_tie in [false, true] {
                        for has_buffer in [false, true] {
                            let buffer = receiver.add(48);
                            buffer.write(table as usize as u32);
                            buffer.add(1).write(flags);
                            buffer.add(2).write(0);
                            fields.add(12).write(0);
                            fields.add(13).write(if has_buffer { buffer as usize as u32 } else { 0 });
                            fields.add(14).write(if has_tie { receiver.add(40) as usize as u32 } else { 0 });
                            assert_eq!(ostream_prepare_output(receiver), receiver);
                            let expected_file = if mode & 1 == 0 { 0 }
                                else if mode & 2 != 0 { 0x08b2f864 }
                                else if mode & 4 != 0 { 0x08b2f8a8 } else { 0 };
                            assert_eq!(fields.add(12).read(), expected_file);
                            assert_eq!(buffer.add(2).read(), u32::from((has_buffer || has_tie) && flags & 1 != 0));
                        }
                    }
                }
            }
            core::ptr::write(core::ptr::addr_of_mut!(HOST_OPS), saved);
        }
    }
}
