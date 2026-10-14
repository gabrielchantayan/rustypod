//! Output-stream sentry constructor — `FUN_083d83e0` @ **0x083d83e0**.
//!
//! True size: 72 bytes, [0x083d83e0, 0x083d8428), ending immediately
//! before the separately linked sentry cleanup. Raw A32 decoding verifies
//! one plain outgoing BL to ostream_prepare_output (0x083d8468), zero
//! predicated BLs; one plain inbound BL at 0x083b5368, zero predicated BLs.
//!
//! Read the adjusted streambuf word, store the stream in sentry word zero,
//! run output preflight, then reload the returned stream's signed vtable
//! adjustment and state at basic_ios+0x10. Write byte +4 as state == 0 and
//! return the sentry. Bytes +5 onward remain untouched. The overwritten
//! initial streambuf read is retained with volatile access. No target
//! deviations; tests substitute preflight to exercise its state mutations.

unsafe fn owner(stream: *mut u32) -> *mut u32 {
    let adjustment = (stream.read() as usize as *const i32).sub(3).read();
    stream.cast::<u8>().wrapping_offset(adjustment as isize).cast()
}

#[cfg(test)]
static mut PREPARE: unsafe fn(*mut u32) -> *mut u32 = |_| panic!("preflight not installed");

/// # Safety
/// `sentry` must provide an aligned writable word and byte +4, and `stream`
/// must satisfy ostream_prepare_output's requirements. Its signed vtable
/// adjustment at -12 must select readable basic_ios words +0x10 and +0x34,
/// both before and after preflight. Storage must not invalidate the stream.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ostream_sentry_construct(sentry: *mut u32, stream: *mut u32) -> *mut u32 {
    let _ = owner(stream).add(13).read_volatile();
    sentry.write(stream as usize as u32);
    #[cfg(not(test))]
    let prepared = super::ostream_prepare_output::ostream_prepare_output(stream);
    #[cfg(test)]
    let prepared = PREPARE(stream);
    let state = owner(prepared).add(4).read();
    sentry.cast::<u8>().add(4).write(u8::from(state == 0));
    sentry
}

#[cfg(test)]
mod tests {
    use super::*;
    static mut SENTRY: *mut u32 = core::ptr::null_mut();
    static mut STATE: u32 = 0;
    static mut ADJUSTMENT: i32 = 0;

    unsafe fn prepare(stream: *mut u32) -> *mut u32 {
        assert_eq!(SENTRY.read(), stream as usize as u32);
        assert_eq!(SENTRY.add(1).read(), 0xa5a5_a5a5);
        // Change the virtual-base adjustment and state during preflight.
        let table = stream.read() as usize as *mut i32;
        table.sub(3).write(ADJUSTMENT);
        owner(stream).add(4).write(STATE);
        stream
    }

    #[test]
    fn post_preflight_state_signed_adjustment_and_byte_only_store() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::OSTREAM_SENTRY_CONSTRUCT, 4096,
        ) else { return; };
        unsafe {
            PREPARE = prepare;
            let stream = slab.add(256).cast::<u32>();
            let table = slab.cast::<i32>();
            stream.write(table.add(3) as usize as u32);
            SENTRY = slab.add(512).cast();
            for adjustment in [-64, 0, 64] {
                for state in [0, 1, 2, 0x100, 0x8000_0000, u32::MAX] {
                    table.write(0);
                    stream.add(13).write(0xdead_beef);
                    stream.add(4).write(if state == 0 { 1 } else { 0 });
                    SENTRY.write(0);
                    SENTRY.add(1).write(0xa5a5_a5a5);
                    SENTRY.add(2).write(0x1234_5678);
                    STATE = state;
                    ADJUSTMENT = adjustment;
                    assert_eq!(ostream_sentry_construct(SENTRY, stream), SENTRY);
                    assert_eq!(SENTRY.read(), stream as usize as u32);
                    assert_eq!(SENTRY.add(1).read(), 0xa5a5_a500 | u32::from(state == 0));
                    assert_eq!(SENTRY.add(2).read(), 0x1234_5678);
                    assert_eq!(owner(stream).add(4).read(), state);
                }
            }
        }
    }
}
