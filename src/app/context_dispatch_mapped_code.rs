//! Original FUN_0817e160 @ 0x0817e160; true size 96 bytes, ending at
//! the next push prologue at 0x0817e1c0. Raw A32: five outgoing plain BLs,
//! zero predicated BLs; incoming: one plain BL (0x0817ddf0), one BLNE
//! (0x0817caa0). Final B targets 0x081b0ab4, not part of this function.
//! For state 3/4, map descriptor byte +5 through 0x080bd6cc. Unless that
//! byte is 'k', a nonzero cached byte causes a second cached-byte lookup
//! and mapping; dispatch the selected mapping even if it is zero.
//! Deviations: reuse existing predicate/cached-byte Rust ports. Unported
//! mapping and dispatch retain their verified retailOS addresses on target;
//! host mapping models the verified 100..121 -> 1..22 table, and dispatch
//! is a replaceable seam. No UI-manager payload or register padding is invented.

#[inline(always)]
unsafe fn map_code(code: u32) -> u32 {
    #[cfg(target_os = "none")]
    {
        let call: unsafe extern "C" fn(u32) -> u32 = core::mem::transmute(0x080b_d6ccusize);
        call(code)
    }
    #[cfg(not(target_os = "none"))]
    { if (100..=121).contains(&code) { code - 99 } else { 0 } }
}

pub type MappedCodeDispatch = unsafe extern "C" fn(u32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_dispatch(_code: u32) {
    panic!("mapped-code dispatch at 0x081b0ab4 requires retailOS");
}

/// Host boundary for the unported retailOS dispatch wrapper.
#[cfg(not(target_os = "none"))]
pub static mut MAPPED_CODE_DISPATCH: MappedCodeDispatch = missing_dispatch;

/// # Safety
/// `context` must be readable through word 8. For state 3/4, word 8 must
/// point to a descriptor readable through byte 5; the embedded object at
/// word 1 must satisfy object_cached_byte's contract unless that byte is 'k'.
/// The retailOS dispatch wrapper (or host seam) must be callable.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn context_dispatch_mapped_code(context: *mut u32) {
    if crate::util::value_predicate::byte_is_three_or_four(context.cast()) == 0 { return; }
    let descriptor = context.add(8).read() as usize as *const u8;
    let mut mapped = map_code(descriptor.add(5).read() as u32);
    let descriptor = context.add(8).read() as usize as *const u8;
    if descriptor.add(5).read() != b'k' {
        let object = context.add(1);
        if crate::app::object_cached_byte::object_cached_byte(object) != 0 {
            mapped = map_code(crate::app::object_cached_byte::object_cached_byte(object));
        }
    }
    #[cfg(target_os = "none")]
    {
        let dispatch: MappedCodeDispatch = core::mem::transmute(0x081b_0ab4usize);
        dispatch(mapped);
    }
    #[cfg(not(target_os = "none"))]
    core::ptr::read_volatile(core::ptr::addr_of!(MAPPED_CODE_DISPATCH))(mapped);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};
    static RESULT: AtomicU32 = AtomicU32::new(u32::MAX);
    unsafe extern "C" fn capture(value: u32) { RESULT.store(value, Ordering::SeqCst); }
    #[repr(C)]
    struct Vtable { prefix: [u32; 2], predicate: unsafe extern "C" fn(*mut u32) -> u32 }
    unsafe extern "C" fn predicate(object: *mut u32) -> u32 {
        let calls = object.add(1).read();
        object.add(1).write(calls + 1);
        let cached = object.add(2).read() as usize as *mut u8;
        let value = if calls == 0 { object.add(3).read() } else { object.add(4).read() };
        cached.add(0x54).cast::<u16>().write(value as u16);
        1
    }

    #[test]
    fn state_gate_special_code_and_mutating_cached_lookup() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::CONTEXT_DISPATCH_MAPPED_CODE, 0x1000,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture(module_path!()));
            return;
        };
        unsafe {
            let context = slab.cast::<u32>();
            let descriptor = slab.add(0x100);
            let vtable = slab.add(0x200).cast::<Vtable>();
            let cached = slab.add(0x300);
            vtable.write(Vtable { prefix: [0; 2], predicate });
            let original = MAPPED_CODE_DISPATCH;
            MAPPED_CODE_DISPATCH = capture;
            for state in 0..=255u32 {
                context.write(state);
                context.add(8).write(0); // Inactive states cannot touch the descriptor.
                if state == 3 || state == 4 { continue; }
                RESULT.store(u32::MAX, Ordering::SeqCst);
                context_dispatch_mapped_code(context);
                assert_eq!(RESULT.load(Ordering::SeqCst), u32::MAX);
            }
            for state in [3, 4] {
                for (code, first, second, expected, calls) in [
                    (b'k', 100, 121, 8, 0),
                    (b'd', 0, 121, 1, 1),
                    (b'y', 100, 101, 2, 2),
                    (b'd', 100, 0, 0, 2),
                    (b'd', 100, 255, 0, 2),
                    (0, 0, 121, 0, 1),
                    (255, 100, 121, 22, 2),
                ] {
                    context.write(state);
                    context.add(1).write(vtable as usize as u32);
                    context.add(2).write(0);
                    context.add(3).write(cached as usize as u32);
                    context.add(4).write(first);
                    context.add(5).write(second);
                    context.add(8).write(descriptor as usize as u32);
                    descriptor.add(5).write(code);
                    context_dispatch_mapped_code(context);
                    assert_eq!(RESULT.load(Ordering::SeqCst), expected);
                    assert_eq!(context.add(2).read(), calls);
                }
            }
            MAPPED_CODE_DISPATCH = original;
        }
    }
}
