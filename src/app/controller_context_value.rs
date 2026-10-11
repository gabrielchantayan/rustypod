//! Controller context value — `FUN_08053820` @ `0x08053820`.
//!
//! True extent: 12 bytes, `0x08053820..0x0805382c`, ending in `bx lr`
//! before the next function's `cmp r1,#3`. Raw aligned A32 decoding finds
//! two plain inbound BLs (0x08172dc8, 0x08172ddc), zero predicated inbound
//! BLs, and zero outgoing calls. Load the controller's context pointer at
//! +0xf00, then return its aligned u32 at +0xafc. The caller caches the
//! low byte and dispatches notifications; finer value semantics are unknown.
//! Deliberate deviations: none; stored pointers remain four-byte words on
//! hosts, and neither pointer is NULL-guarded.

/// Returns the context word used by the controller's notification consumer.
///
/// # Safety
/// `controller` must be aligned and readable at +0xf00. That u32 must
/// encode a valid aligned context pointer readable at +0xafc.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn controller_context_value(controller: *const u32) -> u32 {
    let context = unsafe { controller.add(0xf00 / 4).read() };
    unsafe { (context as usize as *const u32).add(0xafc / 4).read() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn follows_current_context_and_preserves_full_word_without_writes() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::CONTROLLER_CONTEXT_VALUE, 8192,
        ) else {
            crate::testing::note_missing_u32_fixture("app::controller_context_value");
            return;
        };
        let mut controller = [0xa5a5_a5a5u32; 0xf08 / 4];
        unsafe {
            let contexts = core::slice::from_raw_parts_mut(slab.cast::<u32>(), 8192 / 4);
            contexts.fill(0x5a5a_5a5a);
            for (index, value) in [0, 1, 0xff, 0x100, 0x8000_0001, u32::MAX].into_iter().enumerate() {
                let context_index = (index % 2) * (4096 / 4);
                contexts[context_index + 0xafc / 4] = value;
                controller[0xf00 / 4] = slab.add(context_index * 4) as usize as u32;
                let controller_before = controller;
                let contexts_before = contexts.to_vec();
                assert_eq!(controller_context_value(controller.as_ptr()), value);
                assert_eq!(controller, controller_before);
                assert_eq!(contexts, contexts_before.as_slice());
            }
        }
    }
}
