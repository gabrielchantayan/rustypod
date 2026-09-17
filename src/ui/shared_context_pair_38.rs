//! Accessor for an opaque two-word field in the retailOS shared context.

use crate::ui::object_state::shared_context;

/// Byte offset of the opaque two-word field in the shared context.
const SHARED_CONTEXT_PAIR_OFFSET: usize = 0x38;

/// shared_context_pair_38_or_zero — original: `FUN_08369c10` @ `0x08369c10`
/// (36 bytes; the next function starts at `0x08369c34`).
/// Raw ARM: `str lr,[sp,#-4]!; bl 0x08369bec; cmp r0,#0; movne r1,r0;
/// ldrne r1,[r1,#0x3c]; ldrne r0,[r0,#0x38]; moveq r0,#0; moveq r1,#0;
/// ldr pc,[sp],#4`. Binary decoding verifies four direct inbound `bl` call
/// sites, all unconditional (0x080c60c8, 0x0814fdb8, 0x082d4658, and
/// 0x082d4778); its sole outbound call to [`shared_context`] is unconditional.
/// Fetches the lazily initialized shared context, returning its opaque
/// little-endian two-word field at +0x38 as a `u64`, or zero when the getter
/// returns NULL. The low word occupies `r0` and the high word `r1` in the ARM
/// ABI. Deliberate deviations: host builds use the existing shared-context
/// backing storage; target behavior is otherwise identical.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn shared_context_pair_38_or_zero() -> u64 {
    let context = unsafe { shared_context() };
    if context.is_null() {
        return 0;
    }

    let low = unsafe { context.add(SHARED_CONTEXT_PAIR_OFFSET).cast::<u32>().read() };
    let high = unsafe { context.add(SHARED_CONTEXT_PAIR_OFFSET + 4).cast::<u32>().read() };
    u64::from(low) | (u64::from(high) << 32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::object_state::{host_install_shared_context, SHARED_CONTEXT_TEST_LOCK};

    struct SharedContextReset;

    impl Drop for SharedContextReset {
        fn drop(&mut self) {
            unsafe { host_install_shared_context(core::ptr::null_mut()) };
        }
    }

    #[test]
    fn returns_zero_when_shared_context_is_null() {
        let _guard = SHARED_CONTEXT_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = SharedContextReset;
        unsafe { host_install_shared_context(core::ptr::null_mut()) };

        assert_eq!(unsafe { shared_context_pair_38_or_zero() }, 0);
    }

    #[test]
    fn combines_the_two_context_words_in_arm_register_order() {
        let _guard = SHARED_CONTEXT_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = SharedContextReset;
        let mut context = [0u32; 16];
        context[0x38 / 4] = 0x89ab_cdef;
        context[0x3c / 4] = 0x0123_4567;
        unsafe { host_install_shared_context(context.as_mut_ptr().cast()) };

        assert_eq!(unsafe { shared_context_pair_38_or_zero() }, 0x0123_4567_89ab_cdef);
    }
}
