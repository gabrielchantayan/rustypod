//! MOV dispatch-context initializer — original: `FUN_0814d310` @
//! **0x0814d310** (12 bytes, `0x0814d310..0x0814d31c`; three instructions).
//! The next separately linked function starts at `0x0814d31c`, a literal-pool
//! word holding the dispatch-table address `0x08986874`. Full-image ARM branch
//! decoding finds four direct plain unconditional `bl` callers (`0x0820a0f8`,
//! `0x0820a13c`, `0x0821bf50`, and `0x0821c0d0`) and zero predicated forms.
//!
//! Stores the MOV parser dispatch-table word into the context's first target
//! word. Callers subsequently dispatch through the resulting object at vtable
//! offset `+0x24`; its concrete C++ class is not yet recovered. The raw body
//! leaves `r0` unchanged, so this port returns `context` despite Ghidra's void
//! signature. No deliberate deviations.

/// Initialize a MOV parser dispatch context's vtable word.
///
/// # Safety
///
/// `context` must point to one writable, aligned target-width word.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.mov_dispatch_context_init")]
pub unsafe extern "C" fn mov_dispatch_context_init(context: *mut u32) -> *mut u32 {
    unsafe { core::ptr::write_volatile(context, 0x0898_6874) };
    context
}

#[cfg(test)]
mod tests {
    use super::mov_dispatch_context_init;

    #[test]
    fn initializes_only_the_dispatch_word_and_returns_context() {
        let mut context = [0xdead_beefu32, 0x0123_4567, 0x89ab_cdef, 0xfedc_ba98];
        let pointer = context.as_mut_ptr();

        let returned = unsafe { mov_dispatch_context_init(pointer) };

        assert_eq!(returned, pointer);
        assert_eq!(context, [0x0898_6874, 0x0123_4567, 0x89ab_cdef, 0xfedc_ba98]);
    }
}
