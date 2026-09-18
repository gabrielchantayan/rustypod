//! MOV inline-descriptor payload locator — original: `FUN_0814d2f4` @
//! **0x0814d2f4** (16 bytes, `0x0814d2f4..0x0814d304`; four
//! instructions, no literal pool). The next separately linked function starts
//! at `0x0814d304` with `mov r0, #0`. Whole-image A32 decoding finds four
//! incoming plain unconditional `bl` calls (`0x081e3388`, `0x08206160`,
//! `0x0820a230`, and `0x0821c100`) and zero incoming predicated `bl` calls.
//!
//! Stores the address of the three-word inline descriptor payload, immediately
//! after its leading type word, through `payload_out`, then returns status zero.
//! Callers copy or pass the resulting payload as three u32 words. Deliberate
//! deviations: none.

/// Locate a MOV inline descriptor's payload after its leading type word.
///
/// # Safety
///
/// `payload_out` must point to one writable, aligned target-width word. The
/// descriptor address is not dereferenced.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.mov_inline_descriptor_payload")]
pub unsafe extern "C" fn mov_inline_descriptor_payload(
    descriptor: u32,
    payload_out: *mut u32,
) -> u32 {
    unsafe { core::ptr::write_volatile(payload_out, descriptor.wrapping_add(4)) };
    0
}

#[cfg(test)]
mod tests {
    use super::mov_inline_descriptor_payload;

    #[test]
    fn returns_success_and_advances_only_the_payload_output_word() {
        let mut output = [0xdead_beefu32, 0x0123_4567, 0x89ab_cdef];

        let status = unsafe { mov_inline_descriptor_payload(0x0800_1000, unsafe { output.as_mut_ptr().add(1) }) };

        assert_eq!(status, 0);
        assert_eq!(output, [0xdead_beef, 0x0800_1004, 0x89ab_cdef]);
    }

    #[test]
    fn wraps_the_target_address_at_u32_boundary() {
        let mut payload = 0;

        let status = unsafe { mov_inline_descriptor_payload(0xffff_fffc, &mut payload) };

        assert_eq!(status, 0);
        assert_eq!(payload, 0);
    }
}
