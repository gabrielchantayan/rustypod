//! Optional image-format descriptor slots — `FUN_081f0258` @ `0x081f0258`.
//!
//! True extent: 24 bytes, `0x081f0258..0x081f0270`; the next function
//! begins with push {r4-r6,lr}. Whole-image aligned A32 decoding verifies
//! two incoming plain BLs (0x0821af24, 0x0821b234), zero predicated BLs,
//! and zero outgoing calls. Load the context's target-width pointer at
//! +0x30; return zero when absent, otherwise add the 28-byte header size
//! modulo 2^32. Callers index the resulting 36-byte descriptor records.
//! No deliberate behavioral deviations; target addresses remain u32 on hosts.

/// # Safety
/// `context` must be four-byte aligned and readable at word 12 (+0x30).
/// The stored address is not dereferenced or validated.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn image_format_context_slots_get(context: *const u32) -> u32 {
    let base = context.add(12).read();
    if base == 0 { 0 } else { base.wrapping_add(0x1c) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_present_and_wrapping_addresses_preserve_context() {
        for (base, expected) in [
            (0, 0), (1, 0x1d), (0x0800_1000, 0x0800_101c),
            (0xffff_ffe3, u32::MAX), (0xffff_ffe4, 0), (u32::MAX, 0x1b),
        ] {
            let mut context = [0xa5a5_a5a5; 13];
            context[12] = base;
            let before = context;
            assert_eq!(unsafe { image_format_context_slots_get(context.as_ptr()) }, expected);
            assert_eq!(context, before);
        }
    }
}
