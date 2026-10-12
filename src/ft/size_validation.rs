//! Size validation shared by the retailOS loaders at 0x0804112c and 0x08041ae4.

use super::arith::ft_round_add_clear_bit16;

/// ft_validate_combined_size — `FUN_08044a9c` @ 0x08044a9c.
/// True extent: 108 bytes (104 instruction bytes and a 4-byte 0x302 literal),
/// ending at the real function boundary 0x08044b08. Verified raw-word calls:
/// one outgoing plain BL, zero predicated BLs; two incoming plain BLs.
///
/// Rejects a null context slot with -50; a null context takes precedence over
/// the remaining null arguments and returns 0x302. Requires non-null record
/// and payload pointers, but never reads payload. Context flag bit 1 at +0x30
/// selects a byte (+1) or unsigned halfword (+2) size at record +0x1c. Clears
/// bit 16 before calling the existing rounding/addition helper, then returns
/// 0x23 iff its unsigned result exceeds context's halfword at +0x1c shifted
/// right once; otherwise returns zero. No arithmetic or error-code deviations.
/// Host pointer slots use native pointers, while opaque record offsets remain
/// fixed target byte offsets; no more specific upstream API identity is assumed.
/// LLVM inlines the existing arithmetic helper in the ARM build and narrows
/// the flags read to a byte; both preserve the required ordinary-memory result.
///
/// # Safety
/// A non-null `context_slot` must contain a readable native pointer. After the
/// null checks, context must permit aligned reads at +0x1c (u16) and +0x30
/// (u32); record must permit a byte or aligned u16 read at +0x1c, as selected
/// by context flags. `payload` is only checked for null and is never accessed.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_validate_combined_size(
    context_slot: *const *const u8,
    record: *const u8,
    payload: *const u8,
    additional_size: u32,
) -> i32 {
    if context_slot.is_null() {
        return -50;
    }
    let context = *context_slot;
    if context.is_null() {
        return 0x302;
    }
    if record.is_null() || payload.is_null() {
        return -50;
    }
    let flags = *context.add(0x30).cast::<u32>();
    let size = if flags & 2 == 0 {
        u32::from(*record.add(0x1c)) + 1
    } else {
        u32::from(*record.add(0x1c).cast::<u16>()) + 2
    } & !0x10000;
    let combined = ft_round_add_clear_bit16(size, additional_size);
    let capacity = u32::from(*context.add(0x1c).cast::<u16>()) >> 1;
    if combined > capacity { 0x23 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::null;

    fn reference(size: u16, wide: bool, additional: u32, capacity: u16) -> i32 {
        let mut left = if wide { u32::from(size).wrapping_add(2) }
                       else { u32::from(size as u8).wrapping_add(1) } & !0x10000;
        let mut right = additional;
        if left % 2 != 0 { left = left.wrapping_add(1) & !0x10000; }
        if right % 2 != 0 { right = right.wrapping_add(1) & !0x10000; }
        let total = left.wrapping_add(right) & !0x10000;
        if total > u32::from(capacity / 2) { 0x23 } else { 0 }
    }

    #[test]
    fn null_checks_preserve_error_precedence() {
        unsafe {
            assert_eq!(ft_validate_combined_size(null(), null(), null(), 0), -50);
            let absent = null();
            assert_eq!(ft_validate_combined_size(&absent, null(), null(), 0), 0x302);
            let context = [0u32; 13];
            let slot = context.as_ptr().cast::<u8>();
            assert_eq!(ft_validate_combined_size(&slot, null(), slot, 0), -50);
            assert_eq!(ft_validate_combined_size(&slot, slot, null(), 0), -50);
        }
    }

    #[test]
    fn widths_wrapping_unsigned_comparison_and_capacity_boundaries() {
        let sizes = [0u16, 1, 2, 253, 254, 255, 256, 0x7fff, 0xfffd, 0xfffe, 0xffff];
        let additions = [0u32, 1, 2, 3, 0x7fff, 0x8000, 0xffff, 0x10000,
                         0x10001, 0x80000000, 0xfffffffe, 0xffffffff];
        for flags in [0u32, 1, 2, 3, 0xfffffffd, 0xffffffff] {
            for size in sizes {
                for additional in additions {
                    for capacity in [0u16, 1, 2, 3, 4, 5, 510, 511, 512, 0xfffe, 0xffff] {
                        let mut context = [0u32; 13];
                        let mut record = [0u32; 8];
                        context[7] = u32::from(capacity);
                        context[12] = flags;
                        record[7] = u32::from(size);
                        let before_context = context;
                        let before_record = record;
                        let slot = context.as_ptr().cast::<u8>();
                        // Non-null but deliberately unreadable: payload is not dereferenced.
                        let payload = core::ptr::without_provenance::<u8>(1);
                        let actual = unsafe {
                            ft_validate_combined_size(&slot, record.as_ptr().cast(), payload, additional)
                        };
                        assert_eq!(actual, reference(size, flags & 2 != 0, additional, capacity),
                                   "flags={flags:#x} size={size:#x} add={additional:#x} capacity={capacity}");
                        assert_eq!(context, before_context);
                        assert_eq!(record, before_record);
                    }
                }
            }
        }
    }
}
