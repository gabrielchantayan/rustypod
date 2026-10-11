//! NULL-guarded 24-byte clear — `FUN_08058140` @ 0x08058140.
//!
//! True extent [0x08058140, 0x08058150), 16 bytes; the next function
//! begins with PUSH at 0x08058150. Raw-word decoding finds two plain
//! inbound BLs (0x0805ce58, 0x0806d310), zero predicated inbound BLs,
//! and zero outgoing BLs. CMP / MOVNE #24 / BNE bzero / BX LR returns
//! for NULL and otherwise clears exactly 24 bytes through the existing
//! bzero @ 0x0805cfb4. Both callers clear stack argument records.
//!
//! Deliberate deviation: a volatile function-pointer load preserves the
//! callee boundary instead of stock's direct conditional tail branch.
//! The callee's volatile aligned-word/byte writes prevent builtin substitution.

static BZERO: unsafe extern "C" fn(*mut u8, i32) = super::bzero::bzero;

/// Clear 24 bytes at `dst`, or do nothing for NULL.
///
/// # Safety
/// A non-NULL `dst` must point to at least 24 writable bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn null_guarded_zero_24(dst: *mut u8) {
    if !dst.is_null() {
        let clear = core::ptr::read_volatile(core::ptr::addr_of!(BZERO));
        clear(dst, 24);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_is_a_noop() {
        unsafe { null_guarded_zero_24(core::ptr::null_mut()) };
    }

    #[test]
    fn clears_exactly_24_bytes_at_every_alignment() {
        for offset in 4..8 {
            let mut words = [0xa5a5a5a5u32; 10];
            let bytes = unsafe {
                core::slice::from_raw_parts_mut(words.as_mut_ptr().cast::<u8>(), 40)
            };
            let mut expected = [0xa5u8; 40];
            expected[offset..offset + 24].fill(0);
            unsafe { null_guarded_zero_24(bytes.as_mut_ptr().add(offset)) };
            assert_eq!(bytes, &expected, "offset {offset}");
        }
    }
}
