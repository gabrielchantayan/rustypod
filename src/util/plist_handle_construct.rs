//! Empty property-list handle constructor at load address `0x081676ec`.
//!
//! True extent `[0x081676ec, 0x081676fc)`: 16 bytes, four A32 words.
//! Whole-image decoding verifies two inbound plain BLs (`0x080ab3b8`,
//! `0x081c82f8`), zero predicated BLs, and zero outbound BLs. The next
//! function independently clears only the state byte. Clear the node handle
//! word at +0 and the active/kind byte at +4, preserving padding and all
//! following fields, then return the original object pointer. The document
//! constructor consumes that pointer; array access uses the handle and kind.
//! No behavioral deviations; correct Ghidra's void return. A u32 handle keeps
//! target field offsets on hosts without widening it to a native pointer.

/// # Safety
/// `handle` must be word-aligned and writable for at least five bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn plist_handle_construct(handle: *mut u32) -> *mut u32 {
    unsafe {
        handle.write(0);
        handle.cast::<u8>().add(4).write(0);
    }
    handle
}

#[cfg(test)]
mod tests {
    use super::plist_handle_construct;

    #[test]
    fn clears_handle_and_kind_without_touching_padding_or_neighbors() {
        for node in [0, 1, u32::MAX, 0x089abc00] {
            for kind in [0u8, 1, 2, 0xff] {
                let mut words = [0x13579bdfu32, node, u32::from_ne_bytes([kind, 0x5a, 0xa5, 0xff]), 0x2468ace0];
                let handle = unsafe { words.as_mut_ptr().add(1) };
                assert_eq!(unsafe { plist_handle_construct(handle) }, handle);
                assert_eq!(words, [0x13579bdf, 0, u32::from_ne_bytes([0, 0x5a, 0xa5, 0xff]), 0x2468ace0]);
                assert_eq!(unsafe { plist_handle_construct(handle) }, handle);
                assert_eq!(words, [0x13579bdf, 0, u32::from_ne_bytes([0, 0x5a, 0xa5, 0xff]), 0x2468ace0]);
            }
        }
    }
}
