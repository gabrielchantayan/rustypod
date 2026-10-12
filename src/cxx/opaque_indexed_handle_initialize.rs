//! Initialize an opaque indexed handle — retailOS `FUN_0813e624` at load
//! address `0x0813e624` (64 bytes).
//!
//! Raw ARM establishes the exact extent: `push {r2-r6,lr}` opens at
//! `0x0813e624`; `pop {r2-r6,pc}` closes at `0x0813e660`; the next separately
//! linked function opens at `0x0813e664`. Decoding every ARM B/BL-immediate
//! word in `osos.dec` finds six direct callers, all unconditional plain `bl`
//! (`0x081433fc`, `0x0814a950`, `0x081b7630`, `0x0822411c`, `0x0829df58`, and
//! `0x082c8548`); no predicated call reaches this function.
//!
//! The wrapper clears the output pointer and tag byte, obtains an entry from
//! the source's opaque indexed provider at +0x40 using the supplied unsigned
//! index, then writes the result and a zero tag to the five-byte output
//! handle. The provider is a 'liti' ImageLibrary database; lookup calls the
//! canonical `image_library_entry_at` Rust port.
//!
//! Deliberate deviation: host handles use a native-width pointer, placing the
//! tag after it rather than at target byte offset +4; ARM's `repr(C)` layout is
//! exactly the retail five-byte `{u32, u8}` record. Volatile accesses preserve
//! the retail clear-before-lookup and result-copy ordering.

/// Opaque five-byte target handle populated by [`opaque_indexed_handle_initialize`].
#[repr(C)]
pub struct OpaqueIndexedHandle {
    pub entry: *mut u8,
    pub tag: u8,
}

/// Source object whose only recovered field is its indexed provider at +0x40.
#[repr(C)]
pub struct OpaqueIndexedHandleSource {
    _unknown_prefix: [u32; 16],
    pub indexed_provider: *mut u8,
}

/// opaque_indexed_handle_initialize — original: `FUN_0813e624` @ `0x0813e624`
/// (64 bytes; six unconditional direct `bl` call sites).
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_indexed_handle_initialize")]
#[inline(never)]
pub unsafe extern "C" fn opaque_indexed_handle_initialize(
    output: *mut OpaqueIndexedHandle,
    source: *const OpaqueIndexedHandleSource,
    index: u32,
) {
    core::ptr::addr_of_mut!((*output).entry).write_volatile(core::ptr::null_mut());
    core::ptr::addr_of_mut!((*output).tag).write_volatile(0);

    let provider = core::ptr::addr_of!((*source).indexed_provider).read_volatile();
    let entry = crate::app::image_library_entry_at::image_library_entry_at(provider, index)
        as usize as *mut u8;

    core::ptr::addr_of_mut!((*output).entry).write_volatile(entry);
    core::ptr::addr_of_mut!((*output).tag).write_volatile(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_index_replaces_existing_entry_and_clears_tag() {
        let provider = [0x6974_696cu32, 0, 0, 0, 0, 1, 0x5678_9000];
        let source = OpaqueIndexedHandleSource {
            _unknown_prefix: [0; 16],
            indexed_provider: provider.as_ptr() as *mut u8,
        };
        let mut output = OpaqueIndexedHandle {
            entry: 0xdead_beefusize as *mut u8,
            tag: u8::MAX,
        };
        unsafe { opaque_indexed_handle_initialize(&mut output, &source, u32::MAX) };
        assert!(output.entry.is_null());
        assert_eq!(output.tag, 0);
        unsafe { opaque_indexed_handle_initialize(&mut output, &source, 0) };
        assert_eq!(output.entry as usize, 0x5678_9000);
        assert_eq!(output.tag, 0);
    }
}
