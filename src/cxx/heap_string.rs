//! retailOS's one-word heap string holder — a minimal `char *` wrapper
//! class distinct from both the COW `basic_string` ([`crate::cxx::string`])
//! and the two-word `StringObject` ([`crate::cxx::string_object`]).
//!
//! The object is a single word: the payload pointer, NULL when the holder
//! is empty. The methods live in two clusters — the assign/destruct core @
//! 0x0810b3e4..0x0810b610 and the find/suffix/accessor tail @
//! 0x08297d58..0x08297e98:
//!
//! - destructor @ 0x0810b3e4: frees the payload through `free_wrapper` @
//!   0x080e7970 with caller tag 0x14 (20) and zeroes the word; NULL payload
//!   is a no-op.
//! - assign-from-cstr @ 0x0810b514 / assign-from-buffer @ 0x0810b568:
//!   destroy the old payload, allocate `len + 1`, copy, NUL-terminate.
//! - printf-assign @ 0x0810b5cc: vsnprintf into a 512-byte stack buffer,
//!   then assign-from-cstr.
//! - suffix-assign @ 0x08297df8: clears the word, walks the source holder's
//!   payload to its NUL, clamps the skip count to the length, tail-branches
//!   to assign-from-buffer.
//! - data accessor @ 0x08297e34 — ported here as [`heap_string_data`].
//!
//! Sampled call sites build stack instances for device-info strings
//! (`FUN_081502b0` formats "ImageSpecifications" pixel/row values through
//! the printf-assign and passes the accessor's result to the XML writer @
//! 0x0814f924) and for substring surgery (0x08113358 feeds the result to a
//! search, then dup's it via 0x080e7904).
//!
//! Unlike `StringObject::c_str`, the accessor returns the raw word —
//! including NULL for an empty holder. Callers that need a non-NULL string
//! check themselves.

/// The one-word holder object: `data` is the heap `char` buffer (allocated
/// with caller tag 0x14) or NULL.
#[repr(C)]
pub struct HeapString {
    pub data: *mut u8,
}

/// heap_string_data — original: `FUN_08297e34` @ 0x08297e34 (8 bytes, two
/// words `e5900000 e12fff1e`: `ldr r0,[r0]; bx lr`; the next function — a
/// `mov r0,#1; bx lr` — begins at 0x08297e3c, so the extent is exact;
/// **23 plain `bl` call sites, zero predicated and zero data references**,
/// verified by decoding every ARM `B`/`BL` word and every word equal to the
/// address in `osos.dec`).
///
/// The data accessor of the one-word heap string holder described in the
/// module header: returns the payload pointer unchanged — including NULL
/// for an empty holder (no shared-empty substitution, unlike
/// [`crate::cxx::string_object::string_object_c_str`]). No NULL guard on
/// `this` — the original faults on a NULL `this`, and so does the port. The
/// all-unconditional call sites are consistent with that: callers either
/// hold a live stack instance or tolerate a NULL result.
///
/// Deviation: none. The function has its own text section because the exact
/// `ldr r0,[r0]; bx lr` body occurs 22 times in osos.dec (binary-counted);
/// this keeps the exported hook seam distinct if LLVM performs
/// identical-code folding.
#[cfg_attr(target_os = "none", link_section = ".text.heap_string_data")]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn heap_string_data(this: *const HeapString) -> *mut u8 {
    (*this).data
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns the payload pointer unchanged for a live holder.
    #[test]
    fn returns_payload_word() {
        let mut buf = *b"ImageSpecifications\0";
        let holder = HeapString {
            data: buf.as_mut_ptr(),
        };
        let out = unsafe { heap_string_data(&holder) };
        assert_eq!(out, buf.as_mut_ptr());
        assert_eq!(unsafe { *out }, b'I');
    }

    /// An empty holder (NULL word) yields NULL — no empty-string
    /// substitution, unlike StringObject's c_str.
    #[test]
    fn null_payload_passes_through() {
        let holder = HeapString {
            data: core::ptr::null_mut(),
        };
        assert!(unsafe { heap_string_data(&holder) }.is_null());
    }

    /// The word is returned verbatim: an arbitrary non-string bit pattern
    /// (e.g. a dangling or sentinel pointer a caller installed) comes back
    /// unchanged, and the holder itself is not written.
    #[test]
    fn value_verbatim_and_no_write() {
        let sentinel = 0xdeadbeecusize as *mut u8; // unaligned on purpose
        let holder = HeapString { data: sentinel };
        assert_eq!(unsafe { heap_string_data(&holder) }, sentinel);
        assert_eq!(holder.data, sentinel);
    }
}
