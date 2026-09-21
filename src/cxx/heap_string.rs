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
//! - printf-assign @ 0x0810b5cc — ported here as
//!   [`heap_string_format`]: vsnprintf into a 512-byte stack buffer, then
//!   passes the completed C string to the stock assign-from-cstr method.
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

use core::mem::MaybeUninit;

use crate::cxx::string_object::retail_vsnprintf;
use crate::heap::veneers::{free_wrapper, realloc_wrapper};
use crate::libc::strlen_safe::strlen_safe;
use crate::printf::printf_api::VaList;

/// The one-word holder object: `data` is the heap `char` buffer (allocated
/// with caller tag 0x14) or NULL.
#[repr(C)]
pub struct HeapString {
    pub data: *mut u8,
}

/// The caller tag `heap_string_destroy` passes to `free_wrapper`
/// (`mov r1, #0x14` @ 0x0810b3f8).
const HEAP_STRING_PAYLOAD_FREE_TAG: usize = 0x14;

/// heap_string_destroy — original: `FUN_0810b3e4` @ 0x0810b3e4 (40 bytes,
/// words `e92d4010 e1a04000 e5900000 e3500000 08bd8010 e3a01014
/// ebff715b e3a00000 e5840000 e8bd8010`). The sibling at 0x0810b40c opens
/// with `cmp r0,#0`, confirming the complete extent. **19 plain `bl` call
/// sites and zero predicated `bl` forms**, verified by decoding every ARM
/// `B`/`BL` word in `osos.dec`; two predicated tail `b` references (`beq`
/// @ 0x0810b530 and `ble` @ 0x0810b584) are its only non-`bl` branch
/// references. No image word equals 0x0810b3e4, so it has no data/virtual
/// dispatch reference.
///
/// Releases the one-word holder's non-NULL payload through
/// [`free_wrapper`] with caller tag 0x14, then clears the word. A NULL
/// payload takes the raw `popeq {r4,pc}` early return and makes no heap call.
/// There is no NULL guard on `this`: the original's first load faults, as
/// does this port.
///
/// Deviation: Rust expresses the conditional return as `if`; the already
/// ported [`free_wrapper`] dispatches through `HEAP_OPS` rather than the
/// retail image's direct heap path.
#[cfg_attr(target_os = "none", link_section = ".text.heap_string_destroy")]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn heap_string_destroy(this: *mut HeapString) {
    let payload = (*this).data;
    if payload.is_null() {
        return;
    }
    free_wrapper(payload, HEAP_STRING_PAYLOAD_FREE_TAG);
    (*this).data = core::ptr::null_mut();
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

/// The raw `mov r1,#512` bound in `heap_string_format`.
const HEAP_STRING_FORMAT_BUFFER_LEN: usize = 512;

/// heap_string_assign_from_cstr — original: `FUN_0810b514` @ 0x0810b514
/// (84 bytes; **5 plain `bl` call sites, zero predicated forms**, binary-
/// scanned: 0x0809e724, 0x081132c4, 0x081132d0, 0x08113874, 0x081a3634).
/// The next real function begins with `push {r4-r6,lr}` at 0x0810b568,
/// confirming the complete extent.
///
/// Replaces the holder's payload from a C string. A NULL source or an empty
/// source tail-calls [`heap_string_destroy`]. Otherwise it obtains
/// `strlen_safe(source) + 1`, reallocates the current payload through the
/// known `realloc_wrapper` @ 0x080edbf0 with `(tag = 0x14, a4 = 0)`, then
/// copies exactly that many bytes, including the NUL, when allocation succeeds.
/// `this` is never NULL-guarded.
///
/// Deliberate deviations: the tail call becomes a normal Rust call, and
/// `realloc_wrapper` dispatches through `HEAP_OPS` so host tests can observe
/// the otherwise direct retail heap path.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn heap_string_assign_from_cstr(this: *mut HeapString, source: *const u8) {
    if source.is_null() || source.read() == 0 {
        heap_string_destroy(this);
        return;
    }

    let len = strlen_safe(source) + 1;
    let data = realloc_wrapper((*this).data, len, HEAP_STRING_PAYLOAD_FREE_TAG, 0);
    (*this).data = data;
    if !data.is_null() {
        core::ptr::copy_nonoverlapping(source, data, len);
    }
}

/// heap_string_format — original: `FUN_0810b5cc` @ 0x0810b5cc (68 bytes,
/// all code; **20 plain `bl` call sites, zero predicated forms, zero plain
/// `b`, and zero data-word references**, verified by decoding every ARM
/// `B`/`BL` word and every word equal to the address in `osos.dec`).
///
/// The one-word holder's printf-style assignment. Raw ARM spills its incoming
/// registers for the variadic ABI, reserves a 512-byte scratch region at
/// `sp + 4`, then invokes `retail_vsnprintf(scratch, 512, format, args)`.
/// It preserves that formatter result across the stock
/// `assign_from_cstr(this, scratch)` call and returns the result unchanged.
/// The stock assignment owns replacement allocation and copying; the scratch
/// remains caller-owned stack storage. There is no NULL guard on `this` or
/// `format`: the formatter/assignment paths retain retailOS's faulting
/// behavior for invalid inputs. All direct callers are unconditional, which
/// is consistent with live stack holders and supplied format strings.
///
/// Deviation: stable Rust receives the variadic spill as explicit [`VaList`],
/// the crate convention for printf-style retail methods. The assignment is the
/// ported [`heap_string_assign_from_cstr`] method.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn heap_string_format(
    this: *mut HeapString,
    format: *const u8,
    args: VaList,
) -> i32 {
    let mut scratch = MaybeUninit::<[u8; HEAP_STRING_FORMAT_BUFFER_LEN]>::uninit();
    let scratch = scratch.as_mut_ptr() as *mut u8;
    let length = retail_vsnprintf(scratch, HEAP_STRING_FORMAT_BUFFER_LEN, format, args);
    heap_string_assign_from_cstr(this, scratch);
    length
}

/// heap_string_construct_from_cstr — original: `FUN_0810b634` @ 0x0810b634
/// (32 bytes, words `e92d4010 e1a04000 e3a00000 e5840000 e1a00004 ebffffb1
/// e1a00004 e8bd8010`). The next real function starts at 0x0810b654 with
/// `stmdb sp!,{r4,lr}`, confirming the extent. **5 plain `bl` call sites and
/// zero predicated `bl` forms**, independently verified by decoding every ARM
/// branch word in `osos.dec`; all five target this entry directly.
///
/// Initializes the one-word holder to NULL, then delegates the supplied C
/// string to stock `HeapString::assign_from_cstr` @ 0x0810b514. It returns
/// `this` after the assignment, even if the stock allocator leaves it empty.
/// There is no NULL guard: the initial store faults exactly as retailOS does.
///
/// Deviation: delegates to the ported assignment method rather than the
/// original direct branch.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn heap_string_construct_from_cstr(
    this: *mut HeapString,
    source: *const u8,
) -> *mut HeapString {
    (*this).data = core::ptr::null_mut();
    heap_string_assign_from_cstr(this, source);
    this
}



/// heap_string_assign_suffix — original: `FUN_08297df8` @ 0x08297df8
/// (60 bytes, 0x08297df8..0x08297e30). The next independently entered
/// function begins at 0x08297e34 with `ldr r0,[r0]; bx lr`; Ghidra's
/// 160-byte extent absorbs this accessor and later code. **Three inbound
/// plain `bl` call sites (0x08113324, 0x08113388, 0x081a3628), zero
/// predicated `bl` forms; the body has zero `bl` instructions and one
/// unconditional tail `b`**, verified by decoding raw `osos.dec` words.
///
/// Clears `destination.data`, then reads `source.data`. A NULL source returns
/// with destination empty. Otherwise it scans to the NUL, clamps `suffix_len`
/// to that byte length with the ARM unsigned comparison, and tail-branches to
/// assign-from-buffer at 0x0810b568 with the final `suffix_len` bytes. That
/// suffix is copied. Thus zero selects an empty suffix, while a length at
/// least the source length selects the entire source.
/// Deliberate deviation: the raw tail branch is expressed through the ported
/// [`heap_string_assign_from_cstr`] equivalent. After clamping, the selected
/// suffix is NUL-terminated, so that routine's allocation and copy behavior
/// is identical to the stock assign-from-buffer target.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn heap_string_assign_suffix(
    destination: *mut HeapString,
    source: *const HeapString,
    suffix_len: u32,
) {
    (*destination).data = core::ptr::null_mut();
    let source_data = (*source).data;
    if source_data.is_null() {
        return;
    }

    let source_len = strlen_safe(source_data);
    let suffix_len = core::cmp::min(suffix_len as usize, source_len);
    heap_string_assign_from_cstr(destination, source_data.add(source_len - suffix_len));
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::veneers::tests::{free_log, mock_heap, realloc_log, set_alloc_ret};

    /// A non-empty source reallocates the existing payload with the raw
    /// `(tag = 0x14, a4 = 0)` arguments and copies its trailing NUL.
    #[test]
    fn assign_from_cstr_reallocates_and_copies_nul() {
        let _heap = mock_heap();
        let previous = 0xdead_beefusize as *mut u8;
        let source = b"GeniusPlaylist\0";
        let mut output = [0u8; 16];
        set_alloc_ret(output.as_mut_ptr());
        let mut holder = HeapString { data: previous };

        unsafe { heap_string_assign_from_cstr(&mut holder, source.as_ptr()) };

        assert_eq!(holder.data, output.as_mut_ptr());
        assert_eq!(&output[..source.len()], source);
        let (calls, old_data, size, tag, a4) = realloc_log();
        assert_eq!((calls, old_data, size, tag, a4),
            (1, previous, source.len(), HEAP_STRING_PAYLOAD_FREE_TAG, 0));
    }

    /// Both source representations of an empty replacement use the destroy
    /// path instead of asking realloc for a one-byte buffer.
    #[test]
    fn assign_from_null_or_empty_source_destroys_payload() {
        let _heap = mock_heap();
        let first = 0xdead_beefusize as *mut u8;
        let mut holder = HeapString { data: first };

        unsafe { heap_string_assign_from_cstr(&mut holder, b"\0".as_ptr()) };
        assert!(holder.data.is_null());
        assert_eq!(free_log(), (1, first, HEAP_STRING_PAYLOAD_FREE_TAG));
        assert_eq!(realloc_log().0, 0);

        let second = 0xdead_beecusize as *mut u8;
        holder.data = second;
        unsafe { heap_string_assign_from_cstr(&mut holder, core::ptr::null()) };
        assert!(holder.data.is_null());
        assert_eq!(free_log(), (2, second, HEAP_STRING_PAYLOAD_FREE_TAG));
        assert_eq!(realloc_log().0, 0);
    }

    /// Construction clears its old word before delegating, so assignment
    /// reaches realloc with NULL rather than the stale payload.
    #[test]
    fn construct_from_cstr_clears_before_assigning_and_returns_holder() {
        let _heap = mock_heap();
        let source = b"OTGPlaylistInfo\0";
        let mut output = [0u8; 16];
        set_alloc_ret(output.as_mut_ptr());
        let mut holder = HeapString { data: 0xdead_beefusize as *mut u8 };

        let result = unsafe { heap_string_construct_from_cstr(&mut holder, source.as_ptr()) };

        assert_eq!(result, &mut holder as *mut HeapString);
        assert_eq!(holder.data, output.as_mut_ptr());
        assert_eq!(&output[..source.len()], source);
        let (calls, old_data, size, tag, a4) = realloc_log();
        assert_eq!((calls, old_data, size, tag, a4),
            (1, core::ptr::null_mut(), source.len(), HEAP_STRING_PAYLOAD_FREE_TAG, 0));
    }

    /// A live holder releases exactly its payload with tag 0x14, then clears
    /// its only word. The mock payload is deliberately not dereferenced.
    #[test]
    fn destroy_releases_payload_with_tag_then_clears_holder() {
        let _heap = mock_heap();
        let payload = 0xdead_beecusize as *mut u8;
        let mut holder = HeapString { data: payload };

        unsafe { heap_string_destroy(&mut holder) };

        let (calls, freed, tag) = free_log();
        assert_eq!(calls, 1);
        assert_eq!(freed, payload);
        assert_eq!(tag, HEAP_STRING_PAYLOAD_FREE_TAG);
        assert!(holder.data.is_null());
    }

    /// A NULL payload takes the raw early return: it neither invokes the
    /// free path nor changes the already-empty holder.
    #[test]
    fn destroy_null_payload_skips_heap_and_preserves_empty_holder() {
        let _heap = mock_heap();
        let mut holder = HeapString { data: core::ptr::null_mut() };

        unsafe { heap_string_destroy(&mut holder) };

        assert_eq!(free_log().0, 0);
        assert!(holder.data.is_null());
    }


    /// The suffix selection clamps an oversized count, leaves no stale
    /// destination allocation, and routes the selected tail through the
    /// assign-from-buffer-equivalent allocation path.
    #[test]
    fn assign_suffix_clamps_and_replaces_destination() {
        let _heap = mock_heap();
        let mut source_data = *b"OTGPlaylistInfo\0";
        let source = HeapString {
            data: source_data.as_mut_ptr(),
        };
        let mut output = [0u8; 16];
        set_alloc_ret(output.as_mut_ptr());
        let mut destination = HeapString {
            data: 0xdead_beefusize as *mut u8,
        };

        unsafe { heap_string_assign_suffix(&mut destination, &source, 4) };

        assert_eq!(destination.data, output.as_mut_ptr());
        assert_eq!(&output[..5], b"Info\0");
        assert_eq!(realloc_log(), (1, core::ptr::null_mut(), 5, HEAP_STRING_PAYLOAD_FREE_TAG, 0));
        assert_eq!(free_log().0, 0);

        set_alloc_ret(output.as_mut_ptr());
        unsafe { heap_string_assign_suffix(&mut destination, &source, u32::MAX) };
        assert_eq!(destination.data, output.as_mut_ptr());
        assert_eq!(&output[..16], b"OTGPlaylistInfo\0");
        assert_eq!(realloc_log(), (2, core::ptr::null_mut(), 16, HEAP_STRING_PAYLOAD_FREE_TAG, 0));
    }

    /// A NULL source is observed after destination clearing, so it cannot
    /// retain the old payload or enter either heap path.
    #[test]
    fn assign_suffix_null_source_clears_without_heap_call() {
        let _heap = mock_heap();
        let source = HeapString {
            data: core::ptr::null_mut(),
        };
        let mut destination = HeapString {
            data: 0xdead_beefusize as *mut u8,
        };

        unsafe { heap_string_assign_suffix(&mut destination, &source, 0) };

        assert!(destination.data.is_null());
        assert_eq!(realloc_log().0, 0);
        assert_eq!(free_log().0, 0);
    }
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
