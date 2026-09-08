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
use crate::heap::veneers::free_wrapper;

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

/// Stock `HeapString::assign_from_cstr` entry point. It remains stock code:
/// this port is solely the caller at 0x0810b5cc.
#[cfg(target_os = "none")]
const HEAP_STRING_ASSIGN_FROM_CSTR_ADDRESS: usize = 0x0810b514;

type HeapStringAssignFromCstrFn = unsafe extern "C" fn(*mut HeapString, *const u8);

/// Enters the unported assignment method on the device.
///
/// The retail image remains mapped at its load address after the Rust payload
/// is linked, so device code loads this absolute entry and reaches it by `blx`.
#[cfg(target_os = "none")]
unsafe fn heap_string_assign_from_cstr(this: *mut HeapString, source: *const u8) {
    let assign: HeapStringAssignFromCstrFn =
        core::mem::transmute(HEAP_STRING_ASSIGN_FROM_CSTR_ADDRESS);
    assign(this, source);
}

/// Host unit tests replace the still-stock callee with a recorder. A host
/// binary cannot safely execute a load address in the iPod image.
#[cfg(not(target_os = "none"))]
unsafe fn heap_string_assign_from_cstr(this: *mut HeapString, source: *const u8) {
    #[cfg(test)]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(HEAP_STRING_ASSIGN_FROM_CSTR_TEST))(this, source);
    }
    #[cfg(not(test))]
    {
        let _ = (this, source);
        panic!("heap_string_assign_from_cstr is available only in retailOS");
    }
}

#[cfg(test)]
unsafe extern "C" fn heap_string_assign_from_cstr_test_unavailable(
    _this: *mut HeapString,
    _source: *const u8,
) {
    panic!("heap_string_format test recorder was not installed");
}

#[cfg(test)]
static mut HEAP_STRING_ASSIGN_FROM_CSTR_TEST: HeapStringAssignFromCstrFn =
    heap_string_assign_from_cstr_test_unavailable;

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
/// the crate convention for printf-style retail methods. The assign-from-cstr
/// sibling @ 0x0810b514 is intentionally not re-stubbed: device builds call
/// that verified stock entry directly; host tests install a test-only recorder.
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

#[cfg(test)]
mod tests {
    extern crate std;
    use std::vec::Vec;
    use super::*;
    use crate::cxx::string_object::{
        RetailVsnprintfEngineFn, RETAIL_VSNPRINTF_ENGINE, RETAIL_VSNPRINTF_SINK_ADDRESS,
    };
    use crate::heap::veneers::tests::{free_log, mock_heap};

    use crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK;
    use std::sync::MutexGuard;

    static mut FORMAT_ENGINE_BYTE: u8 = 0;
    static mut FORMAT_ENGINE_LEN: usize = 0;
    static mut FORMAT_ENGINE_RESULT: i32 = 0;
    static mut FORMAT_ENGINE_CALL: Option<(usize, usize, usize, usize, usize)> = None;
    static mut ASSIGN_THIS: *mut HeapString = core::ptr::null_mut();
    static mut ASSIGNED_BYTES: Vec<u8> = Vec::new();

    unsafe extern "C" fn recording_format_engine(
        sink: usize,
        cursor: *mut *mut u8,
        maximum: usize,
        format: *const u8,
        args: VaList,
    ) -> i32 {
        let scratch = *cursor;
        let output_len = core::ptr::read_volatile(core::ptr::addr_of!(FORMAT_ENGINE_LEN));
        let written = core::cmp::min(output_len, maximum);
        core::ptr::write_bytes(
            scratch,
            core::ptr::read_volatile(core::ptr::addr_of!(FORMAT_ENGINE_BYTE)),
            written,
        );
        *cursor = scratch.add(written);
        core::ptr::addr_of_mut!(FORMAT_ENGINE_CALL).write(Some((
            sink,
            scratch as usize,
            maximum,
            format as usize,
            args as usize,
        )));
        core::ptr::read_volatile(core::ptr::addr_of!(FORMAT_ENGINE_RESULT))
    }

    unsafe extern "C" fn recording_assign_from_cstr(this: *mut HeapString, source: *const u8) {
        let mut len = 0;
        while source.add(len).read() != 0 {
            len += 1;
        }
        core::ptr::addr_of_mut!(ASSIGN_THIS).write(this);
        core::ptr::addr_of_mut!(ASSIGNED_BYTES)
            .write(core::slice::from_raw_parts(source, len + 1).to_vec());
    }

    /// Restores both process-wide seams even when a test assertion panics.
    struct FormatBench {
        _lock: MutexGuard<'static, ()>,
        previous_engine: RetailVsnprintfEngineFn,
        previous_assign: HeapStringAssignFromCstrFn,
    }

    impl Drop for FormatBench {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(RETAIL_VSNPRINTF_ENGINE)
                    .write_volatile(self.previous_engine);
                core::ptr::addr_of_mut!(HEAP_STRING_ASSIGN_FROM_CSTR_TEST)
                    .write_volatile(self.previous_assign);
            }
        }
    }

    fn format_bench(byte: u8, len: usize, result: i32) -> FormatBench {
        let lock = STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            let previous_engine =
                core::ptr::read_volatile(core::ptr::addr_of!(RETAIL_VSNPRINTF_ENGINE));
            let previous_assign =
                core::ptr::read_volatile(core::ptr::addr_of!(HEAP_STRING_ASSIGN_FROM_CSTR_TEST));
            core::ptr::addr_of_mut!(FORMAT_ENGINE_BYTE).write(byte);
            core::ptr::addr_of_mut!(FORMAT_ENGINE_LEN).write(len);
            core::ptr::addr_of_mut!(FORMAT_ENGINE_RESULT).write(result);
            core::ptr::addr_of_mut!(FORMAT_ENGINE_CALL).write(None);
            core::ptr::addr_of_mut!(ASSIGN_THIS).write(core::ptr::null_mut());
            core::ptr::addr_of_mut!(ASSIGNED_BYTES).write(Vec::new());
            core::ptr::addr_of_mut!(RETAIL_VSNPRINTF_ENGINE).write_volatile(recording_format_engine);
            core::ptr::addr_of_mut!(HEAP_STRING_ASSIGN_FROM_CSTR_TEST)
                .write_volatile(recording_assign_from_cstr);
            FormatBench { _lock: lock, previous_engine, previous_assign }
        }
    }

    #[test]
    fn format_bounds_the_512_byte_scratch_assigns_it_and_returns_count() {
        let mut holder = HeapString { data: 0xdead_beefusize as *mut u8 };
        let format = b"%s\0";
        let args = 0x5555_5555usize as VaList;
        let _bench = format_bench(b'X', 600, -31);

        let result = unsafe { heap_string_format(&mut holder, format.as_ptr(), args) };

        assert_eq!(result, -31, "the conversion result survives assignment");
        let (sink, scratch, maximum, seen_format, seen_args) =
            unsafe { (*core::ptr::addr_of!(FORMAT_ENGINE_CALL)).unwrap() };
        assert_eq!(sink, RETAIL_VSNPRINTF_SINK_ADDRESS);
        assert_eq!(maximum, HEAP_STRING_FORMAT_BUFFER_LEN - 1);
        assert_eq!(seen_format, format.as_ptr() as usize);
        assert_eq!(seen_args, args as usize);
        assert_ne!(scratch, &mut holder as *mut HeapString as usize, "scratch is not the holder");
        assert_eq!(
            unsafe { *core::ptr::addr_of!(ASSIGN_THIS) },
            &mut holder as *mut HeapString
        );
        let assigned = unsafe { (*core::ptr::addr_of!(ASSIGNED_BYTES)).clone() };
        assert_eq!(assigned.len(), HEAP_STRING_FORMAT_BUFFER_LEN);
        assert!(assigned[..HEAP_STRING_FORMAT_BUFFER_LEN - 1].iter().all(|&byte| byte == b'X'));
        assert_eq!(assigned[HEAP_STRING_FORMAT_BUFFER_LEN - 1], 0);
    }

    #[test]
    fn format_assigns_the_empty_string_and_returns_zero() {
        let mut holder = HeapString { data: core::ptr::null_mut() };
        let _bench = format_bench(b'X', 0, 0);

        assert_eq!(
            unsafe { heap_string_format(&mut holder, b"\0".as_ptr(), core::ptr::null()) },
            0
        );
        assert_eq!(unsafe { (*core::ptr::addr_of!(ASSIGNED_BYTES)).clone() }, [0]);
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
