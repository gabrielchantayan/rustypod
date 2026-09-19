//! retailOS string buffer conversions. These preserve the firmware's
//! code-unit encoding, including lone surrogates and permissive decoding.
//! Bounds count characters/code units, not destination bytes. Callers own
//! the readable source and sufficient writable output storage; positive
//! bounds do not imply that the input or output is NUL-terminated.

use super::string_object::{
    string_object_assign_payload, string_object_c_str, string_object_construct_from_utf16,
    string_object_destroy, utf8_codepoint_count_safe, utf8_next_codepoint, StringObject,
    StringObjectVtable, STRING_OBJECT_VTABLE_ADDRESS,
};

use crate::libc::strlen_safe_plus1::strlen_safe_plus1;

#[inline(always)]
unsafe fn write_cursor_byte(cursor: *mut *mut u8, byte: u8) {
    let out = cursor.read();
    cursor.write(out.add(1));
    out.write(byte);
}

/// utf8_write_codepoint — original: FUN_08275ecc @ 0x08275ecc
/// (124 bytes, all code; four BL references and one tail B).
/// Write one unsigned codepoint at *cursor and advance the cursor before
/// each byte store. Values below 0x80 use one byte, below 0x800 two, and
/// everything else three; the high byte of the three-byte form truncates
/// `(codepoint >> 12) | 0xe0` to eight bits. Thus non-BMP values are not
/// standard UTF-8. Zero writes one zero byte; no extra NUL is appended.
/// No deviations. The cursor cell must be valid and its output must have
/// space for up to three bytes. The raw-pointer ABI retains cursor reloads
/// between stores, as in the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn utf8_write_codepoint(cursor: *mut *mut u8, codepoint: u32) {
    if codepoint < 0x80 {
        write_cursor_byte(cursor, codepoint as u8);
        return;
    }
    if codepoint < 0x800 {
        write_cursor_byte(cursor, 0xc0 | (codepoint >> 6) as u8);
    } else {
        write_cursor_byte(cursor, 0xe0 | (codepoint >> 12) as u8);
        write_cursor_byte(cursor, 0x80 | ((codepoint >> 6) & 0x3f) as u8);
    }
    write_cursor_byte(cursor, 0x80 | (codepoint & 0x3f) as u8);
}

/// Emit one UTF-16 code unit without a terminator or surrogate pairing.
#[inline(always)]
unsafe fn write_code_unit(mut out: *mut u8, unit: u16) -> *mut u8 {
    if unit < 0x80 {
        out.write(unit as u8);
        return out.add(1);
    }
    if unit >= 0x800 {
        out.write(0xe0 | (unit >> 12) as u8);
        out = out.add(1);
        out.write(0x80 | ((unit >> 6) & 0x3f) as u8);
    } else {
        out.write(0xc0 | (unit >> 6) as u8);
    }
    out.add(1).write(0x80 | (unit & 0x3f) as u8);
    out.add(2)
}

/// utf16_to_utf8 — original entry @ 0x082766f8 (100 bytes, all code).
/// Ghidra omits this entry and inlines it into FUN_0827654c; its `bne`
/// at 0x082765a0 enters this leaf. Encode each nonzero 16-bit unit as
/// one, two or three bytes, then write a NUL. Surrogates remain separate
/// three-byte units. No deviations; source must be NUL-terminated and
/// output must have space for the encoded bytes and terminator.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn utf16_to_utf8(mut out: *mut u8, mut source: *const u16) {
    loop {
        let unit = source.read();
        out = write_code_unit(out, unit);
        if unit == 0 { return; }
        source = source.add(1);
    }
}

/// utf16_to_utf8_bounded — original: FUN_0827675c @ 0x0827675c
/// (124 bytes, all code). Encode up to `max_code_units` units, stopping
/// after writing a source NUL. Return the nonzero units consumed, not
/// bytes written; exhausting the signed bound adds no terminator.
/// No surrogate pairing or validation. Nonpositive bounds access neither
/// pointer. No deviations; output needs up to three bytes per input unit.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn utf16_to_utf8_bounded(
    mut out: *mut u8, mut source: *const u16, max_code_units: i32,
) -> i32 {
    let mut count = 0;
    while count < max_code_units {
        let unit = source.read();
        out = write_code_unit(out, unit);
        if unit == 0 { break; }
        source = source.add(1);
        count += 1;
    }
    count
}

/// utf8_to_utf16 — original: FUN_082767d8 @ 0x082767d8 (36 bytes).
/// Decode with utf8_next_codepoint and store each result as a halfword,
/// including the terminating zero. The decoder's unsupported high-bit
/// leads also end conversion, and malformed continuation bytes are masked
/// rather than rejected. No deviations; source must satisfy the decoder's
/// readable-sequence contract and output must fit all units plus the NUL.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn utf8_to_utf16(mut out: *mut u16, source: *const u8) {
    let mut cursor = source;
    loop {
        let codepoint = utf8_next_codepoint(&mut cursor);
        out.write(codepoint as u16);
        if codepoint == 0 { return; }
        out = out.add(1);
    }
}

/// utf8_to_utf16_bounded — original: FUN_082767fc @ 0x082767fc
/// (68 bytes). Decode and store at most `max_codepoints` halfwords;
/// return the number of nonzero decoded values. A decoded zero is stored
/// but not counted; reaching the bound adds no NUL. Nonpositive bounds
/// access neither pointer. Decoder quirks are retained without deviations;
/// a positive bound requires readable complete sequences and output space.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn utf8_to_utf16_bounded(
    mut out: *mut u16, source: *const u8, max_codepoints: i32,
) -> i32 {
    let mut cursor = source;
    let mut count = 0;
    while count < max_codepoints {
        let codepoint = utf8_next_codepoint(&mut cursor);
        out.write(codepoint as u16);
        if codepoint == 0 { break; }
        out = out.add(1);
        count += 1;
    }
    count
}

/// utf8_copy_codepoints — original: FUN_082766a0 @ 0x082766a0
/// (88 bytes). Decode one sequence, copy its original bytes forward,
/// then stop if the decoded value was zero. Return nonzero codepoints
/// copied, bounded by the signed limit. This preserves overlong bytes;
/// an unsupported lead copies three bytes and stops without adding NUL.
/// No deviations. Nonpositive bounds access neither pointer; otherwise
/// source and output must fit every consumed sequence (up to three bytes
/// per iteration). Forward overlap has the original byte-loop behavior.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn utf8_copy_codepoints(
    mut out: *mut u8, mut source: *const u8, max_codepoints: i32,
) -> i32 {
    let mut cursor = source;
    let mut count = 0;
    while count < max_codepoints {
        let codepoint = utf8_next_codepoint(&mut cursor);
        while source != cursor {
            out.write(source.read());
            out = out.add(1);
            source = source.add(1);
        }
        if codepoint == 0 { break; }
        count += 1;
    }
    count
}

/// utf8_span_to_utf16_counted — original: FUN_08046c74 @ 0x08046c74
/// (116 bytes of code plus the 4-byte vtable literal @ 0x08046ce8;
/// five `bl` call sites, all unconditional, verified by decoding the raw
/// words in osos.dec: the unported span-assignment helper @ 0x08277188,
/// utf8_codepoint_count_safe @ 0x082770e0, string_object_c_str @
/// 0x082a50b0, utf8_to_utf16_bounded @ 0x082767fc and
/// string_object_destroy @ 0x08277484). Ghidra's 116-byte body extent is
/// correct: the separately linked next function begins at 0x08046cec.
///
/// Stack-construct a temporary two-word StringObject (vtable literal
/// 0x089a6044, NULL payload), fill it from the byte span through the
/// span-assignment helper @ 0x08277188, count the payload's codepoints
/// with utf8_codepoint_count_safe, then convert the object's C string
/// into `destination` with utf8_to_utf16_bounded, bounding by the
/// UNSIGNED minimum of `max_codepoints` and that count (`cmp` / `movcs`).
/// When `out_count` is non-NULL it receives the converter's decoded-count
/// return word; the temporary is destroyed and the function always
/// returns zero.
///
/// Deliberate deviations: 0x08277188 is unported retailOS code
/// (raw-decoded: for an empty span it tail-dispatches vtable slot 3,
/// otherwise vtable slot 2 allocates `len + 1`, memcpy @ 0x08037db0
/// copies `len + 1` bytes and an explicit trailing NUL is stored); it is
/// reached by fixed-address call on target and by a swappable seam on
/// host, matching this module's existing helper boundary. The stack
/// temporary plants the original image vtable address as a value, exactly
/// as the original's literal load does; host code never dereferences it
/// because the seam performs the assignment.
type StringObjectAssignSpanHelper =
    unsafe extern "C" fn(*mut StringObject, *const u8, u32);

#[cfg(target_os = "none")]
const STRING_OBJECT_ASSIGN_SPAN_ADDRESS: usize = 0x0827_7188;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn string_object_assign_span_helper(
    this: *mut StringObject,
    source: *const u8,
    source_len: u32,
) {
    let helper: StringObjectAssignSpanHelper =
        core::mem::transmute(STRING_OBJECT_ASSIGN_SPAN_ADDRESS);
    helper(this, source, source_len);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_string_object_assign_span_helper(
    _this: *mut StringObject,
    _source: *const u8,
    _source_len: u32,
) {
}

#[cfg(not(target_os = "none"))]
static mut STRING_OBJECT_ASSIGN_SPAN_HELPER: StringObjectAssignSpanHelper =
    unavailable_string_object_assign_span_helper;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn string_object_assign_span_helper(
    this: *mut StringObject,
    source: *const u8,
    source_len: u32,
) {
    core::ptr::read_volatile(core::ptr::addr_of!(STRING_OBJECT_ASSIGN_SPAN_HELPER))(
        this,
        source,
        source_len,
    )
}

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn utf8_span_to_utf16_counted(
    source: *const u8,
    source_len: u32,
    destination: *mut u16,
    max_codepoints: u32,
    out_count: *mut u32,
) -> i32 {
    let mut temporary = StringObject {
        vtable: STRING_OBJECT_VTABLE_ADDRESS as *const StringObjectVtable,
        payload: core::ptr::null_mut(),
    };
    string_object_assign_span_helper(&mut temporary, source, source_len);
    let decoded = utf8_codepoint_count_safe(temporary.payload) as u32;
    let text = string_object_c_str(&temporary);
    let bound = core::cmp::min(decoded, max_codepoints);
    let written = utf8_to_utf16_bounded(destination, text, bound as i32);
    if !out_count.is_null() {
        out_count.write(written as u32);
    }
    string_object_destroy(&mut temporary);
    0
}

/// utf16_to_utf8_capped — original: FUN_08046d94 @ 0x08046d94 (188 bytes,
/// 0x08046d94..0x08046e50). Raw ARM has ten plain `bl` instructions and one
/// predicated `blne`; four inbound direct calls are all plain `bl`.
///
/// Construct a temporary StringObject from at most `max_code_units` UTF-16
/// units. While its UTF-8 byte length exceeds `max_bytes`, ask retailOS's
/// still-unported 0x082a52a0 helper for a copy without its final codepoint,
/// assign that copy back, and destroy the intermediate. Copy the surviving
/// UTF-8 codepoints to `destination`, return zero, and optionally report its
/// byte length excluding the NUL. The bound is unsigned, exactly as the ARM
/// `bhi` comparison.
///
/// Deliberate deviation: 0x082a52a0 has no verified identity or Rust port, so
/// it remains a fixed-address target seam. Its observed `(out, source,
/// codepoint_count - 1)` ABI and returned StringObject state are preserved;
/// host tests install the same boundary explicitly.
type StringObjectWithoutLastCodepointHelper =
    unsafe extern "C" fn(*mut StringObject, *const StringObject, i32);

#[cfg(target_os = "none")]
const STRING_OBJECT_WITHOUT_LAST_CODEPOINT_ADDRESS: usize = 0x082a_52a0;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn string_object_without_last_codepoint(
    out: *mut StringObject, source: *const StringObject, codepoint_count: i32,
) {
    let helper: StringObjectWithoutLastCodepointHelper =
        core::mem::transmute(STRING_OBJECT_WITHOUT_LAST_CODEPOINT_ADDRESS);
    helper(out, source, codepoint_count);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_string_object_without_last_codepoint(
    _out: *mut StringObject, _source: *const StringObject, _codepoint_count: i32,
) {
}

#[cfg(not(target_os = "none"))]
static mut STRING_OBJECT_WITHOUT_LAST_CODEPOINT_HELPER: StringObjectWithoutLastCodepointHelper =
    unavailable_string_object_without_last_codepoint;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn string_object_without_last_codepoint(
    out: *mut StringObject, source: *const StringObject, codepoint_count: i32,
) {
    core::ptr::read_volatile(core::ptr::addr_of!(STRING_OBJECT_WITHOUT_LAST_CODEPOINT_HELPER))(
        out, source, codepoint_count,
    )
}

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn utf16_to_utf8_capped(
    source: *const u16,
    max_code_units: i32,
    destination: *mut u8,
    max_bytes: u32,
    out_bytes: *mut u32,
) -> i32 {
    let mut text = core::mem::MaybeUninit::<StringObject>::uninit();
    let text = string_object_construct_from_utf16(text.as_mut_ptr(), source, max_code_units);

    while max_bytes < (strlen_safe_plus1((*text).payload) as u32).wrapping_sub(1) {
        let mut shortened = core::mem::MaybeUninit::<StringObject>::uninit();
        let shortened = shortened.as_mut_ptr();
        string_object_without_last_codepoint(
            shortened,
            text,
            utf8_codepoint_count_safe((*text).payload) as i32,
        );
        string_object_assign_payload(text, (*shortened).payload);
        string_object_destroy(shortened);
    }

    let byte_len = (strlen_safe_plus1((*text).payload) as u32).wrapping_sub(1);
    utf8_copy_codepoints(destination, string_object_c_str(text), utf8_codepoint_count_safe((*text).payload) as i32);
    if !out_bytes.is_null() {
        out_bytes.write(byte_len);
    }
    string_object_destroy(text);
    0
}

/// utf8_to_utf16_counted_buffer — original: FUN_08046c24 @ 0x08046c24
/// (80 bytes, all code; nine direct `bl` call sites verified by scanning
/// osos.dec; all nine are unconditional). Clear the leading u16 in
/// `destination`, then, for a nonempty source span, invoke the surviving
/// conversion helper at 0x08046c74 with a 255-codepoint bound and store its
/// returned codepoint count in that leading u16. A NULL destination or a
/// nonempty span with a NULL source returns -50; an empty span returns zero
/// after clearing the output even when the source is NULL.
///
/// No target deviation: 0x08046c74 remains retailOS code and builds its
/// temporary StringObject before calling the existing UTF-8 decoder. Host
/// tests use a swappable helper because that allocation-backed retailOS
/// dependency is not executable on the host.
type Utf8ToUtf16CountedBufferHelper =
    unsafe extern "C" fn(*const u8, u32, *mut u16, u32, *mut u32) -> i32;

#[cfg(target_os = "none")]
const UTF8_TO_UTF16_COUNTED_BUFFER_HELPER_ADDRESS: usize = 0x0804_6c74;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn utf8_to_utf16_counted_buffer_helper(
    source: *const u8,
    source_len: u32,
    destination: *mut u16,
    max_codepoints: u32,
    out_count: *mut u32,
) -> i32 {
    let helper: Utf8ToUtf16CountedBufferHelper =
        core::mem::transmute(UTF8_TO_UTF16_COUNTED_BUFFER_HELPER_ADDRESS);
    helper(source, source_len, destination, max_codepoints, out_count)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_utf8_to_utf16_counted_buffer_helper(
    _source: *const u8,
    _source_len: u32,
    _destination: *mut u16,
    _max_codepoints: u32,
    _out_count: *mut u32,
) -> i32 {
    0
}

#[cfg(not(target_os = "none"))]
static mut UTF8_TO_UTF16_COUNTED_BUFFER_HELPER: Utf8ToUtf16CountedBufferHelper =
    unavailable_utf8_to_utf16_counted_buffer_helper;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn utf8_to_utf16_counted_buffer_helper(
    source: *const u8,
    source_len: u32,
    destination: *mut u16,
    max_codepoints: u32,
    out_count: *mut u32,
) -> i32 {
    core::ptr::read_volatile(core::ptr::addr_of!(UTF8_TO_UTF16_COUNTED_BUFFER_HELPER))(
        source,
        source_len,
        destination,
        max_codepoints,
        out_count,
    )
}

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn utf8_to_utf16_counted_buffer(
    source: *const u8,
    source_len: u32,
    destination: *mut u16,
    initial_count: u32,
) -> i32 {
    if destination.is_null() {
        return -50;
    }

    destination.write(0);
    if source_len == 0 {
        return 0;
    }
    if source.is_null() {
        return -50;
    }

    let mut count = initial_count;
    let status = utf8_to_utf16_counted_buffer_helper(
        source,
        source_len,
        destination.add(1),
        0xff,
        &mut count,
    );
    destination.write(count as u16);
    status
}

/// cstr_to_counted_u16 — original: FUN_08045f54 @
/// 0x08045f54 (92 bytes, all code; eight direct `bl` call sites verified by
/// scanning osos.dec: 0x0805825c, 0x08058288, 0x080582c8, 0x08058790,
/// 0x0805aa74, 0x08068a2c, 0x080cb238, and 0x080cb284; all unconditional).
/// Clear the leading u16 in `destination`, reject a NULL source or
/// destination with -50, then count source bytes through its first NUL and
/// cap that length at 255. Expand the span to UTF-16 at `destination + 1`
/// through the retailOS helper and store its u32 decoded count truncated to
/// the leading u16. The fourth ABI argument initializes that count; the third
/// is ignored by the stock body.
///
/// Deliberately calls the target of stock's one-instruction
/// `FUN_08046b44` veneer (0x08046c74) through the existing shared boundary,
/// rather than porting that veneer as a second function. This preserves the
/// helper's behavior while keeping this port to its one assigned function.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cstr_to_counted_u16(
    source: *const u8,
    destination: *mut u16,
    _ignored: u32,
    initial_count: u32,
) -> i32 {
    if destination.is_null() {
        return -50;
    }

    destination.write(0);
    if source.is_null() {
        return -50;
    }

    let mut cursor = source;
    let mut source_len = 0_u32;
    while cursor.read_volatile() != 0 {
        source_len = source_len.wrapping_add(1);
        cursor = cursor.add(1);
    }
    source_len = source_len.min(0xff);

    let mut decoded_count = initial_count;
    let status = utf8_to_utf16_counted_buffer_helper(
        source,
        source_len,
        destination.add(1),
        0xff,
        &mut decoded_count,
    );
    destination.write(decoded_count as u16);
    status
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;
    use std::sync::Mutex;

    static COUNTED_BUFFER_HELPER_LOCK: Mutex<()> = Mutex::new(());
    static mut COUNTED_BUFFER_CALLS: u32 = 0;
    static mut COUNTED_BUFFER_ARGS: (usize, u32, usize, u32, usize) = (0, 0, 0, 0, 0);
    static mut COUNTED_BUFFER_INITIAL_COUNT: u32 = 0;

    unsafe extern "C" fn recording_counted_buffer_helper(
        source: *const u8,
        source_len: u32,
        destination: *mut u16,
        max_codepoints: u32,
        out_count: *mut u32,
    ) -> i32 {
        COUNTED_BUFFER_CALLS += 1;
        COUNTED_BUFFER_ARGS = (
            source as usize,
            source_len,
            destination as usize,
            max_codepoints,
            out_count as usize,
        );
        COUNTED_BUFFER_INITIAL_COUNT = out_count.read();
        destination.write(0x1234);
        destination.add(1).write(0);
        out_count.write(0x1_0002);
        -7
    }

    struct CountedBufferHelperGuard(Utf8ToUtf16CountedBufferHelper);

    impl CountedBufferHelperGuard {
        unsafe fn install(helper: Utf8ToUtf16CountedBufferHelper) -> Self {
            let previous = core::ptr::read_volatile(
                core::ptr::addr_of!(UTF8_TO_UTF16_COUNTED_BUFFER_HELPER),
            );
            core::ptr::addr_of_mut!(UTF8_TO_UTF16_COUNTED_BUFFER_HELPER).write_volatile(helper);
            Self(previous)
        }
    }

    impl Drop for CountedBufferHelperGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(UTF8_TO_UTF16_COUNTED_BUFFER_HELPER)
                    .write_volatile(self.0);
            }
        }
    }

    fn install_counted_buffer_recorder() -> CountedBufferHelperGuard {
        unsafe {
            COUNTED_BUFFER_CALLS = 0;
            COUNTED_BUFFER_ARGS = (0, 0, 0, 0, 0);
            COUNTED_BUFFER_INITIAL_COUNT = 0;
            CountedBufferHelperGuard::install(recording_counted_buffer_helper)
        }
    }

    #[test]
    fn nul_terminated_buffer_clears_then_rejects_null_source() {
        let _lock = COUNTED_BUFFER_HELPER_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _helper = install_counted_buffer_recorder();
        let mut destination = [0xbeef_u16; 3];

        assert_eq!(
            unsafe {
                cstr_to_counted_u16(
                    core::ptr::null(), destination.as_mut_ptr(), 0x1234_5678, 9,
                )
            },
            -50
        );
        assert_eq!(destination, [0, 0xbeef, 0xbeef]);
        assert_eq!(unsafe { COUNTED_BUFFER_CALLS }, 0);

        assert_eq!(
            unsafe {
                cstr_to_counted_u16(
                    b"x\0".as_ptr(), core::ptr::null_mut(), 0, 0,
                )
            },
            -50
        );
        assert_eq!(unsafe { COUNTED_BUFFER_CALLS }, 0);
    }

    #[test]
    fn nul_terminated_buffer_counts_through_nul_and_caps_helper_length() {
        let _lock = COUNTED_BUFFER_HELPER_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _helper = install_counted_buffer_recorder();
        let mut long_source = Vec::new();
        long_source.resize(300, b'x');
        long_source.push(0);
        let mut destination = [0xbeef_u16; 3];

        assert_eq!(
            unsafe {
                cstr_to_counted_u16(
                    long_source.as_ptr(), destination.as_mut_ptr(), 0x1234_5678, 0xfeed,
                )
            },
            -7
        );
        assert_eq!(destination, [2, 0x1234, 0]);
        let (seen_source, seen_len, seen_destination, seen_max, seen_count) =
            unsafe { COUNTED_BUFFER_ARGS };
        assert_eq!(seen_source, long_source.as_ptr() as usize);
        assert_eq!(seen_len, 0xff);
        assert_eq!(seen_destination, unsafe { destination.as_mut_ptr().add(1) as usize });
        assert_eq!(seen_max, 0xff);
        assert_ne!(seen_count, 0);
        assert_eq!(unsafe { COUNTED_BUFFER_INITIAL_COUNT }, 0xfeed);
    }

    #[test]
    fn counted_buffer_rejects_invalid_pointers_after_the_stock_clear_order() {
        let _lock = COUNTED_BUFFER_HELPER_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _helper = install_counted_buffer_recorder();

        let mut destination = [0xbeef_u16; 3];
        assert_eq!(
            unsafe {
                utf8_to_utf16_counted_buffer(core::ptr::null(), 1, destination.as_mut_ptr(), 9)
            },
            -50
        );
        assert_eq!(destination, [0, 0xbeef, 0xbeef]);
        assert_eq!(unsafe { COUNTED_BUFFER_CALLS }, 0);

        assert_eq!(
            unsafe {
                utf8_to_utf16_counted_buffer(b"x".as_ptr(), 1, core::ptr::null_mut(), 9)
            },
            -50
        );
        assert_eq!(unsafe { COUNTED_BUFFER_CALLS }, 0);
    }

    #[test]
    fn counted_buffer_empty_span_accepts_null_source_without_the_helper() {
        let _lock = COUNTED_BUFFER_HELPER_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _helper = install_counted_buffer_recorder();
        let mut destination = [0xbeef_u16; 2];

        assert_eq!(
            unsafe {
                utf8_to_utf16_counted_buffer(core::ptr::null(), 0, destination.as_mut_ptr(), 9)
            },
            0
        );
        assert_eq!(destination, [0, 0xbeef]);
        assert_eq!(unsafe { COUNTED_BUFFER_CALLS }, 0);
    }

    #[test]
    fn counted_buffer_forwards_to_the_helper_and_truncates_its_count_to_u16() {
        let _lock = COUNTED_BUFFER_HELPER_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _helper = install_counted_buffer_recorder();
        let source = b"A\xc2\xa2\0";
        let mut destination = [0xbeef_u16; 3];

        assert_eq!(
            unsafe {
                utf8_to_utf16_counted_buffer(source.as_ptr(), 3, destination.as_mut_ptr(), 0xfeed)
            },
            -7
        );
        assert_eq!(destination, [2, 0x1234, 0]);
        let (seen_source, seen_len, seen_destination, seen_max, seen_count) =
            unsafe { COUNTED_BUFFER_ARGS };
        assert_eq!(seen_source, source.as_ptr() as usize);
        assert_eq!(seen_len, 3);
        assert_eq!(seen_destination, unsafe { destination.as_mut_ptr().add(1) as usize });
        assert_eq!(seen_max, 0xff);
        assert_ne!(seen_count, 0);
    }

    // Standard Unicode supplies an independent oracle for scalars. retailOS
    // additionally encodes each surrogate as its own three-byte code unit.
    fn encoded(unit: u16) -> Vec<u8> {
        if let Some(character) = char::from_u32(unit as u32) {
            character.encode_utf8(&mut [0; 4]).as_bytes().to_vec()
        } else {
            std::vec![0xed, 0xa0 + ((unit - 0xd800) / 64) as u8,
                0x80 + (unit % 64) as u8]
        }
    }

    #[test]
    fn cursor_encoder_matches_every_code_unit_without_appending_a_terminator() {
        for unit in 0..=u16::MAX {
            let mut bytes = [0xa5; 5];
            let mut cursor = unsafe { bytes.as_mut_ptr().add(1) };
            unsafe { utf8_write_codepoint(&mut cursor, unit as u32) };
            let expected = encoded(unit);
            assert_eq!(&bytes[1..1 + expected.len()], expected, "unit={unit:#x}");
            assert_eq!(cursor, unsafe { bytes.as_mut_ptr().add(1 + expected.len()) });
            assert_eq!(bytes[0], 0xa5);
            assert!(bytes[1 + expected.len()..].iter().all(|&b| b == 0xa5));
        }
    }

    #[test]
    fn cursor_encoder_preserves_unsigned_three_byte_truncation() {
        for (codepoint, expected) in [
            (0x10000, [0xf0, 0x80, 0x80]), (0x1f600, [0xff, 0x98, 0x80]),
            (0x10ffff, [0xef, 0xbf, 0xbf]), (0x110000, [0xf0, 0x80, 0x80]),
            (0x80000000, [0xe0, 0x80, 0x80]), (u32::MAX, [0xff, 0xbf, 0xbf]),
        ] {
            let mut bytes = [0xa5; 4];
            let mut cursor = bytes.as_mut_ptr();
            unsafe { utf8_write_codepoint(&mut cursor, codepoint) };
            assert_eq!(bytes, [expected[0], expected[1], expected[2], 0xa5]);
            assert_eq!(cursor, unsafe { bytes.as_mut_ptr().add(3) });
        }
    }

    #[test]
    fn every_code_unit_encodes_and_decodes_without_surrogate_pairing() {
        for unit in 0..=u16::MAX {
            let source = [unit, 0];
            let expected = encoded(unit);
            let mut bytes = [0xa5; 5];
            unsafe { utf16_to_utf8(bytes.as_mut_ptr(), source.as_ptr()) };
            assert_eq!(&bytes[..expected.len()], expected, "unit={unit:#x}");
            let end = expected.len() + usize::from(unit != 0);
            assert_eq!(bytes[end - 1], 0);
            assert!(bytes[end..].iter().all(|&b| b == 0xa5));
            let mut decoded = [0xa5a5; 3];
            unsafe { utf8_to_utf16(decoded.as_mut_ptr(), bytes.as_ptr()) };
            assert_eq!(decoded[0], unit);
            if unit != 0 { assert_eq!(decoded[1], 0); }
            assert_eq!(decoded[2], 0xa5a5);
        }
    }

    #[test]
    fn bounded_encoding_matches_every_code_unit_without_an_added_nul() {
        for unit in 0..=u16::MAX {
            let mut bytes = [0xa5; 4];
            let count = unsafe { utf16_to_utf8_bounded(bytes.as_mut_ptr(), &unit, 1) };
            let expected = encoded(unit);
            assert_eq!(count, i32::from(unit != 0));
            assert_eq!(&bytes[..expected.len()], expected, "unit={unit:#x}");
            assert!(bytes[expected.len()..].iter().all(|&b| b == 0xa5));
        }
    }

    #[test]
    fn signed_nonpositive_bounds_do_not_access_either_pointer() {
        for bound in [i32::MIN, -1, 0] {
            unsafe {
                assert_eq!(utf16_to_utf8_bounded(core::ptr::null_mut(), core::ptr::null(), bound), 0);
                assert_eq!(utf8_to_utf16_bounded(core::ptr::null_mut(), core::ptr::null(), bound), 0);
                assert_eq!(utf8_copy_codepoints(core::ptr::null_mut(), core::ptr::null(), bound), 0);
            }
        }
    }

    #[test]
    fn bounds_count_units_and_stop_at_nul_without_touching_the_tail() {
        let units = [0x41, 0x7f, 0x80, 0x7ff, 0x800, 0xd83d, 0xde00, 0xffff, 0, 0x42];
        for bound in 1..=10 {
            let count = bound.min(8) as usize;
            let written = if bound > 8 { 9 } else { count };
            let expected: Vec<u8> = units[..written].iter().flat_map(|&u| encoded(u)).collect();
            let mut bytes = [0xa5; 32];
            assert_eq!(unsafe { utf16_to_utf8_bounded(bytes.as_mut_ptr(), units.as_ptr(), bound) }, count as i32);
            assert_eq!(&bytes[..expected.len()], expected);
            assert!(bytes[expected.len()..].iter().all(|&b| b == 0xa5));
            let mut out = [0xa5a5; 12];
            assert_eq!(unsafe { utf8_to_utf16_bounded(out.as_mut_ptr(), bytes.as_ptr(), bound) }, count as i32);
            assert_eq!(&out[..written], &units[..written]);
            assert!(out[written..].iter().all(|&u| u == 0xa5a5));
        }
    }

    #[test]
    fn decoding_keeps_overlong_surrogate_and_invalid_lead_semantics() {
        for (sequence, expected) in [
            (&b"\xc0\x80"[..], 0), (&b"\xc1\x81"[..], 0x41),
            (&b"\xc2A"[..], 0x81), (&b"\xe0\x81\x81"[..], 0x41),
            (&b"\xed\xa0\x80"[..], 0xd800), (&b"\xf0\x9f\x98"[..], 0),
            (&b"\x80AB"[..], 0), (&b"\xffAB"[..], 0),
        ] {
            let mut source = sequence.to_vec();
            source.push(0);
            let mut out = [0xa5a5; 4];
            let count = unsafe { utf8_to_utf16_bounded(out.as_mut_ptr(), source.as_ptr(), 3) };
            assert_eq!(count, i32::from(expected != 0));
            assert_eq!(out[0], expected);
            if expected != 0 { assert_eq!(out[1], 0); }
            assert_eq!(out[2], 0xa5a5);
            let mut unbounded = [0xa5a5; 4];
            unsafe { utf8_to_utf16(unbounded.as_mut_ptr(), source.as_ptr()) };
            assert_eq!(out, unbounded);
        }
    }

    static SPAN_HELPER_LOCK: Mutex<()> = Mutex::new(());
    static mut SPAN_PAYLOAD: [u8; 64] = [0; 64];
    static mut SPAN_CALLS: u32 = 0;
    static mut SPAN_ARGS: (usize, usize, u32) = (0, 0, 0);

    unsafe extern "C" fn stub_string_object_assign_span(
        this: *mut StringObject,
        source: *const u8,
        source_len: u32,
    ) {
        SPAN_CALLS += 1;
        SPAN_ARGS = (this as usize, source as usize, source_len);
        let payload = core::ptr::addr_of_mut!(SPAN_PAYLOAD).cast::<u8>();
        let len = source_len as usize;
        if len > 0 {
            core::ptr::copy_nonoverlapping(source, payload, len);
        }
        payload.add(len).write(0);
        (*this).payload = payload;
    }

    struct SpanHelperGuard(StringObjectAssignSpanHelper);

    impl SpanHelperGuard {
        unsafe fn install() -> Self {
            let previous =
                core::ptr::read_volatile(core::ptr::addr_of!(STRING_OBJECT_ASSIGN_SPAN_HELPER));
            core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_SPAN_HELPER)
                .write_volatile(stub_string_object_assign_span);
            SPAN_CALLS = 0;
            SPAN_ARGS = (0, 0, 0);
            Self(previous)
        }
    }

    impl Drop for SpanHelperGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_SPAN_HELPER).write_volatile(self.0);
            }
        }
    }

    #[test]
    fn span_to_utf16_converts_reports_count_and_destroys_the_temporary() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let _lock = SPAN_HELPER_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _helper = unsafe { SpanHelperGuard::install() };
        let source = b"ab\xc3\xa9rest";
        let mut destination = [0xa5a5_u16; 6];
        let mut count = 0xdead_u32;

        assert_eq!(
            unsafe {
                utf8_span_to_utf16_counted(
                    source.as_ptr(),
                    4,
                    destination.as_mut_ptr(),
                    0xff,
                    &mut count,
                )
            },
            0
        );
        assert_eq!(&destination[..4], &[0x61, 0x62, 0xe9, 0xa5a5]);
        assert_eq!(count, 3, "three codepoints in four bytes");
        assert_eq!(unsafe { SPAN_CALLS }, 1);
        let (_, seen_source, seen_len) = unsafe { SPAN_ARGS };
        assert_eq!(seen_source, source.as_ptr() as usize);
        assert_eq!(seen_len, 4);
        let (frees, freed, tag) = crate::heap::veneers::tests::free_log();
        assert_eq!(frees, 1, "the temporary's payload is released exactly once");
        assert_eq!(freed, unsafe { core::ptr::addr_of_mut!(SPAN_PAYLOAD).cast::<u8>() });
        assert_eq!(tag, 0x34, "string_object_destroy's free tag");
    }

    #[test]
    fn span_to_utf16_takes_the_unsigned_minimum_of_bound_and_decoded_count() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let _lock = SPAN_HELPER_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _helper = unsafe { SpanHelperGuard::install() };
        let source = b"abcdef";
        let mut destination = [0xa5a5_u16; 6];
        let mut count = 0xdead_u32;

        assert_eq!(
            unsafe {
                utf8_span_to_utf16_counted(
                    source.as_ptr(),
                    4,
                    destination.as_mut_ptr(),
                    2,
                    &mut count,
                )
            },
            0
        );
        assert_eq!(&destination[..4], &[0x61, 0x62, 0xa5a5, 0xa5a5]);
        assert_eq!(count, 2, "the 255-style bound clamps the decoded four");
    }

    #[test]
    fn span_to_utf16_tolerates_a_null_count_out_pointer() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let _lock = SPAN_HELPER_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _helper = unsafe { SpanHelperGuard::install() };
        let source = b"xy";
        let mut destination = [0xa5a5_u16; 4];

        assert_eq!(
            unsafe {
                utf8_span_to_utf16_counted(
                    source.as_ptr(),
                    2,
                    destination.as_mut_ptr(),
                    0xff,
                    core::ptr::null_mut(),
                )
            },
            0
        );
        assert_eq!(&destination[..4], &[0x78, 0x79, 0xa5a5, 0xa5a5]);
    }

    #[test]
    fn span_to_utf16_with_an_empty_span_writes_nothing_and_reports_zero() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let _lock = SPAN_HELPER_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _helper = unsafe { SpanHelperGuard::install() };
        let mut destination = [0xa5a5_u16; 2];
        let mut count = 0xdead_u32;

        assert_eq!(
            unsafe {
                utf8_span_to_utf16_counted(
                    core::ptr::null(),
                    0,
                    destination.as_mut_ptr(),
                    0xff,
                    &mut count,
                )
            },
            0
        );
        assert_eq!(count, 0);
        assert_eq!(
            destination, [0xa5a5; 2],
            "a zero decoded count leaves the bound at zero, which touches no pointer"
        );
    }

    #[test]
    fn copy_preserves_raw_sequences_and_counts_characters_not_bytes() {
        let source = b"A\xc1\x81\xe2\x82\xac\0ignored";
        for (bound, count, bytes) in [(1, 1, 1), (2, 2, 3), (3, 3, 6), (4, 3, 7), (9, 3, 7)] {
            for offset in 0..4 {
                let mut out = [0xa5; 20];
                let result = unsafe { utf8_copy_codepoints(out.as_mut_ptr().add(offset), source.as_ptr(), bound) };
                assert_eq!(result, count);
                assert_eq!(&out[offset..offset + bytes], &source[..bytes]);
                assert!(out[..offset].iter().chain(&out[offset + bytes..]).all(|&b| b == 0xa5));
            }
        }
    }

    #[test]
    fn copy_emits_the_zero_decoding_sequence_before_stopping() {
        for sequence in [&b"\xc0\x80"[..], &b"\xe0\x80\x80"[..], &b"\xf0\x9f\x98"[..], &b"\x80AB"[..]] {
            let mut out = [0xa5; 8];
            assert_eq!(unsafe { utf8_copy_codepoints(out.as_mut_ptr(), sequence.as_ptr(), 1) }, 0);
            assert_eq!(&out[..sequence.len()], sequence);
            assert!(out[sequence.len()..].iter().all(|&b| b == 0xa5));
        }
    }

    #[test]
    fn copy_keeps_forward_overlap_behavior_including_aliases() {
        for (source, destination) in [(0, 0), (2, 0), (0, 1), (0, 2)] {
            let mut actual = *b"abcdefghijklmno\0";
            let mut expected = actual;
            for index in 0..6 { expected[destination + index] = expected[source + index]; }
            let count = unsafe {
                utf8_copy_codepoints(actual.as_mut_ptr().add(destination), actual.as_ptr().add(source), 6)
            };
            assert_eq!(count, 6);
            assert_eq!(actual, expected);
        }
    }
}

#[cfg(test)]
mod utf16_to_utf8_capped_tests {
    extern crate std;

    use super::*;
    use crate::cxx::string_object::{
        StringObjectAssignCstrOps, StringObjectOps, STRING_OBJECT_ASSIGN_CSTR_OPS,
        STRING_OBJECT_OPS,
    };
    use crate::cxx::string_object::tests::STRING_OBJECT_OPS_TEST_LOCK;
    use crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut STORAGE: [[u8; 16]; 4] = [[0; 16]; 4];
    static mut NEXT_STORAGE: usize = 0;
    static mut SHORTENED: [u8; 16] = [0; 16];

    unsafe extern "C" fn allocate(
        this: *mut StringObject, requested_size: usize, _flags: u32,
    ) -> *mut u8 {
        assert!(requested_size <= 16);
        let storage = core::ptr::addr_of_mut!(STORAGE[NEXT_STORAGE]);
        NEXT_STORAGE += 1;
        let storage = storage.cast::<u8>();
        (*this).payload = storage;
        storage
    }

    unsafe extern "C" fn clear(this: *mut StringObject) {
        (*this).payload = core::ptr::null_mut();
    }

    unsafe extern "C" fn release(_this: *mut StringObject) {}

    unsafe extern "C" fn without_last_codepoint(
        out: *mut StringObject, source: *const StringObject, codepoint_count: i32,
    ) {
        assert_eq!(codepoint_count, 3);
        SHORTENED[..4].copy_from_slice(b"A\xc2\xa2\0");
        (*out).vtable = (*source).vtable;
        (*out).payload = core::ptr::addr_of_mut!(SHORTENED).cast();
    }

    struct SeamGuard {
        assign: StringObjectAssignCstrOps,
        object: StringObjectOps,
        helper: StringObjectWithoutLastCodepointHelper,
    }

    impl SeamGuard {
        unsafe fn install() -> Self {
            let guard = Self {
                assign: core::ptr::addr_of!(STRING_OBJECT_ASSIGN_CSTR_OPS).read_volatile(),
                object: core::ptr::addr_of!(STRING_OBJECT_OPS).read_volatile(),
                helper: core::ptr::addr_of!(STRING_OBJECT_WITHOUT_LAST_CODEPOINT_HELPER).read_volatile(),
            };
            core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS).write_volatile(
                StringObjectAssignCstrOps { allocate_payload: allocate, clear_payload: clear },
            );
            core::ptr::addr_of_mut!(STRING_OBJECT_OPS)
                .write_volatile(StringObjectOps { release_payload: release });
            core::ptr::addr_of_mut!(STRING_OBJECT_WITHOUT_LAST_CODEPOINT_HELPER)
                .write_volatile(without_last_codepoint);
            NEXT_STORAGE = 0;
            STORAGE = [[0; 16]; 4];
            SHORTENED = [0; 16];
            guard
        }
    }

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS).write_volatile(self.assign);
                core::ptr::addr_of_mut!(STRING_OBJECT_OPS).write_volatile(self.object);
                core::ptr::addr_of_mut!(STRING_OBJECT_WITHOUT_LAST_CODEPOINT_HELPER)
                    .write_volatile(self.helper);
            }
        }
    }

    #[test]
    fn trims_a_final_codepoint_to_the_unsigned_byte_bound() {
        let _test = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _assign = STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _object = STRING_OBJECT_OPS_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _guard = unsafe { SeamGuard::install() };
        let source = [b'A' as u16, 0xa2, b'B' as u16, 0];
        let mut destination = [0xff; 8];
        let mut byte_count = u32::MAX;

        assert_eq!(unsafe {
            utf16_to_utf8_capped(source.as_ptr(), 3, destination.as_mut_ptr(), 3, &mut byte_count)
        }, 0);
        assert_eq!(&destination[..3], b"A\xc2\xa2");
        assert_eq!(byte_count, 3);
    }

    #[test]
    fn empty_input_needs_no_destination_or_trimming() {
        let _test = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _assign = STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _object = STRING_OBJECT_OPS_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _guard = unsafe { SeamGuard::install() };
        let source = [0u16];
        let mut byte_count = u32::MAX;

        assert_eq!(unsafe {
            utf16_to_utf8_capped(source.as_ptr(), 1, core::ptr::null_mut(), 0, &mut byte_count)
        }, 0);
        assert_eq!(byte_count, 0);
    }
}
