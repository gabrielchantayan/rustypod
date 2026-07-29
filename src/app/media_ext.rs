//! File-extension probes for the media loaders.

use crate::libc::strlen::strlen;
use crate::libc::strncmp::strncmp;
use crate::libc::strncpy::strncpy;

/// is_mpeg4_container_extension — original: `FUN_080ed7c0` @ 0x080ed7c0
/// (180 bytes; 1 `bl` call site, @ 0x0803bf48).
///
/// Tests whether `path` ends in one of the MPEG-4 container family's
/// three-letter extensions. Copies the LAST THREE BYTES of the string
/// into a 3-byte stack buffer with [`strncpy`], ASCII-lowercases them
/// in place (the classic `sub #0x41` / `cmp #25` / `addls #32` range
/// test — only `'A'..='Z'` fold), then [`strncmp`]s the buffer, `n =
/// 3`, against four literals held in the function's own constant pool
/// at 0x080ed874: `"m4v"`, `"m4p"`, `"mp4"`, `"mov"`. Returns 1 on any
/// match, 0 otherwise.
///
/// Faithful details:
/// - The extension is the last three bytes *unconditionally* — there
///   is no `'.'` check, so a three-character filename with no
///   extension is tested as if it were one, and a two-character
///   filename reads one byte *before* the string start (the original
///   computes `path + strlen(path) - 3` with no length guard).
/// - The lowercase loop runs over the buffer by INDEX (`ldrb/strbls
///   [r3, r0]`), exactly three bytes, NUL included when the source
///   ended early.
///
/// Codegen deviations (behavior proven by the tests): LLVM inlines all
/// three libc calls — the strlen and the 3-byte strncpy become open
/// loops, the four strncmp calls fold into a constant decision tree,
/// and the inlined strncpy's zero-pad arm lowers to `__aeabi_memclr`
/// (pre-existing undefined references of that family already sit in the
/// archive and resolve at the firmware link).
///
/// # Safety
/// `path` must be a NUL-terminated string of at least 3 bytes —
/// shorter strings make the original (and this port) read before the
/// start of the string.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn is_mpeg4_container_extension(path: *const u8) -> u32 {
    const EXTENSIONS: [&[u8; 4]; 4] = [b"m4v\0", b"m4p\0", b"mp4\0", b"mov\0"];
    let mut buffer = [0u8; 3];
    let len = strlen(path);
    strncpy(buffer.as_mut_ptr(), path.add(len).sub(3), 3);
    for i in 0..3 {
        let cell = buffer.as_mut_ptr().add(i);
        let byte = cell.read_volatile();
        if byte.wrapping_sub(0x41) <= 0x19 {
            cell.write_volatile(byte + 0x20);
        }
    }
    for extension in EXTENSIONS {
        if strncmp(buffer.as_ptr(), extension.as_ptr(), 3) == 0 {
            return 1;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Pads the front so the under-read of a shorter-than-3 string is
    /// in-bounds and controllable.
    fn probe(bytes: &[u8]) -> u32 {
        let mut buf: Vec<u8> = std::iter::repeat(b'?').take(8).collect();
        buf.extend_from_slice(bytes);
        unsafe { is_mpeg4_container_extension(buf.as_ptr().add(8)) }
    }

    #[test]
    fn accepts_the_four_extensions_case_insensitively() {
        assert_eq!(probe(b".m4v\0"), 1);
        assert_eq!(probe(b".m4p\0"), 1);
        assert_eq!(probe(b".mp4\0"), 1);
        assert_eq!(probe(b".mov\0"), 1);
        assert_eq!(probe(b".M4V\0"), 1);
        assert_eq!(probe(b".M4P\0"), 1);
        assert_eq!(probe(b".MP4\0"), 1);
        assert_eq!(probe(b".MOV\0"), 1);
        assert_eq!(probe(b"song.Mp4\0"), 1);
        assert_eq!(probe(b"video.MoV\0"), 1);
    }

    #[test]
    fn rejects_other_extensions() {
        assert_eq!(probe(b".mp3\0"), 0);
        assert_eq!(probe(b".m4a\0"), 0);
        assert_eq!(probe(b".aac\0"), 0);
        assert_eq!(probe(b".wav\0"), 0);
        assert_eq!(probe(b".jpg\0"), 0);
        assert_eq!(probe(b".moVz\0"), 0, "the window is \"oVz\", not \"mov\"");
        assert_eq!(probe(b".zmoV\0"), 1, "the last three bytes are \"moV\"");
        assert_eq!(probe(b".m4vx\0"), 0, "the window is \"4vx\", not \"m4v\"");
    }

    #[test]
    fn there_is_no_dot_check() {
        // A 3-character name with no dot is tested as if it were an
        // extension; longer names only contribute their last 3 bytes.
        assert_eq!(probe(b"m4v\0"), 1);
        assert_eq!(probe(b"mov\0"), 1);
        assert_eq!(probe(b"xyz\0"), 0);
        assert_eq!(probe(b"amov\0"), 1, "the last three bytes are \"mov\"");
    }

    #[test]
    fn non_letters_are_not_folded() {
        // Bytes outside 'A'..='Z' pass through unchanged: 0x11 ('Q'-0x50)
        // wraps the sub past the range test, digits and punctuation stay.
        assert_eq!(probe(b".m4V\0"), 1);
        assert_eq!(probe(b".m{v\0"), 0, "0x7b is outside the fold range");
        assert_eq!(probe(b".M4v\0"), 1);
    }

    #[test]
    fn the_lowercase_loop_stops_at_exactly_three_bytes() {
        // An uppercase letter just before the extension must survive
        // untouched — the fold covers the copied window only.
        assert_eq!(probe(b"AMP4\0"), 1, "folded window is \"MP4\"");
    }
}
