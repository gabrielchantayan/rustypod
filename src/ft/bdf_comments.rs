//! BDF comment accumulation — FUN_0809867c @ 0x0809867c.
//! Raw A32 extent [0x0809867c, 0x08098704): 136 bytes, no literals;
//! the next entry begins with push. Two outbound plain BLs (ft_mem_realloc
//! @ 0x080986b8, __rt_memcpy veneer @ 0x080986e0), zero predicated BLs.
//! Resize comments to old length + supplied length + 1, store the returned
//! pointer even on error, then on success copy the bytes, append LF, and
//! increase the length. No NUL terminator is appended. Callers in the BDF
//! start/glyph parsers strip COMMENT and its optional following byte.
//! Deliberate deviations: native pointers in the repr(C) host fixture;
//! target fields remain at +0x54, +0x58, +0x4088. Return only the r0 error
//! (r1 is restored, not a second result). Existing allocator may inline.

use crate::ft::memory::{ft_mem_realloc, FtMemory};

/// Partial BDF font record; untouched regions retain their byte contents.
#[repr(C)]
pub struct BdfCommentFont {
    pub prefix: [u32; 21],
    pub comments: *mut u8,
    pub comments_len: i32,
    pub middle: [u32; (0x4088 - 0x5c) / 4],
    pub memory: *mut FtMemory,
}

/// Append a BDF comment and one newline, returning the FreeType error.
///
/// # Safety
/// `font` must be writable and its allocator/storage must satisfy
/// ft_mem_realloc. On success `source` must be readable for `length` bytes
/// and must not alias storage invalidated by reallocation. Counts must
/// describe valid storage; arithmetic follows the original wrapping words.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bdf_append_comment(
    font: *mut BdfCommentFont, source: *const u8, length: i32,
) -> i32 {
    let mut error = 0;
    let old_len = (*font).comments_len;
    (*font).comments = ft_mem_realloc(
        (*font).memory, 1, old_len, old_len.wrapping_add(length).wrapping_add(1),
        (*font).comments, &mut error,
    );
    if error == 0 {
        let destination = (*font).comments.wrapping_offset((*font).comments_len as isize);
        crate::libc::rt_memcpy::__rt_memcpy(destination, source, length as u32 as usize);
        *destination.wrapping_offset(length as isize) = b'\n';
        (*font).comments_len = (*font).comments_len.wrapping_add(length).wrapping_add(1);
    }
    error
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::ft::error::{FT_ERR_INVALID_ARGUMENT, FT_ERR_OUT_OF_MEMORY};

    struct Arena { bytes: [u8; 128], fail: bool }

    unsafe extern "C" fn allocate(memory: *mut FtMemory, size: i32) -> *mut u8 {
        resize(memory, 0, size, core::ptr::null_mut())
    }
    unsafe extern "C" fn release(_: *mut FtMemory, _: *mut u8) {
        panic!("comment append must not free storage");
    }
    unsafe extern "C" fn resize(
        memory: *mut FtMemory, _: i32, size: i32, _: *mut u8,
    ) -> *mut u8 {
        let arena = &mut *((*memory).user as *mut Arena);
        if arena.fail { return core::ptr::null_mut(); }
        assert!(size > 0 && size <= 126);
        arena.bytes.as_mut_ptr().add(1)
    }
    fn font(memory: *mut FtMemory, comments: *mut u8, comments_len: i32) -> BdfCommentFont {
        BdfCommentFont {
            prefix: [0x12345678; 21], comments, comments_len,
            middle: [0x87654321; (0x4088 - 0x5c) / 4], memory,
        }
    }

    #[test]
    fn append_empty_binary_and_repeated_comments_without_nul() {
        let mut arena = Arena { bytes: [0xa5; 128], fail: false };
        let mut memory = FtMemory {
            user: (&mut arena as *mut Arena).cast(),
            alloc: allocate, free: release, realloc: resize,
        };
        let mut font = font(&mut memory, core::ptr::null_mut(), 0);
        let mut expected = std::vec::Vec::new();
        for source in [&b""[..], &b"abc"[..], &b"\0\xff\n"[..], &b"last"[..]] {
            assert_eq!(unsafe { bdf_append_comment(&mut font, source.as_ptr(), source.len() as i32) }, 0);
            expected.extend_from_slice(source);
            expected.push(b'\n');
            assert_eq!(font.comments_len as usize, expected.len());
            assert_eq!(&arena.bytes[1..1 + expected.len()], expected.as_slice());
            assert_eq!(arena.bytes[0], 0xa5);
            assert!(arena.bytes[1 + expected.len()..].iter().all(|&b| b == 0xa5));
            assert_eq!(font.prefix, [0x12345678; 21]);
            assert!(font.middle.iter().all(|&w| w == 0x87654321));
        }
    }

    #[test]
    fn allocation_failure_and_invalid_count_do_not_copy_or_commit_length() {
        for (old_len, error) in [(0, FT_ERR_OUT_OF_MEMORY), (3, FT_ERR_OUT_OF_MEMORY), (-1, FT_ERR_INVALID_ARGUMENT)] {
            let mut arena = Arena { bytes: [0xa5; 128], fail: true };
            let mut memory = FtMemory {
                user: (&mut arena as *mut Arena).cast(),
                alloc: allocate, free: release, realloc: resize,
            };
            let original = if old_len == 0 { core::ptr::null_mut() }
                else { arena.bytes.as_mut_ptr().wrapping_add(1) };
            let mut font = font(&mut memory, original, old_len);
            assert_eq!(unsafe { bdf_append_comment(&mut font, core::ptr::null(), 3) }, error);
            assert_eq!(font.comments_len, old_len);
            if old_len < 0 { assert_eq!(font.comments, original); }
            else { assert!(font.comments.is_null()); }
            assert_eq!(arena.bytes, [0xa5; 128]);
        }
    }

}
