//! Windows FNT font teardown.

use crate::ft::memory::{ft_mem_free, FtMemory};
use crate::ft::stream::{ft_stream_release_frame, FtStream};

/// `FUN_0808487c` @ 0x0808487c, 84 bytes, ending at the next PUSH
/// @ 0x080848d0. Two outgoing plain BLs and one BLNE; two incoming
/// plain BLs, no predicated BLs (whole-image A32 word scan).
///
/// Snapshot face memory (+0x64) and font (+0x84). If a font exists,
/// release its non-null extracted frame (+0xa4) through face stream
/// (+0x68), then free its glyph offsets (+0xac), clear that slot, free
/// the font, and finally clear face->font. Allocator callbacks may mutate
/// the face; the saved allocator and font remain authoritative.
///
/// Deliberate deviation: a native-width temporary frame slot bridges the
/// existing stream API on hosts; the actual target-width slot is cleared
/// immediately after release. ARM fields remain aligned four-byte words.
///
/// # Safety
/// `face` must contain at least 34 aligned u32 words. Non-null font must
/// contain 44 words, with valid allocator-owned blocks and a valid stream
/// when its frame is non-null. Callbacks must keep these records writable
/// until the corresponding final release.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fnt_font_done(face: *mut u32) {
    let font = face.add(0x84 / 4).read() as usize as *mut u32;
    let memory = face.add(0x64 / 4).read() as usize as *mut FtMemory;
    let stream = face.add(0x68 / 4).read() as usize as *mut FtStream;
    if font.is_null() {
        return;
    }
    let mut frame = font.add(0xa4 / 4).read() as usize as *mut u8;
    if !frame.is_null() {
        ft_stream_release_frame(stream, &mut frame);
        font.add(0xa4 / 4).write(0);
    }
    ft_mem_free(memory, font.add(0xac / 4).read() as usize as *mut u8);
    font.add(0xac / 4).write(0);
    ft_mem_free(memory, font.cast());
    face.add(0x84 / 4).write(0);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    struct Recorder {
        face: *mut u32,
        font: *mut u32,
        calls: Vec<(usize, u32, u32, u32)>,
    }

    unsafe extern "C" fn alloc(_: *mut FtMemory, _: i32) -> *mut u8 {
        panic!("unexpected allocation")
    }
    unsafe extern "C" fn realloc(_: *mut FtMemory, _: i32, _: i32, _: *mut u8) -> *mut u8 {
        panic!("unexpected reallocation")
    }
    unsafe extern "C" fn free(memory: *mut FtMemory, block: *mut u8) {
        let record = &mut *((*memory).user as *mut Recorder);
        record.calls.push((block as usize, record.face.add(33).read(),
                           record.font.add(41).read(), record.font.add(43).read()));
        // Subsequent releases must still use the snapshotted allocator.
        record.face.add(25).write(0);
    }
    unsafe extern "C" fn read(_: *mut FtStream, _: u32, _: *mut u8, _: u32) -> u32 {
        panic!("unexpected stream read")
    }

    #[test]
    fn teardown_preserves_release_order_and_handles_absent_resources() {
        let Some(base) = crate::testing::try_map_u32_slab(
            crate::testing::hints::FNT_FONT_DONE, 0x1000,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture("ft/fnt_font"));
            return;
        };
        unsafe {
            let face = base.cast::<u32>();
            let font = base.add(0x100).cast::<u32>();
            let memory = base.add(0x200).cast::<FtMemory>();
            let stream = base.add(0x300).cast::<FtStream>();
            let frame = base.add(0x400);
            let offsets = base.add(0x500);
            let mut record = Recorder { face, font, calls: Vec::new() };
            memory.write(FtMemory { user: (&mut record as *mut Recorder).cast(), alloc, free, realloc });
            for disk in [false, true] {
                for has_frame in [false, true] {
                    for has_offsets in [false, true] {
                        base.write_bytes(0x5a, 0x1b0);
                        face.add(25).write(memory as usize as u32);
                        face.add(26).write(stream as usize as u32);
                        face.add(33).write(font as usize as u32);
                        let frame_word = if has_frame { frame as usize as u32 } else { 0 };
                        let offsets_word = if has_offsets { offsets as usize as u32 } else { 0 };
                        font.add(41).write(frame_word);
                        font.add(43).write(offsets_word);
                        stream.write(FtStream {
                            base: core::ptr::null_mut(), size: 0, pos: 0,
                            descriptor: core::ptr::null_mut(), pathname: core::ptr::null_mut(),
                            read: if disk { Some(read) } else { None }, close: None,
                            memory, cursor: core::ptr::null_mut(), limit: core::ptr::null_mut(),
                        });
                        record.calls.clear();
                        fnt_font_done(face);
                        let font_word = font as usize as u32;
                        let mut expected = Vec::new();
                        if disk && has_frame {
                            expected.push((frame as usize, font_word, frame_word, offsets_word));
                        }
                        if has_offsets {
                            expected.push((offsets as usize, font_word, 0, offsets_word));
                        }
                        expected.push((font as usize, font_word, 0, 0));
                        assert_eq!(record.calls, expected);
                        assert_eq!(face.add(33).read(), 0);
                        assert_eq!(font.add(41).read(), 0);
                        assert_eq!(font.add(43).read(), 0);
                        assert_eq!(font.add(42).read(), 0x5a5a5a5a);
                        assert_eq!(face.add(32).read(), 0x5a5a5a5a);
                    }
                }
            }
            record.calls.clear();
            face.add(25).write(0);
            face.add(26).write(0);
            fnt_font_done(face);
            assert!(record.calls.is_empty());
            assert_eq!(face.add(33).read(), 0);
        }
    }
}
