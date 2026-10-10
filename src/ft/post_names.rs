//! SFNT `post` glyph-name loading.

use crate::ft::stream::{ft_stream_skip, FtStream};

type GotoTable = unsafe extern "C" fn(*mut PostNamesFace, u32, *mut FtStream, *mut u32) -> i32;
#[cfg(target_os = "none")]
type LoadNames = unsafe extern "C" fn(*mut PostNamesFace, *mut FtStream) -> i32;

/// Partial face layout: padding is in target words, pointers widen on hosts.
#[repr(C)]
pub struct PostNamesFace {
    prefix: [u32; 0x68 / 4],
    pub stream: *mut FtStream,
    before_format: [u32; (0x1d0 - 0x6c) / 4],
    pub format: u32,
    before_goto: [u32; (0x1f8 - 0x1d4) / 4],
    pub goto_table: GotoTable,
    before_loaded: [u32; (0x260 - 0x1fc) / 4],
    pub loaded: u8,
}

/// Load glyph names — `FUN_080911cc` at `0x080911cc`.
/// True extent [0x080911cc, 0x0809124c): 128 bytes, comprising 124 bytes
/// of code and the four-byte `post` tag literal. Three plain outgoing BLs,
/// zero predicated BLs, one indirect BLX; two incoming plain BL sites.
/// Locate `post`, snapshot its format, skip its 32-byte header, then invoke
/// the format 2.0 or 2.5 loader. Other formats return error 3. Mark names
/// loaded even on a format-loader error, but not on locate/skip errors.
/// Deliberate deviations: native-width pointers in the host partial layout;
/// unported loaders remain fixed-address firmware calls on the target.
///
/// # Safety
/// `face` must have the retail face layout on ARM, including storage required
/// by its callbacks and the format loaders. Its stream and goto callback must
/// be valid. Host execution of supported formats needs the firmware loaders.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sfnt_load_post_names(face: *mut PostNamesFace) -> i32 {
    load_post_names_with(face, |format, face, stream| {
        #[cfg(target_os = "none")]
        {
            let address = if format == 0x20000 { 0x080893a0usize } else { 0x080895c0usize };
            let load: LoadNames = core::mem::transmute(address);
            load(face, stream)
        }
        #[cfg(not(target_os = "none"))]
        {
            let _ = (format, face, stream);
            panic!("post format loaders require retailOS");
        }
    })
}

unsafe fn load_post_names_with(
    face: *mut PostNamesFace,
    load: impl FnOnce(u32, *mut PostNamesFace, *mut FtStream) -> i32,
) -> i32 {
    let stream = (*face).stream;
    let error = ((*face).goto_table)(face, 0x706f7374, stream, core::ptr::null_mut());
    if error != 0 { return error; }
    let format = (*face).format;
    let error = ft_stream_skip(stream, 32);
    if error != 0 { return error; }
    let error = match format {
        0x20000 | 0x28000 => load(format, face, stream),
        _ => 3,
    };
    (*face).loaded = 1;
    error
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::null_mut;

    unsafe extern "C" fn locate(face: *mut PostNamesFace, tag: u32, stream: *mut FtStream, length: *mut u32) -> i32 {
        assert_eq!(tag, 0x706f7374);
        assert!(length.is_null());
        assert_eq!((*face).stream, stream);
        (*stream).pos = 7;
        0
    }

    unsafe extern "C" fn missing(_: *mut PostNamesFace, _: u32, _: *mut FtStream, _: *mut u32) -> i32 { 0x8e }

    fn fixture(size: u32, format: u32) -> (FtStream, PostNamesFace) {
        let stream = FtStream {
            base: null_mut(), size, pos: 0, descriptor: null_mut(), pathname: null_mut(),
            read: None, close: None, memory: null_mut(), cursor: null_mut(), limit: null_mut(),
        };
        let face = PostNamesFace {
            prefix: [0; 26], stream: null_mut(), before_format: [0; 89], format,
            before_goto: [0; 9], goto_table: locate, before_loaded: [0; 25], loaded: 0,
        };
        (stream, face)
    }

    #[test]
    fn format_results_mark_loaded_even_on_failure() {
        for format in [0x20000, 0x28000] {
            for result in [0, 3, -7] {
                let (mut stream, mut face) = fixture(39, format);
                face.stream = &mut stream;
                let error = unsafe { load_post_names_with(&mut face, |seen, face, stream| {
                    assert_eq!(seen, format);
                    assert_eq!((*stream).pos, 39);
                    // Loader errors may leave partial state; the loaded flag still commits.
                    (*face).format = 0xdead;
                    result
                }) };
                assert_eq!(error, result);
                assert_eq!(face.loaded, 1);
                assert_eq!(face.format, 0xdead);
            }
        }
    }

    #[test]
    fn unknown_formats_skip_header_and_commit_invalid_format() {
        for format in [0, 0x10000, 0x30000, u32::MAX] {
            let (mut stream, mut face) = fixture(39, format);
            face.stream = &mut stream;
            assert_eq!(unsafe { sfnt_load_post_names(&mut face) }, 3);
            assert_eq!((stream.pos, face.loaded), (39, 1));
        }
    }

    #[test]
    fn early_errors_leave_loaded_flag_unchanged() {
        for loaded in [0, 9] {
            let (mut stream, mut face) = fixture(38, 0x20000);
            face.stream = &mut stream;
            face.loaded = loaded;
            assert_eq!(unsafe { load_post_names_with(&mut face, |_, _, _| panic!("loader after failed skip")) }, 0x55);
            assert_eq!((stream.pos, face.loaded), (39, loaded));
            face.goto_table = missing;
            stream.pos = 2;
            assert_eq!(unsafe { load_post_names_with(&mut face, |_, _, _| panic!("loader after missing table")) }, 0x8e);
            assert_eq!((stream.pos, face.loaded), (2, loaded));
        }
    }
}
