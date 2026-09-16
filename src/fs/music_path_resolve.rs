//! Music-library path construction with a volume header @ 0x0806b4a0.
//!
//! Callers hand in a raw path string plus a 260-byte stack buffer; the
//! resolver writes a `u16` volume header followed by the NUL-terminated
//! resolved path, either under the fixed `"iPod_Control\Music\"` prefix or
//! through the retailOS volume-translation helpers.

use crate::libc::strcpy::strcpy;

/// Resident retailOS music-directory volume-digit matcher at `0x0809a7e4`.
pub const MUSIC_DIR_VOLUME_DIGIT_ADDRESS: usize = 0x0809_a7e4;

/// Resident retailOS volume path translator at `0x080ccb44`.
pub const VOLUME_PATH_TRANSLATE_ADDRESS: usize = 0x080c_cb44;

/// Fixed library prefix literal at `0x0806b530` (19 chars plus NUL).
const MUSIC_DIR_PREFIX: &[u8; 20] = b"iPod_Control\\Music\\\0";

/// Error returned when either pointer argument is NULL (`0xffffffce`).
const ERROR_NULL_ARGUMENT: i32 = -50;

/// ABI of the unported matcher `FUN_0809a7e4`: compares `path` against the
/// resident music-directory prefix and, on a match, stores the trailing
/// directory digit (0..=6) through `out_digit`; returns nonzero in r0 when
/// the caller should take the translation path.
pub type MusicDirVolumeDigit =
    unsafe extern "C" fn(path: *const u8, out_digit: *mut u32) -> i32;

/// ABI of the unported translator `FUN_080ccb44`: rewrites `path` into `dst`
/// (at most `max` bytes) when the stored volume digit selects a mapped
/// directory.
pub type VolumePathTranslate =
    unsafe extern "C" fn(dst: *mut u8, path: *const u8, max: u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_music_dir_volume_digit(
    path: *const u8,
    out_digit: *mut u32,
) -> i32 {
    let digit: MusicDirVolumeDigit =
        unsafe { core::mem::transmute(MUSIC_DIR_VOLUME_DIGIT_ADDRESS) };
    unsafe { digit(path, out_digit) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_music_dir_volume_digit(
    _path: *const u8,
    _out_digit: *mut u32,
) -> i32 {
    panic!("music_path_resolve requires volume-digit matcher 0x0809a7e4")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_volume_path_translate(
    dst: *mut u8,
    path: *const u8,
    max: u32,
) {
    let translate: VolumePathTranslate =
        unsafe { core::mem::transmute(VOLUME_PATH_TRANSLATE_ADDRESS) };
    unsafe { translate(dst, path, max) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_volume_path_translate(
    _dst: *mut u8,
    _path: *const u8,
    _max: u32,
) {
    panic!("music_path_resolve requires volume path translator 0x080ccb44")
}

/// Active volume-digit matcher. The target default calls retailOS; host
/// tests replace it to drive both branches.
#[cfg(target_os = "none")]
pub static mut MUSIC_DIR_VOLUME_DIGIT: MusicDirVolumeDigit = firmware_music_dir_volume_digit;
/// Host default deliberately reports an unported direct call.
#[cfg(not(target_os = "none"))]
pub static mut MUSIC_DIR_VOLUME_DIGIT: MusicDirVolumeDigit = missing_music_dir_volume_digit;

/// Active volume path translator. The target default calls retailOS; host
/// tests replace it because `FUN_080ccb44` remains unported.
#[cfg(target_os = "none")]
pub static mut VOLUME_PATH_TRANSLATE: VolumePathTranslate = firmware_volume_path_translate;
/// Host default deliberately reports an unported direct call.
#[cfg(not(target_os = "none"))]
pub static mut VOLUME_PATH_TRANSLATE: VolumePathTranslate = missing_volume_path_translate;

#[inline(always)]
unsafe fn music_dir_volume_digit() -> MusicDirVolumeDigit {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(MUSIC_DIR_VOLUME_DIGIT)) }
}

#[inline(always)]
unsafe fn volume_path_translate() -> VolumePathTranslate {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(VOLUME_PATH_TRANSLATE)) }
}

/// music_path_resolve — original: `FUN_0806b4a0` @ `0x0806b4a0`.
///
/// Verified extent is `0x0806b4a0..0x0806b530` (144 instruction bytes,
/// matching Ghidra's size), followed by the 20-byte prefix literal
/// `"iPod_Control\Music\"` at `0x0806b530..0x0806b544`; the next function
/// starts at `0x0806b544`. Raw decoding of every ARM B/BL in `osos.asm`
/// finds 5 direct `bl` call sites (`0x08053160`, `0x080d7214`, `0x080e2e78`,
/// `0x080e2eb4`, `0x080e5054`), all unconditional; there are no predicated
/// BLs and no tail branches.
///
/// Returns -50 when `dst` or `path` is NULL. Otherwise zeroes the `u16`
/// volume header at `dst[0]`. When the path's flag byte at `+0x24` is set,
/// copies the fixed prefix at `dst + 2` and appends the path at byte offset
/// 21. When clear, the volume-digit matcher (`0x0809a7e4`) receives `path`
/// and a stack word seeded from the fourth argument; a nonzero match routes
/// the path through the translator (`0x080ccb44`, max 0x100) at `dst + 2`
/// and stores the stack word's sign-extended low byte into the header, while
/// a zero result copies the path verbatim at `dst + 2`. Returns 0.
///
/// Deliberate deviations: the two unported callees run through volatile
/// host-test seams; the ported `strcpy` is called directly for all three
/// copies. LLVM inlines the `strcpy` bodies and lowers the constant 20-byte
/// prefix copy to `__aeabi_memcpy` (supplied weakly by compiler_builtins);
/// the semantics are identical to the original BLs.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn music_path_resolve(
    path: *const u8,
    dst: *mut u16,
    _reserved: u32,
    seed: u32,
) -> i32 {
    if dst.is_null() || path.is_null() {
        return ERROR_NULL_ARGUMENT;
    }
    unsafe {
        dst.write(0);
        let mut digit: u32 = seed;
        let body = dst.cast::<u8>().add(2);
        if path.add(0x24).read() != 0 {
            strcpy(body, MUSIC_DIR_PREFIX.as_ptr());
            strcpy(body.add(19), path);
        } else if music_dir_volume_digit()(path, &mut digit) != 0 {
            volume_path_translate()(body, path, 0x100);
            dst.write((digit as u8 as i8) as u16);
        } else {
            strcpy(body, path);
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        path: [u8; 64],
        dst: [u16; 130],
    }

    impl Fixture {
        fn new(path: &str) -> Self {
            let mut fixture = Fixture { path: [0; 64], dst: [0xbeef; 130] };
            fixture.path[..path.len()].copy_from_slice(path.as_bytes());
            fixture
        }

        fn with_flag(mut self) -> Self {
            self.path[0x24] = 1;
            self
        }

        fn resolve(&mut self, seed: u32) -> i32 {
            unsafe {
                music_path_resolve(self.path.as_ptr(), self.dst.as_mut_ptr(), 0, seed)
            }
        }

        fn header(&self) -> u16 {
            self.dst[0]
        }

        fn body(&self) -> &[u8] {
            let bytes = unsafe {
                core::slice::from_raw_parts(self.dst.as_ptr().cast::<u8>(), 260)
            };
            let end = bytes[2..].iter().position(|&b| b == 0).unwrap() + 2;
            &bytes[2..end]
        }
    }

    static mut DIGIT_RESULT: i32 = 0;
    static mut DIGIT_WRITTEN: Option<u32> = None;
    static mut TRANSLATE_CALLS: u32 = 0;
    static mut TRANSLATE_ARGS: (usize, usize, u32) = (0, 0, 0);

    unsafe extern "C" fn fake_digit(_path: *const u8, out_digit: *mut u32) -> i32 {
        unsafe {
            if let Some(value) = DIGIT_WRITTEN {
                out_digit.write(value);
            }
            DIGIT_RESULT
        }
    }

    unsafe extern "C" fn fake_translate(dst: *mut u8, path: *const u8, max: u32) {
        unsafe {
            TRANSLATE_CALLS += 1;
            TRANSLATE_ARGS = (dst as usize, path as usize, max);
        }
    }

    fn install_seams(digit: i32, written: Option<u32>) {
        unsafe {
            DIGIT_RESULT = digit;
            DIGIT_WRITTEN = written;
            TRANSLATE_CALLS = 0;
            TRANSLATE_ARGS = (0, 0, 0);
            MUSIC_DIR_VOLUME_DIGIT = fake_digit;
            VOLUME_PATH_TRANSLATE = fake_translate;
        }
    }

    #[test]
    fn null_arguments_return_error() {
        let mut dst = [0u16; 4];
        let path = b"a\0";
        unsafe {
            assert_eq!(music_path_resolve(path.as_ptr(), core::ptr::null_mut(), 0, 0), -50);
            assert_eq!(music_path_resolve(core::ptr::null(), dst.as_mut_ptr(), 0, 0), -50);
        }
    }

    #[test]
    fn flag_set_prefixes_music_dir_and_appends_path() {
        install_seams(0, None);
        let mut fixture = Fixture::new("track.mp3").with_flag();
        assert_eq!(fixture.resolve(0), 0);
        assert_eq!(fixture.header(), 0);
        assert_eq!(fixture.body(), b"iPod_Control\\Music\\track.mp3");
    }

    #[test]
    fn unmatched_digit_copies_path_verbatim() {
        install_seams(0, None);
        let mut fixture = Fixture::new("HDD1/song");
        assert_eq!(fixture.resolve(7), 0);
        assert_eq!(fixture.header(), 0);
        assert_eq!(fixture.body(), b"HDD1/song");
    }

    #[test]
    fn matched_digit_translates_and_stores_header() {
        install_seams(1, Some(4));
        let mut fixture = Fixture::new("Music/song");
        assert_eq!(fixture.resolve(0), 0);
        assert_eq!(fixture.header(), 4);
        unsafe {
            assert_eq!(TRANSLATE_CALLS, 1);
            let (dst, src, max) = TRANSLATE_ARGS;
            assert_eq!(dst, fixture.dst.as_mut_ptr() as usize + 2);
            assert_eq!(src, fixture.path.as_ptr() as usize);
            assert_eq!(max, 0x100);
        }
    }

    #[test]
    fn header_uses_sign_extended_low_byte_of_seed_when_unwritten() {
        install_seams(1, None);
        let mut fixture = Fixture::new("x");
        assert_eq!(fixture.resolve(0xff), 0);
        assert_eq!(fixture.header(), 0xffff);
    }

    #[test]
    fn header_truncates_seed_to_low_byte() {
        install_seams(1, None);
        let mut fixture = Fixture::new("x");
        assert_eq!(fixture.resolve(0x1234_567f), 0);
        assert_eq!(fixture.header(), 0x7f);
    }
}
