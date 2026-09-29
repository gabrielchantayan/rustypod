//! `fat_dirent_populate_names` — original: `FUN_082e4970` @ `0x082e4970`.
//!
//! Raw `osos.dec` establishes the 160-byte extent `0x082e4970..0x082e4a0f`:
//! the next independently entered function begins at `0x082e4a10`. Whole-image
//! ARM decoding finds two inbound plain `bl` instructions and no predicated
//! `bl` forms. The body has four unconditional calls: two byte copies, the
//! shared 8.3 renderer, and the resident long-name builder.
//!
//! It copies the 8.3 fields from the selected directory entry into the path
//! object, renders their display form at `+0x10d`, copies the FAT metadata at
//! `+0x11c..+0x127`, then lets the resident long-name builder replace that
//! display form. If no long name was produced, it renders the 8.3 form again
//! into the same buffer. Deliberate deviation: the shared 8.3 renderer is
//! reproduced locally, while the unported long-name builder remains a verified
//! retailOS-address boundary with a recording host seam.

use crate::libc::forward_byte_copy::forward_byte_copy;
use crate::fs::fat_short_name_render::fat_short_name_render;

const DIRENT_POINTER_OFFSET: usize = 0x240;
const DISPLAY_NAME_OFFSET: usize = 0x10d;
const METADATA_OFFSET: usize = 0x11c;

type LongNameBuild = unsafe extern "C" fn(*mut u8, *const u8, *mut u8);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn build_long_name(volume: *mut u8, entry: *const u8, output: *mut u8) {
    let builder: LongNameBuild = unsafe { core::mem::transmute(0x082e44b4usize) };
    unsafe { builder(volume, entry, output) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_long_name_builder(_: *mut u8, _: *const u8, _: *mut u8) {
    panic!("fat_dirent_populate_names called without a long-name builder seam")
}
#[cfg(not(target_os = "none"))]
static mut LONG_NAME_BUILDER: LongNameBuild = unavailable_long_name_builder;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn build_long_name(volume: *mut u8, entry: *const u8, output: *mut u8) {
    unsafe { LONG_NAME_BUILDER(volume, entry, output) };
}


/// Populates a FAT path object's raw 8.3, display-name, and directory metadata fields.
///
/// Original: `FUN_082e4970` at `0x082e4970`, 160 bytes; two binary-verified
/// inbound plain-`bl` call sites and zero predicated inbound `bl` forms.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.fat_dirent_populate_names")]
#[inline(never)]
pub unsafe extern "C" fn fat_dirent_populate_names(path: *mut u8) -> *mut u8 {
    let dirent_context = unsafe { path.add(DIRENT_POINTER_OFFSET).cast::<u32>().read() } as usize as *mut u8;
    let entry = unsafe { dirent_context.add(4).cast::<u32>().read() } as usize as *const u8;
    unsafe { forward_byte_copy(path, entry, 8) };
    unsafe { path.add(8).write(0) };
    unsafe { forward_byte_copy(path.add(9), entry.add(8), 3) };
    unsafe { path.add(12).write(0) };
    let display_name = unsafe { fat_short_name_render(path.add(DISPLAY_NAME_OFFSET), path, path.add(9)) };
    unsafe { path.add(METADATA_OFFSET).write(entry.add(11).read()) };
    unsafe { path.add(METADATA_OFFSET + 2).cast::<u16>().write(entry.add(0x16).cast::<u16>().read()) };
    unsafe { path.add(METADATA_OFFSET + 4).cast::<u16>().write(entry.add(0x18).cast::<u16>().read()) };
    unsafe { path.add(METADATA_OFFSET + 8).cast::<u32>().write(entry.add(0x1c).cast::<u32>().read()) };
    let volume = unsafe { dirent_context.cast::<u32>().read() } as usize as *mut u8;
    unsafe { build_long_name(volume, entry.add(0x40), display_name) };
    if unsafe { display_name.read() } == 0 {
        unsafe { fat_short_name_render(display_name, path, path.add(9)) }
    } else {
        display_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use core::ptr;
    use parking_lot::{Mutex, MutexGuard};

    static LOCK: Mutex<()> = Mutex::new(());
    static mut LONG_NAME: [u8; 32] = [0; 32];
    static mut SEEN: (*mut u8, *const u8) = (ptr::null_mut(), ptr::null());

    unsafe extern "C" fn record_long_name(volume: *mut u8, entry: *const u8, output: *mut u8) {
        unsafe { SEEN = (volume, entry) };
        let mut index = 0;
        while unsafe { LONG_NAME[index] } != 0 {
            unsafe { output.add(index).write(LONG_NAME[index]) };
            index += 1;
        }
        unsafe { output.add(index).write(0) };
    }

    struct Restore(LongNameBuild);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { LONG_NAME_BUILDER = self.0 } }
    }
    unsafe fn install() -> (MutexGuard<'static, ()>, Restore) {
        let lock = LOCK.lock();
        let previous = unsafe { LONG_NAME_BUILDER };
        unsafe { LONG_NAME_BUILDER = record_long_name; LONG_NAME = [0; 32]; SEEN = (ptr::null_mut(), ptr::null()) };
        (lock, Restore(previous))
    }

    #[test]
    fn copies_metadata_and_retains_a_long_name() {
        let Some(slab) = try_map_u32_slab(hints::FAT_DIRENT_POPULATE_NAMES, 0x1000) else { return; };
        let (_lock, _restore) = unsafe { install() };
        unsafe {
            slab.write_bytes(0, 0x1000);
            let path = slab;
            let context = slab.add(0x300);
            let entry = slab.add(0x500);
            core::ptr::write_unaligned(path.add(DIRENT_POINTER_OFFSET).cast::<u32>(), context as usize as u32);
            context.cast::<u32>().write(slab.add(0x700) as usize as u32);
            context.add(4).cast::<u32>().write(entry as usize as u32);
            ptr::copy_nonoverlapping(b"README  TXT".as_ptr(), entry, 11);
            entry.add(11).write(0x21);
            ptr::write_unaligned(entry.add(0x16).cast::<u16>(), 0x1234);
            ptr::write_unaligned(entry.add(0x18).cast::<u16>(), 0x5678);
            ptr::write_unaligned(entry.add(0x1c).cast::<u32>(), 0x9abc_def0);
            LONG_NAME[..10].copy_from_slice(b"Read Me!\0\0");
            assert_eq!(fat_dirent_populate_names(path), path.add(DISPLAY_NAME_OFFSET));
            assert_eq!(&*core::slice::from_raw_parts(path, 13), b"README  \0TXT\0");
            assert_eq!(&*core::slice::from_raw_parts(path.add(DISPLAY_NAME_OFFSET), 9), b"Read Me!\0");
            assert_eq!(path.add(METADATA_OFFSET).read(), 0x21);
            assert_eq!(ptr::read_unaligned(path.add(METADATA_OFFSET + 2).cast::<u16>()), 0x1234);
            assert_eq!(ptr::read_unaligned(path.add(METADATA_OFFSET + 4).cast::<u16>()), 0x5678);
            assert_eq!(ptr::read_unaligned(path.add(METADATA_OFFSET + 8).cast::<u32>()), 0x9abc_def0);
            assert_eq!(SEEN, (slab.add(0x700), entry.add(0x40).cast_const()));
        }
    }

    #[test]
    fn falls_back_to_trimmed_short_name_when_long_name_is_empty() {
        let Some(slab) = try_map_u32_slab(hints::FAT_DIRENT_POPULATE_NAMES, 0x1000) else { return; };
        let (_lock, _restore) = unsafe { install() };
        unsafe {
            slab.write_bytes(0, 0x1000);
            let context = slab.add(0x300);
            let entry = slab.add(0x500);
            ptr::write_unaligned(slab.add(DIRENT_POINTER_OFFSET).cast::<u32>(), context as usize as u32);
            context.add(4).cast::<u32>().write(entry as usize as u32);
            ptr::copy_nonoverlapping(b"A       \0\0\0".as_ptr(), entry, 11);
            fat_dirent_populate_names(slab);
            assert_eq!(&*core::slice::from_raw_parts(slab.add(DISPLAY_NAME_OFFSET), 2), b"A\0");
        }
    }
}
