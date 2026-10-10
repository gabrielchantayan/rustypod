//! CFF subfont lifetime management.

use super::cff_index::{cff_index_done, CffIndex};
use super::memory::{ft_mem_free, FtMemory};

/// Retail CFF_SubFontRec fields needed for destruction. Dictionary storage
/// remains opaque; native pointers let host fixtures exercise the real callees.
#[repr(C)]
pub struct CffSubfont {
    pub dictionaries: [u32; 0x85],
    pub local_subrs_index: CffIndex,
    pub num_local_subrs: u32,
    pub local_subrs: *mut *mut u8,
}

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::offset_of!(CffSubfont, local_subrs_index) == 0x214);
    assert!(core::mem::offset_of!(CffSubfont, local_subrs) == 0x230);
    assert!(core::mem::size_of::<CffSubfont>() == 0x234);
};

/// cff_subfont_done — original FUN_0809a2a4 at 0x0809a2a4.
/// True extent [0x0809a2a4, 0x0809a2d4): 48 bytes; the next function
/// begins with push {r4-r11,lr}. Raw A32 words verify two outgoing plain
/// BLs (0x0809a2b8 to cff_index_done, 0x0809a2c4 to ft_mem_free), and
/// two incoming plain BLs (0x08082d74, 0x08082dd4); no predicated BLs.
///
/// A null subfont is inert. Otherwise destroy its local-subroutine INDEX,
/// then reload and free the local-subroutine pointer table with the supplied
/// allocator and clear that pointer. Dictionary storage and count survive.
/// The producer at 0x0809a2d4 creates the INDEX at +0x214, copies its count
/// to +0x22c, and creates the pointer table at +0x230.
///
/// Deliberate deviations: repr(C) native pointers widen host fields; ARM
/// offsets are asserted above. Volatile function-pointer loads retain the
/// existing Rust seams as in cff_index_done rather than inlining cleanup.
///
/// # Safety
/// A non-null `subfont` must be valid and its index must satisfy
/// cff_index_done's contract. A non-null local_subrs must be releasable
/// through `memory`. Callbacks must leave the subfont record valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cff_subfont_done(memory: *mut FtMemory, subfont: *mut CffSubfont) {
    if subfont.is_null() {
        return;
    }
    let done = core::ptr::read_volatile(
        &(cff_index_done as unsafe extern "C" fn(*mut CffIndex)),
    );
    done(core::ptr::addr_of_mut!((*subfont).local_subrs_index));
    let free = core::ptr::read_volatile(
        &(ft_mem_free as unsafe extern "C" fn(*mut FtMemory, *mut u8)),
    );
    free(memory, (*subfont).local_subrs.cast());
    (*subfont).local_subrs = core::ptr::null_mut();
}


#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests {
    use super::*;
    use super::super::stream::FtStream;
    use core::ptr;
    use std::vec::Vec;

    struct Releases {
        blocks: Vec<usize>,
        subfont: *mut CffSubfont,
        replacement: *mut *mut u8,
    }

    unsafe extern "C" fn alloc(_: *mut FtMemory, _: i32) -> *mut u8 { ptr::null_mut() }
    unsafe extern "C" fn realloc(_: *mut FtMemory, _: i32, _: i32, _: *mut u8) -> *mut u8 {
        ptr::null_mut()
    }
    unsafe extern "C" fn free(memory: *mut FtMemory, block: *mut u8) {
        let releases = &mut *((*memory).user as *mut Releases);
        releases.blocks.push(block as usize);
        if !releases.replacement.is_null() {
            (*releases.subfont).local_subrs = releases.replacement;
            releases.replacement = ptr::null_mut();
        }
    }
    fn subfont() -> CffSubfont {
        CffSubfont {
            dictionaries: [0x12345678; 0x85],
            local_subrs_index: CffIndex {
                stream: ptr::null_mut(), count: 7, off_size: 2, _padding: [0; 3],
                data_offset: 42, offsets: ptr::null_mut(), bytes: ptr::null_mut(),
            },
            num_local_subrs: 7, local_subrs: ptr::null_mut(),
        }
    }

    #[test]
    fn null_and_inactive_index_preserve_unowned_fields() {
        unsafe {
            cff_subfont_done(ptr::null_mut(), ptr::null_mut());
            let mut subfont = subfont();
            cff_subfont_done(ptr::null_mut(), &mut subfont);
            assert_eq!(subfont.dictionaries, [0x12345678; 0x85]);
            assert_eq!(subfont.local_subrs_index.count, 7);
            assert_eq!(subfont.local_subrs_index.data_offset, 42);
            assert_eq!(subfont.num_local_subrs, 7);
            assert!(subfont.local_subrs.is_null());
        }
    }

    #[test]
    fn cleanup_reloads_table_after_index_release_and_is_repeatable() {
        unsafe {
            let mut offsets = [1u32, 2];
            let mut old_table = [ptr::null_mut::<u8>(); 2];
            let mut new_table = [ptr::null_mut::<u8>(); 2];
            let mut subfont = subfont();
            subfont.local_subrs = old_table.as_mut_ptr();
            let mut releases = Releases {
                blocks: Vec::new(), subfont: &mut subfont,
                replacement: new_table.as_mut_ptr(),
            };
            let mut memory = FtMemory {
                user: (&mut releases as *mut Releases).cast(), alloc, free, realloc,
            };
            let mut stream = FtStream {
                base: ptr::null_mut(), size: 0, pos: 0, descriptor: ptr::null_mut(),
                pathname: ptr::null_mut(), read: None, close: None, memory: &mut memory,
                cursor: ptr::null_mut(), limit: ptr::null_mut(),
            };
            subfont.local_subrs_index.stream = &mut stream;
            subfont.local_subrs_index.offsets = offsets.as_mut_ptr();
            cff_subfont_done(&mut memory, &mut subfont);
            assert_eq!(releases.blocks, [offsets.as_mut_ptr() as usize, new_table.as_mut_ptr() as usize]);
            assert!(subfont.local_subrs.is_null());
            assert!(subfont.local_subrs_index.stream.is_null());
            assert_eq!(subfont.local_subrs_index.count, 0);
            assert_eq!(subfont.dictionaries, [0x12345678; 0x85]);
            assert_eq!(subfont.num_local_subrs, 7);
            cff_subfont_done(ptr::null_mut(), &mut subfont);
            assert_eq!(releases.blocks, [offsets.as_mut_ptr() as usize, new_table.as_mut_ptr() as usize]);
        }
    }
}
