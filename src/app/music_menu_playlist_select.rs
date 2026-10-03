//! Music-menu playlist selection — `FUN_0822fb28` @ **0x0822fb28**.
//! True extent: **228 bytes**, ending at the next real entry `0x0822fc0c`;
//! 168 instruction bytes plus one literal and two padded command strings.
//! Raw words verify five plain BLs, zero predicated BLs, and three BLXs in
//! the body; inbound calls are one plain BL and one BLNE (two total).
//!
//! Sets controller byte +0xb0 to 1, creates a mode-zero query, invokes its
//! unresolved +0x38 and +0xf0 methods, and requests the cached query result
//! for (0x20005d, 0x200004, 1, 1, 0, 0). Displays MusicMenuPlaylistSelected
//! for any nonzero result, otherwise EmptyMusicPlaylistHilited, then releases
//! the temporary COW string and query and returns handled (1).
//!
//! Deviations: omit the unused allocator-residue r2 argument to the already
//! ported two-argument COW constructor. Native-width host vtable words retain
//! target word indices. The unported cache helper stays at its verified
//! firmware address; virtual targets remain unnamed runtime dispatch.

use crate::cxx::string::{cxx_string_from_cstr, cxx_string_release};
use crate::util::inner_state::query_object_create;
use crate::util::query_object_release::query_object_release_slot;

type CachedQuery = unsafe extern "C" fn(*mut u8, u32, u32, u32, u32, u32, u32) -> u32;
type QueryMethod = unsafe extern "C" fn(*mut u8);
type DisplayCommand = unsafe extern "C" fn(*mut u8, *mut *mut u8);

#[derive(Clone, Copy)]
pub struct SelectionOps {
    pub create: unsafe extern "C" fn(u32) -> *mut u8,
    pub cached_query: CachedQuery,
    pub string_create: unsafe extern "C" fn(*mut *mut u8, *const u8) -> *mut *mut u8,
    pub string_release: unsafe extern "C" fn(*mut *mut u8),
    pub query_release: unsafe extern "C" fn(*mut *mut u8) -> *mut *mut u8,
}

#[cfg(not(target_os = "none"))]
pub static mut MUSIC_MENU_PLAYLIST_SELECTION_OPS: SelectionOps = SelectionOps {
    create: query_object_create, cached_query: controller_cached_query,
    string_create: cxx_string_from_cstr, string_release: cxx_string_release,
    query_release: query_object_release_slot,
};

#[cfg(target_os = "none")]
unsafe extern "C" fn controller_cached_query(
    controller: *mut u8, first: u32, second: u32, reset: u32,
    result_kind: u32, filter: u32, option: u32,
) -> u32 {
    let function: CachedQuery = core::mem::transmute(0x0822_d12cusize);
    function(controller, first, second, reset, result_kind, filter, option)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn controller_cached_query(
    _: *mut u8, _: u32, _: u32, _: u32, _: u32, _: u32, _: u32,
) -> u32 {
    panic!("retail controller cache requires host dependency injection")
}

unsafe fn query_method(query: *mut u8, word: usize) {
    let vtable = (query as *const *const usize).read();
    let function: QueryMethod = core::mem::transmute(vtable.add(word).read());
    function(query);
}

unsafe fn select(controller: *mut u8, ops: SelectionOps) -> u32 {
    controller.add(0xb0).write(1);
    let mut query = (ops.create)(0);
    query_method(query, 0x38 / 4);
    query_method(query, 0xf0 / 4);
    let count = (ops.cached_query)(controller, 0x20005d, 0x200004, 1, 1, 0, 0);
    let command: &[u8] = if count == 0 {
        b"EmptyMusicPlaylistHilited\0"
    } else {
        b"MusicMenuPlaylistSelected\0"
    };
    let mut string = core::ptr::null_mut();
    let command = (ops.string_create)(&mut string, command.as_ptr());
    let vtable = (controller as *const *const usize).read();
    let display: DisplayCommand = core::mem::transmute(vtable.add(0x11c / 4).read());
    display(controller, command);
    (ops.string_release)(&mut string);
    (ops.query_release)(&mut query);
    1
}

/// Select the music playlist menu and display its populated/empty command.
///
/// # Safety
/// `controller` must be writable through +0xb0 and expose vtable +0x11c.
/// The query factory must return an object with +0x38, +0xf0 and +0x1c methods.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn music_menu_playlist_select(controller: *mut u8) -> u32 {
    #[cfg(not(target_os = "none"))]
    return select(controller, core::ptr::read_volatile(core::ptr::addr_of!(MUSIC_MENU_PLAYLIST_SELECTION_OPS)));
    #[cfg(target_os = "none")]
    select(controller, SelectionOps {
        create: query_object_create,
        cached_query: controller_cached_query,
        string_create: cxx_string_from_cstr,
        string_release: cxx_string_release,
        query_release: query_object_release_slot,
    })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::ffi::CStr;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut RESULT: u32 = 0;
    static mut QUERY: *mut u8 = core::ptr::null_mut();
    static mut PHASE: u32 = 0;

    unsafe extern "C" fn create(_: u32) -> *mut u8 { QUERY }
    unsafe extern "C" fn reset(_: *mut u8) { PHASE = 1; }
    unsafe extern "C" fn filter(_: *mut u8) { assert_eq!(PHASE, 1); PHASE = 2; }
    unsafe extern "C" fn cached(c: *mut u8, a: u32, b: u32, r: u32, k: u32, f: u32, o: u32) -> u32 {
        assert_eq!(PHASE, 2);
        assert_eq!(c.add(0xb0).read(), 1);
        assert_eq!((a, b, r, k, f, o), (0x20005d, 0x200004, 1, 1, 0, 0));
        RESULT
    }
    unsafe extern "C" fn string_create(slot: *mut *mut u8, text: *const u8) -> *mut *mut u8 {
        slot.write(text as *mut u8); slot
    }
    unsafe extern "C" fn display(_: *mut u8, slot: *mut *mut u8) {
        let text = CStr::from_ptr(slot.read().cast()).to_bytes();
        assert_eq!(text, if RESULT == 0 { &b"EmptyMusicPlaylistHilited"[..] } else { &b"MusicMenuPlaylistSelected"[..] });
        PHASE = 3;
    }
    unsafe extern "C" fn release_string(_: *mut *mut u8) { assert_eq!(PHASE, 3); PHASE = 4; }
    unsafe extern "C" fn release_query(slot: *mut *mut u8) -> *mut *mut u8 {
        assert_eq!(PHASE, 4); PHASE = 5; slot
    }

    #[test]
    fn empty_and_all_nonzero_counts_choose_command_and_preserve_adjacent_state() {
        let _guard = LOCK.lock();
        let mut query_vtable = [0usize; 0xf0 / 4 + 1];
        query_vtable[0x38 / 4] = reset as *const () as usize;
        query_vtable[0xf0 / 4] = filter as *const () as usize;
        let mut query = query_vtable.as_ptr();
        let mut controller_vtable = [0usize; 0x11c / 4 + 1];
        controller_vtable[0x11c / 4] = display as *const () as usize;
        let mut controller = [0xa5usize; 0xc8 / core::mem::size_of::<usize>()];
        controller[0] = controller_vtable.as_ptr() as usize;
        unsafe {
            QUERY = core::ptr::addr_of_mut!(query).cast();
            let c = controller.as_mut_ptr().cast::<u8>();
            for count in [0, 1, 0x80000000, u32::MAX] {
                RESULT = count; PHASE = 0;
                c.add(0xaf).write(0x5a); c.add(0xb0).write(0xff); c.add(0xb1).write(0xc3);
                assert_eq!(select(c, SelectionOps { create, cached_query: cached, string_create,
                    string_release: release_string, query_release: release_query }), 1);
                assert_eq!(PHASE, 5);
                assert_eq!((c.add(0xaf).read(), c.add(0xb0).read(), c.add(0xb1).read()), (0x5a, 1, 0xc3));
            }
        }
    }
}
