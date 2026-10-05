//! Plays a named sequence, falling back to the manager's default sequence.
//!
//! `FUN_081a2b24` @ 0x081a2b24: true extent 132 bytes through 0x081a2ba8
//! (128 code bytes and the empty-string word at 0x081a2ba4). The next entry
//! starts with push. Raw A32: five plain and two predicated outbound BLs;
//! one plain inbound BL at 0x0821646c and one BLNE at 0x0810a028.
//!
//! Compare the supplied StringObject with a constructed empty string; destroy
//! that temporary before lookup. Empty names do nothing. For nonempty names,
//! look up the sequence, initialize the default on a miss, and play the returned
//! sequence. In particular, the initializer's r0 flows into playback unchanged.
//! Deviations: the empty literal is modeled as a static byte; existing string
//! ports model the vtable and host pointer width. The three unported sequence
//! callees use verified retail addresses on target and mandatory host seams.

//! LLVM removes the C-string null guard because the existing accessor always
//! returns a non-null shared empty string; no reachable behavior is changed.
use crate::cxx::string_object::{StringObject, string_object_c_str,
    string_object_construct_from_cstr, string_object_differs, string_object_destroy};
use core::mem::MaybeUninit;

type FindSequence = unsafe extern "C" fn(*mut u8, *const StringObject) -> *mut u8;
type DefaultSequence = unsafe extern "C" fn(*mut u8) -> *mut u8;
type PlaySequence = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_find(_: *mut u8, _: *const StringObject) -> *mut u8 {
    panic!("install named sequence lookup host seam")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_default(_: *mut u8) -> *mut u8 {
    panic!("install default sequence host seam")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_play(_: *mut u8) {
    panic!("install sequence playback host seam")
}
#[cfg(not(target_os = "none"))]
pub static mut NAMED_SEQUENCE_FIND: FindSequence = missing_find;
#[cfg(not(target_os = "none"))]
pub static mut NAMED_SEQUENCE_DEFAULT: DefaultSequence = missing_default;
#[cfg(not(target_os = "none"))]
pub static mut NAMED_SEQUENCE_PLAY: PlaySequence = missing_play;

/// # Safety
/// `name` must be a valid StringObject. For nonempty names, `manager` must
/// satisfy retail lookup 0x081a2820 and default initialization 0x081a2998.
/// Their result must satisfy playback 0x0826c884, including its count at
/// +0xfac and halfword pairs starting at +0x0c. No null-result guard is added.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn named_sequence_play(manager: *mut u8, name: *const StringObject) {
    if string_object_c_str(name).is_null() { return; }
    let mut empty = MaybeUninit::<StringObject>::uninit();
    string_object_construct_from_cstr(empty.as_mut_ptr(), b"\0".as_ptr());
    let nonempty = string_object_differs(name, empty.as_ptr()) != 0;
    string_object_destroy(empty.as_mut_ptr());
    if !nonempty { return; }

    #[cfg(target_os = "none")]
    let (find, default, play): (FindSequence, DefaultSequence, PlaySequence) = (
        core::mem::transmute(0x081a_2820usize),
        core::mem::transmute(0x081a_2998usize),
        core::mem::transmute(0x0826_c884usize));
    #[cfg(not(target_os = "none"))]
    let (find, default, play) = (
        core::ptr::addr_of!(NAMED_SEQUENCE_FIND).read(),
        core::ptr::addr_of!(NAMED_SEQUENCE_DEFAULT).read(),
        core::ptr::addr_of!(NAMED_SEQUENCE_PLAY).read());
    let mut sequence = find(manager, name);
    if sequence.is_null() { sequence = default(manager); }
    play(sequence);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[repr(C)]
    struct Fixture {
        selected: *mut u8,
        fallback: *mut u8,
        initializations: u32,
    }
    unsafe extern "C" fn find(manager: *mut u8, _: *const StringObject) -> *mut u8 {
        (*manager.cast::<Fixture>()).selected
    }
    unsafe extern "C" fn default(manager: *mut u8) -> *mut u8 {
        let fixture = &mut *manager.cast::<Fixture>();
        fixture.initializations += 1;
        fixture.fallback
    }
    unsafe extern "C" fn play(sequence: *mut u8) {
        // A host playback implementation consumes the selected sequence.
        *sequence = (*sequence).wrapping_add(1);
    }
    #[test]
    fn empty_names_skip_playback_and_nonempty_names_select_or_initialize() {
        unsafe {
            let saved = (NAMED_SEQUENCE_FIND, NAMED_SEQUENCE_DEFAULT, NAMED_SEQUENCE_PLAY);
            NAMED_SEQUENCE_FIND = find;
            NAMED_SEQUENCE_DEFAULT = default;
            NAMED_SEQUENCE_PLAY = play;
            for payload in [core::ptr::null_mut(), b"\0".as_ptr() as *mut u8,
                b"tone\0".as_ptr() as *mut u8, b"\xc3\xa9\0".as_ptr() as *mut u8] {
                for found in [false, true] {
                    let mut selected = 10u8;
                    let mut fallback = 20u8;
                    let mut fixture = Fixture { selected: if found { &mut selected } else { core::ptr::null_mut() },
                        fallback: &mut fallback, initializations: 0 };
                    let name = StringObject { vtable: core::ptr::null(), payload };
                    named_sequence_play((&mut fixture as *mut Fixture).cast(), &name);
                    let active = !payload.is_null() && *payload != 0;
                    assert_eq!(selected, 10 + u8::from(active && found));
                    assert_eq!(fallback, 20 + u8::from(active && !found));
                    assert_eq!(fixture.initializations, u32::from(active && !found));
                }
            }
            (NAMED_SEQUENCE_FIND, NAMED_SEQUENCE_DEFAULT, NAMED_SEQUENCE_PLAY) = saved;
        }
    }
}
