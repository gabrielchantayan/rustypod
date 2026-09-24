//! Activates opaque objects until their virtual query matches a target.
//!
//! `object_activate_until_query_matches` — original: `FUN_08110ac4` @
//! `0x08110ac4` (120 bytes; true extent `0x08110ac4..0x08110b3c`; the next
//! function starts with `push {r4,lr}` at `0x08110b3c`). A full raw-image A32
//! decode finds three direct, unconditional inbound `bl` calls (0x081107ac,
//! 0x081107c0, and 0x08111218), no predicated direct `bl` calls, and four
//! indirect `blx` calls in the body.
//!
//! Algorithm: set the initial object's byte at `+0x0c`, invoke each visited
//! object's vtable slot `+0x50`, then query its slot `+0x1c`. If that first
//! query equals `target`, clear the initial byte and return. Otherwise query
//! the same slot again; a zero result returns with the initial byte set, while
//! a nonzero result becomes the next object. The virtual slot identities are
//! unrecovered and deliberately unnamed. Host builds use seams because ARM
//! vtable function words are four bytes. Deliberate deviations: none.

type ObjectActivate = unsafe extern "C" fn(*mut u8);
type ObjectQuery = unsafe extern "C" fn(*mut u8) -> u32;

const ACTIVE_OFFSET: usize = 0x0c;
const ACTIVATE_SLOT: usize = 0x50;
const QUERY_SLOT: usize = 0x1c;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_object_activate(_object: *mut u8) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_object_query(_object: *mut u8) -> u32 { 0 }

#[cfg(not(target_os = "none"))]
pub static mut OBJECT_ACTIVATE: ObjectActivate = missing_object_activate;
#[cfg(not(target_os = "none"))]
pub static mut OBJECT_QUERY: ObjectQuery = missing_object_query;

#[cfg(target_os = "none")]
unsafe fn object_activate(object: *mut u8) {
    let vtable = unsafe { core::ptr::read_volatile(object.cast::<u32>()) };
    let activate_address = unsafe { core::ptr::read_volatile((vtable as *const u32).add(ACTIVATE_SLOT / 4)) };
    let activate: ObjectActivate = unsafe { core::mem::transmute(activate_address as usize) };
    unsafe { activate(object) };
}

#[cfg(target_os = "none")]
unsafe fn object_query(object: *mut u8) -> u32 {
    let vtable = unsafe { core::ptr::read_volatile(object.cast::<u32>()) };
    let query_address = unsafe { core::ptr::read_volatile((vtable as *const u32).add(QUERY_SLOT / 4)) };
    let query: ObjectQuery = unsafe { core::mem::transmute(query_address as usize) };
    unsafe { query(object) }
}

/// Activates opaque objects while their virtual query advances toward `target`.
///
/// # Safety
/// `initial` and every nonzero query result must be a valid retailOS object;
/// each object needs writable byte `+0x0c` and callable vtable slots `+0x50`
/// and `+0x1c` on ARM.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_activate_until_query_matches(initial: *mut u8, target: u32) {
    unsafe { core::ptr::write_volatile(initial.add(ACTIVE_OFFSET), 1) };
    let mut object = initial;
    loop {
        #[cfg(target_os = "none")]
        unsafe { object_activate(object) };
        #[cfg(not(target_os = "none"))]
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OBJECT_ACTIVATE))(object) };

        #[cfg(target_os = "none")]
        let query = unsafe { object_query(object) };
        #[cfg(not(target_os = "none"))]
        let query = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OBJECT_QUERY))(object) };
        if query == target {
            unsafe { core::ptr::write_volatile(initial.add(ACTIVE_OFFSET), 0) };
            return;
        }

        #[cfg(target_os = "none")]
        let next = unsafe { object_query(object) };
        #[cfg(not(target_os = "none"))]
        let next = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OBJECT_QUERY))(object) };
        if next == 0 { return; }
        object = next as usize as *mut u8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut ACTIVATED: [u32; 4] = [0; 4];
    static mut ACTIVATED_LEN: usize = 0;
    static mut QUERY_SCRIPT: [u32; 8] = [0; 8];
    static mut QUERY_INDEX: usize = 0;

    unsafe extern "C" fn record_activate(object: *mut u8) {
        ACTIVATED[ACTIVATED_LEN] = object as usize as u32;
        ACTIVATED_LEN += 1;
    }
    unsafe extern "C" fn scripted_query(_object: *mut u8) -> u32 {
        let result = QUERY_SCRIPT[QUERY_INDEX];
        QUERY_INDEX += 1;
        result
    }
    unsafe fn install(script: &[u32]) {
        OBJECT_ACTIVATE = record_activate;
        OBJECT_QUERY = scripted_query;
        ACTIVATED = [0; 4];
        ACTIVATED_LEN = 0;
        QUERY_SCRIPT = [0; 8];
        QUERY_SCRIPT[..script.len()].copy_from_slice(script);
        QUERY_INDEX = 0;
    }

    #[test]
    fn clears_initial_flag_when_first_query_matches() {
        let Some(objects) = try_map_u32_slab(hints::OBJECT_ACTIVATE_UNTIL_QUERY_MATCHES, 0x100) else { return; };
        let _lock = TEST_LOCK.lock();
        unsafe {
            objects.write_bytes(0, 0x100);
            let target = 0xfeed_beef;
            install(&[target]);
            object_activate_until_query_matches(objects, target);
            assert_eq!(objects.add(ACTIVE_OFFSET).read(), 0);
            assert_eq!(ACTIVATED_LEN, 1);
            assert_eq!(ACTIVATED[0], objects as usize as u32);
            assert_eq!(QUERY_INDEX, 1);
        }
    }

    #[test]
    fn leaves_initial_flag_set_when_query_cannot_advance() {
        let Some(objects) = try_map_u32_slab(hints::OBJECT_ACTIVATE_UNTIL_QUERY_MATCHES, 0x100) else { return; };
        let _lock = TEST_LOCK.lock();
        unsafe {
            objects.write_bytes(0, 0x100);
            install(&[7, 0]);
            object_activate_until_query_matches(objects, 9);
            assert_eq!(objects.add(ACTIVE_OFFSET).read(), 1);
            assert_eq!(ACTIVATED_LEN, 1);
            assert_eq!(QUERY_INDEX, 2);
        }
    }

    #[test]
    fn advances_only_after_the_second_nonzero_query() {
        let Some(objects) = try_map_u32_slab(hints::OBJECT_ACTIVATE_UNTIL_QUERY_MATCHES, 0x100) else { return; };
        let _lock = TEST_LOCK.lock();
        unsafe {
            objects.write_bytes(0, 0x100);
            let next = objects.add(0x20);
            let target = 0xabc;
            install(&[next as usize as u32, next as usize as u32, target]);
            object_activate_until_query_matches(objects, target);
            assert_eq!(objects.add(ACTIVE_OFFSET).read(), 0);
            assert_eq!(ACTIVATED_LEN, 2);
            assert_eq!(ACTIVATED[0], objects as usize as u32);
            assert_eq!(ACTIVATED[1], next as usize as u32);
            assert_eq!(QUERY_INDEX, 3);
        }
    }
}
