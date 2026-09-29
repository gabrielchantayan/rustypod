//! Path-resolution node construction for a mounted volume.
//!
//! `path_node_create_for_volume` is retailOS `FUN_082e21dc` at `0x082e21dc`.
//! Load address: `0x082e21dc`; true size: 120 bytes (`0x78`), from `push
//! {r4,r5,r6,lr}` through `pop {r4,r5,r6,pc}` at `0x082e2250`; the next
//! separately entered function starts at `0x082e2254`. Raw ARM decoding finds
//! four direct, plain `bl` instructions and no predicated `bl`: node creation
//! at `0x082e21e4`, shared-data lookup at `0x082e21fc`, shared-data release
//! at `0x082e220c`, and initialization at `0x082e2224`.
//!
//! Creates a path node, reuses matching shared data for `(volume, 0, 0)` or
//! initializes the node's new data block with that key, then sets the node's
//! volume pointer and two cursor words from volume `+0x70`. Deliberate
//! deviation: calls the already ported helpers rather than the original direct
//! `bl` instructions; their target behavior is identical.

use super::path_node::path_node_create;
use super::shared_data::{shared_data_find_and_retain, shared_data_initialize, shared_data_release};

const WORD: usize = core::mem::size_of::<*mut u8>();

#[inline(always)]
const fn target_word_offset(target_offset: usize) -> usize {
    target_offset / 4 * WORD
}

#[inline(always)]
unsafe fn write_pointer(base: *mut u8, target_offset: usize, value: *mut u8) {
    (base.add(target_word_offset(target_offset)) as *mut *mut u8).write(value);
}

#[inline(always)]
unsafe fn read_word(base: *const u8, target_offset: usize) -> u32 {
    (base.add(target_word_offset(target_offset)) as *const u32).read()
}

#[inline(always)]
unsafe fn write_word(base: *mut u8, target_offset: usize, value: u32) {
    (base.add(target_word_offset(target_offset)) as *mut u32).write(value);
}

#[cfg(test)]
type HostOps = unsafe extern "C" fn(*mut u8, u32, u32, u32) -> *mut u8;

#[cfg(test)]
unsafe extern "C" fn default_create(_volume: *mut u8, _cluster: u32, _entry: u32, _unused: u32) -> *mut u8 {
    path_node_create()
}

#[cfg(test)]
unsafe extern "C" fn default_find(volume: *mut u8, cluster: u32, entry: u32, _unused: u32) -> *mut u8 {
    shared_data_find_and_retain(volume as usize as u32, cluster, entry)
}

#[cfg(test)]
unsafe extern "C" fn default_initialize(data: *mut u8, volume: u32, cluster: u32, entry: u32) -> *mut u8 {
    shared_data_initialize(data, volume, cluster, entry);
    core::ptr::null_mut()
}

#[cfg(test)]
unsafe extern "C" fn default_release(data: *mut u8, _cluster: u32, _entry: u32, _unused: u32) -> *mut u8 {
    shared_data_release(data)
}

#[cfg(test)]
static mut OPS: [HostOps; 4] = [default_create, default_find, default_initialize, default_release];

#[inline(always)]
unsafe fn create_node() -> *mut u8 {
    #[cfg(test)]
    return OPS[0](core::ptr::null_mut(), 0, 0, 0);
    #[cfg(not(test))]
    path_node_create()
}

#[inline(always)]
unsafe fn find_data(volume: *mut u8) -> *mut u8 {
    #[cfg(test)]
    return OPS[1](volume, 0, 0, 0);
    #[cfg(not(test))]
    shared_data_find_and_retain(volume as usize as u32, 0, 0)
}

#[inline(always)]
unsafe fn initialize_data(data: *mut u8, volume: *mut u8) {
    #[cfg(test)]
    return { OPS[2](data, volume as usize as u32, 0, 0); };
    #[cfg(not(test))]
    { shared_data_initialize(data, volume as usize as u32, 0, 0); }
}

#[inline(always)]
unsafe fn release_data(data: *mut u8) {
    #[cfg(test)]
    return { OPS[3](data, 0, 0, 0); };
    #[cfg(not(test))]
    { shared_data_release(data); }
}

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn path_node_create_for_volume(volume: *mut u8) -> *mut u8 {
    let node = create_node();
    if node.is_null() {
        return core::ptr::null_mut();
    }

    let data = find_data(volume);
    if data.is_null() {
        initialize_data((node.add(target_word_offset(4)) as *const *mut u8).read(), volume);
    } else {
        release_data((node.add(target_word_offset(4)) as *const *mut u8).read());
        write_pointer(node, 4, data);
    }

    write_pointer(node, 0, volume);
    let cursor = read_word(volume, 0x70);
    write_word(node, 8, cursor);
    write_word(node, 0xc, cursor);
    write_word(node, 0x10, 0);
    write_word(node, 0x14, 1);
    node
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut NODE: *mut u8 = core::ptr::null_mut();
    static mut DATA: *mut u8 = core::ptr::null_mut();
    static mut EVENTS: [u8; 4] = [0; 4];
    static mut EVENT_COUNT: usize = 0;

    unsafe fn event(value: u8) { EVENTS[EVENT_COUNT] = value; EVENT_COUNT += 1; }
    unsafe extern "C" fn create(_a: *mut u8, _b: u32, _c: u32, _d: u32) -> *mut u8 { event(1); NODE }
    unsafe extern "C" fn find(_a: *mut u8, _b: u32, _c: u32, _d: u32) -> *mut u8 { event(2); DATA }
    unsafe extern "C" fn initialize(_a: *mut u8, _b: u32, _c: u32, _d: u32) -> *mut u8 { event(3); core::ptr::null_mut() }
    unsafe extern "C" fn release(_a: *mut u8, _b: u32, _c: u32, _d: u32) -> *mut u8 { event(4); core::ptr::null_mut() }

    struct OpsRestore([HostOps; 4]);
    impl Drop for OpsRestore { fn drop(&mut self) { unsafe { OPS = self.0; } } }

    #[repr(align(8))]
    struct Fixture([u8; 0x90]);

    #[test]
    fn returns_null_without_touching_shared_data_when_node_creation_fails() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let _restore = OpsRestore(OPS);
            OPS = [create, find, initialize, release]; NODE = core::ptr::null_mut(); DATA = core::ptr::null_mut(); EVENT_COUNT = 0;
            assert!(path_node_create_for_volume(core::ptr::null_mut()).is_null());
            assert_eq!(&EVENTS[..EVENT_COUNT], &[1]);
        }
    }

    #[test]
    fn reuses_matching_data_and_initializes_all_node_words() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut node = Fixture([0; 0x90]); let mut volume = Fixture([0; 0x90]); let mut retained = Fixture([0; 0x90]);
        unsafe {
            let _restore = OpsRestore(OPS);
            OPS = [create, find, initialize, release]; NODE = node.0.as_mut_ptr(); DATA = retained.0.as_mut_ptr(); EVENT_COUNT = 0;
            write_pointer(NODE, 4, core::ptr::null_mut()); write_word(volume.0.as_mut_ptr(), 0x70, 0x1234_5678);
            assert_eq!(path_node_create_for_volume(volume.0.as_mut_ptr()), NODE);
            assert_eq!(&EVENTS[..EVENT_COUNT], &[1, 2, 4]);
            assert_eq!((NODE as *const *mut u8).read(), volume.0.as_mut_ptr());
            assert_eq!((NODE.add(target_word_offset(4)) as *const *mut u8).read(), DATA);
            assert_eq!(read_word(NODE, 8), 0x1234_5678); assert_eq!(read_word(NODE, 0xc), 0x1234_5678);
            assert_eq!(read_word(NODE, 0x10), 0); assert_eq!(read_word(NODE, 0x14), 1);
        }
    }

    #[test]
    fn initializes_new_data_when_no_matching_data_exists() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut node = Fixture([0; 0x90]); let mut volume = Fixture([0; 0x90]); let mut allocated = Fixture([0; 0x90]);
        unsafe {
            let _restore = OpsRestore(OPS);
            OPS = [create, find, initialize, release]; NODE = node.0.as_mut_ptr(); DATA = core::ptr::null_mut(); EVENT_COUNT = 0;
            write_pointer(NODE, 4, allocated.0.as_mut_ptr()); write_word(volume.0.as_mut_ptr(), 0x70, 9);
            path_node_create_for_volume(volume.0.as_mut_ptr());
            assert_eq!(&EVENTS[..EVENT_COUNT], &[1, 2, 3]);
        }
    }
}
