//! `selected_resource_path_load` — original: `FUN_080523bc` @ `0x080523bc`
//! (200 bytes).
//!
//! Raw `osos.dec` establishes the exact extent `0x080523bc..0x08052484`: the
//! following `push {r4,r5,r6,lr}` begins `FUN_08052484`. The body has six
//! unconditional plain `bl` instructions and no predicated `bl` instructions.
//! It validates an entry's nested `'liti'` container, resolves the selected
//! payload index, retains it while looking up an encoded UTF-16 path, then
//! delegates path materialization and releases the index. A non-null
//! `loaded_out` receives one unless materialization succeeds, even when lookup
//! is skipped or fails.
//!
//! Deliberate deviation: `0x08057c04` is inlined as its canonical
//! `nested_liti_class_check` equivalent. The still-unported materializer at
//! `0x0805c924` remains a fixed-address target call; host tests replace it.

use crate::app::indexed_payload_lookup::indexed_payload_lookup;
use crate::app::nested_liti_class_check::nested_liti_class_check;
use crate::util::tagged_counter::{tagged_counter_try_decrement, tagged_counter_try_increment, TaggedCounter};


type SelectedIndexResolver = unsafe extern "C" fn(*const u32) -> *mut u8;

#[cfg(target_os = "none")]
unsafe fn resolve_selected_index(entry: *const u32) -> *mut u8 {
    let resolver: SelectedIndexResolver = core::mem::transmute(0x0805_2484usize);
    resolver(entry)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_selected_index_resolver(_: *const u32) -> *mut u8 {
    panic!("selected_resource_path_load requires index resolver 0x08052484")
}

#[cfg(not(target_os = "none"))]
static mut SELECTED_INDEX_RESOLVER: SelectedIndexResolver = missing_selected_index_resolver;

#[cfg(not(target_os = "none"))]
unsafe fn resolve_selected_index(entry: *const u32) -> *mut u8 {
    let resolver = core::ptr::read_volatile(core::ptr::addr_of!(SELECTED_INDEX_RESOLVER));
    resolver(entry)
}

const NESTED_CONTAINER_WORD: usize = 1;
const PATH_DESCRIPTOR_WORD: usize = 8;
const PATH_PREFIX_OFFSET: usize = 0x7c4;

type PathMaterializer = unsafe extern "C" fn(u32, *const u16, u32, *mut u16) -> i32;

#[cfg(target_os = "none")]
unsafe fn materialize_path(prefix: u32, path: *const u16, length: u32, output: *mut u16) -> i32 {
    let materializer: PathMaterializer = core::mem::transmute(0x0805_c924usize);
    materializer(prefix, path, length, output)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_path_materializer(_: u32, _: *const u16, _: u32, _: *mut u16) -> i32 {
    panic!("selected_resource_path_load requires materializer 0x0805c924")
}

#[cfg(not(target_os = "none"))]
static mut PATH_MATERIALIZER: PathMaterializer = missing_path_materializer;

#[cfg(not(target_os = "none"))]
unsafe fn materialize_path(prefix: u32, path: *const u16, length: u32, output: *mut u16) -> i32 {
    let materializer = core::ptr::read_volatile(core::ptr::addr_of!(PATH_MATERIALIZER));
    materializer(prefix, path, length, output)
}

/// Loads the selected resource path into `output`.
///
/// # Safety
/// `entry` may be NULL. Otherwise it must be aligned and readable through
/// word 8; its nested container and resolver-produced index must satisfy their
/// respective ported callees. `output` must meet the materializer's contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.selected_resource_path_load")]
pub unsafe extern "C" fn selected_resource_path_load(
    entry: *const u32,
    selector: u32,
    loaded_out: *mut u8,
    output: *mut u16,
) -> i32 {
    let nested_container = if entry.is_null() {
        core::ptr::null()
    } else {
        entry.add(NESTED_CONTAINER_WORD).read() as usize as *const u8
    };
    if nested_liti_class_check(nested_container) == 0 || selector == 0 {
        return -0x32;
    }
    let index = resolve_selected_index(entry);
    if index.is_null() {
        return -0x32;
    }

    let path_descriptor = entry.add(PATH_DESCRIPTOR_WORD).read() as usize as *mut u8;
    let index_base = nested_container.cast::<u32>().add(2).read() as usize as *const u8;
    let mut loaded = 1;
    let mut status = -0x2b;
    tagged_counter_try_increment(index.cast::<TaggedCounter>());

    if !path_descriptor.is_null() {
        let mut encoded_length = 0u32;
        let mut path = core::ptr::null_mut();
        if indexed_payload_lookup(index, path_descriptor as usize as u32, &mut path, &mut encoded_length) == 0 && !path.is_null() {
            let prefix = if path.cast::<u16>().read() == 0x3a {
                index_base.add(PATH_PREFIX_OFFSET) as usize as u32
            } else {
                0
            };
            status = materialize_path(prefix, path.cast(), encoded_length >> 1, output);
            if status == 0 {
                loaded = 0;
            }
        }
    }

    tagged_counter_try_decrement(index.cast::<TaggedCounter>());
    if !loaded_out.is_null() {
        loaded_out.write(loaded);
    }
    status
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn rejects_null_entry_without_writing_loaded_flag() {
        let mut loaded = 0x5a;
        assert_eq!(unsafe { selected_resource_path_load(core::ptr::null(), 7, &mut loaded, core::ptr::null_mut()) }, -0x32);
        assert_eq!(loaded, 0x5a);
    }

    #[test]
    fn rejects_missing_nested_container_before_selector() {
        let entry = [0u32; 9];
        let mut loaded = 0x5a;
        assert_eq!(unsafe { selected_resource_path_load(entry.as_ptr(), 0, &mut loaded, core::ptr::null_mut()) }, -0x32);
        assert_eq!(loaded, 0x5a);
    }
}
