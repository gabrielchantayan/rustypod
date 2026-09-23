//! Query-object display-name resolution.
//!
//! `query_object_display_name` — original: `FUN_0813c2ec` at load address
//! `0x0813c2ec` (168 bytes, `0x0813c2ec..0x0813c393`; 160 bytes of code and
//! the eight-byte `"iPod\0"` literal at `0x0813c38c`). The next independently
//! linked function begins at `0x0813c394`. Whole-image A32 decoding finds
//! **three inbound plain `bl` calls** (`0x08111d50`, `0x082981a4`, and
//! `0x082a193c`) and no predicated inbound `bl` calls. The body has ten
//! plain direct `bl` instructions and no predicated `bl` instructions.
//!
//! It resolves the query object's target-width backend pointer at `+0x40`.
//! A backend with no resource entries constructs `out` from the literal
//! `"iPod"`. Otherwise it reads the first `plst` element from the backend's
//! `+0xf64` resource-table pointer into a 255-unit counted UTF-16 scratch
//! buffer, assigns that buffer to a temporary StringObject, and copy-constructs
//! `out` from the temporary unless it is empty; an empty decoded name again
//! selects `"iPod"`. The temporary is always destroyed.
//!
//! Deliberate deviations: target pointers in the query and backend layouts are
//! loaded as `u32`, so host fixtures retain their four-byte firmware offsets;
//! the ROM `StringObject` vtable is represented by the existing modeled static
//! through the established StringObject ports.

use crate::cxx::string_object::{
    string_default_construct, string_object_assign_utf16, string_object_construct_from_cstr,
    string_object_copy_construct, string_object_destroy, string_object_is_empty, StringObject,
};
use crate::ui::object_resource_count::object_resource_count;
use crate::ui::object_state::object_backend_for_kind;
use crate::ui::plst_counted_string::plst_element_read_counted_string;

const QUERY_BACKEND_OFFSET: usize = 0x40;
const BACKEND_RESOURCE_TABLE_OFFSET: usize = 0xf64;
const DEFAULT_QUERY_NAME: &[u8; 5] = b"iPod\0";

/// Resolve a query object's display name into `out`.
///
/// `query` must contain a target-width backend pointer at `+0x40`. A nonempty
/// backend name requires a readable resource-table pointer at `+0xf64` and a
/// valid first `plst` element. `out` is writable raw StringObject storage.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn query_object_display_name(out: *mut StringObject, query: *const u8) {
    let object = query.add(QUERY_BACKEND_OFFSET).cast::<u32>().read() as usize as *const u8;
    if object_resource_count(object) == 0 {
        string_object_construct_from_cstr(out, DEFAULT_QUERY_NAME.as_ptr());
        return;
    }

    let backend = object_backend_for_kind(object);
    let element = (backend.add(BACKEND_RESOURCE_TABLE_OFFSET).cast::<u32>().read() as usize
        as *mut u8)
        .cast::<u32>()
        .read() as usize as *mut u8;
    let mut name = core::mem::MaybeUninit::<StringObject>::uninit();
    let mut counted = [0u16; 256];
    string_default_construct(name.as_mut_ptr());
    plst_element_read_counted_string(element, counted.as_mut_ptr());
    string_object_assign_utf16(name.as_mut_ptr(), counted.as_ptr().add(1), counted[0] as i32);
    if string_object_is_empty(name.as_ptr()) {
        string_object_construct_from_cstr(out, DEFAULT_QUERY_NAME.as_ptr());
    } else {
        string_object_copy_construct(out, name.as_ptr());
    }
    string_object_destroy(name.as_mut_ptr());
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::string_object::{StringObjectAssignCstrOps, STRING_OBJECT_ASSIGN_CSTR_OPS};
    use parking_lot::Mutex;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut OUTPUT: [u8; 8] = [0; 8];

    unsafe extern "C" fn allocate(_this: *mut StringObject, _size: usize, _flags: u32) -> *mut u8 {
        core::ptr::addr_of_mut!(OUTPUT).cast()
    }
    unsafe extern "C" fn clear(_this: *mut StringObject) {}
    #[test]
    fn empty_resource_table_constructs_the_ipod_default_name() {
        let _lock = OPS_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::QUERY_OBJECT_DISPLAY_NAME, 0x2000) else {
            assert!(note_missing_u32_fixture("ui/query_object_display_name"));
            return;
        };
        let prior = unsafe { core::ptr::addr_of!(STRING_OBJECT_ASSIGN_CSTR_OPS).read_volatile() };
        unsafe {
            core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS).write_volatile(StringObjectAssignCstrOps {
                allocate_payload: allocate,
                clear_payload: clear,
            });
            OUTPUT = [0; 8];
            let query = slab;
            let object = slab.add(0x100);
            query.add(QUERY_BACKEND_OFFSET).cast::<u32>().write(object as usize as u32);
            object.write(1);
            object.add(0xf68).cast::<u32>().write(0);
            let mut out = core::mem::MaybeUninit::<StringObject>::uninit();
            query_object_display_name(out.as_mut_ptr(), query);
            assert_eq!(&OUTPUT[..5], b"iPod\0");
            core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS).write_volatile(prior);
        }
    }
}
