//! Indexed string resource fallback — original: `FUN_081a275c` @ `0x081a275c`.
//!
//! Raw ARM establishes the true 180-byte code extent: `push {r0-r6,lr}` at
//! `0x081a275c` through `pop {r0-r6,pc}` at `0x081a280c`; the following two
//! words are the `"Beep"` literal and the next real function starts at
//! `0x081a2820`. It has seven unconditional plain `bl` instructions, one
//! predicated `blne`, and one indirect `blx` through collection vtable slot
//! `+0x40`. The four direct inbound plain `bl` sites are `0x0810981c`,
//! `0x08109eb0`, `0x0810a538`, and `0x08216460`.
//!
//! Default-constructs `out`, then, when signed `index` is below the collection
//! count at `+0x1c`, calls the collection member at `+0x18` through vtable slot
//! `+0x40`. A nonzero entry word supplies a StringObject at entry word +1. Its
//! payload is assigned to `out`; unless that string equals `"Beep"`, `out` is
//! overwritten with string resource `0x0dad028e` from the current task's
//! provider chain.
//!
//! Deliberate deviation: the virtual method has no recovered identity, so the
//! target calls its actual vtable slot while host tests install a replacement.
//! The host replacement is necessary because retail vtables contain 32-bit
//! function addresses whereas host function pointers are wider.

use crate::app::resource_chain::{resource_chain_find_string, ResourceProvider};
use crate::cxx::string_object::{
    string_default_construct, string_object_assign_payload, string_object_construct_from_cstr,
    string_object_copy_construct, string_object_destroy, string_object_equals, StringObject,
};
use crate::util::context_field::task_ctx_field_0x30;

const COLLECTION_MEMBER_OFFSET: usize = 0x18;
const COLLECTION_COUNT_OFFSET: usize = 0x1c;
const ENTRY_AT_SLOT: usize = 0x40 / 4;
const BEEP_RESOURCE_ID: u32 = 0x0dad_028e;
const BEEP: &[u8] = b"Beep\0";

type IndexedStringEntryAt = unsafe extern "C" fn(*mut u8, i32) -> *mut u32;

#[cfg(target_os = "none")]
unsafe fn indexed_string_entry_at(collection: *mut u8, index: i32) -> *mut u32 {
    let vtable = *(collection as *const *const u32);
    let entry_at: IndexedStringEntryAt = core::mem::transmute(*vtable.add(ENTRY_AT_SLOT));
    entry_at(collection, index)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_indexed_string_entry_at(_collection: *mut u8, _index: i32) -> *mut u32 {
    panic!("indexed_string_resource_fallback requires collection vtable slot +0x40")
}

#[cfg(not(target_os = "none"))]
static mut INDEXED_STRING_ENTRY_AT: IndexedStringEntryAt = missing_indexed_string_entry_at;

#[cfg(not(target_os = "none"))]
unsafe fn indexed_string_entry_at(collection: *mut u8, index: i32) -> *mut u32 {
    INDEXED_STRING_ENTRY_AT(collection, index)
}

/// Default-constructs `out`, assigns indexed collection text, then replaces
/// every non-`"Beep"` value with the task-local beep resource.
///
/// # Safety
/// `out` must be writable as a StringObject. `collection` must expose aligned
/// words at `+0x18` and `+0x1c`; when the index passes the signed bound, its
/// vtable slot `+0x40` must return a readable entry whose first word and, when
/// nonzero, following StringObject word are valid. The task context and its
/// resource chain are also used without NULL checks on the fallback path.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn indexed_string_resource_fallback(
    out: *mut StringObject,
    collection: *mut u8,
    index: i32,
) -> *mut StringObject {
    string_default_construct(out);

    let count = *((collection as *const u8).add(COLLECTION_COUNT_OFFSET) as *const i32);
    if index < count {
        let member = collection.add(COLLECTION_MEMBER_OFFSET);
        let entry = indexed_string_entry_at(member, index);
        if *entry != 0 {
            let mut copied = core::mem::MaybeUninit::<StringObject>::uninit();
            let source = entry.add(1) as *const StringObject;
            string_object_copy_construct(copied.as_mut_ptr(), source);
            if out != copied.as_mut_ptr() {
                string_object_assign_payload(out, (*copied.as_ptr()).payload as *const u8);
            }
            string_object_destroy(copied.as_mut_ptr());

            let mut beep = core::mem::MaybeUninit::<StringObject>::uninit();
            string_object_construct_from_cstr(beep.as_mut_ptr(), BEEP.as_ptr());
            let differs = string_object_equals(out, beep.as_ptr()) != 0;
            string_object_destroy(beep.as_mut_ptr());
            if differs {
                let chain = task_ctx_field_0x30() as usize as *mut ResourceProvider;
                let resource = resource_chain_find_string(chain, BEEP_RESOURCE_ID);
                string_object_assign_payload(out, resource);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    static mut CALLS: usize = 0;
    static mut ENTRY: *mut u32 = core::ptr::null_mut();

    unsafe extern "C" fn entry_at(_collection: *mut u8, _index: i32) -> *mut u32 {
        CALLS += 1;
        ENTRY
    }

    struct CollectionFixture {
        words: [u32; 8],
    }

    impl CollectionFixture {
        fn new(count: i32) -> Self {
            let mut fixture = Self { words: [0; 8] };
            fixture.words[7] = count as u32;
            fixture
        }
    }

    #[test]
    fn out_of_bounds_leaves_a_default_string_without_a_virtual_call() {
        let mut collection = CollectionFixture::new(3);
        let mut out = core::mem::MaybeUninit::<StringObject>::uninit();
        unsafe {
            CALLS = 0;
            INDEXED_STRING_ENTRY_AT = entry_at;
            indexed_string_resource_fallback(out.as_mut_ptr(), collection.words.as_mut_ptr().cast(), 3);
            assert_eq!(CALLS, 0);
            assert!((*out.as_ptr()).payload.is_null());
            string_object_destroy(out.as_mut_ptr());
        }
    }

    #[test]
    fn zero_entry_leaves_a_default_string_after_the_virtual_lookup() {
        let mut collection = CollectionFixture::new(1);
        let mut entry = 0u32;
        let mut out = core::mem::MaybeUninit::<StringObject>::uninit();
        unsafe {
            CALLS = 0;
            ENTRY = &mut entry;
            INDEXED_STRING_ENTRY_AT = entry_at;
            indexed_string_resource_fallback(out.as_mut_ptr(), collection.words.as_mut_ptr().cast(), 0);
            assert_eq!(CALLS, 1);
            assert!((*out.as_ptr()).payload.is_null());
            string_object_destroy(out.as_mut_ptr());
        }
    }
}
