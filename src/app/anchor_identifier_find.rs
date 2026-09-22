//! Finds an anchor identifier by its nonempty name.
//!
//! `anchor_identifier_find` — original: `FUN_0828b50c` @ `0x0828b50c`
//! (144 bytes, `0x0828b50c..0x0828b59c`; the next independently linked
//! function begins at `0x0828b59c`). Raw ARM decoding verifies three plain
//! `bl` instructions, no predicated `bl` instructions, and one virtual `blx`.
//!
//! A name whose payload has no UTF-8 codepoints produces zero without reading
//! the owner. Otherwise, the owner field at +0x3c identifies an indexed
//! collection. The collection's virtual +0x40 accessor yields each candidate;
//! the candidate's raw payload word at +12 is compared to the supplied name.
//!
//! Deliberate deviations: the collection's runtime-selected virtual method is
//! represented by target-width words on device and a widened host vtable in
//! tests. The three identified direct callees are called directly.

use crate::cxx::string_object::{utf8_codepoint_count_safe, utf8_strcmp_safe};
#[cfg(target_os = "none")]
use crate::cxx::string_object::{string_object_c_str, StringObject};

type TargetIndexedCandidate = unsafe extern "C" fn(*mut u8, u32) -> *mut u32;
const INDEXED_CANDIDATE_SLOT: usize = 0x40 / 4;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn indexed_candidate(collection: *mut u8, index: usize) -> *mut u8 {
    let vtable = collection.cast::<u32>().read_volatile() as usize as *const u32;
    let get: TargetIndexedCandidate = core::mem::transmute(vtable.add(INDEXED_CANDIDATE_SLOT).read_volatile() as usize);
    get(collection, index as u32).cast::<u8>().cast::<u32>().read_volatile() as usize as *mut u8
}

#[cfg(not(target_os = "none"))]
type HostIndexedCandidate = unsafe extern "C" fn(*mut u8, usize) -> *mut *mut u8;

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostAnchorIdentifierVtable {
    pub unresolved_00_to_3c: [usize; INDEXED_CANDIDATE_SLOT],
    pub indexed_candidate: HostIndexedCandidate,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostAnchorIdentifierCollection {
    pub vtable: *const HostAnchorIdentifierVtable,
    pub count: usize,
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn indexed_candidate(collection: *mut u8, index: usize) -> *mut u8 {
    let collection = &*collection.cast::<HostAnchorIdentifierCollection>();
    *((*collection.vtable).indexed_candidate)(collection as *const _ as *mut u8, index)
}

unsafe fn candidate_payload(candidate: *const u8) -> *const u8 {
    candidate.add(12).cast::<u32>().read() as usize as *const u8
}

#[inline(always)]
unsafe fn name_c_str(name: *const u8) -> *const u8 {
    #[cfg(target_os = "none")]
    {
        string_object_c_str(name.cast::<StringObject>())
    }
    #[cfg(not(target_os = "none"))]
    {
        name.add(4).cast::<u32>().read() as usize as *const u8
    }
}

/// # Safety
///
/// `name` must be a readable target-layout StringObject. If its payload has a
/// codepoint, `owner + 0x3c` must identify a valid indexed collection whose
/// candidates are readable through their embedded StringObject payload word.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn anchor_identifier_find(
    _context: *mut u8,
    owner: *mut u8,
    name: *const u8,
) -> u32 {
    if utf8_codepoint_count_safe(name.add(4).cast::<u32>().read() as usize as *const u8) == 0 {
        return 0;
    }

    let collection = owner.add(0x3c).cast::<u32>().read() as usize as *mut u8;
    #[cfg(target_os = "none")]
    let count = collection.add(4).cast::<u32>().read() as usize;
    #[cfg(not(target_os = "none"))]
    let count = (*collection.cast::<HostAnchorIdentifierCollection>()).count;

    for index in 0..count {
        let candidate = indexed_candidate(collection, index);
        if utf8_strcmp_safe(candidate_payload(candidate), name_c_str(name)) == 0 {
            return candidate.cast::<u32>().read();
        }
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::{LazyLock, Mutex};

    static LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::ANCHOR_IDENTIFIER_FIND, 0x1000).map(|pointer| pointer as usize)
    });
    static mut CANDIDATES: [*mut u8; 2] = [ptr::null_mut(); 2];
    static mut INDICES: [usize; 2] = [usize::MAX; 2];
    static mut CALLS: usize = 0;

    unsafe extern "C" fn get_candidate(_collection: *mut u8, index: usize) -> *mut *mut u8 {
        INDICES[CALLS] = index;
        CALLS += 1;
        ptr::addr_of_mut!(CANDIDATES[index])
    }

    unsafe fn base() -> *mut u8 { SLAB.expect("fixture mapping was checked") as *mut u8 }

    unsafe fn write_target_ptr(field: *mut u8, value: *const u8) {
        field.cast::<u32>().write(value as usize as u32);
    }

    unsafe fn reset() {
        base().write_bytes(0, 0x1000);
        CANDIDATES = [ptr::null_mut(); 2];
        INDICES = [usize::MAX; 2];
        CALLS = 0;
    }

    static VTABLE: HostAnchorIdentifierVtable = HostAnchorIdentifierVtable {
        unresolved_00_to_3c: [0; INDEXED_CANDIDATE_SLOT], indexed_candidate: get_candidate,
    };

    unsafe fn fixture() -> *mut u8 {
        let owner = base();
        let collection = base().add(0x100).cast::<HostAnchorIdentifierCollection>();
        (*collection).vtable = &VTABLE;
        (*collection).count = 2;
        write_target_ptr(owner.add(0x3c), collection.cast());
        owner
    }

    #[test]
    fn empty_name_returns_zero_without_dereferencing_owner() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        if SLAB.is_none() { assert!(note_missing_u32_fixture("app/anchor_identifier_find")); return; }
        unsafe {
            reset();
            let name = base().add(0x300);
            write_target_ptr(name.add(4), ptr::null());
            assert_eq!(anchor_identifier_find(ptr::null_mut(), ptr::null_mut(), name), 0);
            assert_eq!(CALLS, 0);
        }
    }

    #[test]
    fn returns_first_matching_candidate_identifier_after_scanning_prefix() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        if SLAB.is_none() { assert!(note_missing_u32_fixture("app/anchor_identifier_find")); return; }
        unsafe {
            reset();
            let owner = fixture();
            let name = base().add(0x300);
            let first = base().add(0x400);
            let second = base().add(0x440);
            let wanted = base().add(0x500);
            let other = base().add(0x520);
            wanted.copy_from_nonoverlapping(b"caf\xc3\xa9\0".as_ptr(), 6);
            other.copy_from_nonoverlapping(b"coffee\0".as_ptr(), 7);
            first.cast::<u32>().write(17);
            write_target_ptr(name.add(4), wanted);
            second.cast::<u32>().write(42);
            write_target_ptr(first.add(12), other);
            write_target_ptr(second.add(12), wanted);
            CANDIDATES = [first, second];
            assert_eq!(anchor_identifier_find(ptr::null_mut(), owner, name), 42);
            assert_eq!(INDICES, [0, 1]);
            assert_eq!(CALLS, 2);
        }
    }

    #[test]
    fn returns_zero_after_all_candidates_miss() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        if SLAB.is_none() { assert!(note_missing_u32_fixture("app/anchor_identifier_find")); return; }
        unsafe {
            reset();
            let owner = fixture();
            let name = base().add(0x300);
            let candidate = base().add(0x400);
            let wanted = base().add(0x500);
            let other = base().add(0x520);
            wanted.copy_from_nonoverlapping(b"wanted\0".as_ptr(), 7);
            other.copy_from_nonoverlapping(b"other\0".as_ptr(), 6);
            write_target_ptr(name.add(4), wanted);
            write_target_ptr(candidate.add(12), other);
            CANDIDATES = [candidate, candidate];
            assert_eq!(anchor_identifier_find(ptr::null_mut(), owner, name), 0);
            assert_eq!(INDICES, [0, 1]);
        }
    }
}
