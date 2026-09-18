//! Collects unique handles from an enumerator — `FUN_0816223c` @ `0x0816223c`.
//!
//! Raw `osos.dec` establishes the exact 188-byte extent from `0x0816223c`
//! through `pop {r3,r4,r5,pc}` at `0x081622f4`; `0x081622f8` begins the next
//! function. Whole-image A32 decoding finds four plain `bl` calls and one
//! predicated `blne` call in this body.
//!
//! Algorithm: reject the operation when `0x081622f8` finds an enumerated
//! handle already present in the first target-width vector. Otherwise enumerate
//! handles until the virtual callback returns zero, appending each handle to
//! the vector at +4 and retaining the enumerator reference into the vector at
//! +16. The capacity paths delegate to the stock vector helpers.
//!
//! Deliberate deviation: the opaque collection is addressed as `u32` words,
//! preserving the ARM four-byte pointer-field layout on 64-bit host tests.
//! The unported helper identities are limited to behavior established by the
//! raw call sequence; target builds call their verified fixed addresses and
//! host tests install ABI seams.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const RETAIL_DUPLICATE_CHECK: usize = 0x0816_22f8;
const RETAIL_ENUMERATOR_DEREF: usize = 0x083d_609c;
const RETAIL_HANDLE_VECTOR_GROW: usize = 0x083e_6a14;
const RETAIL_REFERENCE_VECTOR_GROW: usize = 0x083e_0af8;
const RETAIL_REFERENCE_RETAIN: usize = 0x0839_f100;

type DuplicateCheck = unsafe extern "C" fn(*mut u32, *mut u32) -> u32;
type EnumeratorDeref = unsafe extern "C" fn(*mut u32) -> *mut u32;
type HandleVectorGrow = unsafe extern "C" fn(*mut u32, *mut u32, *const u32);
type ReferenceVectorGrow = unsafe extern "C" fn(*mut u32, *mut u32, *mut u32);
type ReferenceRetain = unsafe extern "C" fn(*mut u32, *mut u32);

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct EnumeratedHandleCollectionOps {
    pub duplicate_check: DuplicateCheck,
    pub next_handle: unsafe extern "C" fn(*mut u32, u32) -> u32,
    pub grow_handles: HandleVectorGrow,
    pub grow_references: ReferenceVectorGrow,
    pub retain_reference: ReferenceRetain,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_duplicate_check(_collection: *mut u32, _enumerator: *mut u32) -> u32 { panic!("install enumerated-handle collection host operations") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_next_handle(_enumerator: *mut u32, _previous: u32) -> u32 { panic!("install enumerated-handle collection host operations") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_grow_handles(_vector: *mut u32, _end: *mut u32, _item: *const u32) { panic!("install enumerated-handle collection host operations") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_grow_references(_vector: *mut u32, _end: *mut u32, _enumerator: *mut u32) { panic!("install enumerated-handle collection host operations") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_retain_reference(_destination: *mut u32, _source: *mut u32) { panic!("install enumerated-handle collection host operations") }

#[cfg(not(target_os = "none"))]
pub static mut ENUMERATED_HANDLE_COLLECTION_OPS: EnumeratedHandleCollectionOps = EnumeratedHandleCollectionOps {
    duplicate_check: missing_duplicate_check, next_handle: missing_next_handle, grow_handles: missing_grow_handles,
    grow_references: missing_grow_references, retain_reference: missing_retain_reference,
};

#[inline(always)]
unsafe fn duplicate_check(collection: *mut u32, enumerator: *mut u32) -> u32 {
    #[cfg(target_os = "none")]
    { unsafe { core::mem::transmute::<usize, DuplicateCheck>(RETAIL_DUPLICATE_CHECK)(collection, enumerator) } }
    #[cfg(not(target_os = "none"))]
    { unsafe { core::ptr::read_volatile(addr_of!(ENUMERATED_HANDLE_COLLECTION_OPS.duplicate_check))(collection, enumerator) } }
}

#[inline(always)]
unsafe fn next_handle(enumerator: *mut u32, previous: u32) -> u32 {
    #[cfg(target_os = "none")]
    {
        let holder = unsafe { core::mem::transmute::<usize, EnumeratorDeref>(RETAIL_ENUMERATOR_DEREF)(enumerator) };
        let vtable = unsafe { holder.read() as *const usize };
        let next: unsafe extern "C" fn(*mut u32, u32) -> u32 = unsafe { core::mem::transmute(vtable.add(3).read()) };
        unsafe { next(holder, previous) }
    }
    #[cfg(not(target_os = "none"))]
    { unsafe { core::ptr::read_volatile(addr_of!(ENUMERATED_HANDLE_COLLECTION_OPS.next_handle))(enumerator, previous) } }
}

#[inline(always)]
unsafe fn grow_handles(vector: *mut u32, end: *mut u32, item: *const u32) {
    #[cfg(target_os = "none")]
    { unsafe { core::mem::transmute::<usize, HandleVectorGrow>(RETAIL_HANDLE_VECTOR_GROW)(vector, end, item) } }
    #[cfg(not(target_os = "none"))]
    { unsafe { core::ptr::read_volatile(addr_of!(ENUMERATED_HANDLE_COLLECTION_OPS.grow_handles))(vector, end, item) } }
}
#[inline(always)]
unsafe fn grow_references(vector: *mut u32, end: *mut u32, enumerator: *mut u32) {
    #[cfg(target_os = "none")]
    { unsafe { core::mem::transmute::<usize, ReferenceVectorGrow>(RETAIL_REFERENCE_VECTOR_GROW)(vector, end, enumerator) } }
    #[cfg(not(target_os = "none"))]
    { unsafe { core::ptr::read_volatile(addr_of!(ENUMERATED_HANDLE_COLLECTION_OPS.grow_references))(vector, end, enumerator) } }
}
#[inline(always)]
unsafe fn retain_reference(destination: *mut u32, source: *mut u32) {
    #[cfg(target_os = "none")]
    { unsafe { core::mem::transmute::<usize, ReferenceRetain>(RETAIL_REFERENCE_RETAIN)(destination, source) } }
    #[cfg(not(target_os = "none"))]
    { unsafe { core::ptr::read_volatile(addr_of!(ENUMERATED_HANDLE_COLLECTION_OPS.retain_reference))(destination, source) } }
}

/// Enumerates handles into the collection's paired target-width vectors.
///
/// # Safety
///
/// `collection` must contain vectors at word offsets 1 and 4; `enumerator`
/// must be accepted by the stock enumeration and reference helpers.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn enumerated_handle_collection_append(collection: *mut u32, enumerator: *mut u32) -> u32 {
    if unsafe { duplicate_check(collection, enumerator) } != 0 { return 0; }
    let mut handle = 0;
    loop {
        handle = unsafe { next_handle(enumerator, handle) };
        if handle == 0 { return 1; }
        let handle_vector = unsafe { collection.add(1) };
        let handle_end = unsafe { handle_vector.add(1).read() as *mut u32 };
        if handle_end == unsafe { handle_vector.add(2).read() as *mut u32 } {
            unsafe { grow_handles(handle_vector, handle_end, &handle) };
        } else {
            unsafe { handle_vector.add(1).write(handle_end.add(1) as u32); handle_end.write(handle); }
        }
        let reference_vector = unsafe { collection.add(4) };
        let reference_end = unsafe { reference_vector.add(1).read() as *mut u32 };
        if reference_end == unsafe { reference_vector.add(2).read() as *mut u32 } {
            unsafe { grow_references(reference_vector, reference_end, enumerator) };
        } else {
            unsafe { reference_vector.add(1).write(reference_end.add(1) as u32); retain_reference(reference_end, enumerator); }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;
    static LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| try_map_u32_slab(hints::ENUMERATED_HANDLE_COLLECTION, 0x1000).map(|p| p as usize));
    static mut HANDLES: [u32; 3] = [0; 3]; static mut INDEX: usize = 0; static mut GROWS: u32 = 0;
    unsafe extern "C" fn no_duplicate(_: *mut u32, _: *mut u32) -> u32 { 0 }
    unsafe extern "C" fn duplicate(_: *mut u32, _: *mut u32) -> u32 { 1 }
    unsafe extern "C" fn next(_: *mut u32, _: u32) -> u32 { unsafe { let result = HANDLES[INDEX]; INDEX += 1; result } }
    unsafe extern "C" fn grow(_: *mut u32, _: *mut u32, _: *const u32) { unsafe { GROWS += 1 } }
    unsafe extern "C" fn retain(destination: *mut u32, source: *mut u32) { unsafe { destination.write(source as u32) } }
    unsafe extern "C" fn grow_reference(_: *mut u32, _: *mut u32, _: *mut u32) { unsafe { GROWS += 1 } }
    unsafe fn install(duplicate_check: DuplicateCheck) { ENUMERATED_HANDLE_COLLECTION_OPS = EnumeratedHandleCollectionOps { duplicate_check, next_handle: next, grow_handles: grow, grow_references: grow_reference, retain_reference: retain }; }
    #[test]
    fn duplicate_prevents_enumeration_and_mutation() { let _guard = LOCK.lock(); unsafe { install(duplicate); INDEX = 0; assert_eq!(enumerated_handle_collection_append(core::ptr::null_mut(), core::ptr::null_mut()), 0); assert_eq!(INDEX, 0); } }
    #[test]
    fn appends_each_enumerated_handle_and_retains_enumerator() { let _guard = LOCK.lock(); let Some(base) = *SLAB else { assert!(note_missing_u32_fixture("app/enumerated_handle_collection")); return; }; unsafe { let collection = base as *mut u32; let handles = collection.add(16); let references = collection.add(24); collection.add(1).write(handles as u32); collection.add(2).write(handles as u32); collection.add(3).write(handles.add(3) as u32); collection.add(4).write(references as u32); collection.add(5).write(references as u32); collection.add(6).write(references.add(3) as u32); HANDLES = [7, 9, 0]; INDEX = 0; GROWS = 0; install(no_duplicate); assert_eq!(enumerated_handle_collection_append(collection, 0x1234 as *mut u32), 1); assert_eq!(core::slice::from_raw_parts(handles, 2), &[7, 9]); assert_eq!(core::slice::from_raw_parts(references, 2), &[0x1234, 0x1234]); assert_eq!(GROWS, 0); } }
    #[test]
    fn full_paired_vectors_use_both_growth_helpers() { let _guard = LOCK.lock(); let Some(base) = *SLAB else { assert!(note_missing_u32_fixture("app/enumerated_handle_collection")); return; }; unsafe { let collection = base as *mut u32; let handles = collection.add(16); let references = collection.add(24); collection.add(1).write(handles as u32); collection.add(2).write(handles as u32); collection.add(3).write(handles as u32); collection.add(4).write(references as u32); collection.add(5).write(references as u32); collection.add(6).write(references as u32); HANDLES = [7, 0, 0]; INDEX = 0; GROWS = 0; install(no_duplicate); assert_eq!(enumerated_handle_collection_append(collection, 0x1234 as *mut u32), 1); assert_eq!(GROWS, 2); } }
}
