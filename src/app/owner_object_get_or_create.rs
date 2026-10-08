//! Owner-keyed object cache accessor.
//!
//! `FUN_0810f548` @ `0x0810f548`: 164 bytes, raw extent
//! `[0x0810f548,0x0810f5ec)` followed by a separate PUSH. Four outbound
//! plain BLs, zero predicated BLs; one BLX and one BLXNE. Two inbound
//! plain BLs (0x0812e6b4, 0x08290324), zero predicated BLs.
//! Snapshots the signed collection count, searches pointer records by owner,
//! and returns the first matching object's pointer. On a miss allocates an
//! eight-byte record and a 36-byte object, constructs the object, and appends
//! the record by reference only for a non-NULL construction result. Returns
//! the object through the reloaded record, including append's replacement.
//! Deliberate deviations: native repr(C) pointers allow host fixtures; target
//! fields remain four bytes apart. Host-only seams replace resident collection
//! accessor 0x0810ed8c, construction, and allocation. Target construction calls
//! the existing object_dispatch_entry_construct port directly. No invented
//! null guard, cleanup, or constructor-failure recovery is added.

#[repr(C)]
pub struct OwnerObjectRecord {
    pub owner: *mut u8,
    pub object: *mut u8,
}

#[repr(C)]
pub struct OwnerObjectCollection {
    pub vtable: *const usize,
    pub count: i32,
}

type GetCollection = unsafe extern "C" fn() -> *mut OwnerObjectCollection;
type Construct = unsafe extern "C" fn(*mut u8, *mut u8) -> *mut u8;
type Allocate = unsafe extern "C" fn(usize) -> *mut u8;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_collection() -> *mut OwnerObjectCollection { panic!("resident collection accessor not installed") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_construct(_: *mut u8, _: *mut u8) -> *mut u8 { panic!("resident constructor not installed") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_allocate(_: usize) -> *mut u8 { panic!("host allocator not installed") }

#[cfg(not(target_os = "none"))]
pub static mut OWNER_OBJECT_COLLECTION: GetCollection = missing_collection;
#[cfg(not(target_os = "none"))]
pub static mut OWNER_OBJECT_CONSTRUCT: Construct = missing_construct;
#[cfg(not(target_os = "none"))]
pub static mut OWNER_OBJECT_ALLOCATE: Allocate = missing_allocate;

/// Requires a valid resident collection, records, and virtual methods.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn owner_object_get_or_create(owner: *mut u8) -> *mut u8 {
    #[cfg(target_os = "none")]
    let get: GetCollection = core::mem::transmute(0x0810_ed8cusize);
    #[cfg(target_os = "none")]
    unsafe extern "C" fn construct(storage: *mut u8, owner: *mut u8) -> *mut u8 {
        crate::app::object_dispatch_entry::object_dispatch_entry_construct(storage.cast(), owner.cast()).cast()
    }
    #[cfg(target_os = "none")]
    let allocate: Allocate = crate::heap::veneers::operator_new;
    #[cfg(not(target_os = "none"))]
    let (get, construct, allocate) = (OWNER_OBJECT_COLLECTION, OWNER_OBJECT_CONSTRUCT, OWNER_OBJECT_ALLOCATE);
    let collection = get();
    let count = (*collection).count;
    let mut index = 0i32;
    while index < count {
        let at: unsafe extern "C" fn(*mut OwnerObjectCollection, i32) -> *mut *mut OwnerObjectRecord =
            core::mem::transmute(*(*collection).vtable.add(0x40 / 4));
        let record = *at(collection, index);
        if (*record).owner == owner { return (*record).object; }
        index += 1;
    }
    let mut record = allocate(core::mem::size_of::<OwnerObjectRecord>()).cast::<OwnerObjectRecord>();
    if record.is_null() { return core::ptr::null_mut(); }
    (*record).owner = owner;
    let object = construct(allocate(0x24), owner);
    (*record).object = object;
    if !object.is_null() {
        let append: unsafe extern "C" fn(*mut OwnerObjectCollection, *mut *mut OwnerObjectRecord) =
            core::mem::transmute(*(*collection).vtable.add(0x1c / 4));
        append(collection, &mut record);
    }
    (*record).object
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr;
    use std::vec::Vec;
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    struct Fixture {
        collection: OwnerObjectCollection,
        records: Vec<*mut OwnerObjectRecord>,
        allocations: Vec<usize>,
        storage: OwnerObjectRecord,
        replacement: OwnerObjectRecord,
        object: [u32; 9],
        fail_record: bool,
        fail_object: bool,
        fail_construct: bool,
        replace: bool,
        appended: bool,
    }
    static mut FIXTURE: *mut Fixture = ptr::null_mut();
    unsafe extern "C" fn get() -> *mut OwnerObjectCollection { ptr::addr_of_mut!((*FIXTURE).collection) }
    unsafe extern "C" fn at(_: *mut OwnerObjectCollection, index: i32) -> *mut *mut OwnerObjectRecord {
        // Mutating the live count proves that iteration uses its entry snapshot.
        (*FIXTURE).collection.count = 0;
        (&mut (*FIXTURE).records).as_mut_ptr().add(index as usize)
    }
    unsafe extern "C" fn allocate(size: usize) -> *mut u8 {
        let f = &mut *FIXTURE;
        f.allocations.push(size);
        if size == core::mem::size_of::<OwnerObjectRecord>() {
            if f.fail_record { ptr::null_mut() } else { ptr::addr_of_mut!(f.storage).cast() }
        } else {
            assert_eq!(size, 36);
            if f.fail_object { ptr::null_mut() } else { f.object.as_mut_ptr().cast() }
        }
    }
    unsafe extern "C" fn construct(storage: *mut u8, owner: *mut u8) -> *mut u8 {
        assert_eq!((*FIXTURE).storage.owner, owner);
        if (*FIXTURE).fail_object { assert!(storage.is_null()); }
        if (*FIXTURE).fail_construct { ptr::null_mut() } else { storage }
    }
    unsafe extern "C" fn append(_: *mut OwnerObjectCollection, record: *mut *mut OwnerObjectRecord) {
        let f = &mut *FIXTURE;
        assert_eq!(*record, ptr::addr_of_mut!(f.storage));
        assert_eq!(f.storage.object, f.object.as_mut_ptr().cast());
        f.appended = true;
        if f.replace { *record = ptr::addr_of_mut!(f.replacement); }
    }
    struct Restore(GetCollection, Construct, Allocate);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe {
            OWNER_OBJECT_COLLECTION = self.0; OWNER_OBJECT_CONSTRUCT = self.1; OWNER_OBJECT_ALLOCATE = self.2;
            FIXTURE = ptr::null_mut();
        }}
    }
    #[test]
    fn cache_search_and_miss_boundaries() {
        let _lock = LOCK.lock();
        unsafe {
            let _restore = Restore(OWNER_OBJECT_COLLECTION, OWNER_OBJECT_CONSTRUCT, OWNER_OBJECT_ALLOCATE);
            OWNER_OBJECT_COLLECTION = get; OWNER_OBJECT_CONSTRUCT = construct; OWNER_OBJECT_ALLOCATE = allocate;
            let mut vtable = [0usize; 17];
            vtable[16] = at as *const () as usize; vtable[7] = append as *const () as usize;
            let mut owner = 0u8;
            let owner = &mut owner as *mut u8;
            let mut hit = OwnerObjectRecord { owner, object: owner };
            let mut other = OwnerObjectRecord { owner: ptr::null_mut(), object: ptr::null_mut() };
            for case in 0..7 {
                let mut f = Fixture {
                    collection: OwnerObjectCollection { vtable: vtable.as_ptr(), count: if case == 0 { 3 } else if case == 1 { -1 } else { 0 } },
                    records: std::vec![&mut other, &mut hit, &mut other], allocations: Vec::new(),
                    storage: OwnerObjectRecord { owner: ptr::null_mut(), object: ptr::null_mut() },
                    replacement: OwnerObjectRecord { owner, object: owner }, object: [0; 9],
                    fail_record: case == 2, fail_object: case == 3, fail_construct: case == 3 || case == 4,
                    replace: case == 6, appended: false,
                };
                FIXTURE = &mut f;
                let result = owner_object_get_or_create(owner);
                match case {
                    0 => { assert_eq!(result, owner); assert!(f.allocations.is_empty()); }
                    2 => { assert!(result.is_null()); assert_eq!(f.allocations, [core::mem::size_of::<OwnerObjectRecord>()]); }
                    3 | 4 => { assert!(result.is_null()); assert!(!f.appended); assert!(f.storage.object.is_null()); }
                    6 => { assert_eq!(result, owner); assert!(f.appended); }
                    _ => { assert_eq!(result, f.object.as_mut_ptr().cast()); assert!(f.appended); }
                }
                if case != 0 && case != 2 { assert_eq!(f.allocations, [core::mem::size_of::<OwnerObjectRecord>(), 36]); }
            }
        }
    }
}
