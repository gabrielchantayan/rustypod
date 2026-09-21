//! `lazy_string_tables_initialize` — retailOS `FUN_082a89e0` @ `0x082a89e0`.
//!
//! Raw ARM establishes the exact 152-byte extent `0x082a89e0..0x082a8a74`:
//! `0x082a8a78` starts the separately linked next function. Decoding its words
//! finds three plain direct `bl` calls and no predicated `bl` calls. The routine
//! returns when the global holder's word `+0x10` is nonzero. Otherwise it
//! allocates two 32-byte blocks, initializes opaque string-table objects from
//! the literal C strings `"C"` (count 10, mode 2) and `""` (count 10, mode 1),
//! assigns the first object's source string to five four-byte slots, gives the
//! second object's word `+0x10` the value `0x3f0`, then publishes the first
//! object at holder `+0x10`.
//!
//! Deliberate deviations: the two 0x082xxxxx construction helpers remain
//! resident on target and are exposed as exact host ABI seams; their concrete
//! container identity is not established. The existing tag-2 `operator_new`
//! port replaces its two direct retailOS calls.

use crate::heap::veneers::operator_new;

const RETAIL_HOLDER: usize = 0x08a0_fbcc;
const RETAIL_TABLE_CONSTRUCT: usize = 0x0826_6f34;
const RETAIL_STRING_ASSIGN_CSTR: usize = 0x083d_8ca0;
const TABLE_SIZE: usize = 0x20;
const TABLE_SLOT_COUNT: usize = 10;
const INITIALIZED_SLOT_COUNT: usize = 5;
const TABLE_SOURCE_WORD: usize = 6;
const TABLE_LIMIT_WORD: usize = 4;
const TABLE_LIMIT: u32 = 0x3f0;
static C_SEED: [u8; 2] = *b"C\0";
static EMPTY_SEED: [u8; 1] = *b"\0";

type OpaqueStringTableConstruct = unsafe extern "C" fn(*mut u32, *const u8, u32, u32) -> *mut u32;
type CxxStringAssignCstr = unsafe extern "C" fn(*mut u32, *const u8) -> *mut u32;


#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn allocate_table() -> *mut u8 { operator_new(TABLE_SIZE) }

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn allocate_table() -> *mut u8 { core::ptr::without_provenance_mut(TABLE_SIZE) }
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn holder() -> *mut u32 { RETAIL_HOLDER as *mut u32 }

#[cfg(not(target_os = "none"))]
static mut HOST_HOLDER: [u32; 5] = [0; 5];

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn holder() -> *mut u32 { core::ptr::addr_of_mut!(HOST_HOLDER).cast() }

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn construct_table(storage: *mut u32, seed: *const u8, count: u32, mode: u32) -> *mut u32 {
    core::mem::transmute::<usize, OpaqueStringTableConstruct>(RETAIL_TABLE_CONSTRUCT)(storage, seed, count, mode)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_construct_table(storage: *mut u32, _seed: *const u8, _count: u32, _mode: u32) -> *mut u32 { storage }
#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_STRING_TABLE_CONSTRUCT: OpaqueStringTableConstruct = missing_construct_table;
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn construct_table(storage: *mut u32, seed: *const u8, count: u32, mode: u32) -> *mut u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(OPAQUE_STRING_TABLE_CONSTRUCT))(storage, seed, count, mode)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn assign_cstr(slot: *mut u32, source: *const u8) -> *mut u32 {
    core::mem::transmute::<usize, CxxStringAssignCstr>(RETAIL_STRING_ASSIGN_CSTR)(slot, source)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_assign_cstr(slot: *mut u32, _source: *const u8) -> *mut u32 { slot }
#[cfg(not(target_os = "none"))]
pub static mut CXX_STRING_ASSIGN_CSTR: CxxStringAssignCstr = missing_assign_cstr;
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn assign_cstr(slot: *mut u32, source: *const u8) -> *mut u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(CXX_STRING_ASSIGN_CSTR))(slot, source)
}

/// Initializes the lazy opaque string tables once.
///
/// # Safety
///
/// The resident construction and COW-string assignment helpers retain their
/// retail ABIs. Their allocations must be writable through their documented
/// object words; stock code intentionally has no allocation-failure guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn lazy_string_tables_initialize() {
    let state = holder();
    if core::ptr::read_volatile(state.add(4)) != 0 { return; }

    let first = construct_table(allocate_table().cast(), C_SEED.as_ptr(), TABLE_SLOT_COUNT as u32, 2);
    core::ptr::write_volatile(state.add(2), first as usize as u32);
    let source = first.add(TABLE_SOURCE_WORD).read() as usize as *const u8;
    let slots = first.read() as usize as *mut u32;
    for index in 0..INITIALIZED_SLOT_COUNT { assign_cstr(slots.add(index), source); }

    let second = construct_table(allocate_table().cast(), EMPTY_SEED.as_ptr(), TABLE_SLOT_COUNT as u32, 1);
    core::ptr::write_volatile(state.add(3), second as usize as u32);
    second.add(TABLE_LIMIT_WORD).write(TABLE_LIMIT);
    core::ptr::write_volatile(state.add(4), first as usize as u32);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static FIRST: LazyLock<Option<usize>> = LazyLock::new(|| try_map_u32_slab(hints::LAZY_STRING_TABLES_INITIALIZE_FIRST, 0x80).map(|p| p as usize));
    static SECOND: LazyLock<Option<usize>> = LazyLock::new(|| try_map_u32_slab(hints::LAZY_STRING_TABLES_INITIALIZE_SECOND, 0x80).map(|p| p as usize));
    static mut CONSTRUCT_CALLS: [(usize, u8, u32, u32); 2] = [(0, 0, 0, 0); 2];
    static mut CONSTRUCT_COUNT: usize = 0;
    static mut ASSIGNED: [usize; INITIALIZED_SLOT_COUNT] = [0; INITIALIZED_SLOT_COUNT];
    static mut ASSIGN_COUNT: usize = 0;

    unsafe extern "C" fn construct(storage: *mut u32, seed: *const u8, count: u32, mode: u32) -> *mut u32 {
        CONSTRUCT_CALLS[CONSTRUCT_COUNT] = (storage as usize, seed.read(), count, mode);
        CONSTRUCT_COUNT += 1;
        if mode == 2 { *FIRST.as_ref().unwrap() as *mut u32 } else { *SECOND.as_ref().unwrap() as *mut u32 }
    }
    unsafe extern "C" fn assign(slot: *mut u32, _source: *const u8) -> *mut u32 { ASSIGNED[ASSIGN_COUNT] = slot as usize; ASSIGN_COUNT += 1; slot }

    #[test]
    fn constructs_and_publishes_tables_once() {
        let _guard = TEST_LOCK.lock();
        let (Some(first), Some(second)) = (*FIRST, *SECOND) else {
            assert!(note_missing_u32_fixture("cxx/lazy_string_tables_initialize"));
            return;
        };
        unsafe {
            let first = first as *mut u32;
            let second = second as *mut u32;
            core::ptr::write_bytes(first, 0, 0x20);
            core::ptr::write_bytes(second, 0, 0x20);
            let slots = first.add(16);
            first.write(slots as usize as u32);
            first.add(TABLE_SOURCE_WORD).write(C_SEED.as_ptr() as usize as u32);
            HOST_HOLDER = [0; 5];
            CONSTRUCT_COUNT = 0;
            ASSIGN_COUNT = 0;
            OPAQUE_STRING_TABLE_CONSTRUCT = construct;
            CXX_STRING_ASSIGN_CSTR = assign;
            lazy_string_tables_initialize();
            assert_eq!(
                CONSTRUCT_CALLS.map(|(_, seed, count, mode)| (seed, count, mode)),
                [(b'C', 10, 2), (0, 10, 1)]
            );
            assert_eq!(ASSIGN_COUNT, INITIALIZED_SLOT_COUNT);
            for (index, slot) in ASSIGNED.iter().enumerate() {
                assert_eq!(*slot, slots.add(index) as usize);
            }
            assert_eq!(second.add(TABLE_LIMIT_WORD).read(), TABLE_LIMIT);
            assert_eq!(HOST_HOLDER[2], first as usize as u32);
            assert_eq!(HOST_HOLDER[3], second as usize as u32);
            assert_eq!(HOST_HOLDER[4], first as usize as u32);
            lazy_string_tables_initialize();
            assert_eq!(CONSTRUCT_COUNT, 2);
            assert_eq!(ASSIGN_COUNT, INITIALIZED_SLOT_COUNT);
        }
    }
}
