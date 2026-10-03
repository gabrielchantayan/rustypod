//! Path-loaded numeric-pair table constructor, retailOS FUN_0826c938.
//! Load address 0x0826c938; true extent 92 bytes (88 code + 4-byte empty
//! string at 0x0826c990), next entry 0x0826c994. Raw A32 census: five
//! outbound plain BLs, zero predicated; two inbound plain BLs, zero predicated.
//! Mark valid, construct an empty title, clear the count and 1,000 pairs,
//! copy-construct a temporary path, load the table, destroy the temporary,
//! and return this. The parser may clear valid on open/format failure.
//! Deviations: native-pointer StringObject layout on hosts; modeled string
//! vtable; the ported zero-fill is called through a volatile function pointer
//! to prevent LLVM merging count/pair clearing into a builtin. The parser
//! remains retail code at 0x0826c714 behind an injectable function slot.
//! These two boundaries compile to BLX rather than the original direct BL.
use crate::app::path_object_construct::path_object_copy_construct;
use crate::cxx::string_object::{
    StringObject, string_object_construct_from_cstr, string_object_destroy,
};
use crate::libc::memzero::memzero_aligned;

/// Target offsets: valid +0, title +4, pairs +12, count +0xfac.
#[repr(C)]
pub struct NumericPairTable {
    pub valid: u8,
    pub reserved: [u8; 3],
    pub title: StringObject,
    pub pairs: [[u16; 2]; 1000],
    pub count: u32,
}

pub type LoadPairs = unsafe extern "C" fn(*mut NumericPairTable, *const StringObject);
#[cfg(target_os = "none")]
unsafe extern "C" fn load_pairs(table: *mut NumericPairTable, path: *const StringObject) {
    let load: LoadPairs = core::mem::transmute(0x0826c714usize);
    load(table, path);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn load_pairs(_: *mut NumericPairTable, _: *const StringObject) {
    panic!("numeric-pair file parser requires retailOS");
}

/// Parser boundary; shipped target default invokes retailOS at 0x0826c714.
/// Hosts may install a parser implementation before calling the constructor.
pub static mut NUMERIC_PAIR_TABLE_LOAD: LoadPairs = load_pairs;

/// Construct a table from a caller-owned path. See module header for raw
/// extent, call census, and deliberate deviations. Storage must be writable
/// and aligned; source must be a valid StringObject, disjoint from storage.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn numeric_pair_table_construct(
    this: *mut NumericPairTable, path: *const StringObject,
) -> *mut NumericPairTable {
    let load = core::ptr::read_volatile(core::ptr::addr_of!(NUMERIC_PAIR_TABLE_LOAD));
    construct_with_loader(this, path, load)
}
unsafe fn construct_with_loader(
    this: *mut NumericPairTable, path: *const StringObject, load: LoadPairs,
) -> *mut NumericPairTable {
    (*this).valid = 1;
    string_object_construct_from_cstr(core::ptr::addr_of_mut!((*this).title), b"\0".as_ptr());
    (*this).count = 0;
    let zero: unsafe extern "C" fn(*mut u8, usize) -> *mut u8 =
        core::ptr::read_volatile(&(memzero_aligned as unsafe extern "C" fn(*mut u8, usize) -> *mut u8));
    zero(core::ptr::addr_of_mut!((*this).pairs).cast(), 4000);
    let mut temporary = core::mem::MaybeUninit::<StringObject>::uninit();
    let copied = path_object_copy_construct(temporary.as_mut_ptr(), path);
    load(this, copied);
    string_object_destroy(temporary.as_mut_ptr());
    this
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string_object::STRING_OBJECT_VTABLE;

    unsafe extern "C" fn open_failure(table: *mut NumericPairTable, _: *const StringObject) {
        assert_eq!((*table).valid, 1);
        assert_eq!((*table).count, 0);
        assert_eq!((*table).pairs, [[0; 2]; 1000]);
        assert!((*table).title.payload.is_null());
        (*table).valid = 0;
    }

    unsafe extern "C" fn full_table(table: *mut NumericPairTable, _: *const StringObject) {
        assert_eq!((*table).count, 0);
        assert_eq!((*table).pairs, [[0; 2]; 1000]);
        for (i, pair) in (*table).pairs.iter_mut().enumerate() {
            *pair = [i as u16, u16::MAX - i as u16];
        }
        (*table).count = 1000;
    }

    #[test]
    fn dirty_storage_is_initialized_and_parser_failure_survives() {
        exercise(open_failure, false);
    }

    #[test]
    fn full_capacity_and_extreme_pair_values_survive_temporary_teardown() {
        exercise(full_table, true);
    }

    fn exercise(load: LoadPairs, success: bool) {
        let source = StringObject { vtable: &STRING_OBJECT_VTABLE, payload: core::ptr::null_mut() };
        let mut storage = core::mem::MaybeUninit::<NumericPairTable>::uninit();
        unsafe {
            core::ptr::write_bytes(storage.as_mut_ptr().cast::<u8>(), 0xa5,
                core::mem::size_of::<NumericPairTable>());
            assert_eq!(construct_with_loader(storage.as_mut_ptr(), &source, load), storage.as_mut_ptr());
            let table = storage.assume_init();
            assert_eq!(table.reserved, [0xa5; 3]);
            assert_eq!(table.valid, u8::from(success));
            assert!(source.payload.is_null());
            assert!(table.title.payload.is_null());
            assert_eq!(table.count, if success { 1000 } else { 0 });
            for (i, pair) in table.pairs.iter().enumerate() {
                assert_eq!(*pair, if success { [i as u16, u16::MAX - i as u16] } else { [0, 0] });
            }
        }
    }
}
