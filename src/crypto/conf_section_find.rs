//! Configuration section lookup from retailOS.

use core::ffi::c_void;
use super::obj_dat::{lh_retrieve, Lhash};

/// Target CONF prefix: method, method data, and section/value hash table.
/// Pointer fields widen together on hosts; target table offset remains +8.
#[repr(C)]
pub struct Configuration {
    pub method: *const c_void,
    pub method_data: *mut c_void,
    pub table: *mut Lhash,
}

#[repr(C)]
pub struct ConfigurationValue {
    pub section: *const u8,
    pub name: *const u8,
    pub value: *mut c_void,
}

/// Section-record lookup — `FUN_080733bc` @ 0x080733bc, 44 bytes.
/// Next real function starts at 0x080733e8. Raw-word decoding verifies
/// two incoming plain BLs, no predicated incoming BLs, and one outgoing
/// plain BL to `lh_retrieve` @ 0x082d7e0c (no predicated outgoing BLs).
/// Return NULL if configuration or section is NULL; otherwise construct
/// a key with section and NULL name and retrieve from configuration->table.
/// The stock stack push also supplies r3 as the third key word; preserve
/// that incidental value without assuming what the table callbacks read.
/// r2 is overwritten with zero before use. Deliberate deviations: native
/// host pointer widths via repr(C); otherwise no semantic deviations.
///
/// # Safety
/// Non-NULL configuration must point to a readable Configuration with a
/// valid initialized Lhash. Section and spill_value must meet its callback
/// requirements. The returned record remains owned by the configuration.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn conf_section_find(
    configuration: *const Configuration,
    section: *const u8,
    _unused: u32,
    spill_value: *mut c_void,
) -> *mut ConfigurationValue {
    if configuration.is_null() || section.is_null() {
        return core::ptr::null_mut();
    }
    let key = ConfigurationValue { section, name: core::ptr::null(), value: spill_value };
    unsafe { lh_retrieve((*configuration).table, core::ptr::addr_of!(key).cast()).cast() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::obj_dat::{LhashNode, LHASH_GETRN, LHASH_TEST_LOCK, LhashGetrn};

    struct Restore(LhashGetrn);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { LHASH_GETRN = self.0; } }
    }

    // A section table contains both named values and NULL-name section
    // records. Resolve by string content, not the section pointer identity.
    unsafe extern "C" fn resolve(
        table: *mut Lhash, key: *const c_void, hash: *mut u32,
    ) -> *mut *mut LhashNode {
        unsafe {
            *hash = 0;
            let probe = &*key.cast::<ConfigurationValue>();
            let mut slot = (*table).buckets;
            while !(*slot).is_null() {
                let record = &*(*(*slot)).data.cast::<ConfigurationValue>();
                let mut a = probe.section;
                let mut b = record.section;
                while *a != 0 && *a == *b { a = a.add(1); b = b.add(1); }
                if *a == *b && probe.name == record.name { return slot; }
                slot = slot.add(1);
            }
            slot
        }
    }

    #[test]
    fn null_inputs_return_without_reading_configuration_or_table() {
        unsafe {
            assert!(conf_section_find(core::ptr::null(), b"x\0".as_ptr(), 9, core::ptr::null_mut()).is_null());
            assert!(conf_section_find(core::ptr::dangling(), core::ptr::null(), 9, core::ptr::null_mut()).is_null());
            assert!(conf_section_find(core::ptr::null(), core::ptr::null(), 9, core::ptr::null_mut()).is_null());
        }
    }

    #[test]
    fn finds_section_not_named_value_and_counts_content_misses() {
        let _lock = LHASH_TEST_LOCK.lock();
        let _restore = Restore(unsafe { LHASH_GETRN });
        unsafe { LHASH_GETRN = resolve; }
        let mut named = ConfigurationValue { section: b"default\0".as_ptr(), name: b"key\0".as_ptr(), value: core::ptr::null_mut() };
        let mut section = ConfigurationValue { section: b"default\0".as_ptr(), name: core::ptr::null(), value: core::ptr::dangling_mut() };
        let mut empty = ConfigurationValue { section: b"\0".as_ptr(), name: core::ptr::null(), value: core::ptr::null_mut() };
        let mut nodes = [
            LhashNode { data: core::ptr::addr_of_mut!(named).cast(), next: core::ptr::null_mut() },
            LhashNode { data: core::ptr::addr_of_mut!(section).cast(), next: core::ptr::null_mut() },
            LhashNode { data: core::ptr::addr_of_mut!(empty).cast(), next: core::ptr::null_mut() },
        ];
        let mut slots = [core::ptr::addr_of_mut!(nodes[0]), core::ptr::addr_of_mut!(nodes[1]), core::ptr::addr_of_mut!(nodes[2]), core::ptr::null_mut()];
        let mut table = Lhash::empty();
        table.buckets = slots.as_mut_ptr();
        table.error = 17;
        let configuration = Configuration { method: core::ptr::null(), method_data: core::ptr::null_mut(), table: &mut table };
        let distinct = *b"default\0";
        unsafe {
            assert_eq!(conf_section_find(&configuration, distinct.as_ptr(), u32::MAX, core::ptr::null_mut()), &mut section as *mut _);
            assert_eq!(conf_section_find(&configuration, b"\0".as_ptr(), 0, core::ptr::null_mut()), &mut empty as *mut _);
            assert!(conf_section_find(&configuration, b"missing\0".as_ptr(), 0, core::ptr::null_mut()).is_null());
        }
        assert_eq!(table.error, 0);
        assert_eq!(table.num_retrieve, 2);
        assert_eq!(table.num_retrieve_miss, 1);
    }
}
