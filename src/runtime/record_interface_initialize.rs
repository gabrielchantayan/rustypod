//! Initialize a three-word record through the cached retail interface.
//!
//! `FUN_080437e8` @ 0x080437e8: true size 64 bytes (60 code, 4 literal),
//! next real entry 0x08043828. Raw A32 decoding finds two incoming plain
//! BLs (0x0804373c, 0x080437c8), zero predicated BLs. The body has one
//! plain BL to 0x0805db2c, zero predicated BLs, and one indirect BLX.
//!
//! Read cache 0x08a0f6c4; if NULL, call the verified descriptor getter
//! (LDR r0, literal 0x08a0fb44; BX lr) and publish its result. Reload the
//! cache, invoke descriptor slot +8 with the record, then store the saved
//! value at record +8. No NULL guards, locks, or callback-result handling.
//! Deliberate deviations: host descriptor slots and cache use native-width
//! pointers; the record remains three u32 words on both platforms. Hosts
//! supply storage/getter explicitly. Target retains the stock getter rather
//! than interpreting descriptor contents before firmware initialization.

pub type RecordInitializer = unsafe extern "C" fn(*mut u32);

/// Only the third slot is interpreted; target slots are four bytes apart.
#[repr(C)]
pub struct RecordInterface {
    pub slot_zero: usize,
    pub slot_one: usize,
    pub initialize: RecordInitializer,
}

pub type RecordInterfaceGetter = unsafe extern "C" fn() -> *const RecordInterface;

#[cfg(not(target_os = "none"))]
pub static mut RECORD_INTERFACE_CACHE: *mut *const RecordInterface = core::ptr::null_mut();

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_record_interface() -> *const RecordInterface {
    panic!("install record interface host storage and getter")
}

#[cfg(not(target_os = "none"))]
pub static mut RECORD_INTERFACE_GETTER: RecordInterfaceGetter = missing_record_interface;

/// Initialize through descriptor slot 2, then replace record word 2.
///
/// # Safety
/// `record` must hold at least three aligned writable u32 words, plus any
/// storage required by the selected callback. The firmware cache (or host
/// storage/getter) must be valid and yield a descriptor with a callable
/// initializer. Access must follow the firmware's external synchronization.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_interface_initialize(record: *mut u32, value: u32) {
    #[cfg(target_os = "none")]
    let cache = 0x08a0_f6c4 as *mut *const RecordInterface;
    #[cfg(not(target_os = "none"))]
    let cache = core::ptr::read_volatile(core::ptr::addr_of!(RECORD_INTERFACE_CACHE));
    if core::ptr::read_volatile(cache).is_null() {
        #[cfg(target_os = "none")]
        let getter: RecordInterfaceGetter = core::mem::transmute(0x0805_db2cusize);
        #[cfg(not(target_os = "none"))]
        let getter = core::ptr::read_volatile(core::ptr::addr_of!(RECORD_INTERFACE_GETTER));
        core::ptr::write_volatile(cache, getter());
    }
    let interface = core::ptr::read_volatile(cache);
    let initialize = core::ptr::read(core::ptr::addr_of!((*interface).initialize));
    initialize(record);
    core::ptr::write(record.add(2), value);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut GETS: u32 = 0;
    static INTERFACE: RecordInterface = RecordInterface {
        slot_zero: 0, slot_one: 0, initialize,
    };
    static OVERRIDE: RecordInterface = RecordInterface {
        slot_zero: 0, slot_one: 0, initialize: override_initialize,
    };

    unsafe extern "C" fn getter() -> *const RecordInterface {
        GETS += 1;
        &INTERFACE
    }

    unsafe extern "C" fn initialize(record: *mut u32) {
        assert_eq!(*RECORD_INTERFACE_CACHE, &INTERFACE as *const _);
        // The callback must see the old third word, before the final store.
        *record = *record.add(2);
        *record.add(1) = 0x1234_5678;
        *record.add(2) = 0xdead_beef;
    }

    unsafe extern "C" fn override_initialize(record: *mut u32) {
        *record = !*record.add(2);
        *record.add(1) = 0x8765_4321;
        *record.add(2) = 7;
    }

    #[test]
    fn lazy_publication_reuse_override_and_post_callback_store() {
        let _guard = LOCK.lock();
        unsafe {
            let saved_cache = RECORD_INTERFACE_CACHE;
            let saved_getter = RECORD_INTERFACE_GETTER;
            let mut cache = core::ptr::null();
            RECORD_INTERFACE_CACHE = &mut cache;
            RECORD_INTERFACE_GETTER = getter;
            GETS = 0;
            for value in [0, u32::MAX, 0x8000_0000] {
                let mut record = [11, 22, 0xaabb_ccdd, 0xfeed_face];
                record_interface_initialize(record.as_mut_ptr(), value);
                assert_eq!(record, [0xaabb_ccdd, 0x1234_5678, value, 0xfeed_face]);
                assert_eq!(core::ptr::read_volatile(core::ptr::addr_of!(GETS)), 1);
            }
            cache = &OVERRIDE;
            let mut record = [11, 22, 0xaabb_ccdd, 0xfeed_face];
            record_interface_initialize(record.as_mut_ptr(), 0);
            assert_eq!(record, [!0xaabb_ccdd, 0x8765_4321, 0, 0xfeed_face]);
            assert_eq!(cache, &OVERRIDE as *const _);
            assert_eq!(core::ptr::read_volatile(core::ptr::addr_of!(GETS)), 1);
            RECORD_INTERFACE_CACHE = saved_cache;
            RECORD_INTERFACE_GETTER = saved_getter;
        }
    }
}
