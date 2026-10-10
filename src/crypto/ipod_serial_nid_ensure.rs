//! Lazily register the iPod serial-number ASN.1 object identifier.
//!
//! Original `FUN_08078258` @ 0x08078258: 120 bytes through the next real
//! entry at 0x080782d0 (64 instruction bytes, 56 literal/string bytes).
//! Raw A32 scan: two incoming plain BLs, zero predicated BLs; two outgoing
//! plain BLs, zero predicated BLs. Cache word 2 at 0x08a096bc is checked
//! first, then assigned OBJ_ln2nid("iPod Serial Number"). On zero, assign
//! OBJ_create("1.3.6.1.4.1.63.42", "iPod S/N", "iPod Serial Number").
//! A failed creation leaves zero so a later invocation retries.
//! Deliberate deviations: relocated strings and typed firmware seams for
//! unported OBJ_ln2nid/OBJ_create; host builds use an isolated cache/dispatch.
//! Raw OBJ_create overwrites r3 before use: Ghidra's fourth argument is false.

use core::ptr::{addr_of_mut, read_volatile, write_volatile};

type LongNameToNid = unsafe extern "C" fn(*const u8) -> i32;
type CreateObject = unsafe extern "C" fn(*const u8, *const u8, *const u8) -> i32;

const LONG_NAME: &[u8] = b"iPod Serial Number\0";
const SHORT_NAME: &[u8] = b"iPod S/N\0";
const OID: &[u8] = b"1.3.6.1.4.1.63.42\0";

#[cfg(not(target_os = "none"))]
static mut HOST_CACHE: [i32; 3] = [0; 3];
#[cfg(not(target_os = "none"))]
static mut LONG_NAME_TO_NID: LongNameToNid = missing_lookup;
#[cfg(not(target_os = "none"))]
static mut CREATE_OBJECT: CreateObject = missing_create;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_lookup(_: *const u8) -> i32 {
    panic!("ipod_serial_nid_ensure requires OBJ_ln2nid host fixture")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_create(_: *const u8, _: *const u8, _: *const u8) -> i32 {
    panic!("ipod_serial_nid_ensure requires OBJ_create host fixture")
}

/// Ensure the shared serial-number NID exists. RetailOS serializes callers.
///
/// # Safety
/// Firmware globals and object registry must be initialized; callers must
/// serialize access to the shared cache and registry (also on the host).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ipod_serial_nid_ensure() {
    #[cfg(target_os = "none")]
    let cache = (0x08a0_96bc as *mut i32).add(2);
    #[cfg(not(target_os = "none"))]
    let cache = addr_of_mut!(HOST_CACHE).cast::<i32>().add(2);
    if read_volatile(cache) != 0 {
        return;
    }
    #[cfg(target_os = "none")]
    let lookup: LongNameToNid = core::mem::transmute(0x0805_edc4usize);
    #[cfg(not(target_os = "none"))]
    let lookup = read_volatile(core::ptr::addr_of!(LONG_NAME_TO_NID));
    let nid = lookup(LONG_NAME.as_ptr());
    write_volatile(cache, nid);
    if nid != 0 {
        return;
    }
    #[cfg(target_os = "none")]
    let create: CreateObject = core::mem::transmute(0x0805_eb94usize);
    #[cfg(not(target_os = "none"))]
    let create = read_volatile(core::ptr::addr_of!(CREATE_OBJECT));
    write_volatile(cache, create(OID.as_ptr(), SHORT_NAME.as_ptr(), LONG_NAME.as_ptr()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut LOOKUP_RESULT: i32 = 0;
    static mut CREATE_RESULT: i32 = 0;
    static mut LOOKUPS: usize = 0;
    static mut CREATIONS: usize = 0;

    unsafe extern "C" fn lookup(name: *const u8) -> i32 {
        assert_eq!(core::ffi::CStr::from_ptr(name.cast()).to_bytes(), b"iPod Serial Number");
        LOOKUPS += 1;
        LOOKUP_RESULT
    }
    unsafe extern "C" fn create(oid: *const u8, short: *const u8, long: *const u8) -> i32 {
        assert_eq!(core::ffi::CStr::from_ptr(oid.cast()).to_bytes(), b"1.3.6.1.4.1.63.42");
        assert_eq!(core::ffi::CStr::from_ptr(short.cast()).to_bytes(), b"iPod S/N");
        assert_eq!(core::ffi::CStr::from_ptr(long.cast()).to_bytes(), b"iPod Serial Number");
        assert_eq!(read_volatile(addr_of_mut!(HOST_CACHE).cast::<i32>().add(2)), 0);
        CREATIONS += 1;
        CREATE_RESULT
    }

    #[test]
    fn caches_existing_nids_and_retries_failed_creation() {
        let _guard = LOCK.lock();
        unsafe {
            LONG_NAME_TO_NID = lookup;
            CREATE_OBJECT = create;
            HOST_CACHE = [11, 22, -1];
            LOOKUPS = 0;
            CREATIONS = 0;
            ipod_serial_nid_ensure();
            assert_eq!((LOOKUPS, CREATIONS), (0, 0));
            assert_eq!(HOST_CACHE, [11, 22, -1]);

            HOST_CACHE[2] = 0;
            LOOKUP_RESULT = 713;
            ipod_serial_nid_ensure();
            ipod_serial_nid_ensure();
            assert_eq!(HOST_CACHE, [11, 22, 713]);
            assert_eq!((LOOKUPS, CREATIONS), (1, 0));

            HOST_CACHE[2] = 0;
            LOOKUP_RESULT = 0;
            CREATE_RESULT = 0;
            ipod_serial_nid_ensure();
            assert_eq!(HOST_CACHE, [11, 22, 0]);
            CREATE_RESULT = 714;
            ipod_serial_nid_ensure();
            ipod_serial_nid_ensure();
            assert_eq!(HOST_CACHE, [11, 22, 714]);
            assert_eq!((LOOKUPS, CREATIONS), (3, 2));
            LONG_NAME_TO_NID = missing_lookup;
            CREATE_OBJECT = missing_create;
            HOST_CACHE = [0; 3];
        }
    }
}
