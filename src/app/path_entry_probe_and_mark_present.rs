//! Probe an entry's embedded path and mark the entry complete.
//!
//! Port: [`path_entry_probe_and_mark_present`] — original:
//! `FUN_0839944c` @ **0x0839944c**. Ghidra reports 68 instruction bytes;
//! raw `osos.dec` decoding establishes a 76-byte extent through the two-word
//! literal pool at `0x08399490..0x08399494`, with the next function beginning
//! at `0x08399498`. Decoding every ARM immediate `B`/`BL` word finds **five
//! direct inbound `bl` call sites**, all unconditional (no predicated forms):
//! `0x08329b70`, `0x0832a0e4`, `0x0832a5a8`, `0x0832a700`, and `0x0832a790`.
//!
//! An entry holds a completion byte at +0x00, an embedded `StringObject` path
//! at +0x04, and a signed path-probe hint byte at +0x0c. A null entry returns
//! `0xffffffce`; an already-complete entry returns zero without probing. For
//! an incomplete entry, the function sign-extends the hint, probes the
//! embedded path through [`path_probe_via_facade`], and marks the completion
//! byte only when that probe returns nonzero. It then returns literal
//! `0xffff5b80` for present and `0xffff5b81` for absent paths.
//!
//! Deliberate deviations: none. The existing, ported path-probe facade is
//! called directly; this introduces no new dispatch seam.

use crate::app::path_probe::path_probe_via_facade;
use crate::cxx::string_object::StringObject;

const INVALID_ARGUMENT: u32 = 0xffff_ffce;
const PATH_PRESENT: u32 = 0xffff_5b80;
const PATH_ABSENT: u32 = 0xffff_5b81;
const PATH_OBJECT_OFFSET: usize = 0x04;
const PATH_HINT_OFFSET: usize = 0x0c;

/// path_entry_probe_and_mark_present — original: `FUN_0839944c` @
/// **0x0839944c** (68 instruction bytes plus an 8-byte literal pool; 76 bytes
/// total; **five direct, unconditional inbound `bl` call sites**, verified by
/// decoding every ARM immediate `B`/`BL` word in `osos.dec`).
///
/// Rejects a null entry with `0xffffffce`. A nonzero completion byte returns
/// zero without dereferencing the embedded path. Otherwise probes `entry + 4`
/// with the sign-extended byte at `entry + 12`; zero probe status returns
/// `0xffff5b81`, while nonzero status writes completion byte one and returns
/// `0xffff5b80` from the literal pool.
///
/// # Safety
///
/// When non-null, `entry` must cover bytes +0x00 through +0x0c and contain an
/// embedded [`StringObject`] at +0x04 suitable for [`path_probe_via_facade`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn path_entry_probe_and_mark_present(entry: *mut u8) -> u32 {
    if entry.is_null() {
        return INVALID_ARGUMENT;
    }
    if entry.read() != 0 {
        return 0;
    }

    let path_hint = entry.add(PATH_HINT_OFFSET).read() as i8 as i32 as u32;
    let path = entry.add(PATH_OBJECT_OFFSET).cast::<StringObject>();
    if path_probe_via_facade(path, path_hint) == 0 {
        return PATH_ABSENT;
    }

    entry.write(1);
    PATH_PRESENT
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::path_probe::{
        FacadeObject, FacadeVtable, GuardDestroy, GuardConstruct, InterfaceGuard,
        PathProbeQuery, FACADE_PATH_PROBE_SLOT_INDEX, FACADE_VTABLE_SLOTS,
        PATH_PROBE_FACADE_FETCH, PATH_PROBE_GUARD_CTOR, PATH_PROBE_GUARD_DTOR,
    };
    use core::ptr;

    static mut QUERY_RESULT: u32 = 0;
    static mut QUERY_CALLS: u32 = 0;
    static mut QUERY_PATH: *mut StringObject = ptr::null_mut();
    static mut CTOR_HINT: u32 = 0;
    static mut MOCK_VTABLE: FacadeVtable = FacadeVtable {
        slots: [0; FACADE_VTABLE_SLOTS],
    };
    static mut MOCK_FACADE: FacadeObject = FacadeObject {
        vtable: ptr::null(),
    };

    struct PathProbeSeamGuard;

    impl Drop for PathProbeSeamGuard {
        fn drop(&mut self) {
            unsafe { crate::app::path_probe::tests::restore_firmware_seams() }
        }
    }

    unsafe extern "C" fn record_guard_construct(
        this: *mut InterfaceGuard,
        path_hint: u32,
    ) -> *mut InterfaceGuard {
        CTOR_HINT = path_hint;
        this
    }

    unsafe extern "C" fn record_facade_fetch(
        _guard: *mut InterfaceGuard,
        _selector: u32,
    ) -> *mut FacadeObject {
        ptr::addr_of_mut!(MOCK_FACADE)
    }

    unsafe extern "C" fn record_path_probe(
        _facade: *mut FacadeObject,
        path: *mut StringObject,
    ) -> u32 {
        QUERY_CALLS += 1;
        QUERY_PATH = path;
        QUERY_RESULT
    }

    unsafe extern "C" fn record_guard_destroy(this: *mut InterfaceGuard) -> *mut InterfaceGuard {
        this
    }

    unsafe fn install_path_probe(result: u32) {
        QUERY_RESULT = result;
        QUERY_CALLS = 0;
        QUERY_PATH = ptr::null_mut();
        CTOR_HINT = 0;
        let vtable = ptr::addr_of_mut!(MOCK_VTABLE);
        (*vtable).slots = [0; FACADE_VTABLE_SLOTS];
        (*vtable).slots[FACADE_PATH_PROBE_SLOT_INDEX] = record_path_probe as PathProbeQuery as usize;
        (*ptr::addr_of_mut!(MOCK_FACADE)).vtable = vtable;
        ptr::addr_of_mut!(PATH_PROBE_GUARD_CTOR)
            .write_volatile(record_guard_construct as GuardConstruct);
        ptr::addr_of_mut!(PATH_PROBE_FACADE_FETCH).write_volatile(record_facade_fetch);
        ptr::addr_of_mut!(PATH_PROBE_GUARD_DTOR)
            .write_volatile(record_guard_destroy as GuardDestroy);
    }

    #[test]
    fn validates_completion_then_maps_absent_and_present_probe_statuses() {
        let _probe_lock = crate::app::path_probe::tests::PATH_PROBE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let _restore = PathProbeSeamGuard;

        unsafe {
            assert_eq!(path_entry_probe_and_mark_present(ptr::null_mut()), INVALID_ARGUMENT);

            let mut entry = [0u8; 16];
            entry[PATH_HINT_OFFSET] = 0x80;
            let entry_ptr = entry.as_mut_ptr();

            install_path_probe(0);
            assert_eq!(path_entry_probe_and_mark_present(entry_ptr), PATH_ABSENT);
            assert_eq!(entry[0], 0, "an absent path must not complete the entry");
            assert_eq!(QUERY_CALLS, 1);
            assert_eq!(QUERY_PATH, entry_ptr.add(PATH_OBJECT_OFFSET).cast());
            assert_eq!(CTOR_HINT, 0xffff_ff80, "the hint byte is sign-extended");

            install_path_probe(0x1234_5678);
            assert_eq!(path_entry_probe_and_mark_present(entry_ptr), PATH_PRESENT);
            assert_eq!(entry[0], 1, "a nonzero probe result completes the entry");
            assert_eq!(QUERY_CALLS, 1);

            QUERY_CALLS = 0;
            assert_eq!(path_entry_probe_and_mark_present(entry_ptr), 0);
            assert_eq!(QUERY_CALLS, 0, "a completed entry bypasses the probe");
        }
    }
}
