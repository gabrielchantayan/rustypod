//! Indexed element array derived destructor.
//!
//! `indexed_element_array_destruct` — original: `FUN_083cff80` @
//! **0x083cff80** (56 bytes; true extent `0x083cff80..0x083cffb7`, followed
//! by the vtable literal at `0x083cffb8`; the next real function begins at
//! `0x083cffbc`). Raw ARM decoding finds two inbound plain `bl` calls and no
//! predicated inbound `bl` calls. The body makes one predicated indirect
//! `blxne` through the owned payload's vtable, one plain `bl` to the
//! byte-identical `FUN_083cfef0` cleanup body, and tail-branches to
//! `observable_array_destruct` @ 0x08271d2c.
//!
//! # Algorithm
//!
//! Install the derived vtable, release the optional owned payload at `+0x14`
//! through vtable slot `+0x1c`, dispose indexed elements, then tail-chain to
//! the observable-array destructor. `FUN_083cfef0` uses the vtable-slot-0x40
//! accessor at 0x083d6870, byte-identical to the accessor used by the already
//! ported [`indexed_element_array_destroy`], so this port deliberately reuses
//! that semantic implementation. On the host, test seams replace both nested
//! destructor calls because target-width vtable words cannot hold host
//! callbacks; the production ARM path has no such deviation.

use crate::cxx::indexed_element_array_destroy::indexed_element_array_destroy;
use crate::cxx::observable_array::{observable_array_destruct, ObservableArray};

/// Vtable planted before derived cleanup (literal at 0x083cffb8).
pub const INDEXED_ELEMENT_ARRAY_VTABLE: u32 = 0x089a_3c18;
type IndexedElementArrayPayloadRelease = unsafe extern "C" fn(u32);
type IndexedElementArrayCleanup = unsafe extern "C" fn(*mut u8);
type ObservableArrayDestruct = unsafe extern "C" fn(*mut ObservableArray) -> *mut ObservableArray;
#[cfg(target_os = "none")]
unsafe extern "C" fn indexed_element_array_payload_release(payload: u32) {
    let vtable = (payload as usize as *const u32).read_volatile();
    let release: unsafe extern "C" fn() = core::mem::transmute(
        (vtable as usize as *const u32).add(0x1c / 4).read_volatile(),
    );
    release();
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn indexed_element_array_payload_release(_: u32) {
    panic!("host tests must replace INDEXED_ELEMENT_ARRAY_PAYLOAD_RELEASE");
}

static mut INDEXED_ELEMENT_ARRAY_PAYLOAD_RELEASE: IndexedElementArrayPayloadRelease =
    indexed_element_array_payload_release;
static mut INDEXED_ELEMENT_ARRAY_CLEANUP: IndexedElementArrayCleanup = indexed_element_array_destroy;
static mut INDEXED_ELEMENT_ARRAY_BASE_DESTRUCT: ObservableArrayDestruct = observable_array_destruct;

/// indexed_element_array_destruct — original: `FUN_083cff80` @ 0x083cff80.
///
/// # Safety
///
/// `array` must point to a writable target-layout indexed element array with a
/// readable optional payload word at `+0x14`. A nonzero payload must point to
/// a vtable with a callable slot at `+0x1c`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn indexed_element_array_destruct(array: *mut u8) -> *mut u8 {
    array.cast::<u32>().write_volatile(INDEXED_ELEMENT_ARRAY_VTABLE);

    let payload = array.add(0x14).cast::<u32>().read_volatile();
    if payload != 0 {
        let release =
            core::ptr::addr_of!(INDEXED_ELEMENT_ARRAY_PAYLOAD_RELEASE).read_volatile();
        release(payload);
    }

    let cleanup = core::ptr::addr_of!(INDEXED_ELEMENT_ARRAY_CLEANUP).read_volatile();
    cleanup(array);
    let base_destruct = core::ptr::addr_of!(INDEXED_ELEMENT_ARRAY_BASE_DESTRUCT).read_volatile();
    base_destruct(array.cast::<ObservableArray>());
    array
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [u32; 3] = [0; 3];
    static mut RECEIVER: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn record_payload_release(_: u32) {
        CALLS[0] += 1;
    }

    unsafe extern "C" fn record_cleanup(array: *mut u8) {
        CALLS[1] += 1;
        RECEIVER = array;
    }

    unsafe extern "C" fn record_base_destruct(array: *mut ObservableArray) -> *mut ObservableArray {
        CALLS[2] += 1;
        assert_eq!(array.cast::<u8>(), RECEIVER);
        array
    }

    unsafe fn install_seams() -> (
        IndexedElementArrayPayloadRelease,
        IndexedElementArrayCleanup,
        ObservableArrayDestruct,
    ) {
        let saved = (
            INDEXED_ELEMENT_ARRAY_PAYLOAD_RELEASE,
            INDEXED_ELEMENT_ARRAY_CLEANUP,
            INDEXED_ELEMENT_ARRAY_BASE_DESTRUCT,
        );
        INDEXED_ELEMENT_ARRAY_PAYLOAD_RELEASE = record_payload_release;
        INDEXED_ELEMENT_ARRAY_CLEANUP = record_cleanup;
        INDEXED_ELEMENT_ARRAY_BASE_DESTRUCT = record_base_destruct;
        saved
    }

    unsafe fn restore_seams(
        saved: (
            IndexedElementArrayPayloadRelease,
            IndexedElementArrayCleanup,
            ObservableArrayDestruct,
        ),
    ) {
        INDEXED_ELEMENT_ARRAY_PAYLOAD_RELEASE = saved.0;
        INDEXED_ELEMENT_ARRAY_CLEANUP = saved.1;
        INDEXED_ELEMENT_ARRAY_BASE_DESTRUCT = saved.2;
    }

    #[test]
    fn releases_payload_then_runs_derived_and_base_cleanup() {
        let _guard = TEST_LOCK.lock();
        let Some(array) = try_map_u32_slab(hints::INDEXED_ELEMENT_ARRAY_DESTRUCT, 0x1000) else {
            return;
        };

        unsafe {
            array.write_bytes(0, 0x1000);
            array.add(0x14).cast::<u32>().write_volatile(0x1234_5678);
            CALLS = [0; 3];
            RECEIVER = core::ptr::null_mut();
            let saved = install_seams();
            let result = indexed_element_array_destruct(array);
            restore_seams(saved);

            assert_eq!(result, array);
            assert_eq!(array.cast::<u32>().read_volatile(), INDEXED_ELEMENT_ARRAY_VTABLE);
            assert_eq!(CALLS, [1, 1, 1]);
            assert_eq!(RECEIVER, array);
        }
    }

    #[test]
    fn skips_the_virtual_release_for_a_null_payload() {
        let _guard = TEST_LOCK.lock();
        let Some(array) = try_map_u32_slab(hints::INDEXED_ELEMENT_ARRAY_DESTRUCT, 0x1000) else {
            return;
        };

        unsafe {
            array.write_bytes(0, 0x1000);
            CALLS = [0; 3];
            RECEIVER = core::ptr::null_mut();
            let saved = install_seams();
            indexed_element_array_destruct(array);
            restore_seams(saved);

            assert_eq!(array.cast::<u32>().read_volatile(), INDEXED_ELEMENT_ARRAY_VTABLE);
            assert_eq!(CALLS, [0, 1, 1]);
        }
    }
}
