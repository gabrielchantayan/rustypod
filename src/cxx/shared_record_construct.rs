//! Constructs the shared-handle record used by the process-global registry.
//!
//! ## Original: `FUN_083d9d5c` @ 0x083d9d5c (196 bytes)
//!
//! Raw `osos.dec` establishes the extent `0x083d9d5c..0x083d9e20`: 188 bytes
//! of instructions followed by the two-word literal pool. The next separately
//! linked function begins at `0x083d9e28`. Decoding every ARM B/BL immediate
//! finds four inbound predicated `bl` call sites (0x082a9144, 0x082a91cc,
//! 0x082a921c, and 0x082a926c), no inbound plain calls, and six outbound plain
//! `bl` instructions (two each to `copy_u32_pair` and the other four direct
//! targets); there are no predicated outbound calls.
//!
//! The constructor selects and records a selector-specific layout size, clears
//! its embedded state, acquires the process-wide shared handle at +0x2c,
//! installs the final vtable and selector descriptor, initializes two
//! `{u32::MAX, 0}` pairs, then delegates payload initialization. Target builds
//! call the three unported direct targets at their verified retail addresses;
//! host builds expose ABI seams. Deliberate deviation: the two raw pair-copy
//! calls are expressed as direct word stores because `copy_u32_pair` is a
//! leaf copy whose complete semantics are known.

use crate::cxx::shared_handle_initialize::shared_handle_initialize;

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const INITIAL_VTABLE: u32 = 0x089a_879c;
const FINAL_VTABLE: u32 = 0x089a_86a8;
const RETAIL_SELECTOR_LAYOUT_SIZE: usize = 0x0826_6b64;
const RETAIL_SELECTOR_DESCRIPTOR_INITIALIZE: usize = 0x0826_6c18;
const RETAIL_PAYLOAD_INITIALIZE: usize = 0x083d_9a64;

type SelectorLayoutSize = unsafe extern "C" fn(u32) -> u32;
type SelectorDescriptorInitialize = unsafe extern "C" fn(*mut u32, u32) -> *mut u32;
type PayloadInitialize = unsafe extern "C" fn(*mut u32, u32, u32) -> *mut u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn selector_layout_size(selector: u32) -> u32 {
    core::mem::transmute::<usize, SelectorLayoutSize>(RETAIL_SELECTOR_LAYOUT_SIZE)(selector)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_selector_layout_size(_selector: u32) -> u32 { 0 }

/// Host replacement for unported `FUN_08266b64`.
#[cfg(not(target_os = "none"))]
pub static mut SELECTOR_LAYOUT_SIZE: SelectorLayoutSize = missing_selector_layout_size;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn selector_layout_size(selector: u32) -> u32 {
    core::ptr::read_volatile(addr_of!(SELECTOR_LAYOUT_SIZE))(selector)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn selector_descriptor_initialize(storage: *mut u32, selector: u32) -> *mut u32 {
    core::mem::transmute::<usize, SelectorDescriptorInitialize>(RETAIL_SELECTOR_DESCRIPTOR_INITIALIZE)(storage, selector)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_selector_descriptor_initialize(storage: *mut u32, _selector: u32) -> *mut u32 { storage }

/// Host replacement for unported `FUN_08266c18`.
#[cfg(not(target_os = "none"))]
pub static mut SELECTOR_DESCRIPTOR_INITIALIZE: SelectorDescriptorInitialize = missing_selector_descriptor_initialize;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn selector_descriptor_initialize(storage: *mut u32, selector: u32) -> *mut u32 {
    core::ptr::read_volatile(addr_of!(SELECTOR_DESCRIPTOR_INITIALIZE))(storage, selector)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn payload_initialize(storage: *mut u32, value: u32, count: u32) -> *mut u32 {
    core::mem::transmute::<usize, PayloadInitialize>(RETAIL_PAYLOAD_INITIALIZE)(storage, value, count)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_payload_initialize(storage: *mut u32, _value: u32, _count: u32) -> *mut u32 { storage }

/// Host replacement for unported `FUN_083d9a64`.
#[cfg(not(target_os = "none"))]
pub static mut PAYLOAD_INITIALIZE: PayloadInitialize = missing_payload_initialize;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn payload_initialize(storage: *mut u32, value: u32, count: u32) -> *mut u32 {
    core::ptr::read_volatile(addr_of!(PAYLOAD_INITIALIZE))(storage, value, count)
}

/// `shared_record_construct` — retailOS `FUN_083d9d5c` @ `0x083d9d5c` (196
/// bytes; four incoming predicated `bl` call sites; six outbound plain `bl`
/// instructions and no outbound predicated forms, verified from `osos.dec`).
///
/// # Safety
/// `storage` must point to at least 18 aligned writable target words. Its
/// process-wide shared handle and the unported selector/payload callees must
/// meet their respective retailOS contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn shared_record_construct(storage: *mut u32, selector: u32, value: u32, count: u32) -> *mut u32 {
    let layout_size = selector_layout_size(selector);
    storage.add(1).write(layout_size);
    storage.add(2).write(0);
    storage.write(INITIAL_VTABLE);
    for word in 3..11 { storage.add(word).write(0); }
    shared_handle_initialize(storage.add(11));
    storage.write(FINAL_VTABLE);
    selector_descriptor_initialize(storage.add(12), selector);
    storage.add(13).write(u32::MAX);
    storage.add(14).write(0);
    storage.add(15).write(u32::MAX);
    storage.add(16).write(0);
    storage.add(2).write(0);
    payload_initialize(storage, value, count);
    storage
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::cxx::shared_handle_initialize::{SHARED_HANDLE_GLOBAL, SHARED_HANDLE_INITIALIZE_TEST_LOCK};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex, MutexGuard};

    const WORDS: usize = 0x100;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| try_map_u32_slab(hints::SHARED_RECORD_CONSTRUCT, WORDS * 4).map(|p| p as usize));
    static LOCK: Mutex<()> = Mutex::new(());
    static mut DESCRIPTOR_ARGS: (*mut u32, u32) = (core::ptr::null_mut(), 0);
    static mut PAYLOAD_ARGS: (*mut u32, u32, u32) = (core::ptr::null_mut(), 0, 0);

    unsafe extern "C" fn layout(selector: u32) -> u32 { selector.wrapping_mul(4).wrapping_add(4) }
    unsafe extern "C" fn descriptor(storage: *mut u32, selector: u32) -> *mut u32 { DESCRIPTOR_ARGS = (storage, selector); storage.write(0xd000_0000 | selector); storage }
    unsafe extern "C" fn payload(storage: *mut u32, value: u32, count: u32) -> *mut u32 { PAYLOAD_ARGS = (storage, value, count); storage }

    struct Reset { _lock: MutexGuard<'static, ()>, layout: SelectorLayoutSize, descriptor: SelectorDescriptorInitialize, payload: PayloadInitialize, shared: u32 }
    impl Drop for Reset { fn drop(&mut self) { unsafe { SELECTOR_LAYOUT_SIZE = self.layout; SELECTOR_DESCRIPTOR_INITIALIZE = self.descriptor; PAYLOAD_INITIALIZE = self.payload; SHARED_HANDLE_GLOBAL = self.shared; } } }
    fn reset() -> Reset {
        let lock = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        unsafe {
            let reset = Reset { _lock: lock, layout: SELECTOR_LAYOUT_SIZE, descriptor: SELECTOR_DESCRIPTOR_INITIALIZE, payload: PAYLOAD_INITIALIZE, shared: SHARED_HANDLE_GLOBAL };
            SELECTOR_LAYOUT_SIZE = layout; SELECTOR_DESCRIPTOR_INITIALIZE = descriptor; PAYLOAD_INITIALIZE = payload;
            DESCRIPTOR_ARGS = (core::ptr::null_mut(), 0); PAYLOAD_ARGS = (core::ptr::null_mut(), 0, 0);
            reset
        }
    }

    #[test]
    fn initializes_all_embedded_members_and_forwards_arguments() {
        let _shared = SHARED_HANDLE_INITIALIZE_TEST_LOCK.lock();
        let _reset = reset();
        let Some(fixture) = *FIXTURE else { assert!(note_missing_u32_fixture("cxx/shared_record_construct")); return; };
        unsafe {
            let words = fixture as *mut u32; core::ptr::write_bytes(words.cast::<u8>(), 0xa5, WORDS * 4);
            let shared = words.add(16); shared.add(7).write(u32::MAX); SHARED_HANDLE_GLOBAL = shared as usize as u32;
            let storage = words.add(48); assert_eq!(shared_record_construct(storage, 2, 0x1122_3344, 0x5566_7788), storage);
            assert_eq!(*storage, FINAL_VTABLE); assert_eq!(*storage.add(1), 12); assert_eq!(*storage.add(2), 0);
            assert_eq!(*storage.add(3), 0);
            assert!((3..11).all(|word| *storage.add(word) == 0));
            assert_eq!(*storage.add(11), shared as usize as u32); assert_eq!(*shared.add(7), 0);
            assert_eq!(DESCRIPTOR_ARGS, (storage.add(12), 2)); assert_eq!(*storage.add(12), 0xd000_0002);
            assert_eq!(core::slice::from_raw_parts(storage.add(13), 4), &[u32::MAX, 0, u32::MAX, 0]);
            assert_eq!(PAYLOAD_ARGS, (storage, 0x1122_3344, 0x5566_7788));
        }
    }

    #[test]
    fn preserves_nonstandard_selector_and_wrapping_layout_result() {
        let _shared = SHARED_HANDLE_INITIALIZE_TEST_LOCK.lock();
        let _reset = reset();
        let Some(fixture) = *FIXTURE else { assert!(note_missing_u32_fixture("cxx/shared_record_construct selector")); return; };
        unsafe {
            let words = fixture as *mut u32; core::ptr::write_bytes(words.cast::<u8>(), 0, WORDS * 4);
            let shared = words.add(16); SHARED_HANDLE_GLOBAL = shared as usize as u32;
            let storage = words.add(48); shared_record_construct(storage, u32::MAX, 0, 0);
            assert_eq!(*storage.add(1), 0); assert_eq!(DESCRIPTOR_ARGS, (storage.add(12), u32::MAX));
        }
    }
}
