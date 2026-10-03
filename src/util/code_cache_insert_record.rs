//! Insert a code-cache record — FUN_08243844 @ 0x08243844, 172 bytes.
//! Raw A32 extent is 0x08243844..0x082438f0 (next function's push).
//! Outbound calls: one plain BL, one predicated BLCS, one indirect BLX.
//! Select the kind predicate, compact if wrapping cursor+size reaches capacity
//! or the record array is full, then prepend a 0xcc-byte record. Clear its flags,
//! initialize its payload through predicate vtable slot zero, and store kind's
//! low byte after dispatch. Deliberate deviations: host-only dependency seams;
//! target uses the existing selector and verified retail compactor, not a guess.

#[cfg(test)]
use core::ptr;

type Initialize = unsafe extern "C" fn(*mut Predicate, *mut u32, u32, usize);
#[repr(C)]
struct Predicate { vtable: *const Initialize }

#[cfg(not(test))]
unsafe fn select(kind: u32) -> *mut Predicate {
    super::predicate_for_kind::predicate_for_kind(kind) as usize as *mut Predicate
}
#[cfg(test)]
static mut SELECT: unsafe fn(u32) -> *mut Predicate = missing_select;
#[cfg(test)]
unsafe fn missing_select(_: u32) -> *mut Predicate { panic!("install host predicate") }
#[cfg(test)]
unsafe fn select(kind: u32) -> *mut Predicate {
    unsafe { (ptr::read_volatile(ptr::addr_of!(SELECT)))(kind) }
}

#[cfg(target_os = "none")]
unsafe fn compact(cache: *mut u32) {
    let compact: unsafe extern "C" fn(*mut u32) = unsafe { core::mem::transmute(0x0824_33b4usize) };
    unsafe { compact(cache) }
}
#[cfg(all(not(target_os = "none"), not(test)))]
unsafe fn compact(_: *mut u32) { panic!("requires retail compactor 0x082433b4") }
#[cfg(test)]
static mut COMPACT: unsafe fn(*mut u32) = missing_compact;
#[cfg(test)]
unsafe fn missing_compact(_: *mut u32) { panic!("install host compactor") }
#[cfg(all(test, not(target_os = "none")))]
unsafe fn compact(cache: *mut u32) {
    unsafe { (ptr::read_volatile(ptr::addr_of!(COMPACT)))(cache) }
}

/// `cache` contains target u32 pointer words; its array and intrusive list must
/// be valid, and compaction must leave space for one record and the requested
/// code size. The selected predicate must expose a valid initializer.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn code_cache_insert_record(
    cache: *mut u32, kind: u32, value: u32, code_size: u32,
) -> *mut u32 {
    unsafe {
        let predicate = select(kind);
        if cache.add(1).read().wrapping_add(code_size) >= cache.add(2).read()
            || cache.add(6).read() >= cache.add(7).read() {
            compact(cache);
        }
        let index = cache.add(6).read();
        cache.add(6).write(index.wrapping_add(1));
        let address = cache.add(3).read().wrapping_add(index.wrapping_mul(0xcc));
        let record = address as usize as *mut u32;
        record.add(1).write(cache.add(4).read());
        record.write(0);
        let head = cache.add(4).read();
        if head == 0 {
            cache.add(5).write(address);
        } else {
            (head as usize as *mut u32).write(address);
        }
        cache.add(4).write(address);
        record.add(0x31).write(0);
        let initialize = (*predicate).vtable.read();
        initialize(predicate, record.add(2), value, initialize as usize);
        record.cast::<u8>().add(0xc8).write(kind as u8);
        record
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::sync::LazyLock;
    use parking_lot::Mutex;
    use crate::testing::{hints, try_map_u32_slab, note_missing_u32_fixture};
    static LOCK: Mutex<()> = Mutex::new(());
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(||
        try_map_u32_slab(hints::CODE_CACHE_INSERT_RECORD, 0x1000).map(|p| p as usize));
    static mut GROWS: u32 = 0;
    unsafe extern "C" fn initialize(object: *mut Predicate, payload: *mut u32, value: u32, self_pointer: usize) {
        unsafe {
            assert_eq!(object, ptr::addr_of_mut!(PREDICATE));
            assert_eq!(self_pointer, initialize as usize);
            // Linking/flag clearing precede dispatch; kind storage follows it.
            assert_eq!(payload.sub(2).read(), 0);
            assert_eq!(payload.add(47).read(), 0);
            assert_eq!(payload.cast::<u8>().add(0xc0).read(), 0xa5);
            payload.write(value);
        }
    }
    static VTABLE: Initialize = initialize;
    static mut PREDICATE: Predicate = Predicate { vtable: &VTABLE };
    unsafe fn selector(kind: u32) -> *mut Predicate {
        assert_eq!(kind, 0x102);
        ptr::addr_of_mut!(PREDICATE)
    }
    unsafe fn compact_fixture(cache: *mut u32) {
        unsafe {
            GROWS += 1;
            cache.add(1).write(0);
            cache.add(6).write(0);
            cache.add(4).write(0);
            cache.add(5).write(0);
        }
    }
    #[test]
    fn capacity_boundaries_wrapping_and_intrusive_links() {
        let _guard = LOCK.lock();
        let Some(base) = *FIXTURE else {
            note_missing_u32_fixture("code_cache_insert_record"); return;
        };
        unsafe {
            SELECT = selector;
            COMPACT = compact_fixture;
            let cache = base as *mut u32;
            let records = (base + 0x100) as *mut u32;
            // Equality at either limit compacts; unsigned addition wraps.
            for (cursor, size, used, expected_grows) in [
                (8, 1, 0, 0), (9, 1, 0, 1), (11, 0, 0, 1),
                (0, 0, 2, 1), (u32::MAX, 2, 0, 0),
            ] {
                ptr::write_bytes(base as *mut u8, 0xa5, 0x1000);
                ptr::write_bytes(cache, 0, 11);
                cache.add(1).write(cursor);
                cache.add(2).write(10);
                cache.add(3).write(records as usize as u32);
                cache.add(6).write(used);
                cache.add(7).write(2);
                GROWS = 0;
                let first = code_cache_insert_record(cache, 0x102, 0x12345678, size);
                assert_eq!(first, records);
                assert_eq!(ptr::read_volatile(ptr::addr_of!(GROWS)), expected_grows);
                assert_eq!(cache.add(6).read(), 1);
                assert_eq!(cache.add(4).read(), first as usize as u32);
                assert_eq!(cache.add(5).read(), first as usize as u32);
                assert_eq!(first.add(1).read(), 0);
                assert_eq!(first.add(2).read(), 0x12345678);
                assert_eq!(first.cast::<u8>().add(0xc8).read(), 2);
                assert_eq!(first.add(0x2f).read(), 0xa5a5a5a5);
                assert_eq!(first.add(0x30).read(), 0xa5a5a5a5);
                cache.add(1).write(0);
                let second = code_cache_insert_record(cache, 0x102, 7, 0);
                assert_eq!(second, records.add(51));
                assert_eq!(first.read(), second as usize as u32);
                assert_eq!(second.add(1).read(), first as usize as u32);
                assert_eq!(cache.add(4).read(), second as usize as u32);
                assert_eq!(cache.add(5).read(), first as usize as u32);
                assert_eq!(cache.add(6).read(), 2);
            }
            SELECT = missing_select;
            COMPACT = missing_compact;
        }
    }
}
