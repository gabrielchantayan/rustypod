//! Destroy and release a nullable opaque record.
//!
//! `opaque_record_destroy_and_release` — original: `FUN_0804c8f4` @
//! `0x0804c8f4` (40 bytes; ten ARM words). Raw `osos.dec` establishes the
//! exact extent from `stmdb sp!, {r4,r5,r6,lr}` at `0x0804c8f4` through the
//! tail branch to `0x082cfae8` at `0x0804c918`; `0x0804c91c` begins the next
//! independently entered function. The body has one plain internal `bl` to
//! `0x0804c97c` and no predicated calls. Whole-image A32 decoding finds four
//! inbound plain `bl` calls (`0x0804c160`, `0x08086944`, `0x080a1f9c`, and
//! `0x082b32b0`) and no predicated inbound `bl` calls.
//!
//! Algorithm: NULL returns immediately. Otherwise preserve the record's
//! allocator/context word, destroy its owned contents through `0x0804c97c`,
//! then tail-dispatch the saved context and record to `0x082cfae8`. Deliberate
//! deviation: the two unported helpers remain fixed-address target seams;
//! host tests replace them with recorders to verify their order and arguments.

/// The opaque record's allocator/context pointer at target offset +0x00.
#[repr(C)]
pub struct OpaqueRecord {
    pub allocator: *mut u8,
}

type DestroyContents = unsafe extern "C" fn(*mut OpaqueRecord);
type ReleaseAllocation = unsafe extern "C" fn(*mut u8, *mut OpaqueRecord);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn destroy_contents(record: *mut OpaqueRecord) {
    let destroy: DestroyContents = core::mem::transmute(0x0804_c97cusize);
    destroy(record);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn release_allocation(allocator: *mut u8, record: *mut OpaqueRecord) {
    let release: ReleaseAllocation = core::mem::transmute(0x082c_fae8usize);
    release(allocator, record);
}

#[cfg(not(target_os = "none"))]
static mut DESTROY_CONTENTS: DestroyContents = host_destroy_contents;
#[cfg(not(target_os = "none"))]
static mut RELEASE_ALLOCATION: ReleaseAllocation = host_release_allocation;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_destroy_contents(_record: *mut OpaqueRecord) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_release_allocation(_allocator: *mut u8, _record: *mut OpaqueRecord) {}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn destroy_contents(record: *mut OpaqueRecord) {
    core::ptr::read_volatile(core::ptr::addr_of!(DESTROY_CONTENTS))(record);
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn release_allocation(allocator: *mut u8, record: *mut OpaqueRecord) {
    core::ptr::read_volatile(core::ptr::addr_of!(RELEASE_ALLOCATION))(allocator, record);
}

/// Destroys `record`'s contents and releases its saved allocation through its
/// allocator/context. A NULL `record` is accepted.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_record_destroy_and_release(record: *mut OpaqueRecord) {
    if record.is_null() {
        return;
    }
    let allocator = (*record).allocator;
    destroy_contents(record);
    release_allocation(allocator, record);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static DESTROYED: AtomicUsize = AtomicUsize::new(usize::MAX);
    static RELEASED_ALLOCATOR: AtomicUsize = AtomicUsize::new(usize::MAX);
    static RELEASED_RECORD: AtomicUsize = AtomicUsize::new(usize::MAX);

    unsafe extern "C" fn record_destroy(record: *mut OpaqueRecord) {
        DESTROYED.store(record as usize, Ordering::Relaxed);
        (*record).allocator = core::ptr::null_mut();
    }

    unsafe extern "C" fn record_release(allocator: *mut u8, record: *mut OpaqueRecord) {
        RELEASED_ALLOCATOR.store(allocator as usize, Ordering::Relaxed);
        RELEASED_RECORD.store(record as usize, Ordering::Relaxed);
    }

    #[test]
    fn null_record_skips_both_helpers() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            DESTROY_CONTENTS = record_destroy;
            RELEASE_ALLOCATION = record_release;
        }
        DESTROYED.store(usize::MAX, Ordering::Relaxed);
        RELEASED_ALLOCATOR.store(usize::MAX, Ordering::Relaxed);

        unsafe { opaque_record_destroy_and_release(core::ptr::null_mut()) };

        assert_eq!(DESTROYED.load(Ordering::Relaxed), usize::MAX);
        assert_eq!(RELEASED_ALLOCATOR.load(Ordering::Relaxed), usize::MAX);
    }

    #[test]
    fn saves_allocator_before_destroying_contents_then_releases_record() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            DESTROY_CONTENTS = record_destroy;
            RELEASE_ALLOCATION = record_release;
        }
        let mut allocator = 0_u8;
        let mut record = OpaqueRecord { allocator: &mut allocator };
        DESTROYED.store(usize::MAX, Ordering::Relaxed);
        RELEASED_ALLOCATOR.store(usize::MAX, Ordering::Relaxed);
        RELEASED_RECORD.store(usize::MAX, Ordering::Relaxed);

        unsafe { opaque_record_destroy_and_release(&mut record) };

        assert_eq!(DESTROYED.load(Ordering::Relaxed), &mut record as *mut _ as usize);
        assert_eq!(RELEASED_ALLOCATOR.load(Ordering::Relaxed), &mut allocator as *mut _ as usize);
        assert_eq!(RELEASED_RECORD.load(Ordering::Relaxed), &mut record as *mut _ as usize);
    }
}
