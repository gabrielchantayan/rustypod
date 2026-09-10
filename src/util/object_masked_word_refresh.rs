//! `object_masked_word_refresh` — original: `FUN_082c43d0` @ `0x082c43d0`
//! (32 bytes; 10 verified direct `bl` call sites, all unconditional).
//!
//! Raw ARM extent is exactly 32 bytes (`0x082c43d0..0x082c43f0`): the next
//! separately linked function begins with `subs r2, r0, #0` at `0x082c43f0`.
//! The ten calls are all plain `bl` instructions (`0x0838f9c8` through
//! `0x0838fb60`); none is predicated. Decoding every ARM B/BL word in
//! `osos.dec` verified this count.
//!
//! # Algorithm
//!
//! A non-NULL object is a target-width word layout. The function reads word
//! zero as an opaque source pointer and word 29 (`+0x74`) as a mask/value,
//! passes both to the direct helper at `0x0836f468`, then overwrites word 29
//! with its result. NULL returns without reading or calling. The helper is
//! not ported and its concrete identity is not recovered; the narrow boundary
//! is named only for its observed input/output role. Target builds call the
//! fixed retailOS address; host tests replace the boundary with a recorder.
//!
//! Deliberate deviation: host objects retain the firmware's `u32` word layout
//! rather than using pointer-width Rust fields, so word 29 stays `+0x74` on
//! both 32-bit target and 64-bit host.

use core::ptr;

const OBJECT_MASKED_WORD: usize = 29;
const RETAIL_MASKED_WORD_UPDATE: usize = 0x0836_f468;

type MaskedWordUpdate = unsafe extern "C" fn(*mut u8, u32) -> u32;

/// Executes the unresolved retail helper at its verified load address.
unsafe extern "C" fn firmware_masked_word_update(source: *mut u8, mask: u32) -> u32 {
    #[cfg(target_os = "none")]
    {
        let update: MaskedWordUpdate = core::mem::transmute(RETAIL_MASKED_WORD_UPDATE);
        update(source, mask)
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = (source, mask);
        0
    }
}

/// Boundary for the unported direct helper at `0x0836f468`.
static mut MASKED_WORD_UPDATE: MaskedWordUpdate = firmware_masked_word_update;

#[inline(always)]
unsafe fn masked_word_update() -> MaskedWordUpdate {
    unsafe { ptr::read_volatile(ptr::addr_of!(MASKED_WORD_UPDATE)) }
}

/// Refreshes word 29 (`+0x74`) of `object` through its opaque first-word
/// source pointer.
///
/// # Safety
///
/// If non-NULL, `object` must reference at least 30 writable target-width
/// words. Its first word is passed unchanged as a pointer to the retail
/// helper, whose preconditions remain in force.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_masked_word_refresh(object: *mut u32) {
    if object.is_null() {
        return;
    }

    let source = unsafe { ptr::read(object) as usize as *mut u8 };
    let mask = unsafe { ptr::read(object.add(OBJECT_MASKED_WORD)) };
    let refreshed = unsafe { masked_word_update()(source, mask) };
    unsafe { ptr::write(object.add(OBJECT_MASKED_WORD), refreshed) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{firmware_masked_word_update, object_masked_word_refresh, MaskedWordUpdate, MASKED_WORD_UPDATE, OBJECT_MASKED_WORD};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use parking_lot::{Mutex, MutexGuard};

    static UPDATE_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: usize = 0;
    static mut SEEN_SOURCE: usize = 0;
    static mut SEEN_MASK: u32 = 0;
    static mut RESULT: u32 = 0;

    unsafe extern "C" fn recording_update(source: *mut u8, mask: u32) -> u32 {
        unsafe {
            CALLS += 1;
            SEEN_SOURCE = source as usize;
            SEEN_MASK = mask;
            RESULT
        }
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    fn bench(result: u32) -> Bench {
        let lock = UPDATE_LOCK.lock();
        unsafe {
            CALLS = 0;
            SEEN_SOURCE = 0;
            SEEN_MASK = 0;
            RESULT = result;
            ptr::addr_of_mut!(MASKED_WORD_UPDATE).write(recording_update as MaskedWordUpdate);
        }
        Bench { _lock: lock }
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe { ptr::addr_of_mut!(MASKED_WORD_UPDATE).write(firmware_masked_word_update) };
        }
    }

    fn mapped_object() -> Option<*mut u32> {
        try_map_u32_slab(hints::OBJECT_MASKED_WORD_REFRESH, 0x100).map(|slab| slab.cast())
    }

    #[test]
    fn null_object_does_not_call_the_helper() {
        let _bench = bench(0xfeed_face);

        unsafe { object_masked_word_refresh(ptr::null_mut()) };

        assert_eq!(unsafe { CALLS }, 0);
    }

    #[test]
    fn passes_the_raw_source_and_word_29_then_replaces_that_word() {
        let _bench = bench(0x9abc_def0);
        let Some(object) = mapped_object() else {
            assert!(note_missing_u32_fixture("util::object_masked_word_refresh"));
            return;
        };
        let source = unsafe { object.cast::<u8>().add(0x80) };
        unsafe {
            ptr::write(object, source as usize as u32);
            ptr::write(object.add(OBJECT_MASKED_WORD), 0x1357_9bdf);
            object_masked_word_refresh(object);
        }

        assert_eq!(unsafe { CALLS }, 1);
        assert_eq!(unsafe { SEEN_SOURCE }, source as usize);
        assert_eq!(unsafe { SEEN_MASK }, 0x1357_9bdf);
        assert_eq!(unsafe { ptr::read(object.add(OBJECT_MASKED_WORD)) }, 0x9abc_def0);
    }

    #[test]
    fn null_source_still_dispatches_and_zero_result_is_stored() {
        let _bench = bench(0);
        let Some(object) = mapped_object() else {
            assert!(note_missing_u32_fixture("util::object_masked_word_refresh"));
            return;
        };
        unsafe {
            ptr::write(object, 0);
            ptr::write(object.add(OBJECT_MASKED_WORD), u32::MAX);
            object_masked_word_refresh(object);
        }

        assert_eq!(unsafe { CALLS }, 1);
        assert_eq!(unsafe { SEEN_SOURCE }, 0);
        assert_eq!(unsafe { SEEN_MASK }, u32::MAX);
        assert_eq!(unsafe { ptr::read(object.add(OBJECT_MASKED_WORD)) }, 0);
    }
}
