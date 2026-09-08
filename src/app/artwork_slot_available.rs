//! Availability query for the four artwork slots owned by the class-0x7f80
//! media singleton.
//!
//! `artwork_slot_available` — original: `FUN_081b6d88` @ **0x081b6d88**
//! (**80 bytes**; **19 direct `bl` call sites, all unconditional**).
//!
//! Raw ARM decoding establishes the exact extent `0x081b6d88..0x081b6dd8`:
//!
//! ```text
//! 081b6d88  push {r4-r6, lr}
//! 081b6d8c  r5 = cache; r4 = cache + 0x18; r6 = slot_index
//! 081b6d9c  bl   0x0807f5c4                 ; mutex_lock(cache + 0x18)
//! 081b6da0  r0 = 0
//! 081b6da0  if slot_index <= 3:
//! 081b6dac      slot = cache + slot_index * 24
//! 081b6db4      r0 = [slot + 0x24]
//! 081b6db8      if [slot + 0x38] != 0: r0 = 0
//! 081b6dc4  bl   0x0807f6a0                 ; mutex_unlock(cache + 0x18)
//! 081b6dd0  return r0
//! ```
//!
//! `0x081b6dd8` starts the next separately entered function (`push {r4-r6,
//! lr}`), so there is no literal pool. Decoding every ARM B/BL word in
//! `osos.dec` finds the 19 callers at `0x0822e19c`, `0x0822e364`,
//! `0x0822e434`, `0x0822e504`, `0x0822e5d4`, `0x0822e69c`, `0x0822e878`,
//! `0x0822e9e0`, `0x0822eca8`, `0x0822ed78`, `0x0822ee98`, `0x0822f544`,
//! `0x0822f618`, `0x0822f7b4`, `0x0822fce0`, `0x0822fdb4`, `0x0822fecc`,
//! `0x08230238`, and `0x08230990`; all are unconditional plain `bl`, with
//! no predicated forms. The callers use a non-NULL result to choose
//! `MediaContent*` rather than `NoArt*` resources, establishing these as
//! artwork slots.
//!
//! # Algorithm
//!
//! Take the embedded mutex at `cache + 0x18`. For indexes 0 through 3,
//! return the target-word pointer at `cache + index * 24 + 0x24` only when
//! the byte at `cache + index * 24 + 0x38` is zero. Return NULL for an
//! out-of-range index or a nonzero byte, and release the mutex on every path.
//!
//! # Deliberate deviations
//!
//! The containing class-0x7f80 object has no recovered concrete class name,
//! so this port models only the verified raw layout. Its target pointers are
//! `u32` words even on the 64-bit host; this preserves the ARM offsets rather
//! than using pointer-sized fields. The host-only representation of the
//! embedded mutex is wider than its 8-byte ARM layout, so this function uses
//! byte offsets for the subsequent slot words instead of a Rust struct.

use core::ptr;

use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

const SLOT_COUNT: u32 = 4;
const SLOT_SIZE: usize = 24;
const MUTEX_OFFSET: usize = 0x18;
const SLOT_POINTER_OFFSET: usize = 0x24;
const SLOT_UNAVAILABLE_OFFSET: usize = 0x38;

/// artwork_slot_available — original: `FUN_081b6d88` @ **0x081b6d88**
/// (80 bytes; 19 unconditional direct `bl` call sites, binary-scanned).
///
/// Returns an artwork pointer from one of the cache's four slots only when
/// its unavailable byte is clear. The cache pointer itself is not NULL-checked,
/// exactly as the original; callers must provide a readable object containing
/// the embedded mutex and all queried slot fields.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn artwork_slot_available(
    cache: *mut u8,
    slot_index: u32,
) -> *mut u8 {
    let mutex = cache.add(MUTEX_OFFSET).cast::<Mutex>();
    mutex_lock(mutex);

    let artwork = if slot_index < SLOT_COUNT {
        let slot_offset = slot_index as usize * SLOT_SIZE;
        let pointer = ptr::read(cache.add(slot_offset + SLOT_POINTER_OFFSET).cast::<u32>());
        let unavailable = ptr::read(cache.add(slot_offset + SLOT_UNAVAILABLE_OFFSET));
        if unavailable == 0 {
            pointer as usize as *mut u8
        } else {
            ptr::null_mut()
        }
    } else {
        ptr::null_mut()
    };

    mutex_unlock(mutex);
    artwork
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    extern crate std;
    use std::sync::{LazyLock, Mutex};

    const FIXTURE_LEN: usize = 0x1000;
    const PAYLOAD_OFFSET: usize = 0x300;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static BASE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::ARTWORK_SLOT_AVAILABILITY, FIXTURE_LEN)
            .map(|pointer| pointer as usize)
    });

    struct Fixture {
        cache: *mut u8,
    }

    impl Fixture {
        fn map() -> Option<Self> {
            Some(Self { cache: (*BASE)? as *mut u8 })
        }

        unsafe fn reset(&self) {
            ptr::write_bytes(self.cache, 0, FIXTURE_LEN);
        }

        unsafe fn set_slot(&self, index: u32, pointer: *mut u8, unavailable: u8) {
            let slot_offset = index as usize * SLOT_SIZE;
            self.cache
                .add(slot_offset + SLOT_POINTER_OFFSET)
                .cast::<u32>()
                .write(pointer as usize as u32);
            self.cache
                .add(slot_offset + SLOT_UNAVAILABLE_OFFSET)
                .write(unavailable);
        }

        unsafe fn payload(&self, index: u32) -> *mut u8 {
            self.cache.add(PAYLOAD_OFFSET + index as usize * 16)
        }
    }

    #[test]
    fn returns_each_available_artwork_slot() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(fixture) = Fixture::map() else {
            assert!(note_missing_u32_fixture("app::artwork_slot_available"));
            return;
        };
        unsafe {
            fixture.reset();
            for index in 0..SLOT_COUNT {
                let payload = fixture.payload(index);
                fixture.set_slot(index, payload, 0);
                assert_eq!(artwork_slot_available(fixture.cache, index), payload);
            }
        }
    }

    #[test]
    fn hides_a_slot_with_any_nonzero_unavailable_byte() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(fixture) = Fixture::map() else {
            assert!(note_missing_u32_fixture("app::artwork_slot_available"));
            return;
        };
        unsafe {
            fixture.reset();
            let visible = fixture.payload(0);
            let unavailable = fixture.payload(1);
            fixture.set_slot(0, visible, 0);
            fixture.set_slot(1, unavailable, 0xff);

            assert_eq!(artwork_slot_available(fixture.cache, 0), visible);
            assert!(artwork_slot_available(fixture.cache, 1).is_null());
        }
    }

    #[test]
    fn out_of_range_slots_return_null() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(fixture) = Fixture::map() else {
            assert!(note_missing_u32_fixture("app::artwork_slot_available"));
            return;
        };
        unsafe {
            fixture.reset();
            assert!(artwork_slot_available(fixture.cache, SLOT_COUNT).is_null());
            assert!(artwork_slot_available(fixture.cache, u32::MAX).is_null());
        }
    }
}
