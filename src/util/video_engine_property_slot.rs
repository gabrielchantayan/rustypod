//! video_engine_property_slot — `FUN_0825360c` @ 0x0825360c (60 bytes;
//! 5 direct `bl` call sites in osos: 5 plain, 0 predicated).
//!
//! Raw osos.dec establishes the instruction extent 0x0825360c..0x08253648:
//! its final `pop {r4, pc}` is followed by an independent push prologue. It
//! maps property ids 0x8892 and 0x8893 to the video-engine words at +0xad8 and
//! +0xadc respectively. Any other id calls `latch_first_error(engine, 0x500)`
//! and returns NULL. Deliberate deviations: none.

use crate::util::error_latch::latch_first_error;

const FIRST_PROPERTY_ID: u32 = 0x8892;
const SECOND_PROPERTY_ID: u32 = 0x8893;
const FIRST_PROPERTY_OFFSET: usize = 0xad8;
const SECOND_PROPERTY_OFFSET: usize = 0xadc;
const UNKNOWN_PROPERTY_ERROR: u32 = 0x500;

/// video_engine_property_slot — original: `FUN_0825360c` @ 0x0825360c (60 bytes).
///
/// Returns the word slot for either recognized video-engine property. Unknown
/// property ids latch error 0x500 into the engine's first word and return NULL.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn video_engine_property_slot(
    engine: *mut u8,
    property_id: u32,
) -> *mut u32 {
    match property_id {
        FIRST_PROPERTY_ID => engine.add(FIRST_PROPERTY_OFFSET).cast(),
        SECOND_PROPERTY_ID => engine.add(SECOND_PROPERTY_OFFSET).cast(),
        _ => {
            latch_first_error(engine.cast(), UNKNOWN_PROPERTY_ERROR);
            core::ptr::null_mut()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognized_property_ids_return_their_word_slots_without_touching_error() {
        let mut engine = [0u32; (SECOND_PROPERTY_OFFSET / 4) + 1];
        let engine_ptr = engine.as_mut_ptr().cast::<u8>();

        unsafe {
            assert_eq!(
                video_engine_property_slot(engine_ptr, FIRST_PROPERTY_ID),
                engine_ptr.add(FIRST_PROPERTY_OFFSET).cast()
            );
            assert_eq!(
                video_engine_property_slot(engine_ptr, SECOND_PROPERTY_ID),
                engine_ptr.add(SECOND_PROPERTY_OFFSET).cast()
            );
        }
        assert_eq!(engine[0], 0);
    }

    #[test]
    fn unknown_property_latches_first_error_and_returns_null() {
        let mut engine = [0u32; (SECOND_PROPERTY_OFFSET / 4) + 1];

        unsafe {
            assert!(video_engine_property_slot(engine.as_mut_ptr().cast(), 0).is_null());
            assert_eq!(engine[0], UNKNOWN_PROPERTY_ERROR);

            engine[0] = 0x1234;
            assert!(video_engine_property_slot(engine.as_mut_ptr().cast(), 0x8894).is_null());
        }
        assert_eq!(engine[0], 0x1234);
    }
}
