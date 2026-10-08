//! Predicate selecting the second UI handle metric.
//!
//! `ui_state_is_second_metric` — original `FUN_08132d80` @ **0x08132d80**,
//! 28 bytes (`0x08132d80..0x08132d9c`, next function's PUSH at the end).
//! Whole-image raw A32 decoding verifies two incoming plain BL sites
//! (0x081323f8, 0x08132844), zero predicated incoming BLs, and zero
//! outgoing BLs of either kind.
//!
//! Read the unsigned state byte at object +0x1a. Return exactly 1 for
//! states 7, 5, or 0, otherwise 0. Stock uses chained conditional CMPs
//! followed by MOVEQ/MOVNE and BX LR; no other object fields are accessed.
//! Deliberate deviations: none in behavior; LLVM may choose a different
//! comparison sequence. The name describes the verified metric selection,
//! without assigning an unverified class or meaning to the state values.

/// Tests whether the object's state selects its second handle metric.
///
/// # Safety
/// `object + 0x1a` must point to a readable byte.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_state_is_second_metric(object: *const u8) -> u32 {
    let state = object.add(0x1a).read();
    u32::from(state == 7 || state == 5 || state == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_unsigned_states_return_a_normalized_predicate() {
        let mut object = [0xa5; 0x1b];
        for state in 0..=u8::MAX {
            object[0x1a] = state;
            let expected = match state { 0 | 5 | 7 => 1, _ => 0 };
            assert_eq!(unsafe { ui_state_is_second_metric(object.as_ptr()) }, expected,
                "state {state}");
        }
    }

    #[test]
    fn reads_only_the_state_even_for_unaligned_inactive_objects() {
        let mut storage = [0xff; 0x1d];
        storage[1 + 0x19] = 0;
        storage[1 + 0x1a] = 5;
        let before = storage;
        assert_eq!(unsafe { ui_state_is_second_metric(storage.as_ptr().add(1)) }, 1);
        assert_eq!(storage, before);
        storage[1 + 0x1a] = 0x80;
        assert_eq!(unsafe { ui_state_is_second_metric(storage.as_ptr().add(1)) }, 0);
    }
}
