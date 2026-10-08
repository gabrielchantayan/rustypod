//! Predicate selecting the third UI handle metric.
//!
//! `ui_state_is_third_metric` — original `FUN_0813263c` @ **0x0813263c**,
//! 28 bytes (`0x0813263c..0x08132658`, next independent LDRB at the end).
//! Whole-image raw A32 decoding verifies two incoming plain BL sites
//! (0x0813241c, 0x0813295c), zero predicated incoming BLs, and zero
//! outgoing BLs of either kind.
//!
//! Read the unsigned state byte at object +0x1a. Return exactly 1 for
//! states 7, 5, or 1, otherwise 0. Stock chains CMP/CMPNE instructions
//! then MOVEQ/MOVNE and BX LR; no other object fields are accessed.
//! Deliberate deviations: none in behavior; LLVM may choose a different
//! comparison sequence. The name describes verified metric selection,
//! without assigning an unverified class or meaning to the state values.

/// Tests whether the object's state selects its third handle metric.
///
/// # Safety
/// `object + 0x1a` must point to a readable byte.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_state_is_third_metric(object: *const u8) -> u32 {
    let state = object.add(0x1a).read();
    u32::from(state == 7 || state == 5 || state == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_unsigned_states_return_a_normalized_predicate() {
        let mut object = [0xa5; 0x1b];
        for state in 0..=u8::MAX {
            object[0x1a] = state;
            let expected = match state { 1 | 5 | 7 => 1, _ => 0 };
            assert_eq!(unsafe { ui_state_is_third_metric(object.as_ptr()) }, expected,
                "state {state}");
        }
    }

    #[test]
    fn ignores_active_flag_and_adjacent_bytes_at_every_alignment() {
        for offset in 0..4 {
            let mut storage = [0xff; 0x20];
            storage[offset + 0x19] = 0;
            storage[offset + 0x1a] = 1;
            let before = storage;
            assert_eq!(unsafe { ui_state_is_third_metric(storage.as_ptr().add(offset)) }, 1);
            assert_eq!(storage, before);
            storage[offset + 0x1a] = 0x81;
            assert_eq!(unsafe { ui_state_is_third_metric(storage.as_ptr().add(offset)) }, 0);
        }
    }
}
