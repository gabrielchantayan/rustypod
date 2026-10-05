//! Priority-gated toggle of the class-0x8780 byte at +0xdd.
//!
//! `class_8780_priority_toggle` — original: `FUN_081a2ee8` @ **0x081a2ee8**.
//! True extent: 60 bytes, ending with `pop {pc}` at 0x081a2f20; the next
//! independent function starts with `push {r4,r5,r6,lr}` at 0x081a2f24.
//! Whole-image aligned ARM BL decoding finds two incoming plain BLs
//! (0x081e82b0 and 0x081e83c8), zero predicated BLs. Outgoing: one plain
//! BL to `class_8780_dispatch_state`, zero predicated BLs.
//!
//! Return unless dispatch state is 3. Otherwise map byte +0xdd from 0 to 1,
//! from 1 or 2 to 0, and leave every other value unchanged. Both callers
//! ignore the return registers. Ghidra's final indirect call is a stack
//! return, not virtual dispatch. Deliberate deviations: discard unspecified
//! return-register contents; no business-level meaning is assigned to +0xdd.

use super::class_8780_dispatch_state::class_8780_dispatch_state;

/// # Safety
/// `object` must be readable through +0x8c and, when dispatch state is 3,
/// readable and writable at +0xdd, with no concurrent access to these fields.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn class_8780_priority_toggle(object: *mut u8) {
    if class_8780_dispatch_state(object) != 3 {
        return;
    }
    let value = object.add(0xdd);
    let next = match *value {
        0 => 1,
        1 | 2 => 0,
        _ => return,
    };
    *value = next;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhaustively_maps_bytes_only_in_priority_state() {
        for (priority, secondary, associated) in [
            (0, 0, 0), (0, 1, 0), (0, 1, 1),
            (1, 0, 0), (255, 255, 255),
        ] {
            for value in 0..=u8::MAX {
                let mut object = [0xa5; 0xdf];
                object[0x1c] = priority;
                object[0x8a] = secondary;
                object[0x8c] = associated;
                object[0xdd] = value;
                let mut expected = object;
                if priority != 0 {
                    expected[0xdd] = if value == 0 { 1 }
                        else if value <= 2 { 0 } else { value };
                }
                unsafe { class_8780_priority_toggle(object.as_mut_ptr()) };
                assert_eq!(object, expected, "priority={priority}, byte={value}");
            }
        }
    }

    #[test]
    fn repeated_toggle_normalizes_two_then_alternates() {
        let mut object = [0; 0xde];
        object[0x1c] = 1;
        object[0xdd] = 2;
        for expected in [0, 1, 0, 1] {
            unsafe { class_8780_priority_toggle(object.as_mut_ptr()) };
            assert_eq!(object[0xdd], expected);
        }
    }
}
