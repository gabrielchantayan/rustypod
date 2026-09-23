//! `object_byte_0x946_is_two` — original: `FUN_0817a224` @ `0x0817a224` (20
//! bytes).
//!
//! Raw `osos.dec` words establish the exact A32 body at
//! `0x0817a224..0x0817a237`: `ldrb r0,[r0,#0x946]; cmp r0,#2; movne r0,#0;
//! moveq r0,#1; bx lr`. The `stmdb sp!,{r4-r8,lr}` at `0x0817a238` begins the
//! next real function. A complete raw-image decode finds three inbound plain,
//! unconditional `bl` instructions at `0x0817addc`, `0x0817ae44`, and
//! `0x0817c8ec`; there are no predicated `bl` instructions.
//!
//! Reads the opaque object's byte at `+0x946` and returns one only when it is
//! two. No callee identity is inferred because this leaf has no calls.
//!
//! # Deliberate deviations
//!
//! None.

/// Returns whether the opaque object's byte at target offset `0x946` is two.
///
/// # Safety
///
/// `object` must be non-NULL and readable through `+0x946`; these unchecked
/// preconditions match the original ARM load.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_byte_0x946_is_two(object: *const u8) -> u32 {
    u32::from(unsafe { object.add(0x946).read() } == 2)
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;

    const OBJECT_LEN: usize = 0x947;

    #[test]
    fn accepts_only_byte_value_two_at_target_offset() {
        let mut object = [0u8; OBJECT_LEN];

        for (value, expected) in [(0, 0), (1, 0), (2, 1), (3, 0), (u8::MAX, 0)] {
            object[0x946] = value;
            assert_eq!(unsafe { object_byte_0x946_is_two(object.as_ptr()) }, expected);
        }
    }

    #[test]
    fn ignores_neighbouring_bytes() {
        let mut object = [0u8; OBJECT_LEN];
        object[0x944] = 2;
        object[0x945] = 2;
        object[0x946] = 0;

        assert_eq!(unsafe { object_byte_0x946_is_two(object.as_ptr()) }, 0);

        object[0x946] = 2;
        assert_eq!(unsafe { object_byte_0x946_is_two(object.as_ptr()) }, 1);
    }
}
