//! `fixed3_is_zero` — original: `FUN_0829f7a4` @ 0x0829f7a4 (**36 bytes**,
//! 0x0829f7a4..0x0829f7c8; **3 inbound plain `bl` calls and 0 predicated
//! forms** at 0x0824c3c0, 0x0824c3dc, and 0x0824c3f8; no internal calls).
//!
//! The original reads the first, then third, then second aligned word of a
//! three-word fixed-point vector. It returns one only when all three are zero,
//! short-circuiting later reads after the first nonzero word.
//!
//! # Deliberate deviations
//!
//! `read_volatile` preserves the original's conditional load order and avoids
//! collapsing these observable pointer reads; otherwise there is no deviation.

/// fixed3_is_zero — original: `FUN_0829f7a4` @ 0x0829f7a4 (36 bytes).
///
/// Returns one if the three aligned words at `value` are all zero, otherwise
/// zero. `value` must point to three readable `u32`s; the original has no NULL
/// or alignment guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn fixed3_is_zero(value: *const u32) -> u32 {
    let first = core::ptr::read_volatile(value);
    if first != 0 {
        return 0;
    }

    let third = core::ptr::read_volatile(value.add(2));
    if third != 0 {
        return 0;
    }

    u32::from(core::ptr::read_volatile(value.add(1)) == 0)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn it_accepts_the_all_zero_vector() {
        let value = [0, 0, 0];
        assert_eq!(unsafe { fixed3_is_zero(value.as_ptr()) }, 1);
    }

    #[test]
    fn it_rejects_each_component_independently() {
        for index in 0..3 {
            let mut value = [0, 0, 0];
            value[index] = 0x8000_0000;
            assert_eq!(unsafe { fixed3_is_zero(value.as_ptr()) }, 0, "component {index}");
        }
    }

    #[test]
    fn it_does_not_mutate_the_vector() {
        let value = [0, 0, 0xfeed_face];
        let before = value;
        assert_eq!(unsafe { fixed3_is_zero(value.as_ptr()) }, 0);
        assert_eq!(value, before);
    }
}
