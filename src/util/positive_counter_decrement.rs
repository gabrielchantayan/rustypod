//! Positive counter decrement — `FUN_0806c030` @ 0x0806c030 (20 bytes; 7
//! inbound direct `bl` call sites, all unconditional).
//!
//! The five-instruction ARM leaf reads the signed word at +0x14, decrements it
//! only when positive, and otherwise leaves it unchanged. The verified inbound
//! calls are plain `bl` at 0x0803bc80, 0x080488b8, 0x08048974, 0x08058aa8,
//! 0x08058b54, 0x08064728, and 0x080681bc; there are no predicated or tail
//! branch call sites. The field's higher-level identity remains unresolved, so
//! this port names its directly observed counter behavior rather than inventing
//! an object type. Deliberate deviations: none.

/// Word index of the signed counter in the passed object.
const COUNTER_WORD: usize = 0x14 / core::mem::size_of::<i32>();

/// positive_counter_decrement — original: `FUN_0806c030` @ 0x0806c030
/// (20 bytes).
///
/// Decrements the signed word at `object + 0x14` when it is strictly positive.
/// Zero and negative values remain unchanged. Like the retail ARM loads and
/// stores, this function does not check `object` for NULL.
///
/// # Safety
///
/// `object` must be non-NULL, word aligned, and valid to read and write the
/// signed word at offset +0x14.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.positive_counter_decrement")]
#[inline(never)]
pub unsafe extern "C" fn positive_counter_decrement(object: *mut u8) {
    let counter = object.cast::<i32>().add(COUNTER_WORD);
    let value = counter.read();
    if value > 0 {
        counter.write(value - 1);
    }
}

#[cfg(test)]
mod tests {
    use super::positive_counter_decrement;

    #[test]
    fn decrements_only_positive_counter_values() {
        for (initial, expected) in [
            (i32::MIN, i32::MIN),
            (-1, -1),
            (0, 0),
            (1, 0),
            (2, 1),
            (i32::MAX, i32::MAX - 1),
        ] {
            let mut object = [0x5a5a_5a5au32; 6];
            object[5] = initial as u32;

            unsafe { positive_counter_decrement(object.as_mut_ptr().cast()) };

            assert_eq!(object[5] as i32, expected, "initial value {initial}");
            assert_eq!(object[..5], [0x5a5a_5a5au32; 5]);
        }
    }
}
