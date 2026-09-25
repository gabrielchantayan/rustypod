//! Resource-query accounting — `FUN_08059b88` @ 0x08059b88 (56 bytes).
//!
//! Raw `osos.dec` establishes the exact extent `0x08059b88..0x08059bc0`:
//! `bx lr` ends the body at 0x08059bbc and the next separately entered
//! function starts at 0x08059bc0. The body has no calls. Decoding every ARM
//! B/BL word in `osos.dec` finds three inbound plain `bl` calls at
//! 0x08041b20, 0x08041d94, and 0x080507dc; there are no predicated calls.
//!
//! Every query increments the context's wrapping attempt counter at `+0x5c`.
//! A nonzero resource identifier at descriptor `+0x04` writes one to the
//! output flag and increments the wrapping identified-query counter at
//! context `+0x60`; a zero identifier writes zero without changing that
//! second counter. It always returns zero.
//!
//! Deliberate deviation: none. The pointer arguments retain the original
//! unchecked firmware contract; field accesses are direct target-width words.

use core::ptr;

const ATTEMPT_COUNT_WORD: usize = 0x5c / core::mem::size_of::<u32>();
const IDENTIFIED_QUERY_COUNT_WORD: usize = 0x60 / core::mem::size_of::<u32>();
const RESOURCE_IDENTIFIER_WORD: usize = 1;

/// resource_query_account — original: `FUN_08059b88` @ `0x08059b88`
/// (**56 bytes; 3 plain `bl` callers and no predicated callers**).
///
/// Accounts for one resource query. `context` must point to writable words
/// through `+0x60`; `descriptor` must be readable through `+0x04`; and
/// `has_identifier` must be writable.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.resource_query_account")]
#[inline(never)]
pub unsafe extern "C" fn resource_query_account(
    context: *mut u32,
    descriptor: *const u32,
    has_identifier: *mut u8,
) -> i32 {
    unsafe {
        let attempts = context.add(ATTEMPT_COUNT_WORD);
        ptr::write(attempts, ptr::read(attempts).wrapping_add(1));

        if ptr::read(descriptor.add(RESOURCE_IDENTIFIER_WORD)) == 0 {
            ptr::write(has_identifier, 0);
        } else {
            ptr::write(has_identifier, 1);
            let identified_queries = context.add(IDENTIFIED_QUERY_COUNT_WORD);
            ptr::write(
                identified_queries,
                ptr::read(identified_queries).wrapping_add(1),
            );
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTEXT_WORDS: usize = IDENTIFIED_QUERY_COUNT_WORD + 1;

    #[test]
    fn accounts_for_descriptors_with_and_without_identifiers() {
        let mut context = [0u32; CONTEXT_WORDS];
        let no_identifier = [0, 0];
        let identifier = [0, 0x1234_5678];
        let mut has_identifier = 0xff;

        assert_eq!(
            unsafe { resource_query_account(context.as_mut_ptr(), no_identifier.as_ptr(), &mut has_identifier) },
            0
        );
        assert_eq!(has_identifier, 0);
        assert_eq!(context[ATTEMPT_COUNT_WORD], 1);
        assert_eq!(context[IDENTIFIED_QUERY_COUNT_WORD], 0);

        assert_eq!(
            unsafe { resource_query_account(context.as_mut_ptr(), identifier.as_ptr(), &mut has_identifier) },
            0
        );
        assert_eq!(has_identifier, 1);
        assert_eq!(context[ATTEMPT_COUNT_WORD], 2);
        assert_eq!(context[IDENTIFIED_QUERY_COUNT_WORD], 1);
    }

    #[test]
    fn wraps_both_counters_like_arm_add() {
        let mut context = [0u32; CONTEXT_WORDS];
        let identifier = [0, 1];
        let mut has_identifier = 0;
        context[ATTEMPT_COUNT_WORD] = u32::MAX;
        context[IDENTIFIED_QUERY_COUNT_WORD] = u32::MAX;

        assert_eq!(
            unsafe { resource_query_account(context.as_mut_ptr(), identifier.as_ptr(), &mut has_identifier) },
            0
        );
        assert_eq!(has_identifier, 1);
        assert_eq!(context[ATTEMPT_COUNT_WORD], 0);
        assert_eq!(context[IDENTIFIED_QUERY_COUNT_WORD], 0);
    }
}
