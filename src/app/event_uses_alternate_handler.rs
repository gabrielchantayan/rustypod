//! Event alternate-handler selection.
//!
//! `event_uses_alternate_handler` — original: `FUN_08198c28` @
//! **0x08198c28** (40 bytes; next real function begins at 0x08198c50).
//! Raw ARM decoding verifies **0 direct `bl` calls** in its body (neither plain
//! nor predicated); it has three direct caller `bl` sites.
//!
//! Algorithm: if the context's alternate handler word at `+0xc8` is nonzero,
//! return one when unsigned `(event_kind - 6) >= 12`; this admits kinds
//! `0..=5` and `18..=255`, rejecting only `6..=17`. Deliberate deviation:
//! host tests use ordinary valid pointers rather than the firmware's
//! fixed-address objects.
use core::ptr;

const ALTERNATE_HANDLER_OFFSET: usize = 0xc8;
const EVENT_KIND_OFFSET: usize = 2;
const FIRST_ALTERNATE_HANDLER_KIND: u8 = 6;
const ALTERNATE_HANDLER_KIND_DELTA: u8 = 12;

/// Selects the alternate handler except for event kinds 6 through 17.
///
/// # Safety
///
/// `context` must point to at least `0xcc` readable bytes and `event` must
/// point to at least three readable bytes.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn event_uses_alternate_handler(context: *const u8, event: *const u8) -> u32 {
    let alternate_handler = ptr::read_volatile(context.add(ALTERNATE_HANDLER_OFFSET).cast::<u32>());
    if alternate_handler == 0 {
        return 0;
    }

    let event_kind = ptr::read_volatile(event.add(EVENT_KIND_OFFSET));
    (event_kind.wrapping_sub(FIRST_ALTERNATE_HANDLER_KIND) >= ALTERNATE_HANDLER_KIND_DELTA) as u32
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn requires_an_alternate_handler() {
        let context = [0u32; (ALTERNATE_HANDLER_OFFSET + 4) / 4];
        let event = [0, 0, FIRST_ALTERNATE_HANDLER_KIND];

        assert_eq!(unsafe { event_uses_alternate_handler(context.as_ptr().cast(), event.as_ptr()) }, 0);
    }

    #[test]
    fn accepts_exactly_the_original_unsigned_kind_range() {
        let mut context = [0u32; (ALTERNATE_HANDLER_OFFSET + 4) / 4];
        context[ALTERNATE_HANDLER_OFFSET / 4] = 1;

        for (kind, expected) in [(0, 1), (5, 1), (6, 0), (17, 0), (18, 1), (19, 1), (u8::MAX, 1)] {
            let event = [0, 0, kind];
            assert_eq!(unsafe { event_uses_alternate_handler(context.as_ptr().cast(), event.as_ptr()) }, expected);
        }
    }
}
