//! The function-context release used by SQLite's aggregate cleanup.
//!
//! - `free_function_context` — original: `FUN_082cf36c` @ 0x082cf36c
//!   (28 bytes; 2 plain + 1 predicated inbound `bl` call sites).
//!
//! Raw words `e92d4010 e1a04000 e590001c eb0304dd e1a00004 e8bd4010
//! ea0304da` establish the complete extent through 0x082cf387; the next
//! `cmp r1,#0` at 0x082cf388 begins `vdbe_free_p4`. The function frees the
//! owned payload pointer at target word 7 (+0x1c), then tail-branches to free
//! the context itself.
//!
//! Deliberate deviation: the raw `bl` and tail `b` both target
//! `sqlite3_free` @ 0x083906f4; this port calls its established
//! [`tracked_free`](crate::heap::tracked::tracked_free) seam twice. The
//! target pointer remains a 32-bit word, so host fixtures use a low-address
//! mapping rather than host pointer field offsets.

use crate::heap::tracked::tracked_free;

const FUNCTION_CONTEXT_PAYLOAD_OFFSET: usize = 0x1c;

#[inline(always)]
unsafe fn function_context_payload(context: *mut u8) -> *mut u8 {
    let target_pointer = context.add(FUNCTION_CONTEXT_PAYLOAD_OFFSET).cast::<u32>().read();
    target_pointer as usize as *mut u8
}

/// free_function_context — original: `FUN_082cf36c` @ 0x082cf36c (28 bytes).
///
/// Release the context's owned payload at +0x1c, then release `context`.
/// Neither pointer is NULL-guarded here: `tracked_free` supplies the same
/// NULL handling as the retailOS callee, while the context load itself is
/// deliberately unconditional.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn free_function_context(context: *mut u8) {
    tracked_free(function_context_payload(context));
    tracked_free(context);
}

#[cfg(test)]
mod tests {
    use super::{function_context_payload, FUNCTION_CONTEXT_PAYLOAD_OFFSET};
    use crate::testing::{hints, try_map_u32_slab};

    #[test]
    fn reads_payload_from_target_word_seven() {
        let Some(context) = try_map_u32_slab(hints::SQLITE_FREE_FUNCTION_CONTEXT, 0x1000) else {
            return;
        };
        let expected = 0x3456_7890usize as *mut u8;

        unsafe {
            context.cast::<u32>().add(FUNCTION_CONTEXT_PAYLOAD_OFFSET / 4).write(expected as u32);
            assert_eq!(function_context_payload(context), expected);
        }
    }
}
