//! `parse_free_temporary` — original: `FUN_08376780` @ `0x08376780`
//! (32 bytes; two verified direct `bl` call sites, both unconditional).
//!
//! Raw ARM words establish the exact extent `0x08376780..0x083767a0`:
//! `push {r4,lr}; mov r4,r0; ldr r0,[r4,#8]; bl 0x083906f4; mov r0,#0;
//! str r0,[r4,#8]; str r0,[r4,#0x40]; pop {r4,pc}`. The next independent
//! function starts at `0x083767a0` with `push {r4-r11,lr}`. This body has one
//! plain outbound `bl` and no predicated `bl`; whole-image decoding finds two
//! inbound plain `bl` instructions at `0x082d92e4` and `0x08375798`, and none
//! predicated.
//!
//! It releases the Parse-owned temporary at target offset +0x08 through the
//! established `tracked_free` port, then clears that slot and the related
//! target-width state word at +0x40. Deliberate deviation: pointer slots are
//! represented as u32 words so target offsets remain valid in host fixtures.

const TEMPORARY: usize = 2;
const RELATED_STATE: usize = 0x40 / 4;

/// Frees Parse's temporary allocation and clears its related state word.
///
/// # Safety
///
/// `parse` must point to a writable retailOS Parse-layout object. Its word at
/// +0x08 must be either zero or a payload accepted by `tracked_free`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn parse_free_temporary(parse: *mut u32) {
    let temporary = parse.add(TEMPORARY).read() as usize as *mut u8;
    crate::heap::tracked::tracked_free(temporary);
    parse.add(TEMPORARY).write(0);
    parse.add(RELATED_STATE).write(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::tracked::TAG_TRACKED;
    use crate::heap::veneers::tests::{free_log, mock_heap};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    const SLAB_LEN: usize = 0x1000;
    const PARSE_OFFSET: usize = 0x100;
    const PAYLOAD_OFFSET: usize = 0x300;

    unsafe fn fixture() -> Option<(*mut u32, *mut u8)> {
        let slab = try_map_u32_slab(hints::SQLITE_PARSE_FREE_TEMPORARY, SLAB_LEN)?;
        slab.write_bytes(0, SLAB_LEN);
        Some((slab.add(PARSE_OFFSET) as *mut u32, slab.add(PAYLOAD_OFFSET)))
    }

    #[test]
    fn frees_temporary_then_clears_both_parse_slots() {
        let _heap = mock_heap();
        let Some((parse, payload)) = (unsafe { fixture() }) else {
            note_missing_u32_fixture("sqlite/parse_free_temporary");
            return;
        };

        unsafe {
            (payload.sub(4) as *mut u32).write(4);
            (payload.sub(12) as *mut u32).write(37);
            parse.add(TEMPORARY).write(payload as usize as u32);
            parse.add(RELATED_STATE).write(0xfeed_face);
            parse_free_temporary(parse);

            assert_eq!(parse.add(TEMPORARY).read(), 0);
            assert_eq!(parse.add(RELATED_STATE).read(), 0);
            assert_eq!(free_log(), (1, payload.sub(12), TAG_TRACKED));
        }
    }

    #[test]
    fn null_temporary_still_clears_both_parse_slots_without_freeing() {
        let _heap = mock_heap();
        let Some((parse, _payload)) = (unsafe { fixture() }) else {
            note_missing_u32_fixture("sqlite/parse_free_temporary");
            return;
        };

        unsafe {
            parse.add(RELATED_STATE).write(1);
            parse_free_temporary(parse);

            assert_eq!(parse.add(TEMPORARY).read(), 0);
            assert_eq!(parse.add(RELATED_STATE).read(), 0);
            assert_eq!(free_log().0, 0);
        }
    }
}
