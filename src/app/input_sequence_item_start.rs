//! Input-sequence item start — `FUN_08129330` @ **0x08129330**.
//!
//! Raw extent: **100 bytes**, `0x08129330..0x08129394`; the next function
//! starts with `ldr r0,[r0,#4]`. A complete aligned raw ARM BL scan finds
//! two inbound calls: plain BL at 0x0812a0bc and BLNE at 0x08129ee0.
//! The body contains three plain BL instructions and no predicated BL.
//!
//! Store the low index byte at +0x10, then set +0x24 to the owner's +0xbc
//! minus +0xcc. When owner byte +0xda is zero, set +0x28 to the owner's
//! prID-checked +0xc0 word plus +0xc8 times the signed index byte, minus
//! +0xcc. Finally sample Timer E and store truncated milliseconds at +0x0c.
//! All arithmetic wraps at 32 bits; a nonzero gate preserves +0x28.
//!
//! Deliberate deviations: discard scratch-register results and initialize
//! the timer stack word instead of saving incoming r3 (the timer overwrites
//! it). Tests substitute only the timer read; production calls existing
//! ports directly. Pointer fields remain four-byte target words. No new
//! retail callee seam or singleton dependency is introduced: the existing
//! prID helper is called only with its gate clear.

use crate::app::prid_checked_word_c0::{prid_checked_word_c0, PridCheckedWordState};

#[cfg(test)]
static mut READ_USEC_TIMER: unsafe extern "C" fn(*mut u32) = crate::drivers::timer::read_usec_timer_into;

#[inline(always)]
unsafe fn read_usec_timer(out: *mut u32) {
    #[cfg(test)]
    core::ptr::read_volatile(core::ptr::addr_of!(READ_USEC_TIMER))(out);
    #[cfg(not(test))]
    crate::drivers::timer::read_usec_timer_into(out);
}

/// Start an input-sequence item at a signed byte index.
///
/// # Safety
/// `item` must be writable for eleven aligned words; its first word must
/// point to a readable aligned owner through byte +0xda.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn input_sequence_item_start(item: *mut u32, index: u32) {
    item.cast::<u8>().add(0x10).write(index as u8);
    let owner = item.read() as *const u32;
    item.add(9).write(owner.add(0xbc / 4).read().wrapping_sub(owner.add(0xcc / 4).read()));
    if owner.cast::<u8>().add(0xda).read() == 0 {
        let base = prid_checked_word_c0(owner.cast::<PridCheckedWordState>()) as u32;
        // Reload after the call, as in the original ARM body.
        let owner = item.read() as *const u32;
        let index = item.cast::<u8>().add(0x10).read() as i8 as i32 as u32;
        let position = owner.add(0xc8 / 4).read().wrapping_mul(index)
            .wrapping_add(base).wrapping_sub(owner.add(0xcc / 4).read());
        item.add(10).write(position);
    }
    let mut counter_usec = 0;
    read_usec_timer(&mut counter_usec);
    item.add(3).write(crate::drivers::timer::usec_to_millis(&counter_usec));
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    unsafe extern "C" fn fixed_timer(out: *mut u32) {
        out.write(u32::MAX);
    }

    #[test]
    fn signed_index_wrapping_offsets_and_gate_preserve_unrelated_state() {
        let Some(slab) = try_map_u32_slab(hints::INPUT_SEQUENCE_ITEM_START, 0x1000) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        unsafe {
            let item = slab.cast::<u32>();
            let owner = slab.add(0x100).cast::<u32>();
            READ_USEC_TIMER = fixed_timer;
            for gate in [0u8, 1, 255] {
                for index in [0u32, 1, 127, 128, 255, 0x1234_ff80] {
                    for (origin, base, stride, offset) in [
                        (100u32, 30u32, 7u32, 20u32),
                        (0, u32::MAX, 0x8000_0001, 1),
                    ] {
                        owner.write_bytes(0, 56);
                        owner.add(0xbc / 4).write(origin);
                        owner.add(0xc0 / 4).write(base);
                        owner.add(0xc8 / 4).write(stride);
                        owner.add(0xcc / 4).write(offset);
                        owner.cast::<u8>().add(0xda).write(gate);
                        let mut expected = [0xa5a5_a5a5u32; 11];
                        expected[0] = owner as usize as u32;
                        core::ptr::copy_nonoverlapping(expected.as_ptr(), item, 11);
                        expected[4] = (expected[4] & 0xffff_ff00) | (index & 0xff);
                        expected[9] = ((origin as i64 - offset as i64) & 0xffff_ffff) as u32;
                        if gate == 0 {
                            let signed_index = (index as u8 as i8) as i64;
                            expected[10] = ((base as i64 + stride as i64 * signed_index
                                - offset as i64) & 0xffff_ffff) as u32;
                        }
                        expected[3] = 4_294_967;
                        input_sequence_item_start(item, index);
                        assert_eq!(core::slice::from_raw_parts(item, 11), &expected,
                            "gate={gate}, index={index:#x}");
                    }
                }
            }
        }
    }
}
