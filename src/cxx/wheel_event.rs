//! `wheel_event_button_code` — original: `FUN_082a4f78` @ 0x082a4f78
//! (16 bytes, all code — no literal-pool word; 51 `bl` call sites,
//! binary-scanned).
//!
//! Source: `ipod-decomp/decomp/c/029/082a4f78_FUN_082a4f78.c` (matches
//! the raw ARM exactly).
//!
//! Extracts byte 2 (bits 16..23) of the state word at +0x10 of the
//! control subsystem's **click-wheel event sample** — the record
//! `kernel/wheel_sample.rs`'s `wheel_sample_capture` @ 0x08292a88
//! lazily fills and UI controllers consume. Decoded from the raw ARM:
//!
//! ```text
//! ldr r0, [r0, #0x10]    ; r0 = this->state
//! and r0, r0, #0xff0000  ; keep byte 2
//! mov r0, r0, lsr #0x10  ; ... shifted down
//! bx  lr
//! ```
//!
//! The class identification is call-site driven, not proximity-driven:
//! the function physically sits among the two-word StringObject
//! accessors (`string_object_c_str` @ 0x082a50b0 & co.) purely by ADS
//! translation-unit packaging, and it is NOT a string operation — the
//! COW string rep (cxx/string.rs) is {refcount, capacity, length} plus
//! inline data with no flags byte at +0x10, so the byte plays no part
//! in any short/long string discrimination. The record evidence:
//!
//! - The same handler cluster that calls this accessor (0x0813f6c4 …,
//!   0x08140180 …) also calls `wheel_sample_capture` @ 0x08292a88 and
//!   its rate-getter sibling @ 0x08292adc on the same record
//!   (0x0813f7c0/0x0813f7cc) and reads its elapsed word at +0x0c —
//!   the documented wheel-sample layout: kind +0x04, capture flag
//!   +0x08, elapsed +0x0c, state +0x10, rate +0x14.
//! - At 0x0811a0b4 the byte-3 flag bits of the same +0x10 word are
//!   tested (`tst #0xff000000`; `and #0x1000000`) before the kind ==
//!   0xd gate and this byte's dispatch — byte 3 carries the flags
//!   (0x40000000 is the documented finger-on-wheel gate).
//! - The byte itself is a small-integer code, not a character: call
//!   sites range-compare it (`cmp #0x59; bgt …` at 0x0811a0ec) and
//!   filter/dispatch on values 0x4a..0x4c (skip filter, 0x0810bdd4),
//!   0x57/0x58 (list index -1/+1, 0x0811a184/0x0811a104), 0x59/0x5a
//!   (select paths) and 0x6e/0x6f (0x0810da54, 0x0813f6c8). The kind
//!   word at +0x04 carries 8 / 0xd / 0x15. The exact enum is
//!   undecoded; "button code" is the evidenced role: the per-event
//!   input control the UI dispatches on.
//!
//! ALIASES: the exact 4-word pattern occurs exactly TWICE in osos.dec —
//! here and at 0x082a4f68 (26 `bl` call sites, binary-scanned), a
//! byte-identical twin ADS emitted for a second translation unit (the
//! handle_deref_or_null alias phenomenon). The twin is NOT ported
//! separately; hook it to this symbol. The halfword sibling @
//! 0x082a4f58 (`ldr; lsl #0x10; lsr #0x10` — the low u16 of the same
//! state word, 5 `bl` call sites) is a DIFFERENT body, not an alias,
//! and is not ported here either.
//!
//! No NULL guard on `this`, matching the original's unconditional
//! `ldr`.

/// Byte offset of the wheel event sample's state word (the
/// `kernel/wheel_sample.rs` `SAMPLE_STATE` layout: kind +0x04, flag
/// +0x08, elapsed +0x0c, state +0x10, rate +0x14).
pub const WHEEL_EVENT_STATE_OFFSET: usize = 0x10;

/// wheel_event_button_code — original: `FUN_082a4f78` @ 0x082a4f78
/// (16 bytes; 51 `bl` call sites, binary-scanned).
///
/// Returns byte 2 of the sample's state word — `(state & 0xff0000) >>
/// 0x10`, exactly the original's `and`/`lsr` pair. Reads one word and
/// writes nothing; `this` is not NULL-guarded (the original faults on
/// a NULL `this`, and so does the port on target; the host read is
/// `read_unaligned`, which only widens the accepted alignments).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn wheel_event_button_code(this: *const u8) -> u32 {
    let state = (this.add(WHEEL_EVENT_STATE_OFFSET) as *const u32).read_unaligned();
    (state & 0xff0000) >> 0x10
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_with_state(state: u32) -> [u8; 0x18] {
        let mut sample = [0xa5u8; 0x18];
        sample[WHEEL_EVENT_STATE_OFFSET..WHEEL_EVENT_STATE_OFFSET + 4]
            .copy_from_slice(&state.to_ne_bytes());
        sample
    }

    #[test]
    fn only_byte_two_of_the_state_word_survives() {
        // A distinct value at each byte position in turn; only the
        // byte at bits 16..23 may be returned.
        for position in 0..4u32 {
            let state = 0x5au32 << (position * 8);
            let sample = sample_with_state(state);
            let expected = if position == 2 { 0x5a } else { 0 };
            assert_eq!(
                unsafe { wheel_event_button_code(sample.as_ptr()) },
                expected,
                "state={state:#010x} (value at byte {position})"
            );
        }
    }

    #[test]
    fn byte_two_boundaries_zero_and_ff() {
        let zero = sample_with_state(0);
        assert_eq!(unsafe { wheel_event_button_code(zero.as_ptr()) }, 0);

        let low = sample_with_state(0x0000_0000);
        assert_eq!(unsafe { wheel_event_button_code(low.as_ptr()) }, 0);

        let ff = sample_with_state(0x00ff_0000);
        assert_eq!(unsafe { wheel_event_button_code(ff.as_ptr()) }, 0xff);

        let all = sample_with_state(0xffff_ffff);
        assert_eq!(unsafe { wheel_event_button_code(all.as_ptr()) }, 0xff);
    }

    #[test]
    fn the_sample_is_read_only_and_neighboring_bytes_do_not_leak() {
        // Every other byte 0xff, byte 2 zero: proves the mask kills
        // byte 3 (the flag byte) and the low halfword codes.
        let sample = sample_with_state(0xff00_ffff);
        let before = sample;
        assert_eq!(unsafe { wheel_event_button_code(sample.as_ptr()) }, 0);
        assert_eq!(sample, before, "the accessor writes nothing");
    }
}
