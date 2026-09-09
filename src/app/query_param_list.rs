//! `query_param_list_push` — retailOS `FUN_0827c9c8` @ `0x0827c9c8`.
//!
//! ## Extent and call sites, byte-verified
//!
//! The function is exactly **60 bytes**: fifteen ARM instruction words from
//! `0x0827c9c8` through `0x0827ca00`; `0x0827ca04` begins the separately
//! linked list initializer sibling (`push {r4, lr}`). Decoding every ARM
//! B/BL word in `osos.dec` finds **17** direct call sites, all unconditional
//! `bl` — and all seventeen sit inside the 18-slot binder `FUN_0827c8a8` @
//! `0x0827c8a8` (one per register/stack argument; the 18th slot is inlined
//! there). There are no predicated forms, no tail branches, and no DATA-word
//! references, so the function is never dispatched through a vtable.
//!
//! ## Object and algorithm
//!
//! The receiver is a fixed-capacity bound-parameter list of the media
//! library's SQL query layer (the only callers build statements such as
//! "SELECT version ... FROM genius"; the sibling initializer @ `0x0827ca04`
//! chains `string_default_construct` @ `0x08277440` for the base sub-object,
//! zeroes `count` and the `+0x68` heap token, then fills all 18 slots with
//! the `-1` sentinel and all 18 flag bytes with zero):
//!
//! ```text
//!   +0x00  base sub-object vtable     +0x04  base payload
//!   +0x08  count (u32)                +0x0c  values: u32[18]
//!   +0x54  tagged: u8[18]             +0x68  heap token (operator delete'd)
//! ```
//!
//! Raw ARM, verbatim:
//!
//! ```text
//!   cmn r1, #1            ; value == -1? return unchanged (bxeq lr)
//!   tst r1, #0x80000000
//!   ldrne r3, [r0, #8]    ; tagged: flag byte at +0x54 + count <- 1
//!   movne r2, #1
//!   addne r3, r3, r0
//!   strbne r2, [r3, #84]
//!   ldr   r2, [r0, #8]    ; values[count] <- value with bit31 cleared
//!   bicne r1, r1, #0x80000000
//!   add   r2, r0, r2, lsl #2
//!   str   r1, [r2, #12]
//!   ldr   r1, [r0, #8]    ; count <- count + 1
//!   add   r1, r1, #1
//!   str   r1, [r0, #8]
//!   bx    lr
//! ```
//!
//! A value of `0xffffffff` is the "slot absent" sentinel and is dropped
//! without touching the list. Any other value is appended at `count`: when
//! bit 31 is set, the parallel `tagged` byte for the slot is set to 1 and the
//! bit is stripped from the stored word, so each slot keeps a 31-bit payload
//! plus its sign/type tag separately. `count` then increments. There is no
//! capacity guard: the stock firmware relies on the sole caller never
//! exceeding 18 pushes.
//!
//! ## Deliberate deviation
//!
//! The stock code reloads `count` from memory three times (flag store, value
//! store, increment); the port reads it once. Unobservable: the function
//! touches no memory that could alias the receiver between those reads.

/// query_param_list_push — retailOS `FUN_0827c9c8` @ `0x0827c9c8` (60
/// bytes; 17 binary-verified plain `bl` call sites, all inside the 18-slot
/// binder @ `0x0827c8a8`).
///
/// Appends `value` to the fixed 18-slot parameter list. `0xffffffff` is the
/// sentinel for an absent slot and returns without any store. Otherwise, a
/// set bit 31 sets the slot's `tagged` byte at `+0x54 + count` to 1 and is
/// stripped from the word stored at `values[count]` (`+0x0c + count*4`);
/// `count` at `+0x08` then increments. No NULL guard and no capacity guard:
/// callers must pass a live, 4-byte-aligned list of at least 0x6c bytes and
/// must not push more than 18 values.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn query_param_list_push(list: *mut u8, value: u32) {
    if value == u32::MAX {
        return;
    }

    let count = list.add(0x08).cast::<u32>().read_volatile();
    let mut stored = value;
    if value & 0x8000_0000 != 0 {
        list.add(0x54 + count as usize).write_volatile(1u8);
        stored &= 0x7fff_ffff;
    }
    list.add(0x0c + count as usize * 4)
        .cast::<u32>()
        .write_volatile(stored);
    list.add(0x08)
        .cast::<u32>()
        .write_volatile(count.wrapping_add(1));
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    const SLOTS: usize = 18;

    /// Byte-exact image of the on-device object: base sub-object words,
    /// count, 18 value words, 18 flag bytes, heap token. `#[repr(C)]` keeps
    /// every field at its target offset on any host pointer width.
    #[repr(C)]
    struct ParamList {
        base: [u32; 2],        // +0x00 vtable, +0x04 payload
        count: u32,            // +0x08
        values: [u32; SLOTS],  // +0x0c
        tagged: [u8; SLOTS],   // +0x54
        _pad: [u8; 2],         // +0x66
        token: u32,            // +0x68
    }

    impl ParamList {
        /// Mirrors the sibling initializer @ 0x0827ca04: every slot holds
        /// the -1 sentinel and every tagged byte is clear.
        fn initialized() -> Self {
            ParamList {
                base: [0xdead_beef, 0x1111_2222],
                count: 0,
                values: [u32::MAX; SLOTS],
                tagged: [0; SLOTS],
                _pad: [0xee; 2],
                token: 0x3333_4444,
            }
        }

        fn push(&mut self, value: u32) {
            unsafe { query_param_list_push((self as *mut Self).cast(), value) };
        }
    }

    #[test]
    fn sentinel_minus_one_is_dropped_without_any_store() {
        let mut list = ParamList::initialized();
        list.count = 7;
        let before_values = list.values;
        let before_tagged = list.tagged;

        list.push(u32::MAX);

        assert_eq!(list.count, 7, "sentinel must not advance count");
        assert_eq!(list.values, before_values);
        assert_eq!(list.tagged, before_tagged);
        assert_eq!(list.base, [0xdead_beef, 0x1111_2222]);
        assert_eq!(list.token, 0x3333_4444);
    }

    #[test]
    fn plain_value_is_stored_at_count_and_count_increments() {
        let mut list = ParamList::initialized();

        list.push(42);

        assert_eq!(list.values[0], 42);
        assert_eq!(list.tagged[0], 0, "untagged value sets no flag byte");
        assert_eq!(list.count, 1);
        assert_eq!(
            list.values[1..],
            [u32::MAX; SLOTS - 1],
            "later slots keep the initializer's sentinel"
        );
    }

    #[test]
    fn bit31_tag_sets_flag_byte_and_strips_the_bit() {
        let mut list = ParamList::initialized();
        list.count = 5;

        list.push(0x8000_0000 | 1234);

        assert_eq!(list.values[5], 1234, "bit31 is stripped from the payload");
        assert_eq!(list.tagged[5], 1, "the tag survives in the flag byte");
        assert_eq!(list.count, 6);
    }

    #[test]
    fn value_with_only_bit31_set_is_not_the_sentinel() {
        let mut list = ParamList::initialized();

        list.push(0x8000_0000);

        assert_eq!(list.values[0], 0);
        assert_eq!(list.tagged[0], 1);
        assert_eq!(list.count, 1);
    }

    #[test]
    fn max_31bit_payload_is_stored_unchanged() {
        let mut list = ParamList::initialized();

        list.push(0x7fff_ffff);

        assert_eq!(list.values[0], 0x7fff_ffff);
        assert_eq!(list.tagged[0], 0);
        assert_eq!(list.count, 1);
    }

    #[test]
    fn sequential_pushes_fill_slots_in_order_with_per_slot_tags() {
        let mut list = ParamList::initialized();

        list.push(0);
        list.push(1);
        list.push(u32::MAX);
        list.push(0x8000_0002);
        list.push(3);

        assert_eq!(list.count, 4, "the sentinel left no gap");
        assert_eq!(list.values[..4], [0, 1, 2, 3]);
        assert_eq!(list.tagged[..4], [0, 0, 1, 0]);
        assert_eq!(list.values[4..], [u32::MAX; SLOTS - 4]);
    }
}
