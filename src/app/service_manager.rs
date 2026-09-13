//! The **service-manager singleton** — the framework object that owns
//! retailOS's per-hardware subsystem handlers — plus entry points that hand
//! it out and read its handler records.
//!
//! | address | name | size | `bl` sites |
//! |---|---|---|---|
//! | 0x08165520 | [`service_manager_instance`] | 24 | 17 direct |
//! | 0x081391ec | [`service_manager_instance_veneer`] | 4 | **213** |
//! | 0x08193e84 | [`service_manager_secondary_handler_code_get`] | 20 | 17 direct |
//! | 0x08193e50 | [`service_manager_secondary_handler_state_flags_get`] | 20 | 10 direct |
//! | 0x08193ee8 | [`service_manager_slot_handler_get`] | 20 | 14 direct |
//! | 0x08193efc | [`service_manager_secondary_handler_kind_get`] | 20 | 7 direct |
//! | 0x0819420c | [`service_manager_slot_flags_or`] | 28 | 16 direct |
//!
//! The instance and veneer counts are binary-scanned out of
//! `work/firmware/osos.dec` by decoding every ARM `B`/`BL` word in the image
//! (load base 0x08000000) and resolving its target: 17 `BL` reach
//! 0x08165520 directly, 213 `BL` reach the veneer, and the *only* plain `B`
//! at 0x08165520 is the veneer itself — 230 call sites in total, which is
//! what makes a 24-byte accessor worth porting.
//!
//! ## The holder global
//!
//! The instance lives in the `+4` slot of a small holder struct @
//! 0x089ca948. Only six words in the whole image name that address, all
//! of them literal-pool entries inside the one compilation unit at
//! 0x081653xx-0x0816592c (0x08165360, 0x08165518, 0x08165534,
//! 0x0816557c, 0x08165614, 0x08165930), so the holder is private to
//! this file. Its observed layout:
//!
//! ```text
//! +0x00  u8    constructed   (set to 1 by the ctor @ 0x0816566c)
//! +0x01  u8    ready         (set to 1 by the ctor)
//! +0x04  ptr   instance      <- what this module returns
//! +0x08  u32   hardware model id (0xffffffff when >= 26)
//! +0x0c  u32   capability mask
//! +0x10  u32   capability extra
//! ```
//!
//! 0x089ca948 is one of the runtime-initialized RW pages: the image
//! holds stale UI strings there ("NowPlaying_Font", "Search_Font"),
//! exactly the situation `app/singletons.rs` documents for the
//! 0x089cxxxx caches. The instance slot is therefore the crate static
//! [`SERVICE_MANAGER_INSTANCE`], which starts NULL — the pre-init
//! state.
//!
//! ## What the object is
//!
//! A 0xE8-byte C++ object built once by the lazy constructor-getter @
//! 0x081655e0 (`operator new(0xe8)` then `FUN_0816566c`), *not* ported
//! here. Its constructor reads the hardware model id through the
//! platform-info singleton (`FUN_08259928`, vtable slot +0x34), indexes
//! a 26-entry x 12-byte capability table by it, and then builds up to
//! thirteen subsystem handler objects — one per bit of the 0x1fbf
//! default mask — into the slot table embedded at `this + 4`
//! (`FUN_08193ed4(this + 4, slot, handler)`), plus three more into a
//! second bank (`FUN_08193e98`). Callers reach a handler with
//! `FUN_08193e84`/`FUN_08194080(instance + 4, slot)` and then dispatch
//! through its vtable +0x14 with a (code, arg) pair; the sweep at
//! 0x08165364 walks `slot` 0..12 exactly.
//!
//! Behind the three 0x20-byte primary records sits a second bank at
//! `slot_table + 0x60`: thirteen 8-byte slot records whose word 0 is a
//! flags bitmask (read by the getter @ 0x081941f8, accumulated into by
//! [`service_manager_slot_flags_or`]) and whose word 1 is the slot's
//! handler object pointer (stored by the setter @ 0x08193ed4, read back by
//! [`service_manager_slot_handler_get`] @ 0x08193ee8). The constructor @
//! 0x08194228 zeroes the whole 0x00..0xc8 span, records and bank alike, and
//! clears the byte counter at +0xc8.
//!
//! **The class name does not survive in the image** — the constructor
//! hands no literal to the class-name factory and no name string sits
//! in its body, the same dead end `app/singletons.rs` records for the
//! 0x8900/0x6200/0x7f80 singletons. `service_manager` names the
//! object's *role* (it owns and dispatches to the subsystem handlers)
//! and nothing more; inventing a `TC...` class name would be worse than
//! saying so.
//!
//! ## Deviations
//!
//! - The holder's `+4` slot is the crate static
//!   [`SERVICE_MANAGER_INSTANCE`] rather than a word in the 0x089caxxx
//!   page (see above).
//! - Nothing here constructs. The original 0x08165520 does not either:
//!   a NULL instance is fatal, and the only thing that fills the slot
//!   is 0x081655e0 / `FUN_0816566c`, neither of which is ported. That
//!   makes these two symbols **hook-ready only once something publishes
//!   the instance** — branching stock code at 0x08165520 today would
//!   turn every one of the 230 call sites into a `heap_panic`.
//! - The fatal path is not exercised by the host tests:
//!   [`heap_panic`] is `-> !` and runs the raise/exit/terminate chain,
//!   so a host call cannot return. `cxx/list_splice.rs` leaves its own
//!   `heap_panic` branch untested for the same reason.

#[cfg(test)]
extern crate std;

use crate::heap::veneers::heap_panic;

/// The service-manager singleton (original: the `+4` slot of the holder
/// global @ 0x089ca948 — see the module header's deviation note).
///
/// NULL until the unported constructor-getter @ 0x081655e0 publishes an
/// instance, which is the pre-init state of the original word.
pub static mut SERVICE_MANAGER_INSTANCE: *mut u8 = core::ptr::null_mut();

/// Serializes host tests that replace the singleton slot.
#[cfg(test)]
pub(crate) static SERVICE_MANAGER_INSTANCE_TEST_LOCK: std::sync::Mutex<()> =
    std::sync::Mutex::new(());

/// service_manager_instance — original: `FUN_08165520` @ 0x08165520
/// (24 bytes: five instructions plus the trailing holder literal @
/// 0x08165534; 17 direct `bl` call sites, 230 including the veneer).
///
/// Returns the service-manager singleton. A NULL instance is fatal —
/// the original falls straight through into `bl 0x08030f44`
/// ([`heap_panic`], non-returning), so this accessor never hands out
/// NULL:
///
/// ```text
/// ldr r0, [pc, #12]   ; &holder
/// ldr r0, [r0, #4]    ; holder->instance
/// cmp r0, #0
/// bxne lr             ; return it
/// bl  0x08030f44      ; heap_panic
/// ```
///
/// # Safety
///
/// The returned pointer is only as valid as whatever published
/// [`SERVICE_MANAGER_INSTANCE`]; callers treat it as a `this` for
/// virtual dispatch.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn service_manager_instance() -> *mut u8 {
    let instance = core::ptr::read_volatile(core::ptr::addr_of!(SERVICE_MANAGER_INSTANCE));
    if instance.is_null() {
        heap_panic();
    }
    instance
}

/// service_manager_instance_veneer — original: `thunk_FUN_08165520` @
/// 0x081391ec (4 bytes; **213** `bl` call sites).
///
/// One instruction — `b 0x08165520` — the long-branch veneer the
/// linker planted so the 0x0813xxxx/0x0816xxxx callers could reach
/// [`service_manager_instance`]. The word after it (0x081391f0,
/// `add r1, r0, #0x18`) is the entry of an unrelated function, so the
/// extent really is 4 bytes: this is a direct `B`, not the
/// `ldr pc, [pc, #-4]` + target-word form whose true extent is 8.
///
/// Kept as its own `#[inline(never)]` symbol rather than an alias so a
/// hook at 0x081391ec lands on a real veneer that branches on to the
/// accessor, exactly as the image has it — the built ARM body is
/// `push {fp,lr}; mov fp,sp; pop {fp,lr}; b service_manager_instance`,
/// i.e. the original's tail branch plus the target's mandatory
/// non-leaf frame pointer.
///
/// # Safety
///
/// Same contract as [`service_manager_instance`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn service_manager_instance_veneer() -> *mut u8 {
    service_manager_instance()
}

/// service_manager_secondary_handler_state_flags_get — original:
/// `FUN_08193e50` @ 0x08193e50 (20 bytes; 10 direct, unconditional `bl`
/// call sites).
///
/// Reads the state-flags word at `+0x10` from one of the service manager's
/// three secondary 0x20-byte handler records. Raw ARM is `cmp r1,#3; blge
/// 0x08030f44; add r0,r0,r1,lsl #5; ldr r0,[r0,#16]; bx lr`: signed slots
/// below three, including negative values, pass the original's bounds check
/// and retain its unchecked addressing behavior. Slots three and above
/// terminate through [`heap_panic`]. The paired setter at 0x08193e64 only
/// admits byte-sized values, while callers mask this returned word as a
/// bitfield; state flags therefore names the observed field behavior without
/// inventing a concrete state identity.
///
/// Decoding every ARM `B`/`BL` word in `osos.dec` found exactly 10 direct
/// callers — 0x0818e330, 0x08190710, 0x081932a0, 0x08193ae4, 0x08194aac,
/// 0x081a96fc, 0x081d6d54, 0x081d76e4, 0x082011fc, and 0x08209310 — all
/// unconditional plain `BL`; no predicated direct calls or tail branches
/// target this address. The next distinct function begins at 0x08193e64
/// (`cmp r1,#3`), confirming Ghidra's five-instruction extent.
///
/// Deliberate deviations: none.
///
/// # Safety
///
/// `slot_table` must point to the secondary-table base (`this + 4` in the
/// original) and, for slots 0 through 2, contain at least three aligned
/// eight-word records. Negative slots intentionally retain the firmware's
/// unchecked before-table addressing behavior and are not valid Rust memory
/// accesses.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn service_manager_secondary_handler_state_flags_get(
    slot_table: *const u32,
    slot: i32,
) -> u32 {
    if slot >= 3 {
        heap_panic();
    }
    core::ptr::read(slot_table.wrapping_offset(slot.wrapping_shl(3) as isize).add(4))
}

/// service_manager_secondary_handler_code_get — original: `FUN_08193e84` @
/// 0x08193e84 (20 bytes; 17 direct, unconditional `bl` call sites).
///
/// Reads the low halfword at `+0x1c` from one of the service manager's three
/// secondary 0x20-byte handler records. Raw ARM is `cmp r1,#3; blge
/// 0x08030f44; add r0,r0,r1,lsl #5; ldrh r0,[r0,#28]; bx lr`: signed slots
/// below three, including negative values, pass the original's bounds check
/// and therefore retain its unchecked addressing behavior. Slots three and
/// above terminate through [`heap_panic`]. The field is called a code because
/// callers feed its u16 result to a code-keyed lookup table; no concrete
/// handler-code identity is established.
///
/// Decoding every ARM `B`/`BL` instruction in `osos.dec` found exactly 17
/// direct callers, all unconditional plain `BL`; no predicated direct calls
/// or tail branches target this address. The next distinct function begins at
/// 0x08193e98, confirming the five-instruction extent.
///
/// Deliberate deviations: none.
///
/// # Safety
///
/// `slot_table` must point to the secondary-table base (`this + 4` in the
/// original) and, for slots 0 through 2, contain at least three aligned
/// eight-word records. Negative slots intentionally retain the firmware's
/// unchecked before-table addressing behavior and are not valid Rust memory
/// accesses.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn service_manager_secondary_handler_code_get(
    slot_table: *const u32,
    slot: i32,
) -> u16 {
    if slot >= 3 {
        heap_panic();
    }
    core::ptr::read(
        slot_table
            .wrapping_offset(slot.wrapping_shl(3) as isize)
            .add(7)
            .cast::<u16>(),
    )
}

/// service_manager_secondary_handler_get — original: `FUN_08193ec0` @
/// 0x08193ec0 (20 bytes; 27 direct, unconditional `bl` call sites).
///
/// Reads the handler word from one of the service manager's three secondary
/// 0x20-byte records. Raw ARM is `cmp r1,#3; blge 0x08030f44; add
/// r0,r0,r1,lsl #5; ldr r0,[r0,#8]; bx lr`: signed slots below 3, including
/// negative values, pass the original's bounds check and are consequently
/// unsafe exactly as the firmware is. Slots 3 and above terminate through
/// [`heap_panic`]. The independently decoded B/BL scan found no predicated
/// calls.
///
/// Deliberate deviations: none.
///
/// # Safety
///
/// `slot_table` must point to the secondary-table base (`this + 4` in the
/// original) and, for slots 0 through 2, contain at least three 8-word
/// records. Negative slots intentionally retain the firmware's unchecked
/// addressing behavior and are not valid Rust memory accesses.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn service_manager_secondary_handler_get(
    slot_table: *const u32,
    slot: i32,
) -> *mut u8 {
    if slot >= 3 {
        heap_panic();
    }
    core::ptr::read(slot_table.wrapping_offset(slot.wrapping_shl(3) as isize).add(2))
        as usize as *mut u8
}
/// service_manager_slot_handler_get — original: `FUN_08193ee8` @
/// 0x08193ee8 (20 bytes; 14 direct, unconditional `bl` call sites).
///
/// Returns the handler-object pointer from one of the service manager's
/// thirteen 8-byte slot records. Raw ARM is `cmp r1,#13; blge 0x08030f44;
/// add r0,r0,r1,lsl #3; ldr r0,[r0,#100]; bx lr`: the bank starts at
/// `slot_table + 0x60`, each record is two words, and the handler is word
/// one. The signed check intentionally admits negative slots, which address
/// before the bank exactly as retailOS does; slots 13 and above terminate
/// through [`heap_panic`].
///
/// Decoding every ARM `B`/`BL` word in `osos.dec` found exactly 14 direct
/// callers — 0x08163b7c, 0x08164938, 0x0816494c, 0x081652bc, 0x081653b4,
/// 0x0818e170, 0x0818f844, 0x0818fa8c, 0x08190ccc, 0x08191088,
/// 0x08192bdc, 0x081d6bec, 0x081d6cd8, and 0x081d6d70 — all unconditional
/// plain `BL`; no predicated direct calls or tail branches target this
/// address. The next distinct function begins at 0x08193efc (`cmp r1,#3`),
/// confirming Ghidra's five-instruction extent.
///
/// Deliberate deviations: none.
///
/// # Safety
///
/// `slot_table` must point to the service-manager slot-table base (`this + 4`
/// in the original) backed by at least 0xc8 bytes of aligned storage.
/// Negative slots intentionally retain the firmware's unchecked before-bank
/// addressing behavior and are not valid Rust memory accesses.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.service_manager_slot_handler_get")]
pub unsafe extern "C" fn service_manager_slot_handler_get(
    slot_table: *const u32,
    slot: i32,
) -> *mut u8 {
    if slot >= 13 {
        heap_panic();
    }
    core::ptr::read(slot_table.wrapping_offset(slot.wrapping_shl(1) as isize).add(25))
        as usize as *mut u8
}

/// service_manager_secondary_handler_kind_get — original: `FUN_08193efc` @
/// 0x08193efc (20 bytes; 7 direct, unconditional `bl` call sites).
///
/// Reads the kind word at `+0x14` from one of the service manager's three
/// secondary 0x20-byte handler records. Raw ARM is `cmp r1,#3; blge
/// 0x08030f44; add r0,r0,r1,lsl #5; ldr r0,[r0,#20]; bx lr`: signed slots
/// below three, including negative values, pass the original's bounds check
/// and retain its unchecked addressing behavior. Slots three and above
/// terminate through [`heap_panic`]. The callers compare the returned
/// discrete value against 1 and 0x13 to select handler behavior, so `kind`
/// records the verified role without inventing a concrete handler identity.
///
/// Decoding every ARM `B`/`BL` word in `osos.dec` found exactly 7 direct
/// callers — 0x0818e840, 0x0818f2e8, 0x08190e6c, 0x081924a8, 0x081d760c,
/// 0x081f2e90, and 0x081f2f54 — all unconditional plain `BL`; no predicated
/// direct calls or tail branches target this address. The preceding distinct
/// function ends at 0x08193efc and the following `cmp r1,#3` at 0x08193f10
/// begins the paired setter, confirming the five-instruction extent.
///
/// Deliberate deviations: none.
///
/// # Safety
///
/// `slot_table` must point to the secondary-table base (`this + 4` in the
/// original) and, for slots 0 through 2, contain at least three aligned
/// eight-word records. Negative slots intentionally retain the firmware's
/// unchecked before-table addressing behavior and are not valid Rust memory
/// accesses.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.service_manager_secondary_handler_kind_get")]
pub unsafe extern "C" fn service_manager_secondary_handler_kind_get(
    slot_table: *const u32,
    slot: i32,
) -> u32 {
    if slot >= 3 {
        heap_panic();
    }
    core::ptr::read(slot_table.wrapping_offset(slot.wrapping_shl(3) as isize).add(5))
}

/// service_handler_at — original: `FUN_08194080` @ 0x08194080 (16 bytes;
/// 20 direct, unconditional `bl` call sites).
///
/// Returns word zero of the selected primary handler record. The verified
/// four-instruction ARM body is `cmp r1,#3; blge 0x08030f44; ldr
/// r0,[r0,r1,lsl #5]; bx lr`: records are eight words apart, the comparison
/// is signed, and the handler word is reloaded on every call. A selector
/// greater than or equal to three terminates through [`heap_panic`].
///
/// Decoding every ARM `B`/`BL` instruction in `osos.dec` found 20 direct
/// callers, all unconditional plain `BL`; no predicated or tail branches
/// target this address. The next distinct function begins at 0x08194090
/// (`mov ip,r0`), confirming the 16-byte extent reported by Ghidra.
///
/// Deliberate deviations: none.
///
/// # Safety
///
/// `slot_table` must point at the first word of at least three aligned
/// eight-word records. Negative selectors intentionally retain retailOS's
/// unchecked before-table addressing behavior and are not valid Rust memory
/// accesses.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.service_handler_at")]
pub unsafe extern "C" fn service_handler_at(slot_table: *const u32, selector: i32) -> u32 {
    if selector >= 3 {
        heap_panic();
    }
    core::ptr::read(slot_table.wrapping_offset(selector.wrapping_shl(3) as isize))
}

/// service_manager_slot_flags_or — original: `FUN_0819420c` @ 0x0819420c
/// (28 bytes; 16 direct, unconditional `bl` call sites).
///
/// Accumulates bits into the flags word of one of the service manager's
/// thirteen 8-byte slot records. The bank sits at `slot_table + 0x60`,
/// two words per record: word 0 is the flags word this function updates,
/// word 1 is the slot's handler object pointer (see the module header's
/// bank layout). Raw ARM is `cmp r1,#13; blge 0x08030f44; add r0,r0,r1,
/// lsl #3; ldr r1,[r0,#96]; orr r1,r1,r2; str r1,[r0,#96]; bx lr`: the
/// bounds check is signed, so negative slots pass it and address before
/// the bank exactly as the firmware does; slots 13 and above terminate
/// through [`heap_panic`]. Observed callers accumulate multi-bit masks
/// (0x2c into slot 7, 0x2d into slot 0xc), so this is always an
/// accumulate, never a replace.
///
/// Decoding every ARM `B`/`BL` instruction in `osos.dec` found exactly 16
/// direct callers, all unconditional plain `BL` at 0x0813a308, 0x08165120,
/// 0x08193d00, 0x0819535c, 0x081953c0, 0x08196f68, 0x081af32c,
/// 0x081d7c7c, 0x081e3100, 0x081f26b4, 0x081f2720, 0x081f394c,
/// 0x08200e88, 0x08201254, 0x0820956c, and 0x082095cc; no predicated
/// direct calls or tail branches target this address, and no aligned data
/// word in the image holds it, so it is not vtable-dispatched. The next
/// distinct function begins at 0x08194228 (`push {r4,lr}`), confirming
/// Ghidra's 28-byte extent exactly.
///
/// Deliberate deviations: none. The fatal path is not host-tested:
/// [`heap_panic`] is `-> !` (the module header records why).
///
/// # Safety
///
/// `slot_table` must point to the slot-table base (`this + 4` in the
/// original) backed by at least 0xc8 bytes of aligned, writable storage.
/// Negative slots intentionally retain the firmware's unchecked
/// before-bank addressing behavior and are not valid Rust memory
/// accesses.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.service_manager_slot_flags_or")]
pub unsafe extern "C" fn service_manager_slot_flags_or(
    slot_table: *mut u32,
    slot: i32,
    flags: u32,
) {
    if slot >= 13 {
        heap_panic();
    }
    let flags_word = slot_table
        .wrapping_offset(slot.wrapping_shl(1) as isize)
        .add(0x18);
    core::ptr::write(flags_word, core::ptr::read(flags_word) | flags);
}

#[cfg(test)]
mod handler_at_tests {
    extern crate std;
    use super::*;

    #[test]
    fn reads_primary_handler_words_at_each_valid_record_and_reloads() {
        let mut table = [0u32; 24];
        table[0] = 0x1111_0000;
        table[8] = 0;
        table[16] = 0x3333_0000;

        unsafe {
            assert_eq!(service_handler_at(table.as_ptr(), 0), 0x1111_0000);
            assert_eq!(service_handler_at(table.as_ptr(), 1), 0);
            assert_eq!(service_handler_at(table.as_ptr(), 2), 0x3333_0000);

            table[0] = 0x2222_0000;
            assert_eq!(
                service_handler_at(table.as_ptr(), 0),
                0x2222_0000,
                "the ARM ldr reads the record word on every call"
            );
        }
    }
}

#[cfg(test)]
mod slot_flags_or_tests {
    use super::*;

    /// Word index of slot N's flags word from the table base:
    /// 0x60 bytes of primary records, then two words per slot record.
    const fn flags_index(slot: usize) -> usize {
        0x18 + slot * 2
    }

    #[test]
    fn accumulates_into_each_slot_flags_word_without_touching_neighbors() {
        let mut table = [0u32; 0x18 + 13 * 2];
        table[flags_index(3)] = 0x0000_00f0;
        table[flags_index(3) + 1] = 0xdead_beef; // handler pointer word
        table[flags_index(4)] = 0x5555_5555;

        unsafe {
            let base = table.as_mut_ptr();
            service_manager_slot_flags_or(base, 0, 0x0000_0001);
            service_manager_slot_flags_or(base, 3, 0x0000_000f);
            service_manager_slot_flags_or(base, 12, 0x8000_0000);
        }

        assert_eq!(table[flags_index(0)], 0x0000_0001);
        assert_eq!(
            table[flags_index(3)],
            0x0000_00ff,
            "existing bits survive: the ARM is ldr/orr/str, not a store"
        );
        assert_eq!(
            table[flags_index(3) + 1],
            0xdead_beef,
            "the handler pointer word of the same record is untouched"
        );
        assert_eq!(table[flags_index(4)], 0x5555_5555, "the next slot is untouched");
        assert_eq!(table[flags_index(12)], 0x8000_0000);
        assert!(table[..0x18].iter().all(|&w| w == 0), "primary records are untouched");
    }

    #[test]
    fn repeated_calls_accumulate_and_a_zero_mask_is_a_noop() {
        let mut table = [0u32; 0x18 + 13 * 2];

        unsafe {
            let base = table.as_mut_ptr();
            // The firmware callers' observed shapes: multi-bit masks.
            service_manager_slot_flags_or(base, 7, 0x2c);
            service_manager_slot_flags_or(base, 7, 0x51);
            service_manager_slot_flags_or(base, 7, 0);
        }

        assert_eq!(table[flags_index(7)], 0x7d);
    }

    #[test]
    fn signed_negative_slot_remains_unchecked() {
        // `blge` is a signed compare: slot -1 passes and addresses two
        // words before slot 0's record, exactly like the firmware.
        let mut table = [0u32; 0x18 + 13 * 2];

        unsafe {
            let base = table.as_mut_ptr().add(8);
            service_manager_slot_flags_or(base, -1, 0xffff_0000);
            assert_eq!(table[8 + flags_index(0) - 2], 0xffff_0000);
        }
    }
}

#[cfg(test)]
mod secondary_handler_get_tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn reads_each_secondary_record_handler_word_without_caching() {
        let Some(slab) = try_map_u32_slab(hints::SERVICE_MANAGER_SECONDARY_HANDLER, 4096) else {
            note_missing_u32_fixture("service_manager_secondary_handler_get");
            return;
        };
        let table = slab.cast::<u32>();
        let first = unsafe { slab.add(0x100) };
        let replacement = unsafe { slab.add(0x180) };
        let third = unsafe { slab.add(0x200) };

        unsafe {
            table.add(2).write(first as usize as u32);
            table.add(10).write(0);
            table.add(18).write(third as usize as u32);

            assert_eq!(service_manager_secondary_handler_get(table, 0), first);
            assert_eq!(service_manager_secondary_handler_get(table, 1), core::ptr::null_mut());
            assert_eq!(service_manager_secondary_handler_get(table, 2), third);

            table.add(2).write(replacement as usize as u32);
            assert_eq!(
                service_manager_secondary_handler_get(table, 0),
                replacement,
                "the ARM ldr reloads the handler word on every call"
            );
        }
    }
}

#[cfg(test)]
mod slot_handler_get_tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn reads_each_slot_handler_word_without_caching() {
        let Some(slab) = try_map_u32_slab(hints::SERVICE_MANAGER_SLOT_HANDLER, 4096) else {
            note_missing_u32_fixture("service_manager_slot_handler_get");
            return;
        };
        let table = slab.cast::<u32>();
        let first = unsafe { slab.add(0x100) };
        let replacement = unsafe { slab.add(0x180) };
        let middle = unsafe { slab.add(0x200) };
        let last = unsafe { slab.add(0x280) };

        unsafe {
            assert_eq!(
                service_manager_slot_handler_get(table, 3),
                core::ptr::null_mut(),
                "a zero handler word propagates as NULL"
            );
            table.add(25).write(first as usize as u32);
            table.add(37).write(middle as usize as u32);
            table.add(49).write(last as usize as u32);

            assert_eq!(service_manager_slot_handler_get(table, 0), first);
            assert_eq!(service_manager_slot_handler_get(table, 6), middle);
            assert_eq!(service_manager_slot_handler_get(table, 12), last);

            table.add(25).write(replacement as usize as u32);
            assert_eq!(
                service_manager_slot_handler_get(table, 0),
                replacement,
                "the ARM ldr reloads the handler word on every call"
            );

            assert_eq!(
                service_manager_slot_handler_get(table.add(2), -1),
                replacement,
                "the signed comparison leaves negative slots unchecked"
            );
        }
    }
}

#[cfg(test)]
mod secondary_handler_code_get_tests {
    use super::*;

    #[test]
    fn reads_each_handler_code_low_halfword_and_reloads() {
        let mut table = [0u32; 24];
        table[7] = 0xaaaa_1234;
        table[15] = 0xbbbb_0000;
        table[23] = 0xcccc_d000;

        unsafe {
            assert_eq!(service_manager_secondary_handler_code_get(table.as_ptr(), 0), 0x1234);
            assert_eq!(service_manager_secondary_handler_code_get(table.as_ptr(), 1), 0);
            assert_eq!(service_manager_secondary_handler_code_get(table.as_ptr(), 2), 0xd000);

            table[15] = 0xdddd_0046;
            assert_eq!(
                service_manager_secondary_handler_code_get(table.as_ptr(), 1),
                0x0046,
                "the ARM ldrh reloads the code halfword on every call"
            );
        }
    }

    #[test]
    fn signed_negative_slot_remains_unchecked() {
        let mut table = [0u32; 24];
        table[7] = 0xffff_beef;

        unsafe {
            assert_eq!(
                service_manager_secondary_handler_code_get(table.as_ptr().add(8), -1),
                0xbeef,
            );
        }
    }
}

#[cfg(test)]
mod secondary_handler_state_flags_get_tests {
    use super::*;

    #[test]
    fn reads_each_state_flags_word_and_reloads() {
        let mut table = [0u32; 24];
        table[4] = 0x0000_0001;
        table[12] = 0x0000_000c;
        table[20] = 0x0000_00f0;

        unsafe {
            assert_eq!(service_manager_secondary_handler_state_flags_get(table.as_ptr(), 0), 1);
            assert_eq!(service_manager_secondary_handler_state_flags_get(table.as_ptr(), 1), 0xc);
            assert_eq!(service_manager_secondary_handler_state_flags_get(table.as_ptr(), 2), 0xf0);

            table[12] = 0x0000_0046;
            assert_eq!(
                service_manager_secondary_handler_state_flags_get(table.as_ptr(), 1),
                0x46,
                "the ARM ldr reloads the state-flags word on every call"
            );
        }
    }

    #[test]
    fn signed_negative_slot_remains_unchecked() {
        let mut table = [0u32; 24];
        table[4] = 0x0000_00a5;

        unsafe {
            assert_eq!(
                service_manager_secondary_handler_state_flags_get(table.as_ptr().add(8), -1),
                0xa5,
            );
        }
    }
}

#[cfg(test)]
mod secondary_handler_kind_get_tests {
    use super::*;

    #[test]
    fn reads_each_handler_kind_word_and_reloads() {
        let mut table = [0u32; 24];
        table[5] = 0x0000_0001;
        table[13] = 0x0000_0013;
        table[21] = 0xffff_ffff;
        table[4] = 0xdead_beef;
        table[6] = 0xcafe_babe;

        unsafe {
            assert_eq!(service_manager_secondary_handler_kind_get(table.as_ptr(), 0), 1);
            assert_eq!(service_manager_secondary_handler_kind_get(table.as_ptr(), 1), 0x13);
            assert_eq!(
                service_manager_secondary_handler_kind_get(table.as_ptr(), 2),
                0xffff_ffff
            );

            table[13] = 0x0000_0046;
            assert_eq!(
                service_manager_secondary_handler_kind_get(table.as_ptr(), 1),
                0x46,
                "the ARM ldr reloads the kind word on every call"
            );
        }

        assert_eq!(table[4], 0xdead_beef, "the preceding word is not read");
        assert_eq!(table[6], 0xcafe_babe, "the following word is not read");
    }

    #[test]
    fn signed_negative_slot_remains_unchecked() {
        let mut table = [0u32; 24];
        table[5] = 0xa5a5_5a5a;

        unsafe {
            assert_eq!(
                service_manager_secondary_handler_kind_get(table.as_ptr().add(8), -1),
                0xa5a5_5a5a,
            );
        }
    }
}


#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr;


    /// Installs `instance` and returns the lock guard; the slot is
    /// restored to its NULL pre-init state by `clear`.
    fn publish(instance: *mut u8) -> std::sync::MutexGuard<'static, ()> {
        let guard = SERVICE_MANAGER_INSTANCE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { ptr::write_volatile(ptr::addr_of_mut!(SERVICE_MANAGER_INSTANCE), instance) };
        guard
    }

    fn clear(guard: std::sync::MutexGuard<'static, ()>) {
        unsafe { ptr::write_volatile(ptr::addr_of_mut!(SERVICE_MANAGER_INSTANCE), ptr::null_mut()) };
        drop(guard);
    }

    #[test]
    fn the_slot_starts_null_like_the_uninitialized_holder_word() {
        let guard = SERVICE_MANAGER_INSTANCE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        assert!(unsafe { ptr::read_volatile(ptr::addr_of!(SERVICE_MANAGER_INSTANCE)) }.is_null());
        drop(guard);
    }

    #[test]
    fn the_accessor_returns_the_published_instance() {
        let mut object = [0u8; 0xe8];
        let instance = object.as_mut_ptr();
        let guard = publish(instance);
        assert_eq!(unsafe { service_manager_instance() }, instance);
        clear(guard);
    }

    #[test]
    fn the_accessor_never_caches_and_follows_the_slot() {
        let mut first = [0u8; 0xe8];
        let mut second = [0u8; 0xe8];
        let guard = publish(first.as_mut_ptr());
        unsafe {
            assert_eq!(service_manager_instance(), first.as_mut_ptr());
            assert_eq!(service_manager_instance(), first.as_mut_ptr(), "repeat call");
            ptr::write_volatile(ptr::addr_of_mut!(SERVICE_MANAGER_INSTANCE), second.as_mut_ptr());
            assert_eq!(
                service_manager_instance(),
                second.as_mut_ptr(),
                "the original re-loads the holder word on every call"
            );
        }
        clear(guard);
    }

    #[test]
    fn a_misaligned_instance_pointer_is_passed_through_unchanged() {
        // The original returns the holder word verbatim: no masking, no
        // offsetting (contrast media_player_interface_get's `addne #0x14`).
        let mut storage = [0u8; 0xe9];
        let instance = unsafe { storage.as_mut_ptr().add(1) };
        let guard = publish(instance);
        assert_eq!(unsafe { service_manager_instance() }, instance);
        clear(guard);
    }

    #[test]
    fn the_veneer_reaches_the_same_accessor() {
        let mut object = [0u8; 0xe8];
        let instance = object.as_mut_ptr();
        let guard = publish(instance);
        unsafe {
            assert_eq!(service_manager_instance_veneer(), instance);
            assert_eq!(service_manager_instance_veneer(), service_manager_instance());
        }
        clear(guard);
    }

    #[test]
    fn the_veneer_is_a_distinct_symbol_from_its_target() {
        // The image has two separate entry points; an alias would make a
        // hook at 0x081391ec meaningless.
        assert_ne!(
            service_manager_instance_veneer as usize,
            service_manager_instance as usize
        );
    }

}
