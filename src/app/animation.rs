//! `animation_init` — original: `FUN_08166b88` @ 0x08166b88.
//!
//! The full constructor of retailOS's UI **animation** object: the class
//! that binds three refcounted Q16.16 scalars (the animated value plus its
//! from/to endpoints) and enqueues itself in the firmware's timing wheel.
//! Every caller builds it as
//! `animation_init(operator_new(0x24) @ 0x082aadd4, current, from, to)`
//! (e.g. 0x08180a54: the from/to pair comes straight from two
//! `fixed_value_init(x << 16)` scalars, `current` is the view's stored
//! property slot), so — like [`crate::app::fixed_value::fixed_value_init`] —
//! this constructor runs in caller-allocated storage and returns `this`.
//!
//! ## Extent and call sites, byte-verified
//!
//! The true extent is **212 bytes**, not Ghidra's 204: fifty instruction
//! words run 0x08166b88..0x08166c50 (`pop {r4-r8, pc}`) and the trailing
//! literal pool holds **two** words — the animation vtable 0x08987f00 at
//! 0x08166c54 and the scheduler singleton pointer 0x089cc7e0 at
//! 0x08166c58. Ghidra's "204 bytes" drops that last pool word; the next
//! real function starts at 0x08166c5c (the sibling default constructor,
//! which installs the same vtable but never touches the wheel). The
//! preceding function ends at 0x08166b84: a slot setter for +0x20 whose
//! tail branch into the wheel insert confirmed the callee identities
//! below.
//!
//! **44 `bl` call sites**, verified by decoding every B/BL word in
//! osos.dec: all 44 are plain unconditional `bl` (no predicated forms, no
//! B tail branches), and no DATA word anywhere references the address —
//! callers invoke the constructor directly by name with no NULL guard,
//! always on fresh `operator_new(0x24)` storage.
//!
//! ## Stock algorithm
//!
//! ```text
//! 08166b88  push {r4-r8, lr}
//! 08166b8c  mov r8, r1 / mov r7, r3 / mov r6, r2   ; current, to, from
//! 08166b98  bl  0x08138460        ; refcounted base ctor (ported)
//! 08166ba0  ldr r0, =0x08987f00   ; animation vtable (pool 0x08166c54)
//!           str r0, [r4]          ; overrides the base vtable
//! 08166bac  mov r0, #0 ; str +0x18 / +0x1c / +0x20     ; clear endpoints
//! 08166bc4  ldr r0, [r5]          ; r5 -> global 0x089cc7e0: scheduler ptr
//!           bl  0x082738e0        ; timing_wheel_remove(table, this)
//! 08166bcc  mov r0, r8/r6/r7      ; retain(current), retain(from),
//!           bl  0x08273a14        ; retain(to)
//! 08166be0  ldr/cmp [+0x20], blne 0x082739e0   ; release old current
//! 08166bec  ldr/cmp [+0x18], blne 0x082739e0   ; release old from
//! 08166bf8  ldr/cmp [+0x1c], blne 0x082739e0   ; release old to
//! 08166c04  add r0, r4, #0x18 ; stm r0, {r6, r7, r8}   ; from, to, current
//! 08166c0c  ldr r0, [r6+8] ; ldr r1, [r7+8] ; ldr r3, [r8+8]
//!           ...                   ; unsigned max of the three aux words
//! 08166c38  add r0, #1 ; str [r4+8]     ; rank = max(...) + 1
//! 08166c40  ldr r0, [r5] ; bl 0x08273898  ; timing_wheel_insert(table,this)
//! 08166c4c  mov r0, r4 ; pop {r4-r8, pc}  ; return this
//! ```
//!
//! The three conditional releases read slots that step four just zeroed,
//! so they are statically dead; they are the ADS memberwise-assign idiom
//! (release old value before overwrite) kept here for structure parity —
//! see the test that pins them dead. The rank key at +0x08 reuses the
//! FixedValue aux word convention ([`crate::app::fixed_value`]): a plain
//! scalar leaves aux 0, so an animation over plain scalars lands at rank 1
//! = timing-wheel bucket 0. The wheel itself is the 52-byte singleton the
//! lazy allocator @ 0x082739a0 parks in the global word 0x089cc7e0 (48
//! bytes = 12 bucket heads, then a guard word): insert 0x08273898 buckets
//! a node at `[rank - 1]`, sets the linked flag (bit 0 of byte +0x14) and
//! threads the doubly-linked list through +0x0c/+0x10; remove
//! 0x082738e0 unlinks only when that flag bit is set — which for a freshly
//! zeroed object makes step five a defensive no-op, reproduced anyway.
//!
//! # Deviations
//!
//! - Timing-wheel insertion and removal are direct ports. Retain
//!   0x08273a14 and release 0x082739e0 are direct
//!   [`crate::app::refcounted_value`] ports.
//! - The shared base constructor
//!   [`crate::app::fixed_value::refcounted_base_init`] is ported and called
//!   directly, like the original's direct `bl`.
//! - The scheduler pointer is loaded through the live global word
//!   0x089cc7e0 on target (the singleton may be created lazily after this
//!   image was baked); host builds hand the seams a house-static 12-bucket
//!   table modelled on the allocator above.
//! - [`ANIMATION_VTABLE`] is an address constant only: it lives on the
//!   stale 0x0898xxxx page (the `app/registry.rs` caveat), so the port
//!   reproduces the stored pointer value, never the table's contents.
//! - The rank max recomputes `max(from, to)` in its fall-through arm
//!   exactly like the original (0x08166c30); LLVM folds the duplicate
//!   select, which changes nothing observable.

use crate::app::fixed_value::{refcounted_base_destroy, refcounted_base_init, FixedValue};
use crate::app::refcounted_value::{release_refcounted_value, retain_value};

/// Firmware load address of the animation vtable literal (pool word at
/// 0x08166c54). Address constant only — see the module header's caveat.
pub const ANIMATION_VTABLE: u32 = 0x0898_7f00;

/// Firmware address of the global word holding the timing-wheel singleton
/// pointer (loaded twice via `ldr r5, [pc, #...]`; `ldr r0, [r5]` feeds
/// both wheel calls).
pub const SCHEDULER_SINGLETON_GLOBAL: usize = 0x089c_c7e0;


/// One bucket head per unit of rank: the lazy allocator @ 0x082739a0
/// carves `operator_new(0x34)` and zeroes the first 48 bytes.
pub const TIMING_WHEEL_BUCKETS: usize = 12;

/// The animation object: 0x24 bytes on the 32-bit target (every caller
/// allocates `operator_new(0x24)`). Pointer fields are u32 target
/// pointers, hence the width-independent size.
#[repr(C)]
pub struct Animation {
    /// +0x00: the vtable — [`crate::app::fixed_value::REFCOUNTED_BASE_VTABLE`]
    /// during the base constructor, [`ANIMATION_VTABLE`] after it.
    pub vtable: u32,
    /// +0x04: not written by any function of this family.
    pub opaque_04: u32,
    /// +0x08: the timing-wheel rank: one past the largest endpoint aux
    /// word (unsigned). Insert buckets the node at `rank - 1`.
    pub rank: u32,
    /// +0x0c: wheel link, written only by insert/remove (u32 target ptr).
    pub wheel_prev: u32,
    /// +0x10: wheel link, written only by insert/remove (u32 target ptr).
    pub wheel_next: u32,
    /// +0x14: flags (bit 0 linked-in-wheel, bit 1 refcounted) and the
    /// refcount in bits 2..; zeroed by the base constructor.
    pub flags: u32,
    /// +0x18: retained `from` endpoint (u32 target ptr to a FixedValue).
    pub from_value: u32,
    /// +0x1c: retained `to` endpoint.
    pub to_value: u32,
    /// +0x20: retained animated value — the setter @ 0x08166b2c swaps
    /// exactly this slot and raises the rank, never lowering it.
    pub current_value: u32,
}

const _: () = assert!(core::mem::size_of::<Animation>() == 0x24);
const _: () = assert!(core::mem::offset_of!(Animation, opaque_04) == 0x04);
const _: () = assert!(core::mem::offset_of!(Animation, rank) == 0x08);
const _: () = assert!(core::mem::offset_of!(Animation, wheel_prev) == 0x0c);
const _: () = assert!(core::mem::offset_of!(Animation, wheel_next) == 0x10);
const _: () = assert!(core::mem::offset_of!(Animation, flags) == 0x14);
const _: () = assert!(core::mem::offset_of!(Animation, from_value) == 0x18);
const _: () = assert!(core::mem::offset_of!(Animation, to_value) == 0x1c);
const _: () = assert!(core::mem::offset_of!(Animation, current_value) == 0x20);

/// `timing_wheel_insert` — original: `FUN_08273898` @ 0x08273898 (72
/// bytes).
///
/// Raw decoding confirms the 18 instruction words through `bx lr` at
/// 0x082738dc; the next separately linked function starts at 0x082738e0.
/// Decoding every ARM B/BL word in osos.dec finds seven direct call sites,
/// all unconditional `bl` (0x08160820, 0x08166c48, 0x08167af0,
/// 0x08181074, 0x08197848, 0x081a0fb8, 0x08224a74), no predicated forms,
/// and seven unconditional `b` tail callers (0x080fe5f4, 0x08166ae8,
/// 0x08166b80, 0x081679f0, 0x0819775c, 0x081af454, 0x08273998).
/// No aligned raw DATA word contains this address.
///
/// Inserts `node` at the head of `table[node->rank - 1]`: clear its previous
/// link, preserve the old head as its next link, update that head's previous
/// link when present, and set only linked flag bit 0. It returns when
/// `(rank - 1)` is negative *as a signed word*, or when a signed-nonnegative
/// bucket's node is already linked; as in ARM, there is no null or bounds
/// guard in the insertion path. There are no deliberate deviations.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn timing_wheel_insert(table: *mut u32, node: *mut u32) {
    const RANK: usize = 2;
    const PREV: usize = 3;
    const NEXT: usize = 4;
    const FLAGS: usize = 5;

    let bucket = (*node.add(RANK)).wrapping_sub(1);
    let flags = node.add(FLAGS).cast::<u8>();
    if (bucket as i32) < 0 || *flags & 1 != 0 {
        return;
    }

    *node.add(PREV) = 0;
    let old_head = *table.add(bucket as usize);
    *node.add(NEXT) = old_head;
    *table.add(bucket as usize) = node as usize as u32;
    *flags |= 1;
    if old_head != 0 {
        *((old_head as usize as *mut u32).add(PREV)) = node as usize as u32;
    }
}

/// The first argument both wheel callees receive: the word stored at
/// [`SCHEDULER_SINGLETON_GLOBAL`]. On target that is the live singleton
/// pointer (created lazily @ 0x082739a0); host builds model the created
/// state with a house-static bucket array.
#[cfg(target_os = "none")]
pub(crate) fn scheduler_table() -> *mut u32 {
    unsafe { core::ptr::read_volatile(SCHEDULER_SINGLETON_GLOBAL as *mut u32) as *mut u32 }
}

#[cfg(not(target_os = "none"))]
static mut HOST_SCHEDULER_BUCKETS: [u32; TIMING_WHEEL_BUCKETS] = [0; TIMING_WHEEL_BUCKETS];

#[cfg(not(target_os = "none"))]
pub(crate) fn scheduler_table() -> *mut u32 {
    core::ptr::addr_of_mut!(HOST_SCHEDULER_BUCKETS).cast::<u32>()
}
/// timing_wheel_remove — original: `FUN_082738e0` @ 0x082738e0 (96 bytes).
///
/// Binary decoding of every ARM B/BL word in osos.dec finds 15 direct
/// call sites, all plain unconditional `bl`; there are no predicated `bl`
/// forms. One additional unconditional `b` tail caller at 0x08273a38 loads
/// the scheduler singleton then branches here; no raw DATA word references
/// this address.
///
/// Unlinks a timing-wheel node only when flag bit 0 of its `+0x14` word is
/// set. It selects `table[node->rank - 1]`; if that head is the node, it
/// advances the bucket head to `node->next` when non-NULL. Otherwise, it
/// repairs `node->prev->next` when the predecessor exists. It then repairs
/// `node->next->prev` when the successor exists and clears only flag bit 0.
/// There is deliberately no NULL guard for either argument and no bounds
/// check for `rank - 1`, exactly as the ARM body. The word-index API preserves
/// the shared wheel-prefix layout used by Animation and TimedTransition;
/// there are no deliberate deviations.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn timing_wheel_remove(table: *mut u32, node: *mut u32) {
    const RANK: usize = 2;
    const PREV: usize = 3;
    const NEXT: usize = 4;
    const FLAGS: usize = 5;

    let flags = node.add(FLAGS).cast::<u8>();
    if *flags & 1 == 0 {
        return;
    }

    let bucket = (*node.add(RANK)).wrapping_sub(1) as usize;
    let next = *node.add(NEXT);
    if *table.add(bucket) == node as usize as u32 {
        *table.add(bucket) = next;
    } else {
        let prev = *node.add(PREV);
        if prev != 0 {
            *((prev as usize as *mut u32).add(NEXT)) = next;
        }
    }

    if next != 0 {
        *((next as usize as *mut u32).add(PREV)) = *node.add(PREV);
    }
    *flags &= !1;
}
/// `timing_wheel_remove_global` — original: `FUN_08273a2c` @ 0x08273a2c
/// (20 bytes including its four-byte literal pool at 0x08273a3c).
///
/// Ghidra reports only the four instruction words (16 bytes); the `ldr r0,
/// [pc, #4]` requires the following pool word `0x089cc7e0`, and the next
/// separately linked function begins at 0x08273a40. Decoding every ARM B/BL
/// word in osos.dec finds eight direct call sites, all plain unconditional
/// `bl`; there are no predicated forms, tail callers, or raw DATA-word
/// references. The ARM wrapper receives a wheel node, loads the live
/// scheduler-table pointer from that global, and tail-branches to
/// [`timing_wheel_remove`]. This port makes the same call through
/// [`scheduler_table`], whose existing host model substitutes a house-static
/// table; there are no further deliberate deviations.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn timing_wheel_remove_global(node: *mut u32) {
    timing_wheel_remove(scheduler_table().cast(), node);
}

/// `timing_wheel_insert_global` — original: `FUN_0827398c` @ 0x0827398c
/// (20 bytes including its four-byte literal pool at 0x0827399c).
///
/// Ghidra reports only the four instruction words (16 bytes); the `ldr r0,
/// [pc, #4]` requires the following pool word `0x089cc7e0`, and the next
/// separately linked function begins at 0x082739a0. Decoding every ARM B/BL
/// word in osos.dec finds seven direct call sites, all plain unconditional
/// `bl`; there are no predicated forms. Two unconditional `b` tail callers
/// at 0x081448c4 and 0x08144a9c take the same wrapper, and no raw DATA word
/// references its address.
///
/// The wrapper receives a wheel node, loads the live scheduler-table pointer
/// from global 0x089cc7e0, then tail-branches to [`timing_wheel_insert`].
/// The port makes that direct call through [`scheduler_table`]'s host model;
/// there are no deliberate deviations.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn timing_wheel_insert_global(node: *mut u32) {
    timing_wheel_insert(scheduler_table(), node);
}



/// animation_init — original: `FUN_08166b88` @ 0x08166b88 (212 bytes
/// including the two-word pool; 44 `bl` call sites, binary-verified — see
/// the module header).
///
/// Constructs an animation over `(current, from, to)` in the
/// caller-allocated 0x24 bytes at `this` and returns `this`: run the
/// refcounted base constructor, install the animation vtable, clear the
/// three endpoint slots, unlink defensively from the timing wheel, retain
/// the three arguments in order current/from/to, replay the (statically
/// dead) release-before-overwrite of each slot, store the endpoints, then
/// store `rank = max(from.aux, to.aux, current.aux) + 1` (unsigned,
/// wrapping) and link the object into the wheel.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn animation_init(
    this: *mut Animation,
    current_value: *mut FixedValue,
    from: *mut FixedValue,
    to: *mut FixedValue,
) -> *mut Animation {
    // 08166b98: bl 0x08138460 — the shared refcounted base constructor.
    refcounted_base_init(this.cast::<FixedValue>());
    // 08166ba0..08166ba8: override the base vtable with the derived one.
    (*this).vtable = ANIMATION_VTABLE;
    // 08166bac..08166bb8: str +0x18, +0x1c, +0x20.
    (*this).from_value = 0;
    (*this).to_value = 0;
    (*this).current_value = 0;

    let table = scheduler_table();

    // 08166bc4: defensive unlink — +0x14 just cleared means the firmware
    // body returns on its first flag test; kept for parity.
    timing_wheel_remove(table.cast(), this.cast());

    // 08166bcc..08166bdc: retain(current), retain(from), retain(to).
    retain_value(current_value.cast());
    retain_value(from.cast());
    retain_value(to.cast());

    // 08166be0..08166c00: memberwise-assign release of each OLD slot,
    // checked current (+0x20) first, then from (+0x18), then to (+0x1c).
    // All three loads land on words step three zeroed — dead code the
    // compiler must still be free to keep or drop.
    let old_current = (*this).current_value;
    if old_current != 0 {
        release_refcounted_value(old_current as usize as *mut u8);
    }
    let old_from = (*this).from_value;
    if old_from != 0 {
        release_refcounted_value(old_from as usize as *mut u8);
    }
    let old_to = (*this).to_value;
    if old_to != 0 {
        release_refcounted_value(old_to as usize as *mut u8);
    }

    // 08166c04..08166c08: stm r0={r6,r7,r8} — from, to, current.
    (*this).from_value = from as usize as u32;
    (*this).to_value = to as usize as u32;
    (*this).current_value = current_value as usize as u32;

    // 08166c0c..08166c3c: unsigned max of the three aux words, +1. The
    // fall-through arm recomputes max(from, to) instead of reusing r2,
    // exactly like the original; LLVM folds the duplicate select.
    let from_aux = (*from).aux;
    let to_aux = (*to).aux;
    let current_aux = (*current_value).aux;
    let highest = if from_aux <= to_aux {
        if to_aux <= current_aux {
            current_aux
        } else if from_aux <= to_aux {
            to_aux
        } else {
            from_aux
        }
    } else if from_aux <= current_aux {
        current_aux
    } else {
        from_aux
    };
    (*this).rank = highest.wrapping_add(1);

    timing_wheel_insert(table, this.cast());
    this
}

/// animation_default_init — original: `FUN_08166c5c` @ 0x08166c5c (36
/// instruction bytes: nine ARM words; its separately linked vtable literal
/// 0x08987f00 is at 0x08166c80, making the true extent 40 bytes; the next
/// function begins at 0x08166c84).
///
/// Decoding every ARM `B`/`BL` word in osos.dec finds exactly ten direct
/// callers, all plain unconditional `bl`; there are no predicated call forms,
/// `b` tail callers, or raw DATA-word references. The six calls at
/// 0x08153198..0x081531c0 and four at 0x0816e3bc..0x0816e3d4 construct
/// adjacent 0x24-byte animation elements by feeding each returned pointer
/// into the next address calculation.
///
/// Default-constructs an animation in caller-provided storage: initializes
/// the refcounted base, installs the derived vtable, and clears only the
/// three retained-value slots. The base initializer and following stores
/// preserve `r0`, so the ARM function returns `this`; the port makes that
/// ABI-visible result explicit. No deliberate deviations.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn animation_default_init(this: *mut Animation) -> *mut Animation {
    // 08166c60: bl 0x08138460 — initializes vtable +0x00 and flags +0x14.
    refcounted_base_init(this.cast::<FixedValue>());
    // 08166c64..08166c7c: derived vtable plus the three empty value slots.
    core::ptr::addr_of_mut!((*this).vtable).write_volatile(ANIMATION_VTABLE);
    core::ptr::addr_of_mut!((*this).from_value).write_volatile(0);
    core::ptr::addr_of_mut!((*this).to_value).write_volatile(0);
    core::ptr::addr_of_mut!((*this).current_value).write_volatile(0);
    this
}


/// animation_set_values — original: `FUN_08166a40` @ 0x08166a40 (172
/// instruction bytes; the separately linked pool word at 0x08166aec holds
/// the scheduler-global address). Raw decoding of every ARM B/BL word in
/// osos.dec verifies 18 direct call sites, all unconditional `bl`; there
/// are no predicated BL forms. Three additional unconditional `b` tail
/// callers occur at 0x081675a4, 0x081b836c, and 0x081b8c1c; no raw DATA
/// word references the address.
///
/// Rebinds every retained value slot: unlink `this`, retain
/// `(current_value, from, to)` in that order, release previous
/// `(current, from, to)` slots when non-NULL, store the new values at
/// `+0x18/+0x1c/+0x20`, compute rank as one plus their unsigned maximum
/// with wrapping addition, and relink it. The three slot writes are
/// `from/to/current`, not argument order.
///
/// Timing-wheel insertion, retain, release, and wheel removal are direct
/// ports. The stock code reloads the scheduler-global word for insertion,
/// which this function also does.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn animation_set_values(
    this: *mut Animation,
    current_value: *mut FixedValue,
    from: *mut FixedValue,
    to: *mut FixedValue,
) {

    // 08166a54..08166a60: unlink before changing endpoint slots or rank.
    timing_wheel_remove(scheduler_table().cast(), this.cast());

    // 08166a64..08166a78: retain current, from, then to.
    retain_value(current_value.cast());
    retain_value(from.cast());
    retain_value(to.cast());

    // 08166a7c..08166a9c: release old current, from, then to if present.
    let old_current = (*this).current_value;
    if old_current != 0 {
        release_refcounted_value(old_current as usize as *mut u8);
    }
    let old_from = (*this).from_value;
    if old_from != 0 {
        release_refcounted_value(old_from as usize as *mut u8);
    }
    let old_to = (*this).to_value;
    if old_to != 0 {
        release_refcounted_value(old_to as usize as *mut u8);
    }

    // 08166aa0..08166aa4: stm r0={r6,r7,r8} — from, to, current.
    (*this).from_value = from as usize as u32;
    (*this).to_value = to as usize as u32;
    (*this).current_value = current_value as usize as u32;

    // 08166aa8..08166ad8: max(from.aux, to.aux, current.aux) + 1.
    let from_aux = (*from).aux;
    let to_aux = (*to).aux;
    let current_aux = (*current_value).aux;
    let highest = if from_aux <= to_aux {
        if to_aux <= current_aux {
            current_aux
        } else if from_aux <= to_aux {
            to_aux
        } else {
            from_aux
        }
    } else if from_aux <= current_aux {
        current_aux
    } else {
        from_aux
    };
    (*this).rank = highest.wrapping_add(1);

    // 08166adc..08166ae8: reload the scheduler word and tail-branch to insert.
    timing_wheel_insert(scheduler_table(), this.cast());
}

/// animation_set_current_value — original: `FUN_08166b2c` @ 0x08166b2c
/// (88 instruction bytes; the separate literal-pool word at 0x08166b84
/// holds the scheduler-global address). Binary decoding of every ARM B/BL
/// word in osos.dec finds 30 call sites: all are plain unconditional `bl`;
/// there are no predicated calls, tail branches, or DATA-word references.
///
/// Replaces the retained current-value slot at +0x20. It unlinks `this`
/// from the timing wheel, retains `value`, releases the old current value
/// only when non-NULL, stores `value`, raises `rank` to
/// `max(rank, value.aux + 1)` using unsigned comparison and wrapping
/// addition, then reinserts the node. `value` has no NULL guard because
/// the stock body dereferences `value + 8` unconditionally.
///
/// Timing-wheel insertion, retain, release, and wheel removal are direct
/// ports. The scheduler-global word is read separately for remove and insert,
/// as in the two stock `ldr [r5]` sites.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn animation_set_current_value(
    this: *mut Animation,
    value: *mut FixedValue,
) {

    // 08166b40..08166b44: unlink before changing rank or the slot.
    timing_wheel_remove(scheduler_table().cast(), this.cast());
    // 08166b48..08166b4c: retain the incoming value before releasing old.
    retain_value(value.cast());

    // 08166b50..08166b5c: memberwise-assign's conditional old-value
    // release, then the +0x20 replacement.
    let old_value = (*this).current_value;
    if old_value != 0 {
        release_refcounted_value(old_value as usize as *mut u8);
    }
    (*this).current_value = value as usize as u32;

    // 08166b60..08166b70: candidate = value->aux + 1; `strcc` only raises
    // this->rank, using the CPU's unsigned carry-clear condition.
    let candidate_rank = (*value).aux.wrapping_add(1);
    if (*this).rank < candidate_rank {
        (*this).rank = candidate_rank;
    }

    timing_wheel_insert(scheduler_table(), this.cast());
}

/// animation_destroy — original: `FUN_08166c9c` @ 0x08166c9c (64
/// instruction bytes, sixteen words 0x08166c9c..0x08166cdb, plus the
/// separately linked literal-pool word 0x08987f00 at 0x08166cdc; true
/// extent 68 bytes. The next function opens `bx lr` at 0x08166ce0).
///
/// Binary decoding of every ARM B/BL word in osos.dec verifies exactly
/// **14 call sites**, all plain unconditional `bl`: no predicated forms,
/// no `b` tail callers, and no DATA-word references (the class vtable
/// instead points at the deleting destructor @ 0x08166c84, which
/// NULL-guards `this`, calls this body, then operator-deletes @
/// 0x082aad24). Ten of the 14 sit in two array-destructor walks with
/// `sub r0, r0, #0x24` between calls (0x08153260..0x08153288, six calls;
/// 0x0816760c..0x08167624, four calls) — 0x24 is sizeof(Animation); the
/// callers at 0x081a17e0/0x081eb018 feed the returned `this` pointer
/// onward as their walk cursor, so the return value is load bearing.
///
/// The non-deleting destructor of the animation object — the exact
/// inverse of [`animation_init`]. It reinstalls the derived vtable
/// 0x08987f00 (the classic two-phase C++ teardown store), releases the
/// three retained endpoint values in slot order current (+0x20), from
/// (+0x18), to (+0x1c) — each behind its own NULL check, the ADS
/// `blne` idiom, matching [`release_refcounted_value`]'s guard-less
/// callee — then tail-branches into the ported
/// [`refcounted_base_destroy`], which installs the base vtable, unlinks
/// the node from the timing wheel, and returns `this`. The slots keep
/// their (now released) pointer values; the body never clears them.
///
/// Deliberate deviation: the intermediate derived-vtable store is dead —
/// the base destructor overwrites it and nothing can observe the word in
/// between — so, like animation_init's statically dead releases, the
/// compiler stays free to keep or drop it.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn animation_destroy(this: *mut Animation) -> *mut Animation {
    // 08166ca4..08166ca8: ldr r0, =0x08987f00 ; str r0, [r4] — reinstall
    // the derived vtable (two-phase teardown); the base dtor overwrites it.
    (*this).vtable = ANIMATION_VTABLE;

    // 08166cac..08166ccc: ldr/cmp/blne 0x082739e0 — release current
    // (+0x20), from (+0x18), then to (+0x1c), each NULL-guarded.
    let old_current = (*this).current_value;
    if old_current != 0 {
        release_refcounted_value(old_current as usize as *mut u8);
    }
    let old_from = (*this).from_value;
    if old_from != 0 {
        release_refcounted_value(old_from as usize as *mut u8);
    }
    let old_to = (*this).to_value;
    if old_to != 0 {
        release_refcounted_value(old_to as usize as *mut u8);
    }

    // 08166cd0..08166cd8: mov r0, r4 ; pop {r4, lr} ; b 0x081384a0 — the
    // ported base destructor installs the base vtable, unlinks the wheel
    // node through the scheduler singleton, and returns this.
    refcounted_base_destroy(this.cast::<FixedValue>());
    this
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{
        note_missing_u32_fixture, try_map_u32_slab, SCHEDULER_TABLE_TEST_LOCK,
    };
    use std::sync::{LazyLock, MutexGuard, OnceLock};


    fn take_lock() -> MutexGuard<'static, ()> {
        SCHEDULER_TABLE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    unsafe fn clear_scheduler_table() {
        let table = scheduler_table();
        for bucket in 0..TIMING_WHEEL_BUCKETS {
            table.add(bucket).write(0);
        }
    }

    struct SchedulerTableGuard;

    impl Drop for SchedulerTableGuard {
        fn drop(&mut self) {
            unsafe {
                clear_scheduler_table();
            }
        }
    }

    fn clean_scheduler_table() -> SchedulerTableGuard {
        unsafe {
            clear_scheduler_table();
        }
        SchedulerTableGuard
    }

    /// Fixture addresses inside the low-4-GiB slab, so the animation's
    /// u32 target pointers round-trip exactly.
    #[derive(Clone, Copy)]
    struct Fixture {
        animation: *mut Animation,
        current: *mut FixedValue,
        from: *mut FixedValue,
        to: *mut FixedValue,
    }

    static FIXTURE: OnceLock<Option<usize>> = OnceLock::new();

    fn fixture() -> Option<Fixture> {
        let base = *FIXTURE.get_or_init(|| {
            try_map_u32_slab(crate::testing::hints::ANIMATION_INIT, 0x1000)
                .map(|p| p as usize)
        });
        let base = base? as *mut u8;
        Some(unsafe {
            Fixture {
                animation: base.cast::<Animation>(),
                current: base.add(0x28).cast::<FixedValue>(),
                from: base.add(0x40).cast::<FixedValue>(),
                to: base.add(0x58).cast::<FixedValue>(),
            }
        })
    }

    /// Destructor fixture: identical layout to the constructor's, but a
    /// dedicated mapping — fixture hints are never unmapped, so no two
    /// fixtures may share one.
    static DESTROY_FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(crate::testing::hints::ANIMATION_DESTROY, 0x1000)
            .map(|p| p as usize)
    });

    fn destroy_fixture() -> Option<Fixture> {
        let base = *DESTROY_FIXTURE;
        let base = base? as *mut u8;
        Some(unsafe {
            Fixture {
                animation: base.cast::<Animation>(),
                current: base.add(0x28).cast::<FixedValue>(),
                from: base.add(0x40).cast::<FixedValue>(),
                to: base.add(0x58).cast::<FixedValue>(),
            }
        })
    }

    /// A scalar with flag bit 1 set ("refcounted") and count 1 — what
    /// `fixed_value_init` output looks like once someone retained it.
    fn counted_scalar(at: *mut FixedValue, aux: u32) -> *mut FixedValue {
        unsafe {
            core::ptr::write(
                at,
                FixedValue {
                    vtable: crate::app::fixed_value::FIXED_VALUE_VTABLE,
                    value_q16: 0,
                    aux,
                    opaque: [0, 0],
                    flags: 0b110, // bit 1 set, count 1 in bits 2..
                },
            );
        }
        at
    }

    /// Dirty storage so every write the constructor performs (and every
    /// field it must NOT touch) is observable. Clear the linked flag: these
    /// caller tests do not construct a real wheel chain.
    fn dirty_animation(at: *mut Animation) {
        unsafe {
            core::ptr::write(
                at,
                Animation {
                    vtable: 0xdead_beef,
                    opaque_04: 0x1111_1111,
                    rank: 0xcafe_babe,
                    wheel_prev: 0x2222_2222,
                    wheel_next: 0x3333_3333,
                    flags: 0xffff_fffe,
                    from_value: 0x4444_4444,
                    to_value: 0x5555_5555,
                    current_value: 0x6666_6666,
                },
            );
        }
    }

    static WHEEL_REMOVE_FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(crate::testing::hints::TIMING_WHEEL_REMOVE, 0x1000)
            .map(|p| p as usize)
    });

    fn wheel_remove_fixture() -> Option<[*mut Animation; 3]> {
        let base = *WHEEL_REMOVE_FIXTURE;
        let base = base? as *mut u8;
        Some(unsafe {
            [
                base.cast::<Animation>(),
                base.add(0x24).cast::<Animation>(),
                base.add(0x48).cast::<Animation>(),
            ]
        })
    }

    unsafe fn wheel_node(at: *mut Animation, rank: u32, prev: u32, next: u32, flags: u32) {
        core::ptr::write(
            at,
            Animation {
                vtable: 0,
                opaque_04: 0,
                rank,
                wheel_prev: prev,
                wheel_next: next,
                flags,
                from_value: 0,
                to_value: 0,
                current_value: 0,
            },
        );
    }

    #[test]
    fn wheel_remove_leaves_unlinked_node_and_table_untouched() {
        let _lock = take_lock();
        let Some([node, _, _]) = wheel_remove_fixture() else {
            note_missing_u32_fixture("app::timing_wheel_remove");
            return;
        };
        let mut table = [0xface_cafe; TIMING_WHEEL_BUCKETS];
        unsafe {
            wheel_node(node, 0, 0x1111_1111, 0x2222_2222, 0b110);
            timing_wheel_remove(table.as_mut_ptr(), node.cast());
            assert_eq!((*node).wheel_prev, 0x1111_1111);
            assert_eq!((*node).wheel_next, 0x2222_2222);
            assert_eq!((*node).flags, 0b110);
            assert!(table.iter().all(|word| *word == 0xface_cafe));
        }
    }

    #[test]
    fn wheel_remove_replaces_head_and_repairs_successor() {
        let _lock = take_lock();
        let Some([node, next, _]) = wheel_remove_fixture() else {
            note_missing_u32_fixture("app::timing_wheel_remove");
            return;
        };
        let mut table = [0; TIMING_WHEEL_BUCKETS];
        unsafe {
            wheel_node(node, 1, 0x1234_5678, next as usize as u32, 0b111);
            wheel_node(next, 1, node as usize as u32, 0, 0b111);
            table[0] = node as usize as u32;

            timing_wheel_remove(table.as_mut_ptr(), node.cast());

            assert_eq!(table[0], next as usize as u32);
            assert_eq!((*next).wheel_prev, 0x1234_5678);
            assert_eq!((*node).wheel_next, next as usize as u32);
            assert_eq!((*node).flags, 0b110);
        }
    }

    #[test]
    fn wheel_remove_clears_terminal_bucket_head() {
        let _lock = take_lock();
        let Some([node, _, _]) = wheel_remove_fixture() else {
            note_missing_u32_fixture("app::timing_wheel_remove");
            return;
        };
        let mut table = [0; TIMING_WHEEL_BUCKETS];
        unsafe {
            wheel_node(node, 1, 0, 0, 0b111);
            table[0] = node as usize as u32;

            timing_wheel_remove(table.as_mut_ptr(), node.cast());

            assert_eq!(table[0], 0);
            assert_eq!((*node).flags, 0b110);
        }
    }

    #[test]
    fn wheel_remove_splices_interior_node_without_changing_head() {
        let _lock = take_lock();
        let Some([head, node, next]) = wheel_remove_fixture() else {
            note_missing_u32_fixture("app::timing_wheel_remove");
            return;
        };
        let mut table = [0; TIMING_WHEEL_BUCKETS];
        unsafe {
            wheel_node(head, 1, 0, node as usize as u32, 0b111);
            wheel_node(node, 1, head as usize as u32, next as usize as u32, 0b111);
            wheel_node(next, 1, node as usize as u32, 0, 0b111);
            table[0] = head as usize as u32;

            timing_wheel_remove(table.as_mut_ptr(), node.cast());

            assert_eq!(table[0], head as usize as u32);
            assert_eq!((*head).wheel_next, next as usize as u32);
            assert_eq!((*next).wheel_prev, head as usize as u32);
            assert_eq!((*node).flags, 0b110);
        }
    }
    #[test]
    fn global_wheel_remove_loads_the_scheduler_table() {
        let _lock = take_lock();
        let _table_guard = clean_scheduler_table();
        let Some([node, next, _]) = wheel_remove_fixture() else {
            note_missing_u32_fixture("app::timing_wheel_remove_global");
            return;
        };
        let table = scheduler_table();
        unsafe {
            wheel_node(node, 1, 0x1234_5678, next as usize as u32, 0b111);
            wheel_node(next, 1, node as usize as u32, 0, 0b111);
            table.write(node as usize as u32);

            timing_wheel_remove_global(node.cast());

            assert_eq!(table.read(), next as usize as u32);
            assert_eq!((*next).wheel_prev, 0x1234_5678);
            assert_eq!((*node).flags, 0b110);
        }
    }

    #[test]
    fn timing_wheel_insert_places_an_unlinked_node_in_an_empty_bucket() {
        let _lock = take_lock();
        let Some([node, _, _]) = wheel_remove_fixture() else {
            note_missing_u32_fixture("app::timing_wheel_insert");
            return;
        };
        let mut table = [0; TIMING_WHEEL_BUCKETS];
        unsafe {
            wheel_node(node, 12, 0x1234_5678, 0x8765_4321, 0b110);

            timing_wheel_insert(table.as_mut_ptr(), node.cast());

            assert_eq!(table[11], node as usize as u32);
            assert_eq!((*node).wheel_prev, 0);
            assert_eq!((*node).wheel_next, 0);
            assert_eq!((*node).flags, 0b111);
        }
    }

    #[test]
    fn timing_wheel_insert_repairs_the_old_head_predecessor() {
        let _lock = take_lock();
        let Some([node, head, _]) = wheel_remove_fixture() else {
            note_missing_u32_fixture("app::timing_wheel_insert");
            return;
        };
        let mut table = [0; TIMING_WHEEL_BUCKETS];
        unsafe {
            wheel_node(head, 3, 0, 0, 0b111);
            table[2] = head as usize as u32;
            wheel_node(node, 3, 0x1234_5678, 0x8765_4321, 0b110);

            timing_wheel_insert(table.as_mut_ptr(), node.cast());

            assert_eq!(table[2], node as usize as u32);
            assert_eq!((*node).wheel_prev, 0);
            assert_eq!((*node).wheel_next, head as usize as u32);
            assert_eq!((*node).flags, 0b111);
            assert_eq!((*head).wheel_prev, node as usize as u32);
        }
    }

    #[test]
    fn timing_wheel_insert_leaves_an_already_linked_node_unchanged() {
        let _lock = take_lock();
        let Some([node, _, _]) = wheel_remove_fixture() else {
            note_missing_u32_fixture("app::timing_wheel_insert");
            return;
        };
        let mut table = [0xface_cafe; TIMING_WHEEL_BUCKETS];
        unsafe {
            wheel_node(node, 2, 0x1234_5678, 0x8765_4321, 0b111);

            timing_wheel_insert(table.as_mut_ptr(), node.cast());

            assert!(table.iter().all(|word| *word == 0xface_cafe));
            assert_eq!((*node).wheel_prev, 0x1234_5678);
            assert_eq!((*node).wheel_next, 0x8765_4321);
            assert_eq!((*node).flags, 0b111);
        }
    }

    #[test]
    fn timing_wheel_insert_ignores_a_signed_negative_bucket() {
        let _lock = take_lock();
        let Some([node, _, _]) = wheel_remove_fixture() else {
            note_missing_u32_fixture("app::timing_wheel_insert");
            return;
        };
        let mut table = [0xface_cafe; TIMING_WHEEL_BUCKETS];
        unsafe {
            wheel_node(node, 0, 0x1234_5678, 0x8765_4321, 0b110);

            timing_wheel_insert(table.as_mut_ptr(), node.cast());

            assert!(table.iter().all(|word| *word == 0xface_cafe));
            assert_eq!((*node).wheel_prev, 0x1234_5678);
            assert_eq!((*node).wheel_next, 0x8765_4321);
            assert_eq!((*node).flags, 0b110);
        }
    }

    #[test]
    fn global_wheel_insert_loads_the_scheduler_table() {
        let _lock = take_lock();
        let _table_guard = clean_scheduler_table();
        let Some([node, _, _]) = wheel_remove_fixture() else {
            note_missing_u32_fixture("app::timing_wheel_insert_global");
            return;
        };
        let table = scheduler_table();
        unsafe {
            wheel_node(node, 12, 0x1234_5678, 0x8765_4321, 0b110);

            timing_wheel_insert_global(node.cast());

            assert_eq!(*table.add(11), node as usize as u32);
            assert_eq!((*node).wheel_prev, 0);
            assert_eq!((*node).wheel_next, 0);
            assert_eq!((*node).flags, 0b111);
        }
    }


    #[test]
    fn it_returns_the_storage_it_was_given() {
        let _lock = take_lock();
        let _table_guard = clean_scheduler_table();
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::animation");
            return;
        };
        unsafe {
            dirty_animation(f.animation);
            counted_scalar(f.current, 0);
            counted_scalar(f.from, 0);
            counted_scalar(f.to, 0);

            let returned = animation_init(f.animation, f.current, f.from, f.to);
            assert_eq!(returned, f.animation);
        }
    }

    #[test]
    fn it_installs_the_derived_vtable_and_links_the_base_initialized_node() {
        let _lock = take_lock();
        let _table_guard = clean_scheduler_table();
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::animation");
            return;
        };
        unsafe {
            dirty_animation(f.animation);
            counted_scalar(f.current, 0);
            counted_scalar(f.from, 0);
            counted_scalar(f.to, 0);

            animation_init(f.animation, f.current, f.from, f.to);

            let anim = &*f.animation;
            assert_eq!(anim.vtable, ANIMATION_VTABLE, "0x08987f00, the 0x08166c54 pool word");
            assert_eq!(anim.flags, 1, "insertion sets only the linked flag bit");
            assert_eq!(*scheduler_table(), f.animation as usize as u32);
        }
    }

    #[test]
    fn endpoint_slots_hold_from_to_current_in_target_order() {
        let _lock = take_lock();
        let _table_guard = clean_scheduler_table();
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::animation");
            return;
        };
        unsafe {
            dirty_animation(f.animation);
            counted_scalar(f.current, 0);
            counted_scalar(f.from, 0);
            counted_scalar(f.to, 0);

            animation_init(f.animation, f.current, f.from, f.to);

            let anim = &*f.animation;
            assert_eq!(
                anim.from_value, f.from as usize as u32,
                "+0x18 takes the third argument (r2)"
            );
            assert_eq!(
                anim.to_value, f.to as usize as u32,
                "+0x1c takes the fourth argument (r3)"
            );
            assert_eq!(
                anim.current_value, f.current as usize as u32,
                "+0x20 takes the second argument (r1)"
            );
        }
    }

    #[test]
    fn rank_is_one_plus_the_unsigned_max_of_the_three_aux_words() {
        let _lock = take_lock();
        let _table_guard = clean_scheduler_table();
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::animation");
            return;
        };
        unsafe {
            for &(cur, frm, tou) in &[
                (0u32, 0u32, 0u32),
                (5, 3, 4),
                (3, 5, 4),
                (3, 4, 5),
                (7, 7, 7),
                (11, 1, 2),
            ] {
                clear_scheduler_table();
                dirty_animation(f.animation);
                counted_scalar(f.current, cur);
                counted_scalar(f.from, frm);
                counted_scalar(f.to, tou);

                animation_init(f.animation, f.current, f.from, f.to);

                let expected = cur.max(frm).max(tou) + 1;
                assert_eq!((*f.animation).rank, expected, "aux ({cur:#x}, {frm:#x}, {tou:#x})");
                assert_eq!(*scheduler_table().add((expected - 1) as usize), f.animation as usize as u32);
            }
        }
    }

    #[test]
    fn constructor_retains_arguments_and_links_the_node() {
        let _lock = take_lock();
        let _table_guard = clean_scheduler_table();
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::animation");
            return;
        };
        unsafe {
            dirty_animation(f.animation);
            counted_scalar(f.current, 4);
            counted_scalar(f.from, 0);
            counted_scalar(f.to, 7);

            animation_init(f.animation, f.current, f.from, f.to);

            assert_eq!([(*f.current).flags, (*f.from).flags, (*f.to).flags], [0b1010; 3]);
            assert_eq!((*f.animation).rank, 8);
            assert_eq!(*scheduler_table().add(7), f.animation as usize as u32);
        }
    }

    #[test]
    fn constructor_releases_no_slots_after_clearing_them() {
        let _lock = take_lock();
        let _table_guard = clean_scheduler_table();
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::animation");
            return;
        };
        unsafe {
            dirty_animation(f.animation);
            counted_scalar(f.current, 0);
            counted_scalar(f.from, 0);
            counted_scalar(f.to, 0);

            animation_init(f.animation, f.current, f.from, f.to);

            assert_eq!((*f.current).flags, 0b1010);
            assert_eq!((*f.from).flags, 0b1010);
            assert_eq!((*f.to).flags, 0b1010);
        }
    }

    #[test]
    fn constructor_preserves_unrelated_words_and_replaces_wheel_links() {
        let _lock = take_lock();
        let _table_guard = clean_scheduler_table();
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::animation");
            return;
        };
        unsafe {
            dirty_animation(f.animation);
            counted_scalar(f.current, 0);
            counted_scalar(f.from, 0);
            counted_scalar(f.to, 0);

            animation_init(f.animation, f.current, f.from, f.to);

            let anim = &*f.animation;
            assert_eq!(anim.opaque_04, 0x1111_1111, "+0x04 is not written");
            assert_eq!(anim.wheel_prev, 0);
            assert_eq!(anim.wheel_next, 0);
        }
    }

    #[test]
    fn construction_produces_the_exact_final_word_image() {
        let _lock = take_lock();
        let _table_guard = clean_scheduler_table();
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::animation");
            return;
        };
        unsafe {
            dirty_animation(f.animation);
            counted_scalar(f.current, 9);
            counted_scalar(f.from, 2);
            counted_scalar(f.to, 8);

            animation_init(f.animation, f.current, f.from, f.to);

            let words = core::slice::from_raw_parts(f.animation.cast::<u32>(), 9);
            assert_eq!(
                words,
                &[
                    ANIMATION_VTABLE,
                    0x1111_1111,
                    10,
                    0,
                    0,
                    1,
                    f.from as u32,
                    f.to as u32,
                    f.current as u32,
                ],
                "all nine words after direct wheel insertion"
            );
            assert_eq!(*scheduler_table().add(9), f.animation as usize as u32);
        }
    }

    #[test]
    fn default_init_sets_its_derived_state_and_preserves_other_words() {
        let _lock = take_lock();
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::animation_default_init");
            return;
        };
        unsafe {
            dirty_animation(f.animation);

            let returned = animation_default_init(f.animation);

            assert_eq!(returned, f.animation, "array constructors consume this result");
            let words = core::slice::from_raw_parts(f.animation.cast::<u32>(), 9);
            assert_eq!(
                words,
                &[
                    ANIMATION_VTABLE,
                    0x1111_1111,
                    0xcafe_babe,
                    0x2222_2222,
                    0x3333_3333,
                    0,
                    0,
                    0,
                    0,
                ],
                "the default constructor writes exactly five of nine words"
            );
        }
    }

    #[test]
    fn the_host_scheduler_model_has_twelve_clearable_buckets() {
        let _lock = take_lock();
        let _table_guard = clean_scheduler_table();
        let table = scheduler_table();
        assert!(!table.is_null());
        let buckets = unsafe { core::slice::from_raw_parts(table, TIMING_WHEEL_BUCKETS) };
        assert!(buckets.iter().all(|b| *b == 0));
    }
    #[test]
    fn set_values_rebinds_slots_recomputes_rank_and_relinks() {
        let _lock = take_lock();
        let _table_guard = clean_scheduler_table();
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::animation");
            return;
        };
        unsafe {
            dirty_animation(f.animation);
            counted_scalar(f.current, 8);
            counted_scalar(f.from, 3);
            counted_scalar(f.to, 11);
            (*f.current).flags = 0b1010;
            (*f.from).flags = 0b1010;
            (*f.to).flags = 0b1010;
            (*f.animation).current_value = f.current as usize as u32;
            (*f.animation).from_value = f.from as usize as u32;
            (*f.animation).to_value = f.to as usize as u32;

            animation_set_values(f.animation, f.to, f.current, f.from);

            assert_eq!((*f.animation).from_value, f.current as usize as u32);
            assert_eq!((*f.animation).to_value, f.from as usize as u32);
            assert_eq!((*f.animation).current_value, f.to as usize as u32);
            assert_eq!((*f.animation).rank, 12);
            assert_eq!([(*f.current).flags, (*f.from).flags, (*f.to).flags], [0b1010; 3]);
            assert_eq!((*f.animation).opaque_04, 0x1111_1111);
            assert_eq!((*f.animation).wheel_prev, 0);
            assert_eq!((*f.animation).wheel_next, 0);
            assert_eq!((*scheduler_table().add(11)), f.animation as usize as u32);
        }
    }

    #[test]
    fn set_values_skips_empty_slots_after_retaining_arguments() {
        let _lock = take_lock();
        let _table_guard = clean_scheduler_table();
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::animation");
            return;
        };
        unsafe {
            dirty_animation(f.animation);
            counted_scalar(f.current, 1);
            counted_scalar(f.from, 2);
            counted_scalar(f.to, 3);
            (*f.animation).current_value = 0;
            (*f.animation).from_value = 0;
            (*f.animation).to_value = 0;

            animation_set_values(f.animation, f.current, f.from, f.to);

            assert_eq!([(*f.current).flags, (*f.from).flags, (*f.to).flags], [0b1010; 3]);
            assert_eq!((*f.animation).rank, 4);
            assert_eq!(*scheduler_table().add(3), f.animation as usize as u32);
        }
    }

    #[test]
    fn setter_unlinks_retains_releases_replaces_and_relinks() {
        let _lock = take_lock();
        let _table_guard = clean_scheduler_table();
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::animation");
            return;
        };
        unsafe {
            dirty_animation(f.animation);
            counted_scalar(f.current, 3);
            (*f.current).flags = 0b1010;
            counted_scalar(f.from, 9);
            (*f.animation).current_value = f.current as usize as u32;
            (*f.animation).rank = 4;
            (*f.animation).wheel_prev = 0;
            (*f.animation).wheel_next = 0;
            (*f.animation).flags |= 1;
            *scheduler_table().add(3) = f.animation as usize as u32;

            animation_set_current_value(f.animation, f.from);

            assert_eq!((*f.animation).current_value, f.from as usize as u32);
            assert_eq!((*f.animation).rank, 10);
            assert_eq!((*f.current).flags, 0b110, "old value loses one reference");
            assert_eq!((*f.from).flags, 0b1010, "incoming value gains one reference");
            assert_eq!((*f.animation).opaque_04, 0x1111_1111, "+0x04 is untouched");
            assert_eq!((*f.animation).from_value, 0x4444_4444, "+0x18 is untouched");
            assert_eq!((*f.animation).to_value, 0x5555_5555, "+0x1c is untouched");
            assert_eq!((*f.animation).wheel_prev, 0);
            assert_eq!((*f.animation).wheel_next, 0);
            assert_eq!(*scheduler_table().add(3), 0);
            assert_eq!(*scheduler_table().add(9), f.animation as usize as u32);
        }
    }

    #[test]
    fn setter_never_lowers_rank_and_raises_to_the_aux_candidate() {
        let _lock = take_lock();
        let _table_guard = clean_scheduler_table();
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::animation");
            return;
        };
        unsafe {
            for &(rank, aux, expected) in &[(1, 0, 1), (7, 0, 7), (3, 8, 9), (12, 11, 12)] {
                clear_scheduler_table();
                dirty_animation(f.animation);
                counted_scalar(f.current, 0);
                counted_scalar(f.from, aux);
                (*f.current).flags = 0b1010;
                (*f.animation).current_value = f.current as usize as u32;
                (*f.animation).rank = rank;

                animation_set_current_value(f.animation, f.from);

                assert_eq!((*f.animation).rank, expected, "rank {rank:#x}, aux {aux:#x}");
                assert_eq!(*scheduler_table().add((expected - 1) as usize), f.animation as usize as u32);
            }
        }
    }

    #[test]
    fn setter_skips_release_for_an_empty_current_slot() {
        let _lock = take_lock();
        let _table_guard = clean_scheduler_table();
        let Some(f) = fixture() else {
            note_missing_u32_fixture("app::animation");
            return;
        };
        unsafe {
            dirty_animation(f.animation);
            counted_scalar(f.from, 0);
            (*f.animation).current_value = 0;
            (*f.animation).rank = 1;

            animation_set_current_value(f.animation, f.from);

            assert_eq!((*f.animation).current_value, f.from as usize as u32);
            assert_eq!((*f.animation).rank, 1);
            assert_eq!(*scheduler_table(), f.animation as usize as u32);
        }
    }

    #[test]
    fn destroy_releases_three_slots_returns_this_and_leaves_the_base_image() {
        let _lock = take_lock();
        let Some(f) = destroy_fixture() else {
            note_missing_u32_fixture("app::animation_destroy");
            return;
        };
        unsafe {
            dirty_animation(f.animation); // flags 0xffff_fffe: linked bit clear
            counted_scalar(f.current, 0xaaaa_0001);
            counted_scalar(f.from, 0xbbbb_0002);
            counted_scalar(f.to, 0xcccc_0003);
            (*f.current).flags = 0b1010; // count 2: a live reference survives
            (*f.from).flags = 0b1010;
            (*f.to).flags = 0b1010;
            (*f.animation).current_value = f.current as usize as u32;
            (*f.animation).from_value = f.from as usize as u32;
            (*f.animation).to_value = f.to as usize as u32;

            let returned = animation_destroy(f.animation);

            assert_eq!(returned, f.animation, "the base dtor's this passthrough");
            let words = core::slice::from_raw_parts(f.animation.cast::<u32>(), 9);
            assert_eq!(
                words,
                &[
                    crate::app::fixed_value::REFCOUNTED_BASE_VTABLE, // +0x00: base dtor wins
                    0x1111_1111,  // +0x04: untouched
                    0xcafe_babe,  // +0x08: rank untouched
                    0x2222_2222,  // +0x0c: untouched (wheel never linked)
                    0x3333_3333,  // +0x10: untouched
                    0xffff_fffe,  // +0x14: flags untouched, linked bit stayed clear
                    f.from as usize as u32,    // +0x18: released but never cleared
                    f.to as usize as u32,      // +0x1c
                    f.current as usize as u32, // +0x20
                ],
                "the destructor releases the values, not the slots"
            );
            assert_eq!(
                [(*f.current).flags, (*f.from).flags, (*f.to).flags],
                [0b110; 3],
                "each retained value loses exactly one reference"
            );
        }
    }

    #[test]
    fn destroy_skips_null_slots_and_drains_a_last_reference() {
        let _lock = take_lock();
        let Some(f) = destroy_fixture() else {
            note_missing_u32_fixture("app::animation_destroy");
            return;
        };
        unsafe {
            dirty_animation(f.animation);
            counted_scalar(f.current, 0); // count 1: this release drains it
            counted_scalar(f.from, 0xdead);
            counted_scalar(f.to, 0);
            (*f.to).flags = 0b1010; // count 2
            (*f.animation).current_value = f.current as usize as u32;
            (*f.animation).from_value = 0; // the blne guard skips the call
            (*f.animation).to_value = f.to as usize as u32;

            let returned = animation_destroy(f.animation);

            assert_eq!(returned, f.animation);
            assert_eq!(
                (*f.current).flags,
                0b010,
                "count drained to zero; the host deleting-dtor dispatch defaults to a no-op"
            );
            assert_eq!((*f.from).flags, 0b110, "NULL slot: the value is never touched");
            assert_eq!((*f.to).flags, 0b110, "one reference released");
            assert_eq!(
                (*f.animation).vtable,
                crate::app::fixed_value::REFCOUNTED_BASE_VTABLE
            );
        }
    }

    #[test]
    fn destroy_unlinks_a_wheel_node_through_the_base_destructor() {
        let _lock = take_lock();
        let _table_guard = clean_scheduler_table();
        let Some(f) = destroy_fixture() else {
            note_missing_u32_fixture("app::animation_destroy");
            return;
        };
        unsafe {
            dirty_animation(f.animation);
            (*f.animation).current_value = 0;
            (*f.animation).from_value = 0;
            (*f.animation).to_value = 0;
            (*f.animation).rank = 1;
            (*f.animation).wheel_prev = 0;
            (*f.animation).wheel_next = 0;
            (*f.animation).flags = 0b111; // linked + refcounted + count 1
            let table = scheduler_table();
            *table = f.animation as usize as u32; // bucket 0 head is the node

            let returned = animation_destroy(f.animation);

            assert_eq!(returned, f.animation);
            assert_eq!(*table, 0, "the base dtor clears the singleton bucket head");
            assert_eq!((*f.animation).flags, 0b110, "only the linked bit clears");
            assert_eq!(
                (*f.animation).vtable,
                crate::app::fixed_value::REFCOUNTED_BASE_VTABLE
            );
        }
    }

}
