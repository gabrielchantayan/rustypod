//! `fixed_value_init` — original: `FUN_081523b8` @ 0x081523b8
//! (32 bytes; **138 `bl` call sites**, one of the hottest unported
//! small leaves in the app framework), and its sibling default
//! constructor `fixed_value_default_init` — original: `FUN_081523dc`
//! @ 0x081523dc (20 bytes; builds FixedValue arrays in place with a
//! 0x18 stride).
//!
//! The value constructor of retailOS's UI property/animation framework:
//! it builds a refcounted **Q16.16 fixed-point scalar** object in
//! caller-allocated storage and returns it.
//!
//! ```text
//! stmdb sp!,{r4,lr}
//! mov   r4, r1              ; keep the value across the ctor call
//! bl    0x08138460          ; refcounted base-class constructor
//! ldr   r1, =0x08986998     ; the derived (scalar) vtable
//! stmia r0, {r1, r4}        ; vtable -> +0x00, value -> +0x04
//! mov   r1, #0
//! str   r1, [r0, #0x8]      ; aux word -> 0
//! ldmia sp!,{r4,pc}         ; return this
//! ```
//!
//! ## What the object is
//!
//! Every caller allocates the storage with `operator_new(0x18)`
//! (@ 0x082aadd4) and passes the scalar as `x << 16` — Q16.16 fixed
//! point (the `util/fixed.rs` `fixed16` convention; typical literals
//! are 0xff0000 = 255.0, 0xa00000 = 160.0, 0x1400000 = 320.0). The
//! results are stored as view-property slots (+0xc4, +0xd0, +0xe0 of
//! the owning view object) or handed, as (from, to) pairs, to the
//! animation constructor `FUN_08166b88`, which retains both
//! (retain @ 0x08273a14: flags bit 1 set -> `+0x14 += 4`), releases
//! them on teardown (release @ 0x082739e0: `+0x14 -= 4`, and when the
//! count drains it dispatches the deleting destructor through vtable
//! slot +0x04), and reads the +0x08 word of each of its three value
//! arguments keeping the maximum — so +0x08 is an aux/rank word that a
//! plain scalar leaves 0.
//!
//! The refcounted base constructor [`refcounted_base_init`] @
//! 0x08138460 (36 instruction bytes; the separate 4-byte vtable
//! literal is at 0x08138484; 22 call sites) is shared by every class,
//! among them the animation object `FUN_08166b88` and the default
//! scalar ctor `FUN_081523dc`. It installs the base vtable 0x08984ca0
//! at +0x00 and zeroes the flags/refcount word at +0x14 with an odd
//! two-step sequence — `ldrb/bic #3/strb` on the flags byte, then
//! `ldr/and #3/str` on the word — which always lands 0: the byte clear
//! kills flag bits 0..1, and the word mask then keeps only those
//! (now-zero) bits, dropping any count the word held.
//!
//! ## Deviations
//!
//! Both vtables are kept as **address constants**. Their contents in
//! the decrypted image are stale — the `app/registry.rs` caveat
//! (0x08989718: "that one page of the image does not match what the
//! device runs") covers this whole 0x0898xxxx page; the slots there
//! point into what the image holds as 16-bit data tables, not code.
//! What the ports reproduce are the stored 32-bit pointer values,
//! which are exact.

/// The derived (Q16.16 scalar) vtable, installed by [`fixed_value_init`]
/// (original literal @ 0x081523d8). An address constant — see the
/// module header's vtable caveat.
pub const FIXED_VALUE_VTABLE: u32 = 0x0898_6998;

/// The refcounted base class's vtable, installed by
/// [`refcounted_base_init`] (original literal @ 0x08138484) and
/// immediately overridden by [`FIXED_VALUE_VTABLE`] in
/// [`fixed_value_init`]. An address constant, same caveat.
pub const REFCOUNTED_BASE_VTABLE: u32 = 0x0898_4ca0;

/// The refcounted Q16.16 scalar object: 0x18 bytes on the 32-bit
/// target (every caller allocates `operator_new(0x18)`; the default
/// constructor's array stride is 0x18).
#[repr(C)]
pub struct FixedValue {
    /// +0x00: the vtable — [`REFCOUNTED_BASE_VTABLE`] during the base
    /// constructor, [`FIXED_VALUE_VTABLE`] after it. A raw address
    /// word: the table's contents are stale in the decrypted image
    /// (see the module header).
    pub vtable: u32,
    /// +0x04: the scalar, Q16.16 fixed point (callers pass `x << 16`).
    pub value_q16: i32,
    /// +0x08: zeroed here. The animation constructor `FUN_08166b88`
    /// reads this word off each of its three value arguments and keeps
    /// the maximum — an aux/rank word a plain scalar leaves 0.
    pub aux: u32,
    /// +0x0c..+0x13: not touched by either constructor.
    pub opaque: [u32; 2],
    /// +0x14: flags (bits 0..1) and the refcount (bits 2..; retain
    /// @ 0x08273a14 adds 4, release @ 0x082739e0 subtracts 4 and
    /// dispatches the deleting destructor at vtable +0x04 when the
    /// count drains). The base constructor zeroes the whole word.
    pub flags: u32,
}

// The target layout is deliberately also preserved on 64-bit test hosts:
// vtable fields in firmware objects are always 32-bit ARM addresses.
const _: [u8; 0x04] = [0; core::mem::offset_of!(FixedValue, value_q16)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(FixedValue, aux)];
const _: [u8; 0x14] = [0; core::mem::offset_of!(FixedValue, flags)];
const _: [u8; 0x18] = [0; core::mem::size_of::<FixedValue>()];

/// `refcounted_base_init` — original: `FUN_08138460` @ 0x08138460
/// (36 bytes: nine ARM instructions; the vtable literal is separately
/// at 0x08138484).
///
/// Installs the base-class vtable at +0x00, then clears the
/// flags/refcount word at +0x14. The raw ARM sequence is `str` of the
/// literal vtable, `ldrb/bic/strb` to clear the low two flag bits, then
/// `ldr/and/str` to retain only those now-clear bits. The final word is
/// consequently zero for every initial state. Every access is a
/// volatile 32-bit-target-layout access so the byte/word store ordering
/// and offsets remain explicit under LLVM.
///
/// # Safety
///
/// `this` must identify a live, 4-byte-aligned firmware object with at
/// least 0x18 writable bytes. Its +0x00 word and +0x14 byte/word must be
/// valid for the target's plain stores.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn refcounted_base_init(this: *mut FixedValue) {
    let object = this.cast::<u8>();
    (object as *mut u32).write_volatile(REFCOUNTED_BASE_VTABLE);

    let flags_byte = object.add(0x14);
    flags_byte.write_volatile(flags_byte.read_volatile() & !0x3);

    let flags_word = flags_byte.cast::<u32>();
    flags_word.write_volatile(flags_word.read_volatile() & 0x3);
}

/// fixed_value_init — original: `FUN_081523b8` @ 0x081523b8 (32 bytes).
///
/// Constructs a Q16.16 scalar value object in the caller-allocated
/// 0x18 bytes at `this` and returns `this`: run the refcounted base
/// constructor, then override the vtable with the scalar one, store
/// `value_q16` at +0x04 and zero the +0x08 aux word.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn fixed_value_init(
    this: *mut FixedValue,
    value_q16: i32,
) -> *mut FixedValue {
    refcounted_base_init(this);
    (*this).vtable = FIXED_VALUE_VTABLE;
    (*this).value_q16 = value_q16;
    (*this).aux = 0;
    this
}

/// fixed_value_default_init — original: `FUN_081523dc` @ 0x081523dc
/// (20 bytes).
///
/// The default constructor of the same refcounted Q16.16 scalar class:
/// runs the refcounted base constructor, then overrides the vtable with
/// the scalar one — and stores nothing else. The original:
///
/// ```text
/// str  lr, [sp, #-0x4]!
/// bl   0x08138460           ; refcounted base-class constructor
/// ldr  r1, [0x081523f0]     ; the derived (scalar) vtable 0x08986998
/// str  r1, [r0, #0x0]       ; vtable -> +0x00
/// ldr  pc, [sp], #0x4       ; return this
/// ```
///
/// Unlike [`fixed_value_init`], the +0x04 scalar and the +0x08 aux word
/// are left untouched — its callers are array builders
/// (`FUN_08280fc0`, `FUN_081eadec`, `FUN_081a167c`, `FUN_081b8e74`)
/// that chain it over consecutive objects at a 0x18 stride, so a
/// default-constructed element's value/aux words keep whatever the
/// storage held.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn fixed_value_default_init(this: *mut FixedValue) -> *mut FixedValue {
    refcounted_base_init(this);
    (*this).vtable = FIXED_VALUE_VTABLE;
    this
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// A scratch object pre-filled with sentinels, so the constructor's
    /// writes (and the fields it must NOT write) are all observable.
    fn dirty() -> FixedValue {
        FixedValue {
            vtable: 0xdead_beef,
            value_q16: 0x0bad_f00d_u32 as i32,
            aux: 0xcafe_babe,
            opaque: [0x1111_1111, 0x2222_2222],
            flags: 0xffff_ffff,
        }
    }

    #[test]
    fn it_returns_the_same_object_it_was_given() {
        let mut object = dirty();
        let this = core::ptr::addr_of_mut!(object);
        assert_eq!(unsafe { fixed_value_init(this, 0x1400000) }, this);
    }

    #[test]
    fn it_installs_the_derived_vtable_over_the_base_one() {
        let mut object = dirty();
        unsafe { fixed_value_init(core::ptr::addr_of_mut!(object), 0) };
        assert_eq!(object.vtable, FIXED_VALUE_VTABLE, "0x08986998, the 0x081523d8 literal");
    }

    #[test]
    fn the_base_constructor_installs_its_vtable_and_zeroes_the_flags_word() {
        let mut object = dirty();
        unsafe { refcounted_base_init(core::ptr::addr_of_mut!(object)) };
        assert_eq!(object.vtable, REFCOUNTED_BASE_VTABLE, "0x08984ca0, the 0x08138484 literal");
        assert_eq!(object.flags, 0, "byte clear + word mask always lands 0");
        // The sequence only touches +0x00 and +0x14.
        assert_eq!(object.value_q16, 0x0bad_f00d_u32 as i32);
        assert_eq!(object.aux, 0xcafe_babe);
        assert_eq!(object.opaque, [0x1111_1111, 0x2222_2222]);
    }

    #[test]
    fn refcounted_base_init_uses_the_target_word_and_byte_offsets() {
        let mut object = dirty();
        let raw = unsafe {
            core::slice::from_raw_parts(
                core::ptr::addr_of!(object).cast::<u8>(),
                core::mem::size_of::<FixedValue>(),
            )
        };
        unsafe { refcounted_base_init(core::ptr::addr_of_mut!(object)) };

        assert_eq!(
            &raw[0x00..0x04],
            &REFCOUNTED_BASE_VTABLE.to_le_bytes(),
            "first is the 32-bit vtable str at +0x00"
        );
        assert_eq!(
            &raw[0x04..0x14],
            &[
                0x0d, 0xf0, 0xad, 0x0b, // value_q16
                0xbe, 0xba, 0xfe, 0xca, // aux
                0x11, 0x11, 0x11, 0x11, // opaque[0]
                0x22, 0x22, 0x22, 0x22, // opaque[1]
            ],
            "no byte between the two target stores is touched"
        );
        assert_eq!(&raw[0x14..0x18], &[0; 4], "the final word str is +0x14");
    }

    #[test]
    fn the_flags_word_lands_zero_from_any_prior_bits() {
        // The original's two-step (clear bits 0..1 of the low byte, then
        // keep only bits 0..1 of the word) yields 0 no matter what the
        // word held — a dirty refcount and every flag combination alike.
        for prior in [0u32, 1, 2, 3, 4, 0xffff_fffc, 0xffff_ffff, 0x8000_0000] {
            let mut object = dirty();
            object.flags = prior;
            unsafe { refcounted_base_init(core::ptr::addr_of_mut!(object)) };
            assert_eq!(object.flags, 0, "prior {prior:#x}");
        }
    }

    #[test]
    fn it_stores_the_q16_value_verbatim() {
        // The callers' literals: 0.0, 255.0, 160.0 (half the 320px
        // screen), 320.0 — plus the bit-pattern edges.
        let values: Vec<i32> = std::vec![
            0,
            1,
            -1,
            0x00ff_0000,
            0x00a0_0000,
            0x0140_0000,
            i32::MAX,
            i32::MIN,
            0x0001_0000,
            -0x0001_0000,
        ];
        for value in values {
            let mut object = dirty();
            unsafe { fixed_value_init(core::ptr::addr_of_mut!(object), value) };
            assert_eq!(object.value_q16, value, "{value:#x} round-trips");
        }
    }

    #[test]
    fn it_zeroes_the_aux_word() {
        let mut object = dirty();
        unsafe { fixed_value_init(core::ptr::addr_of_mut!(object), 0x00a0_0000) };
        assert_eq!(object.aux, 0, "the animation ctor's max-key is 0 for a plain scalar");
    }

    #[test]
    fn it_leaves_the_untouched_fields_alone() {
        let mut object = dirty();
        unsafe { fixed_value_init(core::ptr::addr_of_mut!(object), -1) };
        assert_eq!(object.opaque, [0x1111_1111, 0x2222_2222], "+0x0c/+0x10 are not written");
    }

    #[test]
    fn construction_produces_the_exact_final_state() {
        let mut object = dirty();
        let this = core::ptr::addr_of_mut!(object);
        let returned = unsafe { fixed_value_init(this, 0x00ff_0000) };
        assert_eq!(returned, this);
        assert_eq!(object.vtable, FIXED_VALUE_VTABLE);
        assert_eq!(object.value_q16, 0x00ff_0000);
        assert_eq!(object.aux, 0);
        assert_eq!(object.flags, 0, "the base ctor's zero survives the override");
        assert_eq!(object.opaque, [0x1111_1111, 0x2222_2222]);
    }

    #[test]
    fn default_init_returns_the_same_object_it_was_given() {
        let mut object = dirty();
        let this = core::ptr::addr_of_mut!(object);
        assert_eq!(unsafe { fixed_value_default_init(this) }, this);
    }

    #[test]
    fn default_init_installs_the_derived_vtable_over_the_base_one() {
        let mut object = dirty();
        unsafe { fixed_value_default_init(core::ptr::addr_of_mut!(object)) };
        assert_eq!(object.vtable, FIXED_VALUE_VTABLE, "0x08986998, the 0x081523f0 literal");
        assert_eq!(object.flags, 0, "the base ctor's zero survives the override");
    }

    #[test]
    fn default_init_leaves_the_value_and_aux_words_untouched() {
        // Unlike fixed_value_init, the default ctor stores no scalar and
        // does not zero +0x08 — array elements keep their dirty words.
        let mut object = dirty();
        unsafe { fixed_value_default_init(core::ptr::addr_of_mut!(object)) };
        assert_eq!(object.value_q16, 0x0bad_f00d_u32 as i32, "+0x04 is not written");
        assert_eq!(object.aux, 0xcafe_babe, "+0x08 is not written");
        assert_eq!(object.opaque, [0x1111_1111, 0x2222_2222]);
    }

    #[test]
    #[cfg(target_pointer_width = "32")]
    fn default_init_constructs_an_array_at_the_0x18_stride() {
        // The callers' pattern: chain the default ctor over consecutive
        // 0x18-byte slots (`FUN_081523dc(p); FUN_081523dc(p + 0x18); ...`).
        // 32-bit target only: on the 64-bit host `vtable: usize` widens
        // the struct past 0x18 bytes (see `layout_checks`), so the
        // target stride is not the host stride.
        let mut objects = [dirty(), dirty(), dirty()];
        let base = core::ptr::addr_of_mut!(objects[0]);
        for i in 0..3 {
            let slot = unsafe { base.byte_add(0x18 * i) };
            assert_eq!(unsafe { fixed_value_default_init(slot) }, slot);
        }
        for object in &objects {
            assert_eq!(object.vtable, FIXED_VALUE_VTABLE);
            assert_eq!(object.flags, 0);
            assert_eq!(object.value_q16, 0x0bad_f00d_u32 as i32);
            assert_eq!(object.aux, 0xcafe_babe);
        }
    }
}
