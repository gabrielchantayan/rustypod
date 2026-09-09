//! `selector_item_base_construct` — original: `FUN_08218b10` @
//! `0x08218b10` (124 bytes of code, `0x08218b10..0x08218b8c`, plus a
//! three-word literal pool at `0x08218b8c..0x08218b98`; the next function's
//! `push {r4, r5, r6, r7, r8, lr}` begins at `0x08218b98`, so the raw
//! extent is exact).
//!
//! # What it is
//!
//! Base-class constructor of an unidentified 0x180-byte selector-item
//! object. All seventeen call sites (verified by decoding every ARM B/BL
//! word in osos.dec: `0x08218da0`, `0x082224d8`, `0x08228e48`,
//! `0x08234b30`, `0x08234f54`, `0x08237a80`, `0x08237bf0`, `0x08237fec`,
//! `0x0823ad74`, `0x0823af28`, `0x0825db80`, `0x0825dfd0`, `0x08260c54`,
//! `0x08261094`, `0x08261570`, `0x0826ac34`, `0x0826b084` — all
//! unconditional `bl`, no predicated forms, no tail `b`, no data
//! references) are derived-class constructors
//! with an identical shape: `push {r2, r3, r4, lr}`, plant two stack
//! arguments, `bl 0x08218b10`, then immediately overwrite the vtable word
//! at +0x00 with their own and store derived fields at +0x18/+0x1c/+0x20.
//! That post-call vtable overwrite is what marks this as a base class.
//!
//! # Algorithm
//!
//! ```text
//! push {r4, lr}
//! ldr  ip, =0x08993c60        ; this base class's vtable
//! ldr  r4, [sp, #12]          ; stack argument 6: flag byte
//! ldr  lr, [sp, #8]           ; stack argument 5: context word
//! str  ip, [r0]               ; +0x00 vtable
//! ldrb ip, [r0, #4]
//! bic  ip, ip, #1
//! orr  ip, ip, r4             ; flags byte: bit0 <- arg6 (whole low byte)
//! bic  ip, ip, #2             ; bit1 always cleared
//! strb ip, [r0, #4]           ; +0x04 flags
//! str  lr, [r0, #8]           ; +0x08 context word
//! strb r1, [r0, #0xb4]        ; +0xb4 item id byte
//! str  r2, [r0, #0xb8]        ; +0xb8 descriptor word
//! strb r3, [r0, #0xbc]        ; +0xbc kind byte
//! add  r0, r0, #0xc0
//! bl   0x0810ebbc             ; pair_header_base_construct on +0xc0
//! sub  r4, r0, #0xc0          ; recover `this` from the base ctor result
//! mov  r0, #0
//! str  r0, [r4, #0x178]       ; trailing words cleared
//! str  r0, [r4, #0x17c]
//! add  r0, r4, #12
//! mov  r1, #0xa8
//! bl   0x08037db8             ; memzero +0x0c..+0xb3 via the IRAM veneer
//! ldr  r1, =0x801c
//! mov  r0, r4
//! str  r1, [r4, #0xc]         ; selector record: selector 0x801c
//! mov  r1, #8
//! strb r1, [r4, #0x10]        ; record byte 8
//! ldr  r1, =0x08ae5444
//! str  r1, [r4, #0x14]        ; record impl thunk
//! pop  {r4, pc}               ; return `this`
//! ```
//!
//! Layout (0x180 bytes total): vtable +0x00, flags byte +0x04, context
//! word +0x08, 12-byte selector record {selector 0x801c, byte 8, impl
//! 0x08ae5444} at +0x0c..+0x17 inside the zeroed +0x0c..+0xb3 span,
//! caller fields at +0xb4/+0xb8/+0xbc, the 0xb8-byte PairHeaderBase
//! subobject at +0xc0..+0x177 (built by the ported
//! [`crate::cxx::pair_header::pair_header_base_construct`]), and the
//! cleared trailing words +0x178/+0x17c.
//!
//! The selector record ties this class into the fixed selector table
//! `selector_record_address` @ 0x08218aec maps (selectors 0x801c..=0x8029,
//! 12-byte records). Anomaly documented, not resolved: the {selector,
//! impl} pair table at 0x0826acd0 lists the very same impl thunk
//! 0x08ae5444 under selector **0x801d**, while this constructor plants it
//! next to selector 0x801c; 0x08ae5444 itself is a mid-function entry
//! (`mov r2, sp; mov r1, #1; mov r0, #25; ...; pop {ip, pc}`) whose
//! owning function is unidentified.
//!
//! # Deliberate deviations
//!
//! - The original zero-fills +0x0c..+0xb3 through the IRAM veneer
//!   0x08037db8; the port calls the ported
//!   [`crate::libc::memzero::memzero_aligned`] directly (the established
//!   idiom — the veneer exists only to reach the IRAM mirror).
//! - `this` is recovered from the base constructor's result minus 0xc0
//!   exactly as the ARM does, so the base port's return value controls
//!   where the trailing clears and selector record land.
//!
//! No dispatch seams: both callees (0x0810ebbc, 0x08037db8) are ported.

use crate::cxx::pair_header::pair_header_base_construct;
use crate::libc::memzero::memzero_aligned;

/// This base class's vtable literal at 0x08218b8c. Its slots point into
/// the {selector, impl} pair table at 0x0826acd0; the class is
/// unidentified (every caller overwrites the vtable with its own).
const SELECTOR_ITEM_BASE_VTABLE: u32 = 0x0899_3c60;
/// Default selector planted at +0x0c (literal at 0x08218b90).
const SELECTOR_ITEM_BASE_SELECTOR: u32 = 0x801c;
/// Default selector-record byte planted at +0x10.
const SELECTOR_ITEM_BASE_RECORD_BYTE: u8 = 8;
/// Default selector-record impl thunk planted at +0x14 (literal at
/// 0x08218b94).
const SELECTOR_ITEM_BASE_IMPL: u32 = 0x08ae_5444;

/// selector_item_base_construct — original: `FUN_08218b10` @ `0x08218b10`
/// (124 bytes).
///
/// Constructs the 0x180-byte selector-item base object at `this` and
/// returns `this`. `item_id`, `descriptor` and `item_kind` land at
/// +0xb4/+0xb8/+0xbc, `context` at +0x08, and `enable_flag`'s low byte is
/// ORed into the flags byte at +0x04 with bit 1 forced clear. Field
/// semantics beyond the observed call-site values (small per-class id
/// bytes, per-class descriptor pointers, kind byte 9, context words
/// 24/44/80) are unrecovered; the names are structural.
///
/// # Safety
/// `this` must point at 0x180 writable, 4-byte-aligned bytes; the base
/// subobject's grand-base dependency must be configured as documented by
/// [`pair_header_base_construct`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selector_item_base_construct(
    this: *mut u32,
    item_id: u8,
    descriptor: u32,
    item_kind: u8,
    context: u32,
    enable_flag: u8,
) -> *mut u32 {
    this.write(SELECTOR_ITEM_BASE_VTABLE);
    let flags = this.cast::<u8>().add(4);
    flags.write((flags.read() & !0x01 | enable_flag) & !0x02);
    this.add(2).write(context);
    this.cast::<u8>().add(0xb4).write(item_id);
    this.add(0xb8 / 4).write(descriptor);
    this.cast::<u8>().add(0xbc).write(item_kind);
    let object = pair_header_base_construct(this.add(0xc0 / 4)).sub(0xc0 / 4);
    object.add(0x178 / 4).write(0);
    object.add(0x17c / 4).write(0);
    memzero_aligned(object.cast::<u8>().add(0xc), 0xa8);
    object.add(0xc / 4).write(SELECTOR_ITEM_BASE_SELECTOR);
    object.cast::<u8>().add(0x10).write(SELECTOR_ITEM_BASE_RECORD_BYTE);
    object.add(0x14 / 4).write(SELECTOR_ITEM_BASE_IMPL);
    object
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::cxx::pair_header::{PairHeaderElementArrayOps, PAIR_HEADER_ELEMENT_ARRAY_OPS};
    use std::vec;

    /// Constructor dependency swaps are global; serialize on the same
    /// crate-wide lock `cxx::pair_header`'s tests use.
    fn lock_ops() -> std::sync::MutexGuard<'static, ()> {
        crate::testing::CPP_ARRAY_OPS_TEST_LOCK.lock().unwrap()
    }

    /// Objects span 0x180 bytes: the last writes land at +0x17c.
    const OBJECT_WORDS: usize = 0x180 / 4;
    const FILL: u32 = 0xaaaa_5555;

    /// PairHeaderBase's vtable literal (0x0810ebf4), re-stated here so the
    /// test does not depend on `cxx::pair_header`'s private constant.
    const EMBEDDED_BASE_VTABLE: u32 = 0x0898_1630;

    /// Inert reset stand-in with the same ABI as the seam default;
    /// installed on drop so a failed assertion cannot poison other tests.
    unsafe extern "C" fn inert_reset(
        this: *mut u32,
        _field_count: u32,
        _field_size: u32,
        _allocation_header_bytes: u32,
        _initializer_argument: u32,
        _element_initializer: u32,
        _initializer_context: u32,
        _allocator_callback: u32,
        _allocator_context: u32,
        _allocation_flags: u32,
        _zero_initialize: u32,
    ) -> *mut u32 {
        this
    }

    struct OpsGuard;

    impl OpsGuard {
        fn install(ops: PairHeaderElementArrayOps) -> Self {
            unsafe {
                core::ptr::addr_of_mut!(PAIR_HEADER_ELEMENT_ARRAY_OPS).write_volatile(ops);
            }
            OpsGuard
        }
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(PAIR_HEADER_ELEMENT_ARRAY_OPS).write_volatile(
                    PairHeaderElementArrayOps { reset: inert_reset },
                );
            }
        }
    }

    fn byte_at(object: &[u32], offset: usize) -> u8 {
        object[offset / 4].to_le_bytes()[offset % 4]
    }

    /// Full layout check against the ARM store sequence: identity words,
    /// caller fields, the zeroed +0x0c..+0xb3 span with its selector
    /// record, the embedded PairHeaderBase, and the trailing clears.
    #[test]
    fn constructs_identity_record_and_clears() {
        let _lock = lock_ops();
        let _guard = OpsGuard::install(PairHeaderElementArrayOps { reset: inert_reset });
        unsafe {
            let mut storage = vec![FILL; OBJECT_WORDS];
            let this = storage.as_mut_ptr();
            let ret = selector_item_base_construct(this, 0x31, 0xdead_beef, 9, 0x50, 1);

            assert_eq!(ret, this, "constructor returns `this`");
            assert_eq!(storage[0], SELECTOR_ITEM_BASE_VTABLE);
            assert_eq!(storage[2], 0x50, "context word lands at +0x08");
            assert_eq!(byte_at(&storage, 0xb4), 0x31);
            assert_eq!(storage[0xb8 / 4], 0xdead_beef);
            assert_eq!(byte_at(&storage, 0xbc), 9);
            assert_eq!(byte_at(&storage, 4), (0x55 & !0x01 | 1) & !0x02);

            // Selector record inside the zeroed +0x0c..+0xb3 span.
            assert_eq!(storage[0x0c / 4], 0x801c);
            assert_eq!(storage[0x10 / 4], 8, "record byte 8, upper bytes zeroed");
            assert_eq!(storage[0x14 / 4], 0x08ae_5444);
            assert!(
                storage[0x18 / 4..0xb4 / 4].iter().all(|&word| word == 0),
                "+0x18..+0xb3 is zero-filled"
            );

            // Embedded PairHeaderBase subobject at +0xc0.
            assert_eq!(storage[0xc0 / 4], EMBEDDED_BASE_VTABLE);
            assert_eq!(storage[0x178 / 4], 0);
            assert_eq!(storage[0x17c / 4], 0);
        }
    }

    /// The flags update is `(old & !1 | flag) & !2`, not an assignment:
    /// upper bits of the pre-existing byte survive, bit 1 never does —
    /// including a bit-1 contribution from the flag argument itself.
    #[test]
    fn flags_byte_update_is_read_modify_write() {
        let _lock = lock_ops();
        let _guard = OpsGuard::install(PairHeaderElementArrayOps { reset: inert_reset });
        unsafe {
            for (flag, expected) in [(0u8, 0xfcu8), (1, 0xfd), (0xff, 0xfd)] {
                let mut storage = vec![0xffff_ffffu32; OBJECT_WORDS];
                selector_item_base_construct(storage.as_mut_ptr(), 0, 0, 0, 0, flag);
                assert_eq!(
                    byte_at(&storage, 4),
                    expected,
                    "flag {:#04x}: (0xff & !1 | flag) & !2",
                    flag
                );
            }
        }
    }

    /// Ordering proof against the original: the vtable is planted and the
    /// caller fields stored BEFORE the embedded base-constructor chain
    /// runs, while the trailing clears, the +0x0c zero-fill and the
    /// selector record all land AFTER it.
    #[test]
    fn vtable_and_fields_precede_base_chain_then_clears() {
        let _lock = lock_ops();
        static mut SEEN_VTABLE: u32 = 0;
        static mut SEEN_TRAILING: u32 = 0;
        static mut SEEN_SPAN_WORD: u32 = 0;
        static mut SEEN_ID_BYTE: u8 = 0;

        unsafe extern "C" fn recording_reset(
            this: *mut u32,
            _field_count: u32,
            _field_size: u32,
            _allocation_header_bytes: u32,
            _initializer_argument: u32,
            _element_initializer: u32,
            _initializer_context: u32,
            _allocator_callback: u32,
            _allocator_context: u32,
            _allocation_flags: u32,
            _zero_initialize: u32,
        ) -> *mut u32 {
            // The grand-base reset receives this + 0xc0 (base subobject)
            // + 4 (grand base) + 0x2c (body) = this + 0xf0.
            let object = (this as *const u32).sub(0xf0 / 4);
            core::ptr::addr_of_mut!(SEEN_VTABLE).write_volatile(object.read());
            core::ptr::addr_of_mut!(SEEN_TRAILING).write_volatile(object.add(0x178 / 4).read());
            core::ptr::addr_of_mut!(SEEN_SPAN_WORD).write_volatile(object.add(0x0c / 4).read());
            core::ptr::addr_of_mut!(SEEN_ID_BYTE)
                .write_volatile(object.cast::<u8>().add(0xb4).read());
            this
        }

        let _guard = OpsGuard::install(PairHeaderElementArrayOps {
            reset: recording_reset,
        });
        unsafe {
            let mut storage = vec![FILL; OBJECT_WORDS];
            selector_item_base_construct(storage.as_mut_ptr(), 0x31, 0, 0, 0, 0);

            assert_eq!(
                core::ptr::addr_of!(SEEN_VTABLE).read_volatile(),
                SELECTOR_ITEM_BASE_VTABLE,
                "vtable is planted before the base chain"
            );
            assert_eq!(
                core::ptr::addr_of!(SEEN_ID_BYTE).read_volatile(),
                0x31,
                "caller fields are stored before the base chain"
            );
            assert_eq!(
                core::ptr::addr_of!(SEEN_TRAILING).read_volatile(),
                FILL,
                "trailing words are cleared after the base chain"
            );
            assert_eq!(
                core::ptr::addr_of!(SEEN_SPAN_WORD).read_volatile(),
                FILL,
                "+0x0c span is zero-filled after the base chain"
            );
            // And after return the chain's effects are all visible.
            assert_eq!(storage[0x0c / 4], 0x801c);
            assert_eq!(storage[0x178 / 4], 0);
        }
    }
}
