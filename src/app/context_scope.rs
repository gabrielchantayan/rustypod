//! The application framework's 20-byte **context scope** — the stack-local
//! RAII record 110 functions build on entry and tear down on exit.
//!
//! Three functions live here, all decoded from the raw words in
//! `work/firmware/osos.dec` (load base 0x08000000) rather than from Ghidra:
//!
//! | address | bytes | `bl` | `b` | role |
//! |---|---|---|---|---|
//! | 0x082840e8 | 44 code + 4 literal | 110 | 1 | [`context_scope_init`] — the constructor |
//! | 0x08283f3c | 52 code + 4 literal | 1 | 1 | [`context_scope_capture`] — its one callee |
//! | 0x08284188 | 4 | 120 | 0 | [`context_scope_drop`] — the trivial destructor |
//!
//! ## What the record is
//!
//! Every one of the 110 constructor sites has the same shape: reserve a
//! 20-byte slot in the frame, construct, run the block, destruct. For
//! example at 0x08044e38:
//!
//! ```text
//! sub  sp, sp, #20
//! ...
//! ldr  r1, [r4, #0xf40] ; mov r0, sp ; mov r2, #0
//! bl   0x082840e8        ; scope(subject, flag=0)
//! ...                    ; the guarded block
//! mov  r0, sp
//! bl   0x08284188        ; ~scope()
//! add  sp, sp, #20
//! ```
//!
//! The record's five words are
//!
//! ```text
//! +0x00  class descriptor  0x089a6600   (also planted by the sibling
//!                                        constructors @ 0x08284118 and the
//!                                        copy constructor @ 0x0828414c)
//! +0x04  subject           the constructor's r1, usually NULL
//! +0x08  app context       (*APP_ROOT_OBJECT)[0x30]
//! +0x0c  owner id          context[0xf60] ? context[0xf60][0x18] : 0
//! +0x10  flag byte         the constructor's r2, usually 0
//! ```
//!
//! and the class's other members confirm the reading: 0x08283ff8 and
//! 0x08284044 both dispatch the *subject*'s vtable slot +0x0c and then act on
//! the subject (`FUN_08048204`/`FUN_08061378` and the recursive view teardown
//! `FUN_080491dc`). So +0x04 is an optional view/element the scope owns, and
//! +0x08/+0x0c are the application context captured at construction time.
//! The class name does not survive anywhere in the image — no literal reaches
//! the class-name factory @ 0x0820b230 — so the symbols describe the shape,
//! they do not invent a `TCSomething`.
//!
//! Verified against the raw bytes (every B/BL word in osos.dec decoded):
//!
//! - **0x082840e8 is 48 bytes, not Ghidra's 44.** The eleven instructions run
//!   0x082840e8..0x08284110; the word at 0x08284114 is the literal
//!   `0x089a6600` that `ldr r0, [pc, #32]` loads. Ghidra dropped the trailing
//!   literal, exactly the failure mode this repo has hit before. 110 `bl`
//!   sites plus one tail `b`.
//! - **0x08284188 is not a veneer.** Its single word is `0xe12fff1e` = `bx
//!   lr`; a veneer would read `0xe51ff004` (`ldr pc, [pc, #-4]`) followed by a
//!   target word, and a dispatch stub would be a `b`. There is nothing to
//!   follow: the class's destructor is genuinely empty, which is why the same
//!   4 bytes are shared by 120 call sites. The extent is exact on both sides —
//!   0x08284184 is the closing `bx lr` of the deleting destructor at
//!   0x0828417c, and 0x0828418c is the first instruction of the assignment
//!   operator (37 `bl` sites of its own).
//! - Call-site shapes: 99 of the 110 constructor sites set `mov r2, #0` within
//!   four instructions (flag clear) and 71 set `mov r1, #0` (no subject); 87
//!   have a 0x08284188 site within the following 0x800 bytes, the pairing the
//!   RAII reading predicts.
//!
//! ## Deviations
//!
//! The firmware reads its root object through the global word @ 0x089ca674
//! (120 literal references image-wide). Following `heap/block_mgr.rs` and
//! `app/context.rs`, that word is modeled as the crate static
//! [`APP_ROOT_OBJECT`] instead of an absolute address: the 0x089cxxxx page is
//! runtime-initialized RW data, and the decrypted image carries stale UI
//! string bytes there, so the image value is not the runtime value.
//!
//! It defaults to NULL — the pre-initialization state. **Only the non-NULL
//! subject path touches it**, so the 71 default-constructing call sites are
//! unaffected; the other path is not hook-ready until integration assigns the
//! static, and it faults on NULL exactly where the original would.
//!
//! Every field is addressed as a `u32` at a word-aligned byte offset, never
//! through a Rust struct, so the layout is identical on the 32-bit target and
//! on a 64-bit host.

/// Class descriptor planted at +0x00 (literal pool word @ 0x08284114; the
/// same value sits at 0x08284148 and 0x08284178 for the sibling and copy
/// constructors).
pub const CONTEXT_SCOPE_DESCRIPTOR: u32 = 0x089a_6600;

/// Size of the record: five words, matching the `sub sp, sp, #20` at the
/// call sites and the `add r0, r0, #20` chaining at 0x0827e304.
pub const CONTEXT_SCOPE_SIZE: usize = 20;

/// Word index of the optional subject the scope holds (+0x04).
const WORD_SUBJECT: usize = 1;

/// Word index of the captured application context (+0x08).
const WORD_CONTEXT: usize = 2;

/// Word index of the captured owner id (+0x0c).
const WORD_OWNER: usize = 3;

/// Byte offset of the flag the constructor stores with `strb r2, [r3, #16]`.
pub const CONTEXT_SCOPE_FLAG: usize = 0x10;

/// Offset of the application context inside the root object
/// (`ldr r1, [r1, #0x30]`).
pub const ROOT_CONTEXT_OFFSET: usize = 0x30;

/// Offset of the owner record inside the application context
/// (`ldr r1, [r1, #0xf60]`).
pub const CONTEXT_OWNER_OFFSET: usize = 0xf60;

/// Offset of the id inside the owner record (`ldrne r1, [r1, #0x18]`).
pub const OWNER_ID_OFFSET: usize = 0x18;

/// The application root object: the firmware's global word @ 0x089ca674,
/// modeled as a crate static (see the module header's deviation note).
/// NULL is the pre-initialization state and is only ever dereferenced on the
/// non-NULL subject path.
///
/// This is the crate's **single** model of that word — 0x089ca674 is the
/// framework's system root, with 120 literal-pool references image-wide, and
/// `app/scoped_context.rs` derives the same three fields from it through this
/// static. Its address stands in for 0x089ca674, so a read is the original's
/// `ldr rN, [pc, #imm]; ldr rN, [rN]` pair, and wiring it once at integration
/// serves every reader.
pub static mut APP_ROOT_OBJECT: *mut u8 = core::ptr::null_mut();

/// Reads [`APP_ROOT_OBJECT`] the one way every reader must: volatile, because
/// the word is written at runtime and a build in which nothing writes it must
/// not constant-fold the NULL in.
#[inline(always)]
pub(crate) unsafe fn app_root_object() -> *mut u8 {
    core::ptr::read_volatile(core::ptr::addr_of!(APP_ROOT_OBJECT))
}

/// Reads a word-aligned `u32` field of a foreign firmware object.
#[inline(always)]
unsafe fn field(object: *const u8, offset: usize) -> u32 {
    object.add(offset).cast::<u32>().read()
}

/// context_scope_capture — original: `FUN_08283f3c` @ 0x08283f3c
/// (56 bytes: 52 code, 0x08283f3c..0x08283f6c, plus the 4-byte global literal
/// at 0x08283f70 that Ghidra's 52 drops; 1 `bl` site plus the tail `b` from
/// the sibling constructor's argument adapter @ 0x08283e80).
///
/// Stores `subject` at +0x04 and captures the application context into
/// +0x08/+0x0c.
///
/// With a NULL subject nothing is dereferenced: both +0x08 and +0x0c are
/// zeroed and the root global is never read (the original's `streq` / `beq`
/// pair). Otherwise it walks root -> +0x30 (stored at +0x08) -> +0xf60, and
/// stores that record's +0x18 at +0x0c, or 0 when the record is NULL.
///
/// # Safety
/// `scope` must point at [`CONTEXT_SCOPE_SIZE`] writable, word-aligned bytes.
/// A non-NULL `subject` additionally requires [`APP_ROOT_OBJECT`] to be a
/// live root object, as it is on the device.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn context_scope_capture(scope: *mut u8, subject: *mut u8) {
    let words = scope.cast::<u32>();
    words.add(WORD_SUBJECT).write(subject as usize as u32);

    if subject.is_null() {
        words.add(WORD_CONTEXT).write(0);
        words.add(WORD_OWNER).write(0);
        return;
    }

    let context = field(app_root_object(), ROOT_CONTEXT_OFFSET);
    words.add(WORD_CONTEXT).write(context);

    let owner = field(context as usize as *const u8, CONTEXT_OWNER_OFFSET);
    let owner_id = if owner == 0 {
        0
    } else {
        field(owner as usize as *const u8, OWNER_ID_OFFSET)
    };
    words.add(WORD_OWNER).write(owner_id);
}

/// context_scope_init — original: `FUN_082840e8` @ 0x082840e8
/// (48 bytes: 44 code + the 4-byte descriptor literal at 0x08284114;
/// **110 `bl` call sites plus one tail `b`**, binary-scanned over osos.dec).
///
/// The class's primary constructor. It plants the descriptor at +0x00, zeroes
/// +0x04, captures the application context through [`context_scope_capture`],
/// stores the low byte of `flag` at +0x10, and returns `this` in the ADS C++
/// convention.
///
/// The +0x04 zero store is retained even though the capture immediately
/// overwrites it — it is in the original (`mov r0, #0; str r0, [r3, #4]`
/// before the `bl`), and dropping it would change what a mocked or
/// re-entrant capture observes.
///
/// The sibling constructor @ 0x08284118 (12 `bl` sites) is the same body with
/// a handle-unwrapping adapter in front; it is not ported here.
///
/// # Safety
/// As [`context_scope_capture`]: `scope` must point at
/// [`CONTEXT_SCOPE_SIZE`] writable, word-aligned bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn context_scope_init(
    scope: *mut u8,
    subject: *mut u8,
    flag: u8,
) -> *mut u8 {
    let words = scope.cast::<u32>();
    words.write(CONTEXT_SCOPE_DESCRIPTOR);
    words.add(WORD_SUBJECT).write(0);
    context_scope_capture(scope, subject);
    scope.add(CONTEXT_SCOPE_FLAG).write(flag);
    scope
}

/// context_scope_drop — original: `FUN_08284188` @ 0x08284188
/// (**4 bytes — the single word `0xe12fff1e`, `bx lr`**; 120 `bl` call sites,
/// no `b` sites, binary-scanned over osos.dec).
///
/// The class's non-deleting destructor, and it is empty: the record owns
/// nothing that needs releasing, so the compiler emitted a bare return and
/// shared it across all 120 sites. It is not a veneer and there is no hidden
/// body behind it — see the module header for the byte-level argument.
///
/// `r0` is untouched, so the ADS convention's `this` return is preserved.
///
/// # Safety
/// Nothing is dereferenced; `scope` may be any value, including NULL.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn context_scope_drop(scope: *mut u8) -> *mut u8 {
    scope
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{
        hints, note_missing_u32_fixture, try_map_u32_slab, APP_ROOT_TEST_LOCK,
    };


    const FILL: u8 = 0xa5;

    /// A word-aligned scratch record with four guard bytes past its end, so
    /// an over-wide flag store would be visible.
    #[repr(align(4))]
    struct Record([u8; CONTEXT_SCOPE_SIZE + 4]);

    impl Record {
        fn new() -> Self {
            Self([FILL; CONTEXT_SCOPE_SIZE + 4])
        }

        fn word(&self, index: usize) -> u32 {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&self.0[index * 4..index * 4 + 4]);
            u32::from_le_bytes(bytes)
        }
    }

    /// Fixture root object graph: root at +0, context at +0x100, owner record
    /// at +0x1100. The context needs 0xf64 bytes, hence the spacing.
    struct RootFixture {
        base: *mut u8,
    }

    const ROOT_AT: usize = 0;
    const CONTEXT_AT: usize = 0x100;
    const OWNER_AT: usize = 0x1100;
    const SUBJECT_AT: usize = 0x1200;
    const FIXTURE_LEN: usize = 0x2000;

    impl RootFixture {
        /// One mapping for the whole module, cached (the
        /// `heap/client_populate.rs` `try_slab` precedent).
        /// [`try_map_u32_slab`] does not pass `MAP_FIXED`, so a second
        /// request for the same hint lands wherever the kernel likes —
        /// above 4 GiB on a 64-bit host — and the test that asked for it
        /// would skip on EVERY host while the suite still reported green.
        /// Every caller holds `APP_ROOT_TEST_LOCK`, so one shared region
        /// is safe; it is re-zeroed on each acquisition.
        fn map() -> Option<Self> {
            use std::sync::OnceLock;
            static BASE: OnceLock<Option<usize>> = OnceLock::new();
            let base = (*BASE.get_or_init(|| {
                try_map_u32_slab(hints::CONTEXT_SCOPE, FIXTURE_LEN).map(|p| p as usize)
            }))? as *mut u8;
            unsafe { core::ptr::write_bytes(base, 0, FIXTURE_LEN) };
            Some(Self { base })
        }

        fn at(&self, offset: usize) -> *mut u8 {
            unsafe { self.base.add(offset) }
        }

        fn put(&self, object: usize, offset: usize, value: u32) {
            unsafe { self.base.add(object + offset).cast::<u32>().write(value) };
        }
    }

    #[test]
    fn default_construction_plants_the_descriptor_and_zeroes_the_record() {
        let mut record = Record::new();
        let this = record.0.as_mut_ptr();

        let returned = unsafe { context_scope_init(this, core::ptr::null_mut(), 0) };

        assert_eq!(returned, this, "the ADS constructor returns this");
        assert_eq!(record.word(0), CONTEXT_SCOPE_DESCRIPTOR);
        assert_eq!(record.word(1), 0, "+0x04 subject");
        assert_eq!(record.word(2), 0, "+0x08 context");
        assert_eq!(record.word(3), 0, "+0x0c owner id");
        assert_eq!(record.0[CONTEXT_SCOPE_FLAG], 0, "+0x10 flag");
        assert_eq!(
            &record.0[CONTEXT_SCOPE_FLAG + 1..],
            &[FILL; 7],
            "the flag store is one byte wide; +0x11 onward is untouched"
        );
    }

    #[test]
    fn only_the_low_byte_of_the_flag_argument_is_stored() {
        for flag in [0u8, 1, 0x7f, 0xff] {
            let mut record = Record::new();
            let this = record.0.as_mut_ptr();
            unsafe { context_scope_init(this, core::ptr::null_mut(), flag) };
            assert_eq!(record.0[CONTEXT_SCOPE_FLAG], flag);
            assert_eq!(&record.0[CONTEXT_SCOPE_FLAG + 1..], &[FILL; 7]);
        }
    }

    #[test]
    fn a_null_subject_never_reads_the_root_global() {
        let _lock = APP_ROOT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut record = Record::new();
        unsafe {
            // A root that would fault if it were dereferenced.
            APP_ROOT_OBJECT = 0x1 as *mut u8;
            context_scope_init(record.0.as_mut_ptr(), core::ptr::null_mut(), 0);
            APP_ROOT_OBJECT = core::ptr::null_mut();
        }
        assert_eq!(record.word(2), 0);
        assert_eq!(record.word(3), 0);
    }

    #[test]
    fn a_subject_captures_the_context_and_the_owner_id() {
        let _lock = APP_ROOT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(fixture) = RootFixture::map() else {
            assert!(note_missing_u32_fixture("app::context_scope"));
            return;
        };

        let context = fixture.at(CONTEXT_AT) as usize as u32;
        let owner = fixture.at(OWNER_AT) as usize as u32;
        fixture.put(ROOT_AT, ROOT_CONTEXT_OFFSET, context);
        fixture.put(CONTEXT_AT, CONTEXT_OWNER_OFFSET, owner);
        fixture.put(OWNER_AT, OWNER_ID_OFFSET, 0xdead_beef);

        let subject = fixture.at(SUBJECT_AT);
        let mut record = Record::new();
        unsafe {
            APP_ROOT_OBJECT = fixture.at(ROOT_AT);
            context_scope_init(record.0.as_mut_ptr(), subject, 1);
            APP_ROOT_OBJECT = core::ptr::null_mut();
        }

        assert_eq!(record.word(0), CONTEXT_SCOPE_DESCRIPTOR);
        assert_eq!(record.word(1), subject as usize as u32);
        assert_eq!(record.word(2), context);
        assert_eq!(record.word(3), 0xdead_beef);
        assert_eq!(record.0[CONTEXT_SCOPE_FLAG], 1);
    }

    #[test]
    fn a_null_owner_record_yields_a_zero_owner_id_but_still_stores_the_context() {
        let _lock = APP_ROOT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(fixture) = RootFixture::map() else {
            assert!(note_missing_u32_fixture("app::context_scope"));
            return;
        };

        let context = fixture.at(CONTEXT_AT) as usize as u32;
        fixture.put(ROOT_AT, ROOT_CONTEXT_OFFSET, context);
        fixture.put(CONTEXT_AT, CONTEXT_OWNER_OFFSET, 0);

        let mut record = Record::new();
        unsafe {
            APP_ROOT_OBJECT = fixture.at(ROOT_AT);
            context_scope_init(record.0.as_mut_ptr(), fixture.at(SUBJECT_AT), 0);
            APP_ROOT_OBJECT = core::ptr::null_mut();
        }

        assert_eq!(record.word(2), context, "+0x08 is stored before the test");
        assert_eq!(record.word(3), 0);
    }

    #[test]
    fn capture_overwrites_a_dirty_record_without_touching_the_descriptor() {
        let mut record = Record::new();
        let this = record.0.as_mut_ptr();
        unsafe {
            this.cast::<u32>().write(0x1111_1111);
            this.cast::<u32>().add(WORD_CONTEXT).write(0x2222_2222);
            this.cast::<u32>().add(WORD_OWNER).write(0x3333_3333);
            context_scope_capture(this, core::ptr::null_mut());
        }
        assert_eq!(record.word(0), 0x1111_1111, "capture does not plant +0x00");
        assert_eq!(record.word(1), 0);
        assert_eq!(record.word(2), 0);
        assert_eq!(record.word(3), 0);
    }

    #[test]
    fn the_destructor_is_a_bare_return_that_preserves_this() {
        let mut record = Record::new();
        let this = record.0.as_mut_ptr();
        unsafe { context_scope_init(this, core::ptr::null_mut(), 3) };
        let before = record.0;

        assert_eq!(unsafe { context_scope_drop(this) }, this);
        assert_eq!(record.0, before, "the destructor writes nothing");
        assert_eq!(
            unsafe { context_scope_drop(core::ptr::null_mut()) },
            core::ptr::null_mut(),
            "NULL is safe: nothing is dereferenced"
        );
    }
}
