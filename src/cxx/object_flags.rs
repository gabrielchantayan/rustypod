//! Object-header flag predicates and the singleton flag-word counter
//! accessor ported from retailOS.

/// object_low_flags_clear — original: `FUN_0808539c` @ `0x0808539c`
/// (20 bytes; source: `ipod-decomp/decomp/c/005/0808539c_FUN_0808539c.c`).
///
/// Loads the 32-bit flag word at offset `+0x04` of an aligned object and
/// returns 1 exactly when its low three bits are all clear; it returns 0
/// otherwise. The retail sequence is `ldr; tst #7; moveq #1; movne #0; bx lr`.
/// The object type and meanings of the individual bits are still unknown, so
/// the name describes the verified field-level behavior.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_low_flags_clear(object: *const u8) -> u32 {
    u32::from((object.add(4).cast::<u32>().read_volatile() & 0x7) == 0)
}

/// object_value_set_flags_clear — original: `FUN_08085344` @ `0x08085344`
/// (16 bytes; source: `ipod-decomp/decomp/c/005/08085344_FUN_08085344.c`).
///
/// Initializes the two-word object header: stores `value` into the 32-bit
/// word at offset `+0x00` and clears the whole 32-bit flag word at offset
/// `+0x04` (the same flag word object_low_flags_clear @ 0x0808539c tests).
/// The retail sequence is `str r1,[r0]; mov r1,#0; str r1,[r0,#4]; bx lr`.
/// All three call sites (0x081b0594, 0x081b05c4, 0x081b06f4) apply it to
/// the sub-header at object+0xb8 with a value loaded from a data cursor,
/// so the header reads as { position-or-pointer, flags }; the concrete
/// object type is still unidentified, so the name describes the verified
/// field-level behavior.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_value_set_flags_clear(object: *mut u8, value: u32) {
    object.cast::<u32>().write_volatile(value);
    object.add(4).cast::<u32>().write_volatile(0);
}

/// Dispatcher op for the acquire half of the bracket around
/// [`object_flags_fetch_increment`] (`mov r0, #0x9` @ 0x08085364).
const LOCK_DISPATCH_ACQUIRE: u32 = 9;
/// Dispatcher op for the release half (`mov r0, #0xa` @ 0x08085388).
const LOCK_DISPATCH_RELEASE: u32 = 10;
/// Lock selected for the bracket (`mov r1, #0x2`; the third and fourth
/// dispatcher arguments are always zero here).
const SINGLETON_LOCK: u32 = 2;

/// Injection point for `FUN_08043b94`, the retailOS lock dispatcher: the
/// `bl` @ 0x08085368 passes (op, lock, 0, 0) before the increment and the
/// `bl` @ 0x0808538c passes the release op after it. Op 9/10 pairs
/// bracket critical sections throughout retailOS (59 `bl 0x08043b94`
/// sites); the dispatcher's own negative-argument path performs a
/// timeout-queue wait, confirming the acquire/release roles.
pub type LockDispatch = unsafe extern "C" fn(u32, u32, u32, u32);

/// Spins forever: [`object_flags_fetch_increment`] must not run before
/// target integration installs the retailOS dispatcher.
unsafe extern "C" fn missing_lock_dispatch(
    _op: u32,
    _lock: u32,
    _reserved_a: u32,
    _reserved_b: u32,
) {
    loop {
        core::hint::spin_loop();
    }
}

/// RetailOS dependency of [`object_flags_fetch_increment`]. Target
/// integration must install the real `FUN_08043b94`; focused host tests
/// replace it with a recording seam.
pub static mut OBJECT_FLAGS_FETCH_INCREMENT_LOCK: LockDispatch = missing_lock_dispatch;

#[inline(always)]
unsafe fn lock_dispatch() -> LockDispatch {
    core::ptr::read_volatile(core::ptr::addr_of!(OBJECT_FLAGS_FETCH_INCREMENT_LOCK))
}

/// Load address of the fixed retailOS singleton whose +0x04 word
/// [`object_flags_fetch_increment`] increments: the literal pool word
/// @ 0x08085398 holds 0x08a0e9e0, and the object is shared with the
/// lock-dispatch machinery (FUN_08075914 lazily points its +0x00 word at
/// the embedded vtable @ 0x08a0e9ec; FUN_080439e0 / FUN_08043e04 call
/// through its vtable slots +0x14 / +0x0c).
#[cfg(target_os = "none")]
const SINGLETON_OBJECT: *mut u32 = 0x08a0_e9e0 as *mut u32;

/// Host stand-in for the firmware singleton: the +0x00 vtable word is
/// unused by this function; the +0x04 word is the counter under test.
#[cfg(not(target_os = "none"))]
static mut HOST_SINGLETON_OBJECT: [u32; 2] = [0; 2];

/// The aligned 32-bit word at +0x04 of the singleton.
#[inline(always)]
unsafe fn singleton_flags_word() -> *mut u32 {
    #[cfg(target_os = "none")]
    {
        SINGLETON_OBJECT.add(1)
    }
    #[cfg(not(target_os = "none"))]
    {
        core::ptr::addr_of_mut!(HOST_SINGLETON_OBJECT).cast::<u32>().add(1)
    }
}

/// object_flags_fetch_increment — original: `FUN_08085354` @ `0x08085354`
/// (68 bytes: 64 of code plus the 4-byte singleton pointer literal
/// @ 0x08085398; source:
/// `ipod-decomp/decomp/c/005/08085354_FUN_08085354.c`).
///
/// Fetch-and-increment of the fixed singleton's +0x04 word — the same
/// header offset object_low_flags_clear @ 0x0808539c tests and
/// object_value_set_flags_clear @ 0x08085344 clears on their
/// caller-passed objects — under the retailOS lock dispatcher
/// `FUN_08043b94`: acquire (9, 2, 0, 0), read the word, store the value
/// plus one, release (10, 2, 0, 0), and return the pre-increment value.
/// The retail sequence is `stmdb sp!,{r4,lr}; bl dispatch(9,2,0,0);
/// ldr r4,[obj,#4]; add r1,r4,#1; str r1,[obj,#4]; bl dispatch(10,2,0,0);
/// mov r0,r4; ldmia sp!,{r4,pc}`. The word's role (plain counter versus
/// sequence number) is unverified, so the name claims only the observed
/// fetch-and-increment.
///
/// Deviations: the unported dispatcher rides the
/// [`OBJECT_FLAGS_FETCH_INCREMENT_LOCK`] seam (house pattern — see
/// app/node_list.rs's NODE_LIST_ENQUEUE_OPS) instead of a direct `bl`,
/// and host builds substitute test storage for the firmware singleton
/// @ 0x08a0e9e0.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_flags_fetch_increment() -> u32 {
    let dispatch = lock_dispatch();
    dispatch(LOCK_DISPATCH_ACQUIRE, SINGLETON_LOCK, 0, 0);
    let word = singleton_flags_word();
    let previous = word.read_volatile();
    word.write_volatile(previous.wrapping_add(1));
    dispatch(LOCK_DISPATCH_RELEASE, SINGLETON_LOCK, 0, 0);
    previous
}

/// Status-class mask: the retailOS FreeType fork encodes the error class
/// in the low byte of a status word (`and r0, r4, #0xff` @ 0x080853d0 /
/// 0x08085430 / 0x0808543c; the caller FT_Open_Face masks the same way @
/// 0x0804d824-0x0804d830).
const STATUS_CLASS_MASK: u32 = 0xff;
/// Status class 2 — the "format not recognized" class (`cmp r0, #0x2` @
/// 0x080853d4): every driver's open returned it, so the resource-fork /
/// dfont retry is worthwhile. Same value as upstream FreeType's
/// `FT_Err_Unknown_File_Format`.
const STATUS_UNKNOWN_FILE_FORMAT: u32 = 2;
/// Status class 0x55 (`cmp r0, #0x55` @ 0x08085440): the second class
/// that falls through to the fallback-rule chain. The class's own
/// producer is unlocated, so only its routing role is claimed.
const STATUS_FALLBACK_RULE_CLASS: u32 = 0x55;
/// `open_args` flag word bit (`tst r0, #0x4` @ 0x0808544c) gating the
/// fallback-rule chain FUN_080db8ac ("Try rule %d: %s offset %d ...").
const OPEN_ARGS_FALLBACK_RULES: u32 = 0x4;

/// Format string @ 0x0808547c, passed to `ft_error_trace` with
/// `open_args[3]` (the pathname) before the dfont retry.
const TRY_AS_DFONT_FORMAT: &[u8; 21] = b"Try as dfont: %s ...\0";
/// Outcome word @ 0x08085494 selected when the dfont retry returns 0.
const OUTCOME_SUCCESSFUL: &[u8; 11] = b"successful\0";
/// Outcome word @ 0x080854a0 selected otherwise.
const OUTCOME_FAILED: &[u8; 7] = b"failed\0";
/// Format string @ 0x080854a8 for the outcome trace (`adr r0, 0x80854a8`
/// @ 0x08085428).
const OUTCOME_FORMAT: &[u8; 4] = b"%s\n\0";

/// Resource-fork probe `FUN_08076510` (unported): reads the Mac resource
/// header off the stream and, when it parses, delegates to the dfont
/// open with the computed data-fork offset.
pub type ResourceForkProbe =
    unsafe extern "C" fn(library: *mut u32, stream: *mut u32, face_index: i32, face_out: *mut u32) -> u32;
/// Dfont open `FUN_0807f478` (unported): tries two resource tags through
/// the sfnt drivers; [`ft_open_face_dfont_fallback`] always passes
/// `offset` 0 (`mov r2, #0x0` @ 0x080853f8).
pub type DfontOpen = unsafe extern "C" fn(
    library: *mut u32,
    stream: *mut u32,
    offset: u32,
    face_index: i32,
    face_out: *mut u32,
) -> u32;
/// Fallback-rule chain `FUN_080db8ac` (unported): walks the rule table
/// derived from the pathname, re-opening through FT_Open_Face per rule.
pub type FallbackRuleChain = unsafe extern "C" fn(
    library: *mut u32,
    stream: *mut u32,
    face_index: i32,
    face_out: *mut u32,
    open_args: *const u32,
) -> u32;

/// The unported callees of [`ft_open_face_dfont_fallback`], grouped in
/// the house ops-struct pattern (app/node_list.rs's NODE_LIST_ENQUEUE_OPS).
pub struct DfontFallbackOps {
    pub probe_resource_fork: ResourceForkProbe,
    pub open_dfont: DfontOpen,
    pub run_fallback_rules: FallbackRuleChain,
}

/// Spins forever: [`ft_open_face_dfont_fallback`] must not run before
/// target integration installs the retailOS callees.
unsafe extern "C" fn missing_resource_fork_probe(
    _library: *mut u32,
    _stream: *mut u32,
    _face_index: i32,
    _face_out: *mut u32,
) -> u32 {
    loop {
        core::hint::spin_loop();
    }
}

/// Spins forever: see [`missing_resource_fork_probe`].
unsafe extern "C" fn missing_dfont_open(
    _library: *mut u32,
    _stream: *mut u32,
    _offset: u32,
    _face_index: i32,
    _face_out: *mut u32,
) -> u32 {
    loop {
        core::hint::spin_loop();
    }
}

/// Spins forever: see [`missing_resource_fork_probe`].
unsafe extern "C" fn missing_fallback_rule_chain(
    _library: *mut u32,
    _stream: *mut u32,
    _face_index: i32,
    _face_out: *mut u32,
    _open_args: *const u32,
) -> u32 {
    loop {
        core::hint::spin_loop();
    }
}

/// RetailOS dependencies of [`ft_open_face_dfont_fallback`]. Target
/// integration must install the real `FUN_08076510` / `FUN_0807f478` /
/// `FUN_080db8ac`; focused host tests replace them with recording seams.
pub static mut DFONT_FALLBACK_OPS: DfontFallbackOps = DfontFallbackOps {
    probe_resource_fork: missing_resource_fork_probe,
    open_dfont: missing_dfont_open,
    run_fallback_rules: missing_fallback_rule_chain,
};

#[inline(always)]
unsafe fn dfont_fallback_ops() -> DfontFallbackOps {
    core::ptr::read_volatile(core::ptr::addr_of!(DFONT_FALLBACK_OPS))
}

/// Load address of the retailOS trace-level block whose +0x34 word gates
/// the two `ft_error_trace` calls: the literal pool word @ 0x08085478
/// holds 0x08b209dc. The block is this FreeType fork's per-component
/// trace verbosity table; the +0x34 slot covers the open-face path.
#[cfg(target_os = "none")]
const TRACE_LEVELS: *const i32 = 0x08b2_09dc as *const i32;

/// Host stand-in for the firmware trace-level block: only the +0x34 word
/// (index 13) is read; zero-init means "no tracing".
#[cfg(not(target_os = "none"))]
static mut HOST_TRACE_LEVELS: [i32; 14] = [0; 14];

/// The signed trace level at +0x34 of the trace-level block. Read twice
/// per dfont retry, exactly like the retail `ldr r0, [r6, #0x34]` @
/// 0x080853e0 and 0x08085410; the comparison is signed (`blt` /
/// `ldrge`+`blge` against #3).
#[inline(always)]
unsafe fn dfont_trace_level() -> i32 {
    #[cfg(target_os = "none")]
    {
        TRACE_LEVELS.add(0x34 / 4).read_volatile()
    }
    #[cfg(not(target_os = "none"))]
    {
        core::ptr::addr_of!(HOST_TRACE_LEVELS).cast::<i32>().add(0x34 / 4).read_volatile()
    }
}

/// ft_open_face_dfont_fallback — original: `FUN_080853b0` @ `0x080853b0`
/// (200 bytes: 196 of code 0x080853b0..0x08085474 plus the 4-byte
/// trace-levels pointer literal @ 0x08085478; source:
/// `ipod-decomp/decomp/c/005/080853b0_FUN_080853b0.c`).
///
/// The format-fallback stage of FT_Open_Face (FUN_0804d6b8), reached from
/// the single call site @ 0x0804d844 after every registered font driver
/// rejected the stream. It first re-probes the stream as a Mac resource
/// fork (`FUN_08076510(library, stream, face_index, face_out)`). When
/// that comes back with the low-byte class 2 (unknown format), it traces
/// `"Try as dfont: %s ..."` with `open_args[3]` (pathname), retries as a
/// data-fork resource file (`FUN_0807f478(library, stream, 0, face_index,
/// face_out)`), and traces `"successful"`/`"failed"` by whether the retry
/// returned 0 — both traces only when the signed trace level at
/// 0x08b209dc+0x34 exceeds 2. If the surviving status class is then 2 or
/// 0x55 and `open_args[0]` (flags) has bit 0x4 set, it makes a final
/// attempt through the fallback-rule chain
/// `FUN_080db8ac(library, stream, face_index, face_out, open_args)` and
/// returns that status; in every other case the current status is
/// returned unchanged. The retail sequence is `stmdb sp!,{r3-r11,lr};
/// ldr r5,[sp,#0x28]` (fifth argument homed from the stack) …
/// `bl 0x08076510; bl 0x0807f478; bl 0x080db8ac; mov r0,r4;
/// ldmia sp!,{r3-r11,pc}`.
///
/// Deviations: the three unported callees ride the [`DFONT_FALLBACK_OPS`]
/// seam (house pattern) instead of direct `bl`s; the ported
/// [`ft_error_trace`](crate::ft::trace::ft_error_trace) takes the two
/// trace calls directly (its retail varargs shim is already ported); the
/// unused r2/r3 slots of the trace calls, garbage in retail, are passed
/// as 0; and host builds substitute test storage for the firmware
/// trace-level block @ 0x08b209dc.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_open_face_dfont_fallback(
    library: *mut u32,
    stream: *mut u32,
    face_index: i32,
    face_out: *mut u32,
    open_args: *const u32,
) -> u32 {
    let ops = dfont_fallback_ops();
    let mut result = (ops.probe_resource_fork)(library, stream, face_index, face_out);
    if result & STATUS_CLASS_MASK == STATUS_UNKNOWN_FILE_FORMAT {
        if dfont_trace_level() > 2 {
            crate::ft::trace::ft_error_trace(
                TRY_AS_DFONT_FORMAT.as_ptr(),
                open_args.add(3).read_volatile(),
                0,
                0,
            );
        }
        result = (ops.open_dfont)(library, stream, 0, face_index, face_out);
        if dfont_trace_level() > 2 {
            let outcome = if result == 0 {
                OUTCOME_SUCCESSFUL.as_ptr()
            } else {
                OUTCOME_FAILED.as_ptr()
            };
            crate::ft::trace::ft_error_trace(OUTCOME_FORMAT.as_ptr(), outcome as u32, 0, 0);
        }
    }
    let class = result & STATUS_CLASS_MASK;
    if class != STATUS_UNKNOWN_FILE_FORMAT && class != STATUS_FALLBACK_RULE_CLASS {
        return result;
    }
    if open_args.read_volatile() & OPEN_ARGS_FALLBACK_RULES != 0 {
        result = (ops.run_fallback_rules)(library, stream, face_index, face_out, open_args);
    }
    result
}

/// `FT_FaceRec.family_name` (+0x14; the `str r5,[r4,#0x14]` @
/// 0x0808560c). Addressed by word index, like cxx/handle.rs's
/// handle_deref_field12: byte-exact on the 32-bit target, disjoint
/// from the face's other words on a 64-bit host.
const FACE_FAMILY_NAME_WORD: usize = 0x14 / 4;
/// `FT_FaceRec.style_name` (+0x18; the `str r5,[r4,#0x18]` @
/// 0x08085610).
const FACE_STYLE_NAME_WORD: usize = 0x18 / 4;
/// `FT_FaceRec.available_sizes` (+0x20; the `ldr r1,[r4,#0x20]` @
/// 0x08085620 and the `str r5,[r4,#0x20]` @ 0x0808562c).
const FACE_AVAILABLE_SIZES_WORD: usize = 0x20 / 4;
/// `FT_FaceRec.driver` (+0x60; the `ldr r0,[r0,#0x60]` @ 0x08085600).
const FACE_DRIVER_WORD: usize = 0x60 / 4;
/// `FT_FaceRec.memory` (+0x64; the `ldr r1,[r4,#0x64]` @ 0x08085614).
const FACE_MEMORY_WORD: usize = 0x64 / 4;
/// `PFR_FaceRec.phy_font` (+0x120; the `add r0,r4,#0x120` @
/// 0x08085618): `FT_FaceRec` (0x84) + `PFR_HeaderRec` + `PFR_LogFont`
/// of the retailOS fork's PFR_FaceRec.
const FACE_PHY_FONT_WORD: usize = 0x120 / 4;
/// `FT_ModuleRec.memory` (+0x08; the `ldr r6,[r0,#0x8]` @ 0x08085608),
/// reached through the face's driver — upstream
/// `pfrface->driver->root.memory`.
const MODULE_MEMORY_WORD: usize = 0x08 / 4;

/// Physical-font teardown `FUN_080a3554` (unported): upstream
/// FreeType `pfr_phy_font_done` (pfrload.c). Frees and zeroes the
/// PFR physical-font record's owned fields — the pointer fields at
/// +0x3c..+0x80 plus the extra-items `FT_List` at +0x88, whose nodes
/// it walks and frees — all through `ft_mem_free`. Identified by its
/// sole call site (@ 0x0808561c, inside [`pfr_face_done`]) matching
/// upstream's `pfr_phy_font_done( &face->phy_font, FT_FACE_MEMORY )
///`, and by its sibling `FUN_080a3624` = `pfr_phy_font_load` (whose
/// trace string reads "pfr_phy_font_load: invalid physical font" and
/// which `FT_LIST`-initializes the same +0x88 list: `head = NULL;
/// tail = &head`).
pub type PfrPhyFontDone =
    unsafe extern "C" fn(phys: *mut *mut u8, memory: *mut crate::ft::memory::FtMemory);

/// Spins forever: [`pfr_face_done`] must not run before target
/// integration installs the retailOS `FUN_080a3554`.
unsafe extern "C" fn missing_pfr_phy_font_done(
    _phys: *mut *mut u8,
    _memory: *mut crate::ft::memory::FtMemory,
) {
    loop {
        core::hint::spin_loop();
    }
}

/// RetailOS dependency of [`pfr_face_done`]. Target integration must
/// install the real `FUN_080a3554`; focused host tests replace it with
/// a recording seam.
pub static mut PFR_PHY_FONT_DONE: PfrPhyFontDone = missing_pfr_phy_font_done;

#[inline(always)]
unsafe fn pfr_phy_font_done() -> PfrPhyFontDone {
    core::ptr::read_volatile(core::ptr::addr_of!(PFR_PHY_FONT_DONE))
}

/// pfr_face_done (FreeType `pfr_face_done`, pfrdrivr.c) — original:
/// `FUN_080855f8` @ `0x080855f8` (60 bytes; source:
/// `ipod-decomp/decomp/c/005/080855f8_FUN_080855f8.c`).
///
/// The PFR driver's `FT_Done_Face`. Loads the allocator from the
/// face's driver (`FT_FaceRec.driver` @ +0x60 → `FT_ModuleRec.memory`
/// @ +0x08, upstream `pfrface->driver->root.memory`), NULLs
/// `family_name` (+0x14) and `style_name` (+0x18) so no dangling
/// pointers outlive the face, tears down the embedded physical-font
/// record at +0x120 with the face's own memory (+0x64) through
/// `pfr_phy_font_done` (`FUN_080a3554`), then `FT_FREE`s
/// `available_sizes` (+0x20) with the driver memory —
/// `ft_mem_free(memory, available_sizes)` plus the macro's own NULL
/// store. The retail sequence is `stmdb sp!,{r4,r5,r6,lr};
/// ldr r0,[r0,#0x60]; ldr r6,[r0,#0x8]; str #0 @ +0x14/+0x18;
/// bl 0x080a3554(face+0x120, [face,#0x64]); bl 0x082cfae8(r6,
/// [face,#0x20]); str #0 @ +0x20; ldmia sp!,{r4,r5,r6,pc}`.
///
/// Identification: 0 `bl 0x080855f8` call sites and no data pointer
/// anywhere in the decrypted image — it is reached through the PFR
/// driver class's `done_face` slot, whose record does not survive in
/// osos.dec (upstream stores it adjacent to `init_face` =
/// `FUN_08085634`, likewise absent; the class record presumably sits
/// in one of the image's undecrypted zero holes). The PFR pin is
/// `FUN_08085634` itself, which checks the PFR header signature at
/// `PFR_Face` +0x84 (the `header` right after the 0x84-byte
/// `FT_FaceRec`), plus `pfr_phy_font_load`'s trace string.
///
/// Deviations: the unported `pfr_phy_font_done` rides the
/// [`PFR_PHY_FONT_DONE`] seam (house pattern — see
/// [`OBJECT_FLAGS_FETCH_INCREMENT_LOCK`]) instead of a direct `bl`;
/// the already-ported [`ft_mem_free`](crate::ft::memory::ft_mem_free)
/// @ 0x082cfae8 takes the `FT_FREE` half directly (LLVM inlines its
/// null-guarded `blx [memory,#8]` body — the same inlining deviation
/// ft_mem_alloc's entry records); and the face
/// fields are addressed by word index (byte-exact +0x14..+0x120 on
/// the 32-bit target; each field stays disjoint on a 64-bit host —
/// the same model as cxx/handle.rs's handle_deref_field12).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pfr_face_done(face: *mut *mut u8) {
    let driver = face.add(FACE_DRIVER_WORD).read_volatile();
    let memory = driver
        .cast::<*mut crate::ft::memory::FtMemory>()
        .add(MODULE_MEMORY_WORD)
        .read_volatile();
    face.add(FACE_FAMILY_NAME_WORD).write_volatile(core::ptr::null_mut());
    face.add(FACE_STYLE_NAME_WORD).write_volatile(core::ptr::null_mut());
    pfr_phy_font_done()(
        face.add(FACE_PHY_FONT_WORD),
        face.add(FACE_MEMORY_WORD).read_volatile().cast::<crate::ft::memory::FtMemory>(),
    );
    let available_sizes = face.add(FACE_AVAILABLE_SIZES_WORD);
    crate::ft::memory::ft_mem_free(memory, available_sizes.read_volatile());
    available_sizes.write_volatile(core::ptr::null_mut());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An aligned stand-in for the unidentified retail object header.
    #[repr(C, align(4))]
    struct ObjectHeader {
        bytes: [u8; 8],
    }

    fn invoke(flags: u32) -> u32 {
        let mut object = ObjectHeader { bytes: [0; 8] };
        object.bytes[4..8].copy_from_slice(&flags.to_le_bytes());
        unsafe { object_low_flags_clear(object.bytes.as_ptr()) }
    }

    fn invoke_init(initial: [u8; 8], value: u32) -> [u8; 8] {
        let mut object = ObjectHeader { bytes: initial };
        unsafe { object_value_set_flags_clear(object.bytes.as_mut_ptr(), value) };
        object.bytes
    }

    fn reference(flags: u32) -> u32 {
        u32::from(flags & 0x7 == 0)
    }

    #[test]
    fn low_flag_combinations_match_reference() {
        for low_flags in 0..8 {
            assert_eq!(invoke(low_flags), reference(low_flags));
        }
    }

    #[test]
    fn higher_bits_do_not_affect_low_flag_predicate() {
        for flags in [0x8, 0x10, 0x8000_0000, 0xffff_fff8, 0xa5a5_a5a8] {
            assert_eq!(invoke(flags), 1, "flags={flags:#010x}");
        }
    }

    #[test]
    fn any_set_low_flag_makes_result_false() {
        for high_bits in [0, 0x8, 0x1234_5600, 0xffff_fff8] {
            for low_flags in 1..8 {
                let flags = high_bits | low_flags;
                assert_eq!(invoke(flags), 0, "flags={flags:#010x}");
            }
        }
    }

    #[test]
    fn init_stores_value_and_clears_flag_word() {
        for value in [0, 1, 0x0800_0000, 0xdead_beef, 0xffff_ffff] {
            let object = invoke_init([0xaa; 8], value);
            assert_eq!(&object[0..4], &value.to_le_bytes(), "value={value:#010x}");
            assert_eq!(&object[4..8], &[0; 4], "value={value:#010x}");
        }
    }

    #[test]
    fn init_clears_every_flag_bit_pattern() {
        for flags in [0x7u32, 0xffff_ffff, 0xa5a5_a5a5, 0x8000_0000, 0x1234_5678] {
            let mut initial = [0xcc; 8];
            initial[4..8].copy_from_slice(&flags.to_le_bytes());
            let object = invoke_init(initial, 0x1111_2222);
            assert_eq!(&object[4..8], &[0; 4], "flags={flags:#010x}");
        }
    }

    #[test]
    fn init_leaves_low_flags_clear_predicate_true() {
        let mut object = ObjectHeader { bytes: [0xff; 8] };
        unsafe { object_value_set_flags_clear(object.bytes.as_mut_ptr(), 42) };
        assert_eq!(unsafe { object_low_flags_clear(object.bytes.as_ptr()) }, 1);
    }

    extern crate std;
    use std::sync::{Mutex as StdMutex, MutexGuard as StdMutexGuard};

    /// Serializes the tests that swap the lock-dispatch seam and the host
    /// singleton storage.
    static FETCH_INCREMENT_TEST_LOCK: StdMutex<()> = StdMutex::new(());

    /// One recorded dispatcher invocation: the four arguments plus the
    /// singleton +0x04 word observed at call time, which pins the acquire
    /// before the store and the release after it.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct LockCall {
        op: u32,
        lock: u32,
        reserved_a: u32,
        reserved_b: u32,
        word_at_call: u32,
    }

    const NO_LOCK_CALL: LockCall =
        LockCall { op: 0, lock: 0, reserved_a: 0, reserved_b: 0, word_at_call: 0 };

    static mut LOCK_CALLS: [LockCall; 8] = [NO_LOCK_CALL; 8];
    static mut LOCK_CALL_COUNT: usize = 0;

    unsafe extern "C" fn recording_lock_dispatch(
        op: u32,
        lock: u32,
        reserved_a: u32,
        reserved_b: u32,
    ) {
        let word_at_call = singleton_flags_word().read_volatile();
        let count = LOCK_CALL_COUNT;
        assert!(count < 8, "lock dispatcher called more than 8 times");
        LOCK_CALLS[count] = LockCall { op, lock, reserved_a, reserved_b, word_at_call };
        LOCK_CALL_COUNT = count + 1;
    }

    /// Installs the recording seam, seeds the host singleton's +0x04 word,
    /// and returns the guard serializing the swap.
    fn install_recording_lock(initial: u32) -> StdMutexGuard<'static, ()> {
        let guard = FETCH_INCREMENT_TEST_LOCK.lock().unwrap();
        unsafe {
            singleton_flags_word().write_volatile(initial);
            LOCK_CALL_COUNT = 0;
            OBJECT_FLAGS_FETCH_INCREMENT_LOCK = recording_lock_dispatch;
        }
        guard
    }

    fn uninstall_recording_lock() {
        unsafe { OBJECT_FLAGS_FETCH_INCREMENT_LOCK = missing_lock_dispatch };
    }

    fn recorded_calls() -> (usize, [LockCall; 8]) {
        unsafe { (LOCK_CALL_COUNT, LOCK_CALLS) }
    }

    #[test]
    fn fetch_increment_returns_previous_and_stores_next() {
        for initial in [0u32, 1, 7, 0xffff_fffe, 0xdead_beef, 0xa5a5_a5a5] {
            let _guard = install_recording_lock(initial);
            let returned = unsafe { object_flags_fetch_increment() };
            assert_eq!(returned, initial, "initial={initial:#010x}");
            assert_eq!(
                unsafe { singleton_flags_word().read_volatile() },
                initial.wrapping_add(1),
                "initial={initial:#010x}"
            );
            uninstall_recording_lock();
        }
    }

    #[test]
    fn fetch_increment_wraps_at_u32_max() {
        let _guard = install_recording_lock(0xffff_ffff);
        let returned = unsafe { object_flags_fetch_increment() };
        assert_eq!(returned, 0xffff_ffff);
        // ARM `add r1, r4, #1` wraps modulo 2^32; no overflow trap.
        assert_eq!(unsafe { singleton_flags_word().read_volatile() }, 0);
        uninstall_recording_lock();
    }

    #[test]
    fn consecutive_calls_return_strictly_increasing_values() {
        let _guard = install_recording_lock(41);
        for expected in 41..44 {
            assert_eq!(unsafe { object_flags_fetch_increment() }, expected);
        }
        assert_eq!(unsafe { singleton_flags_word().read_volatile() }, 44);
        uninstall_recording_lock();
    }

    #[test]
    fn increment_is_bracketed_by_acquire_and_release() {
        let _guard = install_recording_lock(0x1234_5678);
        let returned = unsafe { object_flags_fetch_increment() };
        assert_eq!(returned, 0x1234_5678);
        let (count, calls) = recorded_calls();
        assert_eq!(count, 2, "exactly one acquire and one release");
        assert_eq!(
            calls[0],
            LockCall { op: 9, lock: 2, reserved_a: 0, reserved_b: 0, word_at_call: 0x1234_5678 },
            "acquire (9,2,0,0) precedes the store"
        );
        assert_eq!(
            calls[1],
            LockCall { op: 10, lock: 2, reserved_a: 0, reserved_b: 0, word_at_call: 0x1234_5679 },
            "release (10,2,0,0) follows the store"
        );
        uninstall_recording_lock();
    }

    #[test]
    fn whole_word_increments_through_set_low_flag_bits() {
        // The add is a plain whole-word increment: it neither preserves
        // nor specially treats the low three bits the neighbor predicate
        // tests.
        for (initial, expected) in [(0x7u32, 0x8u32), (0xffff_fff7, 0xffff_fff8), (0xff, 0x100)] {
            let _guard = install_recording_lock(initial);
            assert_eq!(unsafe { object_flags_fetch_increment() }, initial);
            assert_eq!(unsafe { singleton_flags_word().read_volatile() }, expected);
            uninstall_recording_lock();
        }
    }

    // --- ft_open_face_dfont_fallback ---

    /// Serializes the tests that swap the dfont-fallback ops seam, the
    /// host trace-level block, and the scripted callee results.
    static DFONT_FALLBACK_TEST_LOCK: StdMutex<()> = StdMutex::new(());

    /// One recorded seam or sink invocation, in call order.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum FallbackEvent {
        Probe { library: usize, stream: usize, face_index: i32, face_out: usize },
        Dfont { library: usize, stream: usize, offset: u32, face_index: i32, face_out: usize },
        Rules {
            library: usize,
            stream: usize,
            face_index: i32,
            face_out: usize,
            open_args: usize,
        },
        Trace { format: [u8; 24], arg1: u32 },
    }

    const NO_EVENT: FallbackEvent = FallbackEvent::Trace { format: [0; 24], arg1: 0 };

    static mut FALLBACK_EVENTS: [FallbackEvent; 8] = [NO_EVENT; 8];
    static mut FALLBACK_EVENT_COUNT: usize = 0;
    static mut PROBE_RESULT: u32 = 0;
    static mut DFONT_RESULT: u32 = 0;
    static mut RULES_RESULT: u32 = 0;

    /// Never-dereferenced sentinels pinned by the recorded arguments.
    const LIBRARY: usize = 0x1111_0000;
    const STREAM: usize = 0x2222_0000;
    const FACE_INDEX: i32 = -1;
    const FACE_OUT: usize = 0x4444_0000;
    static PATHNAME: &[u8; 26] = b"/System/Fonts/Chicane.ttf\0";

    fn record(event: FallbackEvent) {
        unsafe {
            let count = FALLBACK_EVENT_COUNT;
            assert!(count < 8, "fallback seams called more than 8 times");
            FALLBACK_EVENTS[count] = event;
            FALLBACK_EVENT_COUNT = count + 1;
        }
    }

    unsafe extern "C" fn recording_probe(
        library: *mut u32,
        stream: *mut u32,
        face_index: i32,
        face_out: *mut u32,
    ) -> u32 {
        record(FallbackEvent::Probe {
            library: library as usize,
            stream: stream as usize,
            face_index,
            face_out: face_out as usize,
        });
        PROBE_RESULT
    }

    unsafe extern "C" fn recording_dfont(
        library: *mut u32,
        stream: *mut u32,
        offset: u32,
        face_index: i32,
        face_out: *mut u32,
    ) -> u32 {
        record(FallbackEvent::Dfont {
            library: library as usize,
            stream: stream as usize,
            offset,
            face_index,
            face_out: face_out as usize,
        });
        DFONT_RESULT
    }

    unsafe extern "C" fn recording_rules(
        library: *mut u32,
        stream: *mut u32,
        face_index: i32,
        face_out: *mut u32,
        open_args: *const u32,
    ) -> u32 {
        record(FallbackEvent::Rules {
            library: library as usize,
            stream: stream as usize,
            face_index,
            face_out: face_out as usize,
            open_args: open_args as usize,
        });
        RULES_RESULT
    }

    unsafe extern "C" fn recording_trace_sink(
        format: *const u8,
        arg1: u32,
        _arg2: u32,
        _arg3: u32,
    ) {
        let mut bytes = [0u8; 24];
        for (index, slot) in bytes.iter_mut().enumerate() {
            let byte = format.add(index).read();
            *slot = byte;
            if byte == 0 {
                break;
            }
        }
        record(FallbackEvent::Trace { format: bytes, arg1 });
    }

    /// Installs the recording seams with scripted results, seeds the host
    /// trace level, and optionally hooks the trace sink. Returns the
    /// guards serializing the swaps (dfont lock first, then the trace
    /// lock, always in that order).
    fn install_recording_fallback(
        probe: u32,
        dfont: u32,
        rules: u32,
        level: i32,
        trace: bool,
    ) -> (StdMutexGuard<'static, ()>, Option<StdMutexGuard<'static, ()>>) {
        let guard = DFONT_FALLBACK_TEST_LOCK.lock().unwrap();
        let trace_guard = if trace {
            let trace_guard = crate::ft::trace::TEST_TRACE_LOCK.lock().unwrap();
            unsafe { crate::ft::trace::ft_set_trace_sink(Some(recording_trace_sink)) };
            Some(trace_guard)
        } else {
            None
        };
        unsafe {
            PROBE_RESULT = probe;
            DFONT_RESULT = dfont;
            RULES_RESULT = rules;
            FALLBACK_EVENT_COUNT = 0;
            core::ptr::addr_of_mut!(HOST_TRACE_LEVELS)
                .cast::<i32>()
                .add(0x34 / 4)
                .write_volatile(level);
            DFONT_FALLBACK_OPS = DfontFallbackOps {
                probe_resource_fork: recording_probe,
                open_dfont: recording_dfont,
                run_fallback_rules: recording_rules,
            };
        }
        (guard, trace_guard)
    }

    fn uninstall_recording_fallback(trace: bool) {
        unsafe {
            DFONT_FALLBACK_OPS = DfontFallbackOps {
                probe_resource_fork: missing_resource_fork_probe,
                open_dfont: missing_dfont_open,
                run_fallback_rules: missing_fallback_rule_chain,
            };
            if trace {
                crate::ft::trace::ft_set_trace_sink(None);
            }
        }
    }

    fn invoke_fallback(flags: u32) -> (u32, usize, [FallbackEvent; 8]) {
        let open_args = [flags, 0, 0, PATHNAME.as_ptr() as u32];
        let result = unsafe {
            ft_open_face_dfont_fallback(
                LIBRARY as *mut u32,
                STREAM as *mut u32,
                FACE_INDEX,
                FACE_OUT as *mut u32,
                open_args.as_ptr(),
            )
        };
        unsafe { (result, FALLBACK_EVENT_COUNT, FALLBACK_EVENTS) }
    }

    fn probe_event() -> FallbackEvent {
        FallbackEvent::Probe {
            library: LIBRARY,
            stream: STREAM,
            face_index: FACE_INDEX,
            face_out: FACE_OUT,
        }
    }

    fn dfont_event() -> FallbackEvent {
        FallbackEvent::Dfont {
            library: LIBRARY,
            stream: STREAM,
            offset: 0,
            face_index: FACE_INDEX,
            face_out: FACE_OUT,
        }
    }

    fn rules_event(open_args: usize) -> FallbackEvent {
        FallbackEvent::Rules {
            library: LIBRARY,
            stream: STREAM,
            face_index: FACE_INDEX,
            face_out: FACE_OUT,
            open_args,
        }
    }

    fn format_bytes(nul_terminated: &[u8]) -> [u8; 24] {
        let mut bytes = [0u8; 24];
        bytes[..nul_terminated.len()].copy_from_slice(nul_terminated);
        bytes
    }

    #[test]
    fn probe_success_returns_zero_and_stops() {
        // Flags set and trace level high: neither matters once the probe
        // succeeds.
        let _guards = install_recording_fallback(0, 0xdead, 0xbeef, 3, true);
        let (result, count, events) = invoke_fallback(OPEN_ARGS_FALLBACK_RULES);
        assert_eq!(result, 0);
        assert_eq!(count, 1);
        assert_eq!(events[0], probe_event());
        uninstall_recording_fallback(true);
    }

    #[test]
    fn unrelated_error_class_returned_unchanged() {
        for status in [6u32, 0x1234_5678, 0xaaaa_aa34, 0xffff_ff01] {
            let _guards = install_recording_fallback(status, 0, 0, 3, true);
            let (result, count, events) = invoke_fallback(OPEN_ARGS_FALLBACK_RULES);
            assert_eq!(result, status, "status={status:#010x}");
            assert_eq!(count, 1, "status={status:#010x}");
            assert_eq!(events[0], probe_event(), "status={status:#010x}");
            uninstall_recording_fallback(true);
        }
    }

    #[test]
    fn unknown_format_retries_as_dfont_with_zero_offset() {
        let _guards = install_recording_fallback(2, 0, 0xbeef, 0, false);
        let (result, count, events) = invoke_fallback(OPEN_ARGS_FALLBACK_RULES);
        assert_eq!(result, 0);
        // The dfont retry's third argument is always 0 (mov r2, #0 @
        // 0x080853f8), and a successful retry never reaches the rule
        // chain even with the rules flag set.
        assert_eq!(count, 2);
        assert_eq!(events[0], probe_event());
        assert_eq!(events[1], dfont_event());
        uninstall_recording_fallback(false);
    }

    #[test]
    fn dfont_failure_with_rules_flag_runs_chain() {
        for rules_result in [0u32, 7, 0x55, 0xdead_beef] {
            let _guards = install_recording_fallback(2, 2, rules_result, 0, false);
            let (result, count, events) = invoke_fallback(OPEN_ARGS_FALLBACK_RULES);
            assert_eq!(result, rules_result, "rules_result={rules_result:#010x}");
            assert_eq!(count, 3, "rules_result={rules_result:#010x}");
            assert_eq!(events[0], probe_event());
            assert_eq!(events[1], dfont_event());
            match events[2] {
                FallbackEvent::Rules { library, stream, face_index, face_out, .. } => {
                    assert_eq!(
                        (library, stream, face_index, face_out),
                        (LIBRARY, STREAM, FACE_INDEX, FACE_OUT),
                        "rules_result={rules_result:#010x}"
                    );
                }
                other => panic!("expected rule-chain call, got {other:?}"),
            }
            uninstall_recording_fallback(false);
        }
    }

    #[test]
    fn dfont_failure_without_rules_flag_returns_status() {
        for flags in [0u32, 0x3, 0x8, 0xffff_fffb] {
            let _guards = install_recording_fallback(2, 2, 0, 0, false);
            let (result, count, events) = invoke_fallback(flags);
            assert_eq!(result, 2, "flags={flags:#010x}");
            assert_eq!(count, 2, "flags={flags:#010x}");
            assert_eq!(events[0], probe_event(), "flags={flags:#010x}");
            assert_eq!(events[1], dfont_event(), "flags={flags:#010x}");
            uninstall_recording_fallback(false);
        }
    }

    #[test]
    fn rule_class_skips_dfont_and_runs_chain() {
        let _guards = install_recording_fallback(0x55, 0xdead, 9, 0, false);
        let (result, count, events) = invoke_fallback(OPEN_ARGS_FALLBACK_RULES);
        assert_eq!(result, 9);
        assert_eq!(count, 2);
        assert_eq!(events[0], probe_event());
        assert!(matches!(events[1], FallbackEvent::Rules { .. }));
        uninstall_recording_fallback(false);
        drop(_guards);

        let _guards = install_recording_fallback(0x55, 0xdead, 9, 0, false);
        let (result, count, events) = invoke_fallback(0);
        assert_eq!(result, 0x55, "no rules flag: status returned unchanged");
        assert_eq!(count, 1);
        assert_eq!(events[0], probe_event());
        uninstall_recording_fallback(false);
    }

    #[test]
    fn status_class_ignores_high_bits() {
        // 0x...02 behaves exactly like class 2: dfont retry happens.
        let _guards = install_recording_fallback(0xffff_ff02, 0, 0, 0, false);
        let (result, count, events) = invoke_fallback(0);
        assert_eq!(result, 0);
        assert_eq!(count, 2);
        assert_eq!(events[1], dfont_event());
        uninstall_recording_fallback(false);
        drop(_guards);

        // 0x...55 behaves exactly like class 0x55: straight to the chain.
        let _guards = install_recording_fallback(0xffff_ff55, 0xdead, 3, 0, false);
        let (result, count, events) = invoke_fallback(OPEN_ARGS_FALLBACK_RULES);
        assert_eq!(result, 3);
        assert_eq!(count, 2);
        assert!(matches!(events[1], FallbackEvent::Rules { .. }));
        uninstall_recording_fallback(false);
    }

    #[test]
    fn rule_chain_receives_original_open_args_pointer() {
        let _guards = install_recording_fallback(2, 2, 0, 0, false);
        let open_args = [OPEN_ARGS_FALLBACK_RULES, 0, 0, PATHNAME.as_ptr() as u32];
        let result = unsafe {
            ft_open_face_dfont_fallback(
                LIBRARY as *mut u32,
                STREAM as *mut u32,
                FACE_INDEX,
                FACE_OUT as *mut u32,
                open_args.as_ptr(),
            )
        };
        assert_eq!(result, 0);
        unsafe {
            assert_eq!(FALLBACK_EVENT_COUNT, 3);
            assert_eq!(FALLBACK_EVENTS[2], rules_event(open_args.as_ptr() as usize));
        }
        uninstall_recording_fallback(false);
    }

    #[test]
    fn dfont_retry_traces_attempt_and_outcome_above_level_two() {
        // Successful retry: "successful".
        let _guards = install_recording_fallback(2, 0, 0, 3, true);
        let (result, count, events) = invoke_fallback(0);
        assert_eq!(result, 0);
        assert_eq!(count, 4);
        assert_eq!(events[0], probe_event());
        assert_eq!(
            events[1],
            FallbackEvent::Trace {
                format: format_bytes(b"Try as dfont: %s ...\0"),
                arg1: PATHNAME.as_ptr() as u32,
            }
        );
        assert_eq!(events[2], dfont_event());
        assert_eq!(
            events[3],
            FallbackEvent::Trace {
                format: format_bytes(b"%s\n\0"),
                arg1: OUTCOME_SUCCESSFUL.as_ptr() as u32,
            }
        );
        uninstall_recording_fallback(true);
        drop(_guards);

        // Failed retry: "failed".
        let _guards = install_recording_fallback(2, 9, 0, 3, true);
        let (result, count, events) = invoke_fallback(0);
        assert_eq!(result, 9);
        assert_eq!(count, 4);
        assert_eq!(
            events[3],
            FallbackEvent::Trace {
                format: format_bytes(b"%s\n\0"),
                arg1: OUTCOME_FAILED.as_ptr() as u32,
            }
        );
        uninstall_recording_fallback(true);
    }

    #[test]
    fn dfont_retry_is_silent_at_or_below_level_two() {
        for level in [i32::MIN, -1, 0, 2] {
            let _guards = install_recording_fallback(2, 0, 0, level, true);
            let (result, count, events) = invoke_fallback(0);
            assert_eq!(result, 0, "level={level}");
            assert_eq!(count, 2, "level={level}");
            assert_eq!(events[0], probe_event(), "level={level}");
            assert_eq!(events[1], dfont_event(), "level={level}");
            uninstall_recording_fallback(true);
        }
    }

    // --- pfr_face_done ---

    /// Serializes the tests that swap the phy-font-teardown seam and
    /// the recording allocator below.
    static PFR_FACE_DONE_TEST_LOCK: StdMutex<()> = StdMutex::new(());

    /// Word count of the mock face: the highest touched field is
    /// `phy_font` at word 0x48, whose address is only passed on.
    const FACE_WORDS: usize = FACE_PHY_FONT_WORD + 1;

    static mut SEAM_PHYS: *mut *mut u8 = core::ptr::null_mut();
    static mut SEAM_MEMORY: *mut crate::ft::memory::FtMemory = core::ptr::null_mut();
    static mut SEAM_CALLS: usize = 0;
    /// Allocator free-call count observed when the seam ran: pins the
    /// phy-font teardown ahead of the `available_sizes` free.
    static mut SEAM_FREE_COUNT_AT_CALL: usize = 0;
    static mut FREE_CALLS: usize = 0;
    static mut FREE_MEMORY_ARG: *mut crate::ft::memory::FtMemory = core::ptr::null_mut();
    static mut FREE_BLOCK_ARG: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_phy_font_done(
        phys: *mut *mut u8,
        memory: *mut crate::ft::memory::FtMemory,
    ) {
        SEAM_PHYS = phys;
        SEAM_MEMORY = memory;
        SEAM_FREE_COUNT_AT_CALL = FREE_CALLS;
        SEAM_CALLS += 1;
    }

    unsafe extern "C" fn recording_free(
        memory: *mut crate::ft::memory::FtMemory,
        block: *mut u8,
    ) {
        FREE_MEMORY_ARG = memory;
        FREE_BLOCK_ARG = block;
        FREE_CALLS += 1;
    }

    unsafe extern "C" fn unused_alloc(
        _memory: *mut crate::ft::memory::FtMemory,
        _size: i32,
    ) -> *mut u8 {
        panic!("pfr_face_done never allocates")
    }

    unsafe extern "C" fn unused_realloc(
        _memory: *mut crate::ft::memory::FtMemory,
        _cur: i32,
        _new: i32,
        _block: *mut u8,
    ) -> *mut u8 {
        panic!("pfr_face_done never reallocates")
    }

    fn recording_memory() -> crate::ft::memory::FtMemory {
        crate::ft::memory::FtMemory {
            user: core::ptr::null_mut(),
            alloc: unused_alloc,
            free: recording_free,
            realloc: unused_realloc,
        }
    }

    /// A face/driver/memory triplet. [`MockFace::wire`] fills the
    /// cross-pointers once the struct sits at its final address —
    /// they point into the struct itself, so wiring before the move
    /// would leave them dangling.
    struct MockFace {
        words: [*mut u8; FACE_WORDS],
        driver_words: [*mut crate::ft::memory::FtMemory; 3],
        driver_memory: crate::ft::memory::FtMemory,
        face_memory: crate::ft::memory::FtMemory,
        block: u8,
    }

    fn mock_face() -> MockFace {
        MockFace {
            words: [core::ptr::null_mut(); FACE_WORDS],
            driver_words: [core::ptr::null_mut(); 3],
            driver_memory: recording_memory(),
            face_memory: recording_memory(),
            block: 0xa5,
        }
    }

    impl MockFace {
        /// Wires the retail PFR face layout: face word 0x18 -> driver,
        /// driver word 2 -> `driver_memory`, face word 0x19 ->
        /// `face_memory`, face word 8 -> `block`.
        fn wire(&mut self) {
            self.driver_words[MODULE_MEMORY_WORD] =
                core::ptr::addr_of_mut!(self.driver_memory);
            self.words[FACE_DRIVER_WORD] = self.driver_words.as_mut_ptr().cast::<u8>();
            self.words[FACE_MEMORY_WORD] =
                (core::ptr::addr_of_mut!(self.face_memory)).cast::<u8>();
            self.words[FACE_AVAILABLE_SIZES_WORD] = core::ptr::addr_of_mut!(self.block);
        }
    }

    /// Installs the recording seam and zeroes the recorders; returns
    /// the guard serializing the swap.
    fn install_recording_teardown() -> StdMutexGuard<'static, ()> {
        let guard = PFR_FACE_DONE_TEST_LOCK.lock().unwrap();
        unsafe {
            SEAM_PHYS = core::ptr::null_mut();
            SEAM_MEMORY = core::ptr::null_mut();
            SEAM_CALLS = 0;
            SEAM_FREE_COUNT_AT_CALL = usize::MAX;
            FREE_CALLS = 0;
            FREE_MEMORY_ARG = core::ptr::null_mut();
            FREE_BLOCK_ARG = core::ptr::null_mut();
            PFR_PHY_FONT_DONE = recording_phy_font_done;
        }
        guard
    }

    fn uninstall_recording_teardown() {
        unsafe { PFR_PHY_FONT_DONE = missing_pfr_phy_font_done };
    }

    #[test]
    fn nulls_family_style_and_available_sizes_words() {
        let _guard = install_recording_teardown();
        let mut mock = mock_face();
        mock.wire();
        mock.words[FACE_FAMILY_NAME_WORD] = 0x1111_1111usize as *mut u8;
        mock.words[FACE_STYLE_NAME_WORD] = 0x2222_2222usize as *mut u8;
        let available = mock.words[FACE_AVAILABLE_SIZES_WORD];
        unsafe { pfr_face_done(mock.words.as_mut_ptr()) };
        assert!(mock.words[FACE_FAMILY_NAME_WORD].is_null());
        assert!(mock.words[FACE_STYLE_NAME_WORD].is_null());
        assert!(
            mock.words[FACE_AVAILABLE_SIZES_WORD].is_null(),
            "FT_FREE nulls the pointer after freeing"
        );
        assert_eq!(unsafe { FREE_BLOCK_ARG }, available);
        uninstall_recording_teardown();
    }

    #[test]
    fn tears_down_phy_font_with_face_memory() {
        let _guard = install_recording_teardown();
        let mut mock = mock_face();
        mock.wire();
        let face_ptr = mock.words.as_mut_ptr();
        let face_memory = core::ptr::addr_of_mut!(mock.face_memory);
        unsafe { pfr_face_done(face_ptr) };
        assert_eq!(unsafe { SEAM_CALLS }, 1);
        assert_eq!(
            unsafe { SEAM_PHYS },
            unsafe { face_ptr.add(FACE_PHY_FONT_WORD) },
            "the embedded physical-font record is at word 0x48 (+0x120)"
        );
        assert_eq!(
            unsafe { SEAM_MEMORY },
            face_memory,
            "the teardown runs under FT_FACE_MEMORY (face +0x64)"
        );
        uninstall_recording_teardown();
    }

    #[test]
    fn frees_available_sizes_through_driver_root_memory() {
        let _guard = install_recording_teardown();
        let mut mock = mock_face();
        mock.wire();
        let driver_memory = core::ptr::addr_of_mut!(mock.driver_memory);
        let face_memory = core::ptr::addr_of_mut!(mock.face_memory);
        let block = mock.words[FACE_AVAILABLE_SIZES_WORD];
        unsafe { pfr_face_done(mock.words.as_mut_ptr()) };
        assert_eq!(unsafe { FREE_CALLS }, 1);
        assert_eq!(
            unsafe { FREE_MEMORY_ARG },
            driver_memory,
            "FT_FREE uses driver->root.memory, not the face memory"
        );
        assert_ne!(unsafe { FREE_MEMORY_ARG }, face_memory);
        assert_eq!(unsafe { FREE_BLOCK_ARG }, block);
        uninstall_recording_teardown();
    }

    #[test]
    fn phy_font_teardown_precedes_available_sizes_free() {
        let _guard = install_recording_teardown();
        let mut mock = mock_face();
        mock.wire();
        unsafe { pfr_face_done(mock.words.as_mut_ptr()) };
        assert_eq!(unsafe { SEAM_CALLS }, 1);
        assert_eq!(
            unsafe { SEAM_FREE_COUNT_AT_CALL },
            0,
            "the free has not run yet when pfr_phy_font_done is called"
        );
        assert_eq!(unsafe { FREE_CALLS }, 1);
        uninstall_recording_teardown();
    }

    #[test]
    fn null_available_sizes_reaches_no_allocator() {
        let _guard = install_recording_teardown();
        let mut mock = mock_face();
        mock.wire();
        mock.words[FACE_AVAILABLE_SIZES_WORD] = core::ptr::null_mut();
        unsafe { pfr_face_done(mock.words.as_mut_ptr()) };
        assert_eq!(
            unsafe { FREE_CALLS },
            0,
            "ft_mem_free short-circuits a null block"
        );
        assert_eq!(unsafe { SEAM_CALLS }, 1, "the phy teardown still runs");
        assert!(mock.words[FACE_FAMILY_NAME_WORD].is_null());
        assert!(mock.words[FACE_STYLE_NAME_WORD].is_null());
        uninstall_recording_teardown();
    }
}
