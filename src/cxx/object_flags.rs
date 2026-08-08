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

/// Bitstream read-and-advance `FUN_080ebbe0` (unported): 28 bytes of
/// `stmdb sp!,{r4,r5,lr}; bl 0x080efa38; ldr r1,[r4,#0x4];
/// add r1,r1,r5; str r1,[r4,#0x4]; ldmia sp!,{r4,r5,pc}` — returns
/// the `bit_count` bits FUN_080efa38 fetches MSB-first from the
/// +0x00 buffer at the +0x04 bit position, then advances +0x04 by
/// `bit_count`. 64 `bl 0x080ebbe0` sites, all in the video header
/// parser cluster 0x0807d7xx..0x080f1xxx.
pub type BitstreamReadAdvance =
    unsafe extern "C" fn(stream: *mut u8, bit_count: u32) -> u32;

/// Spins forever: [`bitstream_stuffing_to_byte_check`] must not run
/// before target integration installs the retailOS `FUN_080ebbe0`.
unsafe extern "C" fn missing_bitstream_read_advance(
    _stream: *mut u8,
    _bit_count: u32,
) -> u32 {
    loop {
        core::hint::spin_loop();
    }
}

/// RetailOS dependency of [`bitstream_stuffing_to_byte_check`]. Target
/// integration must install the real `FUN_080ebbe0`; focused host
/// tests replace it with a recording seam.
pub static mut BITSTREAM_READ_ADVANCE: BitstreamReadAdvance =
    missing_bitstream_read_advance;

#[inline(always)]
unsafe fn bitstream_read_advance() -> BitstreamReadAdvance {
    core::ptr::read_volatile(core::ptr::addr_of!(BITSTREAM_READ_ADVANCE))
}

/// bitstream_stuffing_to_byte_check — original: `FUN_0808554c` @
/// `0x0808554c` (80 bytes; source:
/// `ipod-decomp/decomp/c/005/0808554c_FUN_0808554c.c`).
///
/// Validates and consumes one byte-alignment stuffing sequence of the
/// {data-pointer @ +0x00, bit-position @ +0x04} stream object whose
/// initializer is [`object_value_set_flags_clear`] @ 0x08085344
/// ({value, 0} into +0x00/+0x04) and whose predicate
/// [`object_low_flags_clear`] @ 0x0808539c reports "+0x04 low three
/// bits clear" — the bit position sitting on a byte boundary. Reads
/// one bit, which must be 0, then keeps reading bits, each of which
/// must be 1, until the position is byte-aligned again; returns 0
/// once aligned and 1 the moment any bit breaks the pattern. Every
/// read goes through the read-and-advance `FUN_080ebbe0(stream, 1)`
/// (`mov r1, #0x1` @ 0x08085554 and @ 0x08085568), so each call
/// nudges the +0x04 position by one. The retail sequence is
/// `stmdb sp!,{r4,lr}; mov r4,r0; mov r1,#1; bl 0x080ebbe0;
/// cmp #0; bne-ret1; loop: mov r0,r4; bl 0x0808539c; cmp #0;
/// beq-read; mov r0,#0; pop; read: mov r1,#1; mov r0,r4;
/// bl 0x080ebbe0; cmp #1; bne-ret1; b-loop`.
///
/// Identification: the only 2 `bl 0x0808554c` sites (@ 0x080ed0e8
/// and @ 0x080f0cec, grep -c on decomp/osos.asm) sit in the video
/// header parser that matches 32-bit start codes 0x000001B5 /
/// 0x000001B3 (`sub r12,r0,#0x100; subs r12,r12,#0xb5/#0xb3` @
/// 0x080ecfcc/0x080f0d14), a 24-bit == 1 prefix with an 8-bit code
/// < 0x20 (@ 0x080ed104-0x080ed120), MPEG's video_signal_type field
/// pattern (1-bit flag gating 3-bit format, 1-bit range, and a
/// 1-bit colour-description flag gating three 8-bit tables @
/// 0x080ed074-0x080ed0e0), and FUN_0807d724's scan to the next
/// 0x000001xx start code (which both callers run only when this
/// function returns 0). The 0-bit-then-1-bits-to-the-byte-boundary
/// shape is the byte-alignment stuffing an MPEG-style stream writes
/// before a start code, and the return value gates the scan for
/// that start code. The parser's own name is unlocated, so the
/// name claims only the verified bitstream behavior.
///
/// Deviations: the unported read-and-advance rides the
/// [`BITSTREAM_READ_ADVANCE`] seam (house pattern — see
/// [`OBJECT_FLAGS_FETCH_INCREMENT_LOCK`]) instead of a direct `bl`;
/// the ported [`object_low_flags_clear`] takes the byte-alignment
/// test directly.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn bitstream_stuffing_to_byte_check(stream: *mut u8) -> u32 {
    if bitstream_read_advance()(stream, 1) != 0 {
        return 1;
    }
    loop {
        if object_low_flags_clear(stream) != 0 {
            return 0;
        }
        if bitstream_read_advance()(stream, 1) != 1 {
            return 1;
        }
    }
}

/// namespace_provider_count — original: `FUN_08369780` @ `0x08369780`
/// (16 bytes; source:
/// `ipod-decomp/decomp/c/033/08369780_FUN_08369780.c`).
///
/// Returns the signed entry-count word at +0x00 of a namespace-providers
/// object, or -1 when `providers` is NULL. This is the complete
/// `cmp/ldrne/mvneq/bx lr` leaf: the negative null sentinel makes the
/// signed `count > index` check in [`registry_key_hash`] fail for every
/// non-negative index. No deviations.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn namespace_provider_count(providers: *const u32) -> i32 {
    if providers.is_null() {
        -1
    } else {
        providers.read_volatile() as i32
    }
}

/// Namespace-provider table index `FUN_08369864` (unported): 20 bytes
/// of `cmp r0,#0x0; ldrne r0,[r0,#0x4]; ldrne r0,[r0,r1,lsl #0x2];
/// moveq r0,#0x0; bx lr` — the provider object at `table[index]` of
/// the providers object's +0x04 table, or null. Its `index` argument
/// arrives in r1 as the key's +0x00 word (loaded @ 0x080855bc).
pub type RegistryProviderAt =
    unsafe extern "C" fn(providers: *const u32, index: u32) -> *const u32;

/// The registry's default name hash `FUN_082d7e54` (unported): 88
/// bytes @ 0x082d7e54. Walks the NUL-terminated name with a per-byte
/// salt: for byte `b` at position `i` it forms `c = b | (0x100*(i+1))`,
/// rotates the accumulator left by `(c ^ (c >> 2)) & 0xf` (the retail
/// `rsb`+`ror` pair), XORs in `c*c`, and folds the result as
/// `h ^ (h >> 16)`; a null or empty name hashes to 0. Also the type
/// of a provider object's vtable slot +0x00 — the per-namespace
/// override [`registry_key_hash`] calls in its place (the `blx r1`
/// @ 0x080855d8).
pub type RegistryNameHash = unsafe extern "C" fn(name: *const u8) -> u32;

/// The unported callees of [`registry_key_hash`], grouped in the house
/// ops-struct pattern (app/node_list.rs's NODE_LIST_ENQUEUE_OPS).
pub struct RegistryKeyHashOps {
    pub provider_at: RegistryProviderAt,
    pub default_name_hash: RegistryNameHash,
}

/// Spins forever: [`registry_key_hash`] must not run before target
/// integration installs the retailOS provider-table accessor.
unsafe extern "C" fn missing_provider_at(
    _providers: *const u32,
    _index: u32,
) -> *const u32 {
    loop {
        core::hint::spin_loop();
    }
}

/// Spins forever: [`registry_key_hash`] must not run before target
/// integration installs the retailOS default name hash.
unsafe extern "C" fn missing_default_name_hash(_name: *const u8) -> u32 {
    loop {
        core::hint::spin_loop();
    }
}

/// RetailOS dependencies of [`registry_key_hash`]. Target integration
/// must install the real `FUN_08369864` / `FUN_082d7e54`; focused host
/// tests replace them with recording seams.
pub static mut REGISTRY_KEY_HASH_OPS: RegistryKeyHashOps = RegistryKeyHashOps {
    provider_at: missing_provider_at,
    default_name_hash: missing_default_name_hash,
};

#[inline(always)]
unsafe fn registry_key_hash_ops() -> RegistryKeyHashOps {
    core::ptr::read_volatile(core::ptr::addr_of!(REGISTRY_KEY_HASH_OPS))
}

/// Load address of the fixed retailOS string-registry singleton whose
/// +0x08 word [`registry_key_hash`] reads for the namespace-providers
/// array: the literal pool word @ 0x080855f4 holds 0x08a0ea6c. The
/// singleton's +0x00 word is the registry's hash map (lazily created
/// by FUN_0805e93c through FUN_082d7d08); its +0x08 providers array
/// is shared with the registry insert FUN_0805e7dc, which notifies
/// vtable slot +0x08 of the same entry [`registry_key_hash`] hashes
/// through.
#[cfg(target_os = "none")]
const REGISTRY_SINGLETON: *mut *const u32 = 0x08a0_ea6c as *mut *const u32;

/// Host stand-in for the firmware singleton: only the +0x08 word
/// (slot 2) is read; null means "no providers array".
#[cfg(not(target_os = "none"))]
static mut HOST_REGISTRY_SINGLETON: [*const u32; 3] = [core::ptr::null(); 3];

/// The aligned pointer word at +0x08 of the singleton. Read twice on
/// the provider path, exactly like the retail `ldr r0,[r5,#0x8]` @
/// 0x080855ac and its reload @ 0x080855c8.
#[inline(always)]
unsafe fn registry_providers_word() -> *mut *const u32 {
    #[cfg(target_os = "none")]
    {
        REGISTRY_SINGLETON.add(2)
    }
    #[cfg(not(target_os = "none"))]
    {
        core::ptr::addr_of_mut!(HOST_REGISTRY_SINGLETON).cast::<*const u32>().add(2)
    }
}

/// registry_key_hash — original: `FUN_080855a0` @ `0x080855a0` (84
/// bytes of code, 0x080855a0..0x080855f3, trailed by the 4-byte
/// singleton-address literal @ 0x080855f4 holding 0x08a0ea6c; source:
/// `ipod-decomp/decomp/c/005/080855a0_FUN_080855a0.c`).
///
/// The key hash of the retailOS string registry rooted at the fixed
/// singleton @ 0x08a0ea6c. A key is three words — namespace index
/// (+0x00), unused (+0x04), name string pointer (+0x08) — and the
/// hash combines the index with a hash of the name: when the
/// singleton's +0x08 providers array exists and its signed entry
/// count exceeds the key's index (`ble` @ 0x080855c4 falls back),
/// the provider object at `table[index]` supplies the name hash
/// through its vtable slot +0x00; otherwise the registry's default
/// name hash `FUN_082d7e54` computes it. The return is the key's
/// index word — reloaded after the hash call (`ldr r1,[r4,#0x0]` @
/// 0x080855e8) — XORed with the name hash. The retail sequence is
/// `stmdb sp!,{r4,r5,r6,lr}; ldr r5,=0x08a0ea6c; ldr r0,[r5,#0x8];
/// beq-fallback; bl 0x08369780; ldr r1,[r4,#0x0]; cmp; ble-fallback;
/// ldr r0,[r5,#0x8] (reload); bl 0x08369864; ldr r1,[r0,#0x0];
/// ldr r0,[r4,#0x8]; blx r1; fallback: ldr r0,[r4,#0x8];
/// bl 0x082d7e54; join: ldr r1,[r4,#0x0]; eor r0,r1,r0;
/// ldmia sp!,{r4,r5,r6,pc}`.
///
/// Identification: 0 `bl 0x080855a0` call sites and no data pointer
/// anywhere in osos.dec (binary-scanned) — like [`pfr_face_done`]
/// next door, the record referencing it does not survive the
/// decrypted image. The registry itself is pinned by the singleton's
/// other users (literal pools @ 0x0805e8a4 / 0x0805e938 / 0x0805e984
/// / 0x0807d174): FUN_0805e7dc inserts {index, flag, name, value}
/// nodes into the singleton's +0x00 hash map and then notifies the
/// same providers array's entry through vtable slot +0x08;
/// FUN_0805e8a8 looks nodes up by {index, name}, chasing +0x0c value
/// links up to ten deep while the 0x8000 flag bit is clear. The
/// subsystem's own name is unlocated, so "registry" names only this
/// observed insert/lookup/notify cluster.
///
/// Deviations: the two unported callees ride the
/// [`REGISTRY_KEY_HASH_OPS`] seam (house pattern — see
/// [`DFONT_FALLBACK_OPS`]) instead of direct `bl`s; host builds
/// substitute test storage for the firmware singleton @ 0x08a0ea6c;
/// and the key and singleton words are addressed by pointer-sized
/// word index (byte-exact +0x00/+0x08 on the 32-bit target, disjoint
/// slots on a 64-bit host — the same model as [`pfr_face_done`]'s
/// face words).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn registry_key_hash(key: *const usize) -> u32 {
    let ops = registry_key_hash_ops();
    let providers = registry_providers_word().read_volatile();
    let name_hash = if providers.is_null() {
        (ops.default_name_hash)(key.add(2).read_volatile() as *const u8)
    } else {
        let count = namespace_provider_count(providers);
        let index = key.read_volatile();
        if count > index as i32 {
            let providers = registry_providers_word().read_volatile();
            let provider = (ops.provider_at)(providers, index as u32);
            let hash_name = provider.cast::<RegistryNameHash>().read_volatile();
            hash_name(key.add(2).read_volatile() as *const u8)
        } else {
            (ops.default_name_hash)(key.add(2).read_volatile() as *const u8)
        }
    };
    key.read_volatile() as u32 ^ name_hash
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

    // --- registry_key_hash ---

    /// Serializes the tests that swap the registry ops seam, the host
    /// singleton's providers word, and the scripted callee results.
    static REGISTRY_KEY_HASH_TEST_LOCK: StdMutex<()> = StdMutex::new(());

    /// One recorded seam or provider-vtable invocation, in call order.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum RegistryEvent {
        ProviderAt { providers: usize, index: u32 },
        DefaultHash { name: usize },
        VtableHash { name: usize },
    }

    static mut REGISTRY_EVENTS: [Option<RegistryEvent>; 8] = [None; 8];
    static mut REGISTRY_EVENT_COUNT: usize = 0;
    static mut PROVIDER_AT_RESULT: *const u32 = core::ptr::null();
    static mut DEFAULT_HASH_RESULT: u32 = 0;
    static mut VTABLE_HASH_RESULT: u32 = 0;
    /// When non-null, the recording default hash rewrites the key's
    /// index word through this alias before returning — pins the
    /// `ldr r1,[r4,#0x0]` reload @ 0x080855e8.
    static mut KEY_INDEX_ALIAS: *mut usize = core::ptr::null_mut();
    static mut KEY_INDEX_REWRITE: usize = 0;

    /// Vtable slot +0x00 of the mock provider object.
    static mut PROVIDER_VTABLE_SLOT: RegistryNameHash = recording_vtable_hash;


    fn record_registry_event(event: RegistryEvent) {
        unsafe {
            let count = REGISTRY_EVENT_COUNT;
            assert!(count < 8, "registry seam called more than 8 times");
            REGISTRY_EVENTS[count] = Some(event);
            REGISTRY_EVENT_COUNT = count + 1;
        }
    }


    unsafe extern "C" fn recording_provider_at(
        providers: *const u32,
        index: u32,
    ) -> *const u32 {
        record_registry_event(RegistryEvent::ProviderAt {
            providers: providers as usize,
            index,
        });
        PROVIDER_AT_RESULT
    }

    unsafe extern "C" fn recording_default_hash(name: *const u8) -> u32 {
        record_registry_event(RegistryEvent::DefaultHash { name: name as usize });
        let alias = KEY_INDEX_ALIAS;
        if !alias.is_null() {
            alias.write_volatile(KEY_INDEX_REWRITE);
        }
        DEFAULT_HASH_RESULT
    }

    unsafe extern "C" fn recording_vtable_hash(name: *const u8) -> u32 {
        record_registry_event(RegistryEvent::VtableHash { name: name as usize });
        VTABLE_HASH_RESULT
    }

    fn registry_events() -> (usize, [Option<RegistryEvent>; 8]) {
        unsafe { (REGISTRY_EVENT_COUNT, REGISTRY_EVENTS) }
    }

    /// Installs the recording sibling seams, points the host singleton's
    /// providers word at `providers`, zeroes the recorders, and returns
    /// the guard serializing the swap.
    fn install_registry_seam(providers: *const u32) -> StdMutexGuard<'static, ()> {
        let guard = REGISTRY_KEY_HASH_TEST_LOCK.lock().unwrap();
        unsafe {
            REGISTRY_EVENT_COUNT = 0;
            PROVIDER_AT_RESULT = core::ptr::null();
            DEFAULT_HASH_RESULT = 0;
            VTABLE_HASH_RESULT = 0;
            KEY_INDEX_ALIAS = core::ptr::null_mut();
            registry_providers_word().write_volatile(providers);
            REGISTRY_KEY_HASH_OPS = RegistryKeyHashOps {
                provider_at: recording_provider_at,
                default_name_hash: recording_default_hash,
            };
        }
        guard
    }

    fn uninstall_registry_seam() {
        unsafe {
            registry_providers_word().write_volatile(core::ptr::null());
            REGISTRY_KEY_HASH_OPS = RegistryKeyHashOps {
                provider_at: missing_provider_at,
                default_name_hash: missing_default_name_hash,
            };
        }
    }

    /// A three-word registry key: index, unused, name pointer.
    fn mock_key(index: usize, name: &[u8]) -> [usize; 3] {
        [index, 0, name.as_ptr() as usize]
    }

    #[repr(C)]
    struct NamespaceProviders {
        entry_count: u32,
        table_word: u32,
    }

    #[test]
    fn namespace_provider_count_returns_minus_one_for_null() {
        assert_eq!(unsafe { namespace_provider_count(core::ptr::null()) }, -1);
    }

    #[test]
    fn namespace_provider_count_reads_the_signed_entry_count_word() {
        let empty = NamespaceProviders {
            entry_count: 0,
            table_word: 0xdead_beef,
        };
        let populated = NamespaceProviders {
            entry_count: 7,
            table_word: 0,
        };
        let negative = NamespaceProviders {
            entry_count: u32::MAX,
            table_word: 0xfeed_face,
        };

        assert_eq!(unsafe { namespace_provider_count(&empty.entry_count) }, 0);
        assert_eq!(unsafe { namespace_provider_count(&populated.entry_count) }, 7);
        assert_eq!(unsafe { namespace_provider_count(&negative.entry_count) }, -1);
    }

    #[test]
    fn null_providers_uses_default_name_hash() {
        let _guard = install_registry_seam(core::ptr::null());
        unsafe { DEFAULT_HASH_RESULT = 0xabcd_1234 };
        let name = b"settings\0";
        let key = mock_key(7, name);
        let result = unsafe { registry_key_hash(key.as_ptr()) };
        assert_eq!(result, 7 ^ 0xabcd_1234, "index XOR default name hash");
        let (count, events) = registry_events();
        assert_eq!(count, 1, "no provider machinery runs for a null array");
        assert_eq!(
            events[0],
            Some(RegistryEvent::DefaultHash { name: name.as_ptr() as usize }),
            "the default hash receives the key's +0x08 name pointer"
        );
        uninstall_registry_seam();
    }

    #[test]
    fn count_not_above_index_uses_default_name_hash() {
        for (provider_count, index) in [(-1i32, 0usize), (0, 0), (1, 1), (2, 7)] {
            let providers_word = provider_count as u32;
            let providers = core::ptr::addr_of!(providers_word);
            let _guard = install_registry_seam(providers);
            unsafe {
                DEFAULT_HASH_RESULT = 0x0101_0101;
            }
            let name = b"boot\0";
            let key = mock_key(index, name);
            let result = unsafe { registry_key_hash(key.as_ptr()) };
            assert_eq!(
                result,
                index as u32 ^ 0x0101_0101,
                "count={provider_count} index={index:#x}: the signed ble gate fell back"
            );
            let (count, events) = registry_events();
            assert_eq!(count, 1, "count={provider_count} index={index:#x}");
            assert_eq!(
                events[0],
                Some(RegistryEvent::DefaultHash { name: name.as_ptr() as usize }),
                "provider_at is never reached when count <= index"
            );
            uninstall_registry_seam();
        }
    }

    #[test]
    fn count_above_index_uses_provider_vtable_slot_zero() {
        for index in [0usize, 1, 7] {
            let provider_count = index as u32 + 1;
            let providers = core::ptr::addr_of!(provider_count);
            let _guard = install_registry_seam(providers);
            let vtable_hash = 0x5555_0000 | index as u32;
            unsafe {
                PROVIDER_AT_RESULT = core::ptr::addr_of!(PROVIDER_VTABLE_SLOT).cast::<u32>();
                VTABLE_HASH_RESULT = vtable_hash;
            }
            let name = b"diag\0";
            let key = mock_key(index, name);
            let result = unsafe { registry_key_hash(key.as_ptr()) };
            assert_eq!(result, index as u32 ^ vtable_hash, "index={index:#x}");
            let (count, events) = registry_events();
            assert_eq!(count, 2, "index={index:#x}");
            assert_eq!(
                events[0],
                Some(RegistryEvent::ProviderAt {
                    providers: providers as usize,
                    index: index as u32,
                })
            );
            assert_eq!(
                events[1],
                Some(RegistryEvent::VtableHash { name: name.as_ptr() as usize }),
                "vtable slot +0x00 of the indexed provider hashes the name"
            );
            uninstall_registry_seam();
        }
    }

    #[test]
    fn signed_gate_treats_high_bit_index_as_negative() {
        let provider_count = 1u32;
        let providers = core::ptr::addr_of!(provider_count);
        let _guard = install_registry_seam(providers);
        unsafe {
            PROVIDER_AT_RESULT = core::ptr::addr_of!(PROVIDER_VTABLE_SLOT).cast::<u32>();
            VTABLE_HASH_RESULT = 0x1234_5678;
        }
        let name = b"x\0";
        let key = mock_key(0x8000_0000, name);
        let result = unsafe { registry_key_hash(key.as_ptr()) };
        assert_eq!(result, 0x8000_0000 ^ 0x1234_5678);
        let (count, events) = registry_events();
        assert_eq!(count, 2, "a negative-as-i32 index passes the signed ble gate");
        assert_eq!(
            events[0],
            Some(RegistryEvent::ProviderAt {
                providers: providers as usize,
                index: 0x8000_0000,
            }),
            "the unsigned table index is the raw key word"
        );
        uninstall_registry_seam();
    }


    #[test]
    fn final_xor_reloads_the_index_word() {
        let _guard = install_registry_seam(core::ptr::null());
        let name = b"k\0";
        let mut key = mock_key(4, name);
        unsafe {
            DEFAULT_HASH_RESULT = 0xffff_00ff;
            KEY_INDEX_ALIAS = key.as_mut_ptr();
            KEY_INDEX_REWRITE = 9;
        }
        let result = unsafe { registry_key_hash(key.as_ptr()) };
        assert_eq!(
            result,
            9 ^ 0xffff_00ff,
            "the ldr r1,[r4,#0x0] @ 0x080855e8 reloads the index after the hash call"
        );
        uninstall_registry_seam();
    }

    // --- bitstream_stuffing_to_byte_check ---

    /// Serializes the tests that swap the bitstream read-advance seam
    /// and the scripted stream data.
    static STUFFING_TEST_LOCK: StdMutex<()> = StdMutex::new(());

    /// The stream object's +0x00 word is a data pointer only to the
    /// (unported) retail read-advance; the host seam below reads the
    /// scripted bits from this global instead, so test objects only
    /// need their +0x04 position word — the word
    /// [`object_low_flags_clear`] tests.
    static mut STUFFING_DATA: [u8; 8] = [0; 8];

    /// One recorded read-advance call: the stream pointer and the
    /// requested bit count.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct StuffingRead {
        stream: usize,
        bit_count: u32,
    }

    const NO_READ: StuffingRead = StuffingRead { stream: 0, bit_count: 0 };

    static mut STUFFING_READS: [StuffingRead; 16] = [NO_READ; 16];
    static mut STUFFING_READ_COUNT: usize = 0;

    /// A faithful host stand-in for `FUN_080ebbe0`: fetches
    /// `bit_count` bits MSB-first at the stream's +0x04 bit position
    /// (the FUN_080efa38 fetch — bit `i` is bit `7 - (i & 7)` of byte
    /// `i >> 3`), then advances +0x04 by `bit_count` — the retail
    /// `ldr r1,[r4,#0x4]; add; str` — and records the call.
    unsafe extern "C" fn real_bitstream_read_advance(stream: *mut u8, bit_count: u32) -> u32 {
        let position = stream.add(4).cast::<u32>();
        let mut bit_position = position.read_volatile();
        let mut value = 0u32;
        for _ in 0..bit_count {
            let byte = STUFFING_DATA[(bit_position >> 3) as usize];
            value = (value << 1) | u32::from(byte >> (7 - (bit_position & 7)) & 1);
            bit_position += 1;
        }
        position.write_volatile(bit_position);
        let count = STUFFING_READ_COUNT;
        assert!(count < 16, "read-advance seam called more than 16 times");
        STUFFING_READS[count] = StuffingRead { stream: stream as usize, bit_count };
        STUFFING_READ_COUNT = count + 1;
        value
    }

    /// An aligned stand-in for the stream object: +0x00 unused by the
    /// host seam, +0x04 the bit position.
    #[repr(C, align(4))]
    struct StuffingStream {
        words: [u32; 2],
    }

    /// Installs the real read-advance seam and seeds the scripted
    /// bits, returning the guard serializing the swap.
    fn install_bitstream_seam(data: [u8; 8]) -> StdMutexGuard<'static, ()> {
        let guard = STUFFING_TEST_LOCK.lock().unwrap();
        unsafe {
            STUFFING_DATA = data;
            STUFFING_READ_COUNT = 0;
            BITSTREAM_READ_ADVANCE = real_bitstream_read_advance;
        }
        guard
    }

    fn uninstall_bitstream_seam() {
        unsafe { BITSTREAM_READ_ADVANCE = missing_bitstream_read_advance };
    }

    fn stuffing_reads() -> (usize, [StuffingRead; 16]) {
        unsafe { (STUFFING_READ_COUNT, STUFFING_READS) }
    }

    /// Runs the ported function on a stream whose +0x04 word starts
    /// at `start_position`, returning (result, final position).
    fn invoke_stuffing_check(start_position: u32) -> (u32, u32) {
        let mut stream = StuffingStream { words: [0, start_position] };
        let result =
            unsafe { bitstream_stuffing_to_byte_check(stream.words.as_mut_ptr().cast::<u8>()) };
        (result, stream.words[1])
    }

    /// Independent formulation of the retail control flow: first bit
    /// must be 0, every following bit must be 1, stop (success) at
    /// the next byte boundary. Returns (result, final position).
    fn reference_stuffing_check(data: &[u8; 8], start_position: u32) -> (u32, u32) {
        let bit = |position: u32| {
            u32::from(data[(position >> 3) as usize] >> (7 - (position & 7)) & 1)
        };
        let mut position = start_position;
        let first = bit(position);
        position += 1;
        if first != 0 {
            return (1, position);
        }
        loop {
            if position & 7 == 0 {
                return (0, position);
            }
            let next = bit(position);
            position += 1;
            if next != 1 {
                return (1, position);
            }
        }
    }

    #[test]
    fn first_bit_set_returns_one_after_a_single_read() {
        for start_position in [0u32, 1, 3, 7, 8, 12, 15] {
            let _guard = install_bitstream_seam([0xff; 8]);
            let (result, final_position) = invoke_stuffing_check(start_position);
            assert_eq!(result, 1, "start={start_position}");
            assert_eq!(final_position, start_position + 1, "start={start_position}");
            let (count, reads) = stuffing_reads();
            assert_eq!(count, 1, "start={start_position}: one read, no padding scan");
            assert_eq!(reads[0].bit_count, 1, "start={start_position}");
            uninstall_bitstream_seam();
        }
    }

    #[test]
    fn full_byte_stuffing_returns_zero_after_eight_reads() {
        // 0x7f = 0b0111_1111: the 0 bit then seven 1 bits reaches the
        // boundary at position 8.
        let _guard = install_bitstream_seam([0x7f; 8]);
        let (result, final_position) = invoke_stuffing_check(0);
        assert_eq!(result, 0);
        assert_eq!(final_position, 8);
        let (count, reads) = stuffing_reads();
        assert_eq!(count, 8, "one 0 bit plus seven 1 bits");
        assert!(
            reads[..8].iter().all(|read| read.bit_count == 1),
            "every read goes through FUN_080ebbe0(stream, 1)"
        );
        uninstall_bitstream_seam();
    }

    #[test]
    fn aligned_after_first_bit_returns_zero_without_padding_reads() {
        // Start at bit 7: the single 0 bit lands exactly on the byte
        // boundary, so no padding bits are read at all.
        let _guard = install_bitstream_seam([0x00, 0xfe, 0, 0, 0, 0, 0, 0]);
        let (result, final_position) = invoke_stuffing_check(7);
        assert_eq!(result, 0);
        assert_eq!(final_position, 8);
        let (count, _) = stuffing_reads();
        assert_eq!(count, 1);
        uninstall_bitstream_seam();
    }

    #[test]
    fn zero_in_the_padding_returns_one_at_that_bit() {
        // 0x5f = 0b0101_1111: 0, 1, then a 0 at bit 2 ends the scan.
        let _guard = install_bitstream_seam([0x5f; 8]);
        let (result, final_position) = invoke_stuffing_check(0);
        assert_eq!(result, 1);
        assert_eq!(final_position, 3, "first bit plus two padding reads");
        let (count, _) = stuffing_reads();
        assert_eq!(count, 3);
        uninstall_bitstream_seam();
    }

    #[test]
    fn mid_byte_start_consumes_only_to_the_boundary() {
        // Start at bit 3 of 0x0f = 0b0000_1111: bit 3 is 0, bits 4..8
        // are 1, boundary at 8 — five reads total.
        let _guard = install_bitstream_seam([0x0f; 8]);
        let (result, final_position) = invoke_stuffing_check(3);
        assert_eq!(result, 0);
        assert_eq!(final_position, 8);
        let (count, _) = stuffing_reads();
        assert_eq!(count, 5);
        uninstall_bitstream_seam();
    }

    #[test]
    fn stream_pointer_is_passed_through_to_every_read() {
        let _guard = install_bitstream_seam([0x7f; 8]);
        let mut stream = StuffingStream { words: [0, 0] };
        let result =
            unsafe { bitstream_stuffing_to_byte_check(stream.words.as_mut_ptr().cast::<u8>()) };
        assert_eq!(result, 0);
        let (count, reads) = stuffing_reads();
        assert_eq!(count, 8);
        let expected = stream.words.as_mut_ptr().cast::<u8>() as usize;
        assert!(
            reads[..8].iter().all(|read| read.stream == expected),
            "r4 holds the stream across the whole loop (mov r0,r4 @ 0x0808556c/0x08085584)"
        );
        uninstall_bitstream_seam();
    }

    #[test]
    fn matches_reference_over_positions_and_patterns() {
        let mut patterns: std::vec::Vec<[u8; 8]> =
            (0..=0xffu8).map(|byte| [byte; 8]).collect();
        // Deterministic pseudo-random multi-byte patterns.
        let mut state = 0x1234_5678u32;
        for _ in 0..64 {
            let mut pattern = [0u8; 8];
            for slot in &mut pattern {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                *slot = state as u8;
            }
            patterns.push(pattern);
        }
        for pattern in patterns {
            for start_position in 0..15u32 {
                let _guard = install_bitstream_seam(pattern);
                let (result, final_position) = invoke_stuffing_check(start_position);
                let (expected_result, expected_position) =
                    reference_stuffing_check(&pattern, start_position);
                assert_eq!(
                    (result, final_position),
                    (expected_result, expected_position),
                    "pattern={pattern:02x?} start={start_position}"
                );
                let (count, _) = stuffing_reads();
                assert_eq!(
                    count as u32,
                    final_position - start_position,
                    "one read-advance call per consumed bit, start={start_position}"
                );
                uninstall_bitstream_seam();
            }
        }
    }
}
