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

/// Call ABI used by the FT_Open_Face fallback seam for the MacBinary
/// resource-fork probe.
pub type ResourceForkProbe =
    unsafe extern "C" fn(library: *mut u32, stream: *mut u32, face_index: i32, face_out: *mut u32) -> u32;

/// resource_fork_probe — original: `FUN_08076510` @ `0x08076510`
/// (220 bytes; source: `ipod-decomp/decomp/c/005/08076510_FUN_08076510.c`).
///
/// Probes a stream for a MacBinary header before dispatching the flattened
/// resource fork to `FUN_0807f478`. It seeks to zero and reads 128 bytes,
/// propagating either `FT_Stream_*` error unchanged. It accepts exactly the
/// MacBinary checks in the ARM: bytes 0, 74, 82, and 63 are zero; the
/// filename length at byte 1 is 1..=33; and the byte immediately after the
/// filename is zero. On a malformed header it returns status class 2
/// (`FT_Err_Unknown_File_Format`). Otherwise, it reads the big-endian
/// data-fork length at bytes 83..86 and passes
/// `128 + align_up(data_fork_length, 128)` as the resource-fork offset to
/// the dfont opener, returning that call's result unchanged. The ARM body is
/// `seek(0); read(128); header tests; ldrb 0x53..0x56; add #127; bic #127;
/// add #128; bl 0x0807f478`.
///
/// The resource-map validation and `POST`/`sfnt` dispatch now run through
/// the ported [`dfont_open`]. Its still-unported resource-header/type lookup
/// and driver dependencies remain behind [`DFONT_OPEN_OPS`] seams.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn resource_fork_probe(
    library: *mut u32,
    stream: *mut u32,
    face_index: i32,
    face_out: *mut u32,
) -> u32 {
    let stream_record = stream.cast::<crate::ft::stream::FtStream>();
    let seek_error = crate::ft::stream::ft_stream_seek(stream_record, 0);
    if seek_error != 0 {
        return seek_error as u32;
    }

    let mut header = core::mem::MaybeUninit::<[u8; 128]>::uninit();
    let read_error =
        crate::ft::stream::ft_stream_read(stream_record, header.as_mut_ptr().cast(), 128);
    if read_error != 0 {
        return read_error as u32;
    }
    let header = header.as_ptr().cast::<u8>();
    let filename_length = header.add(1).read() as usize;
    if header.read() != 0
        || header.add(74).read() != 0
        || header.add(82).read() != 0
        || filename_length == 0
        || filename_length > 33
        || header.add(63).read() != 0
        || header.add(2 + filename_length).read() != 0
    {
        return STATUS_UNKNOWN_FILE_FORMAT;
    }

    let data_fork_length = (u32::from(header.add(83).read()) << 24)
        | (u32::from(header.add(84).read()) << 16)
        | (u32::from(header.add(85).read()) << 8)
        | u32::from(header.add(86).read());
    let resource_fork_offset = (data_fork_length.wrapping_add(127) & !127).wrapping_add(128);
    dfont_open(library, stream, resource_fork_offset, face_index, face_out)
}

/// `FUN_0804e38c` (`ft_raccess_get_header_info`): validates the repeated
/// resource header at `offset`, then returns the absolute resource-map and
/// resource-data offsets. The function remains unported.
pub type DfontResourceHeader = unsafe extern "C" fn(
    library: *mut u32,
    stream: *mut u32,
    offset: u32,
    resource_map_offset: *mut u32,
    resource_data_offset: *mut u32,
) -> u32;

/// `FUN_0804e17c` (`ft_raccess_get_data_offsets`): looks up one resource
/// type in the resource map, allocating its resource-data offset array.
/// The function remains unported.
pub type DfontResourceTypeLookup = unsafe extern "C" fn(
    library: *mut u32,
    stream: *mut u32,
    resource_map_offset: u32,
    resource_data_offset: u32,
    resource_tag: u32,
    resource_offsets_out: *mut *mut u32,
    resource_count_out: *mut u32,
) -> u32;

/// `FUN_080c63cc` / `FUN_080c6634`: driver-specific openers for `POST` and
/// `sfnt` resources. Both consume the offset array but do not own it.
pub type DfontDriverOpen = unsafe extern "C" fn(
    library: *mut u32,
    stream: *mut u32,
    resource_offsets: *mut u32,
    resource_count: u32,
    face_index: i32,
    face_out: *mut u32,
) -> u32;

/// Unported dependencies of [`dfont_open`]. Their signatures and ordering
/// are pinned by the four direct `bl`s in its ARM body; target integration
/// installs the retail functions until they are ported.
pub struct DfontOpenOps {
    pub read_resource_header: DfontResourceHeader,
    pub find_resource_type: DfontResourceTypeLookup,
    pub open_post: DfontDriverOpen,
    pub open_sfnt: DfontDriverOpen,
}

unsafe extern "C" fn missing_dfont_resource_header(
    _library: *mut u32,
    _stream: *mut u32,
    _offset: u32,
    _resource_map_offset: *mut u32,
    _resource_data_offset: *mut u32,
) -> u32 {
    loop {
        core::hint::spin_loop();
    }
}

unsafe extern "C" fn missing_dfont_resource_type(
    _library: *mut u32,
    _stream: *mut u32,
    _resource_map_offset: u32,
    _resource_data_offset: u32,
    _resource_tag: u32,
    _resource_offsets_out: *mut *mut u32,
    _resource_count_out: *mut u32,
) -> u32 {
    loop {
        core::hint::spin_loop();
    }
}

unsafe extern "C" fn missing_dfont_driver(
    _library: *mut u32,
    _stream: *mut u32,
    _resource_offsets: *mut u32,
    _resource_count: u32,
    _face_index: i32,
    _face_out: *mut u32,
) -> u32 {
    loop {
        core::hint::spin_loop();
    }
}

/// Target integration must replace these slots with retailOS
/// `FUN_0804e38c`, `FUN_0804e17c`, `FUN_080c63cc`, and `FUN_080c6634`
/// respectively until those functions are ported.
pub static mut DFONT_OPEN_OPS: DfontOpenOps = DfontOpenOps {
    read_resource_header: missing_dfont_resource_header,
    find_resource_type: missing_dfont_resource_type,
    open_post: missing_dfont_driver,
    open_sfnt: missing_dfont_driver,
};

#[inline(always)]
unsafe fn dfont_open_ops() -> DfontOpenOps {
    core::ptr::read_volatile(core::ptr::addr_of!(DFONT_OPEN_OPS))
}

/// `POST` and `sfnt`, interpreted as the big-endian resource-type words
/// returned by `FT_Stream_ReadLong`.
const RESOURCE_TAG_POST: u32 = 0x504f_5354;
const RESOURCE_TAG_SFNT: u32 = 0x7366_6e74;

/// dfont_open — original: `FUN_0807f478` @ `0x0807f478` (228 bytes;
/// source: `ipod-decomp/decomp/c/005/0807f478_FUN_0807f478.c`; the
/// adjacent resource-tag literals are at 0x0807f55c and 0x0807f560).
///
/// Opens one font face from a flattened Mac resource fork. It first
/// validates the resource header at `offset`, recovering its absolute map
/// and data offsets. It then searches for `POST` resources; if found, that
/// offset array is dispatched to the PostScript resource driver
/// (`FUN_080c63cc`). Only a nonzero `POST` lookup result triggers the
/// second, `sfnt`, lookup and its TrueType/OpenType driver
/// (`FUN_080c6634`). A header error, or the second lookup error, returns
/// unchanged. After either driver returns (success or failure), the
/// resource-offset array is released through the library's `FT_Memory`.
/// Thus a `POST` driver error is final and cannot fall through to `sfnt`.
///
/// The ARM sequence is `bl 0x0804e38c; bl 0x0804e17c(POST);
/// bl 0x080c63cc | bl 0x0804e17c(sfnt); bl 0x080c6634;
/// bl 0x082cfae8`, with face index and output passed unchanged to the
/// selected driver. Deviations: the four unported callees use
/// [`DFONT_OPEN_OPS`] (the house ops-struct seam) while the already-ported
/// [`crate::ft::memory::ft_mem_free`] is called directly.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn dfont_open(
    library: *mut u32,
    stream: *mut u32,
    offset: u32,
    face_index: i32,
    face_out: *mut u32,
) -> u32 {
    let ops = dfont_open_ops();
    let mut resource_map_offset = 0;
    let mut resource_data_offset = 0;
    let mut result = (ops.read_resource_header)(
        library,
        stream,
        offset,
        &mut resource_map_offset,
        &mut resource_data_offset,
    );
    if result != 0 {
        return result;
    }

    let mut resource_offsets = core::ptr::null_mut();
    let mut resource_count = 0;
    result = (ops.find_resource_type)(
        library,
        stream,
        resource_map_offset,
        resource_data_offset,
        RESOURCE_TAG_POST,
        &mut resource_offsets,
        &mut resource_count,
    );
    if result == 0 {
        result = (ops.open_post)(
            library,
            stream,
            resource_offsets,
            resource_count,
            face_index,
            face_out,
        );
    } else {
        result = (ops.find_resource_type)(
            library,
            stream,
            resource_map_offset,
            resource_data_offset,
            RESOURCE_TAG_SFNT,
            &mut resource_offsets,
            &mut resource_count,
        );
        if result != 0 {
            return result;
        }
        result = (ops.open_sfnt)(
            library,
            stream,
            resource_offsets,
            resource_count,
            face_index,
            face_out,
        );
    }

    if !resource_offsets.is_null() {
        let memory = library
            .cast::<*mut crate::ft::memory::FtMemory>()
            .read_volatile();
        crate::ft::memory::ft_mem_free(memory, resource_offsets.cast());
    }
    result
}
/// Fallback-rule chain `FUN_080db8ac` (unported): walks the rule table
/// derived from the pathname, re-opening through FT_Open_Face per rule.
pub type FallbackRuleChain = unsafe extern "C" fn(
    library: *mut u32,
    stream: *mut u32,
    face_index: i32,
    face_out: *mut u32,
    open_args: *const u32,
) -> u32;

/// The fallback-rule chain remains unported from
/// [`ft_open_face_dfont_fallback`], grouped in the house ops-struct pattern
/// (app/node_list.rs's NODE_LIST_ENQUEUE_OPS). The ported
/// [`resource_fork_probe`] and [`dfont_open`] are installed by default.
pub struct DfontFallbackOps {
    pub probe_resource_fork: ResourceForkProbe,
    pub run_fallback_rules: FallbackRuleChain,
}

/// Spins forever: [`ft_open_face_dfont_fallback`] must not run the optional
/// fallback-rule chain before target integration installs `FUN_080db8ac`.
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

/// RetailOS dependency of [`ft_open_face_dfont_fallback`]. The ported
/// [`resource_fork_probe`] remains in the existing probe seam for target
/// integration and focused host tests; the ported [`dfont_open`] is called
/// directly. Target integration must still install `FUN_080db8ac`.
pub static mut DFONT_FALLBACK_OPS: DfontFallbackOps = DfontFallbackOps {
    probe_resource_fork: resource_fork_probe,
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
/// Deviations: the ported resource-fork probe and unported fallback-rule
/// callee ride [`DFONT_FALLBACK_OPS`] (house pattern) instead of direct
/// `bl`s; the ported [`dfont_open`] and
/// [`ft_error_trace`](crate::ft::trace::ft_error_trace) take their calls
/// directly (its retail varargs shim is already ported); the unused r2/r3
/// slots of the trace calls, garbage in retail, are passed as 0; and host
/// builds substitute test storage for the firmware trace-level block @
/// 0x08b209dc.
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
        result = dfont_open(library, stream, 0, face_index, face_out);
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

/// namespace_provider_at — original: `FUN_08369864` @ `0x08369864`
/// (20 bytes; source:
/// `ipod-decomp/decomp/c/033/08369864_FUN_08369864.c`).
///
/// Returns `table[index]`, where `table` is the provider-pointer table at
/// `providers + 0x04`, or null when `providers` is null. The raw
/// `cmp/ldrne/ldrne/moveq/bx lr` guards only `providers`: a non-null object
/// with a null table pointer is invalid and the second load faults, just as
/// it does in retailOS. The second load scales `index` by four (`lsl #2`).
/// On 64-bit host tests, the pointer stored at target byte offset `+0x04`
/// is deliberately unaligned; `read_unaligned` preserves that target layout.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn namespace_provider_at(
    providers: *const u32,
    index: u32,
) -> *const u32 {
    if providers.is_null() {
        core::ptr::null()
    } else {
        #[cfg(target_os = "none")]
        let table = providers.add(1).cast::<*const u32>().read_volatile();
        #[cfg(not(target_os = "none"))]
        let table = core::ptr::read_unaligned(providers.add(1).cast::<*const u32>());
        table
            .cast::<*const u32>()
            .wrapping_add(index as usize)
            .read_volatile()
    }
}

/// Registry fallback name hash — original: `FUN_082d7e54` @ `0x082d7e54`
/// (88 bytes; source:
/// `ipod-decomp/decomp/c/031/082d7e54_FUN_082d7e54.c`).
///
/// Hashes a NUL-terminated registry name. A null pointer or a name whose
/// first byte is NUL returns the zero accumulator. Otherwise, for every
/// unsigned byte `b` at position `i`, it forms
/// `c = b | (0x100 * (i + 1))`, rotates the 32-bit accumulator left by
/// `(c ^ (c >> 2)) & 0xf`, XORs `c * c`, then folds the final accumulator
/// as `h ^ (h >> 16)`. The byte-position salt advances modulo $2^{32}$.
/// This is the default path of [`registry_key_hash`] when a namespace does
/// not provide its vtable override. The raw ARM is `ldrb; orr; eor/lsr;
/// and #0xf; rsb #0; ror; mul; ldrb; add #0x100; eor`, so the register
/// `ror` by the negated count is expressed as `rotate_left`. No deviations.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn registry_default_name_hash(name: *const u8) -> u32 {
    if name.is_null() || name.read() == 0 {
        return 0;
    }

    let mut cursor = name;
    let mut salt = 0x100u32;
    let mut hash = 0u32;
    loop {
        let salted_byte = u32::from(cursor.read()) | salt;
        let rotation = (salted_byte ^ (salted_byte >> 2)) & 0xf;
        hash = hash.rotate_left(rotation) ^ salted_byte.wrapping_mul(salted_byte);

        cursor = cursor.add(1);
        if cursor.read() == 0 {
            break;
        }
        salt = salt.wrapping_add(0x100);
    }

    hash ^ (hash >> 16)
}

/// Provider vtable slot +0x00, invoked by [`registry_key_hash`] instead of
/// [`registry_default_name_hash`] for a selected namespace.
pub type RegistryNameHash = unsafe extern "C" fn(name: *const u8) -> u32;

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
/// No deviations: the default fallback
/// [`registry_default_name_hash`] and [`namespace_provider_at`] are ported
/// and called directly. Host builds substitute test storage for the firmware
/// singleton @ 0x08a0ea6c; and the key and singleton words are addressed by
/// pointer-sized word index (byte-exact +0x00/+0x08 on the 32-bit target,
/// disjoint slots on a 64-bit host — the same model as
/// [`pfr_face_done`]'s face words).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn registry_key_hash(key: *const usize) -> u32 {
    let providers = registry_providers_word().read_volatile();
    let name_hash = if providers.is_null() {
        registry_default_name_hash(key.add(2).read_volatile() as *const u8)
    } else {
        let count = namespace_provider_count(providers);
        let index = key.read_volatile();
        if count > index as i32 {
            let provider = namespace_provider_at(providers, index as u32);
            let provider_hash = provider.cast::<RegistryNameHash>().read_volatile();
            provider_hash(key.add(2).read_volatile() as *const u8)
        } else {
            registry_default_name_hash(key.add(2).read_volatile() as *const u8)
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

/// `PFR_PhyFontRec.horizontal.num_stem_snaps` (+0x3c).
const PFR_HORIZONTAL_STEM_COUNT_WORD: usize = 0x3c / 4;
/// `PFR_PhyFontRec.horizontal.stem_snaps` (+0x40): an alias into the
/// vertical allocation, so it is cleared but never freed separately.
const PFR_HORIZONTAL_STEM_SNAPS_WORD: usize = 0x40 / 4;
/// `PFR_PhyFontRec.vertical.num_stem_snaps` (+0x48).
const PFR_VERTICAL_STEM_COUNT_WORD: usize = 0x48 / 4;
/// `PFR_PhyFontRec.vertical.stem_snaps` (+0x4c), the sole snap allocation.
const PFR_VERTICAL_STEM_SNAPS_WORD: usize = 0x4c / 4;
const PFR_FONT_ID_WORD: usize = 0x50 / 4;
const PFR_FAMILY_NAME_WORD: usize = 0x54 / 4;
const PFR_STYLE_NAME_WORD: usize = 0x58 / 4;
const PFR_NUM_STRIKES_WORD: usize = 0x5c / 4;
const PFR_MAX_STRIKES_WORD: usize = 0x60 / 4;
const PFR_STRIKES_WORD: usize = 0x64 / 4;
const PFR_NUM_BLUE_VALUES_WORD: usize = 0x68 / 4;
const PFR_BLUE_VALUES_WORD: usize = 0x6c / 4;
const PFR_NUM_CHARS_WORD: usize = 0x78 / 4;
const PFR_CHARS_OFFSET_WORD: usize = 0x7c / 4;
const PFR_CHARS_WORD: usize = 0x80 / 4;
const PFR_NUM_KERN_PAIRS_WORD: usize = 0x84 / 4;
/// `PFR_PhyFontRec.kern_items` (+0x88); each item starts with its next link.
const PFR_KERN_ITEMS_WORD: usize = 0x88 / 4;
const PFR_KERN_ITEMS_TAIL_WORD: usize = 0x8c / 4;

/// pfr_phy_font_done — original: `FUN_080a3554` @ `0x080a3554`
/// (208 bytes; source:
/// `ipod-decomp/decomp/c/006/080a3554_FUN_080a3554.c`).
///
/// Tears down the owned allocations in an embedded `PFR_PhyFontRec`.
/// In the exact retail order, it `FT_FREE`s the font ID, family name, style
/// name, vertical stem-snap allocation, strikes, character records, and blue
/// values; after each free it writes that slot to zero.  It then clears the
/// associated counts and aliases, walks the +0x88 kerning-item forward list
/// by loading each node's first-word `next` link *before* freeing that node,
/// and finally zeros the list head, tail, and pair count.  The horizontal
/// snap pointer is only an interior alias of the vertical allocation and is
/// consequently cleared, not freed.
///
/// This is FreeType's upstream `pfr_phy_font_done` from `pfrload.c`; the
/// ARM offsets agree with `PFR_PhyFontRec` on 32-bit ARM.  The function has
/// no entry null guard: `phys` and `memory` must be valid, as in retailOS.
/// Individual allocation slots and the list head may be null because
/// [`crate::ft::memory::ft_mem_free`] suppresses the allocator callback for
/// a null block.  Target-byte offsets are represented as word indices so
/// host fixtures retain disjoint 32-bit target slots.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pfr_phy_font_done(
    phys: *mut *mut u8,
    memory: *mut crate::ft::memory::FtMemory,
) {
    let field = phys.add(PFR_FONT_ID_WORD);
    crate::ft::memory::ft_mem_free(memory, field.read_volatile());
    field.write_volatile(core::ptr::null_mut());

    let field = phys.add(PFR_FAMILY_NAME_WORD);
    crate::ft::memory::ft_mem_free(memory, field.read_volatile());
    field.write_volatile(core::ptr::null_mut());

    let field = phys.add(PFR_STYLE_NAME_WORD);
    crate::ft::memory::ft_mem_free(memory, field.read_volatile());
    field.write_volatile(core::ptr::null_mut());

    let field = phys.add(PFR_VERTICAL_STEM_SNAPS_WORD);
    crate::ft::memory::ft_mem_free(memory, field.read_volatile());
    field.write_volatile(core::ptr::null_mut());
    phys.add(PFR_VERTICAL_STEM_COUNT_WORD)
        .write_volatile(core::ptr::null_mut());
    phys.add(PFR_HORIZONTAL_STEM_SNAPS_WORD)
        .write_volatile(core::ptr::null_mut());
    phys.add(PFR_HORIZONTAL_STEM_COUNT_WORD)
        .write_volatile(core::ptr::null_mut());

    let field = phys.add(PFR_STRIKES_WORD);
    crate::ft::memory::ft_mem_free(memory, field.read_volatile());
    field.write_volatile(core::ptr::null_mut());
    phys.add(PFR_NUM_STRIKES_WORD)
        .write_volatile(core::ptr::null_mut());
    phys.add(PFR_MAX_STRIKES_WORD)
        .write_volatile(core::ptr::null_mut());

    let field = phys.add(PFR_CHARS_WORD);
    crate::ft::memory::ft_mem_free(memory, field.read_volatile());
    field.write_volatile(core::ptr::null_mut());
    phys.add(PFR_NUM_CHARS_WORD)
        .write_volatile(core::ptr::null_mut());
    phys.add(PFR_CHARS_OFFSET_WORD)
        .write_volatile(core::ptr::null_mut());

    let field = phys.add(PFR_BLUE_VALUES_WORD);
    crate::ft::memory::ft_mem_free(memory, field.read_volatile());
    field.write_volatile(core::ptr::null_mut());
    phys.add(PFR_NUM_BLUE_VALUES_WORD)
        .write_volatile(core::ptr::null_mut());

    let mut item = phys.add(PFR_KERN_ITEMS_WORD).read_volatile();
    while !item.is_null() {
        let next = item.cast::<*mut u8>().read_volatile();
        crate::ft::memory::ft_mem_free(memory, item);
        item = next;
    }
    phys.add(PFR_KERN_ITEMS_WORD)
        .write_volatile(core::ptr::null_mut());
    phys.add(PFR_KERN_ITEMS_TAIL_WORD)
        .write_volatile(core::ptr::null_mut());
    phys.add(PFR_NUM_KERN_PAIRS_WORD)
        .write_volatile(core::ptr::null_mut());
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
/// Deviations: the already-ported [`ft_mem_free`](crate::ft::memory::ft_mem_free)
/// @ 0x082cfae8 takes the `FT_FREE` half directly (LLVM inlines its
/// null-guarded `blx [memory,#8]` body — the same inlining deviation
/// ft_mem_alloc's entry records); and the face fields are addressed by word
/// index (byte-exact +0x14..+0x120 on the 32-bit target; each field stays
/// disjoint on a 64-bit host — the same model as
/// cxx/handle.rs's handle_deref_field12).
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
    pfr_phy_font_done(
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

    // --- dfont_open ---

    /// Serializes tests that replace the four unported dfont-open
    /// dependencies and records the offset-array release.
    static DFONT_OPEN_TEST_LOCK: StdMutex<()> = StdMutex::new(());

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum DfontOpenEvent {
        Header { offset: u32 },
        Lookup { tag: u32, resource_map: u32, resource_data: u32 },
        Post { offsets: usize, count: u32, face_index: i32, face_out: usize },
        Sfnt { offsets: usize, count: u32, face_index: i32, face_out: usize },
    }

    const NO_DFONT_OPEN_EVENT: DfontOpenEvent = DfontOpenEvent::Header { offset: 0 };
    static mut DFONT_OPEN_EVENTS: [DfontOpenEvent; 8] = [NO_DFONT_OPEN_EVENT; 8];
    static mut DFONT_OPEN_EVENT_COUNT: usize = 0;
    static mut HEADER_RESULT: u32 = 0;
    static mut POST_LOOKUP_RESULT: u32 = 0;
    static mut SFNT_LOOKUP_RESULT: u32 = 0;
    static mut POST_DRIVER_RESULT: u32 = 0;
    static mut SFNT_DRIVER_RESULT: u32 = 0;
    static mut DFONT_OPEN_FREE_MEMORY: usize = 0;
    static mut DFONT_OPEN_FREE_BLOCK: usize = 0;
    static mut POST_RESOURCE_OFFSETS: [u32; 2] = [0; 2];
    static mut SFNT_RESOURCE_OFFSETS: [u32; 3] = [0; 3];

    const DFONT_RESOURCE_MAP_OFFSET: u32 = 0x1234_5000;
    const DFONT_RESOURCE_DATA_OFFSET: u32 = 0x1234_6000;
    const DFONT_FACE_INDEX: i32 = -1;
    const DFONT_FACE_OUT: usize = 0x4444_1234;

    fn record_dfont_open(event: DfontOpenEvent) {
        unsafe {
            let count = DFONT_OPEN_EVENT_COUNT;
            assert!(count < DFONT_OPEN_EVENTS.len(), "dfont open called too many seams");
            DFONT_OPEN_EVENTS[count] = event;
            DFONT_OPEN_EVENT_COUNT = count + 1;
        }
    }

    unsafe extern "C" fn recording_resource_header(
        _library: *mut u32,
        _stream: *mut u32,
        offset: u32,
        resource_map_offset: *mut u32,
        resource_data_offset: *mut u32,
    ) -> u32 {
        record_dfont_open(DfontOpenEvent::Header { offset });
        if HEADER_RESULT == 0 {
            resource_map_offset.write(DFONT_RESOURCE_MAP_OFFSET);
            resource_data_offset.write(DFONT_RESOURCE_DATA_OFFSET);
        }
        HEADER_RESULT
    }

    unsafe extern "C" fn recording_resource_type_lookup(
        _library: *mut u32,
        _stream: *mut u32,
        resource_map_offset: u32,
        resource_data_offset: u32,
        tag: u32,
        resource_offsets_out: *mut *mut u32,
        resource_count_out: *mut u32,
    ) -> u32 {
        record_dfont_open(DfontOpenEvent::Lookup {
            tag,
            resource_map: resource_map_offset,
            resource_data: resource_data_offset,
        });
        let (result, offsets, count) = if tag == RESOURCE_TAG_POST {
            (POST_LOOKUP_RESULT, core::ptr::addr_of_mut!(POST_RESOURCE_OFFSETS).cast(), 2)
        } else {
            assert_eq!(tag, RESOURCE_TAG_SFNT);
            (SFNT_LOOKUP_RESULT, core::ptr::addr_of_mut!(SFNT_RESOURCE_OFFSETS).cast(), 3)
        };
        if result == 0 {
            resource_offsets_out.write(offsets);
            resource_count_out.write(count);
        }
        result
    }

    unsafe extern "C" fn recording_post_driver(
        _library: *mut u32,
        _stream: *mut u32,
        offsets: *mut u32,
        count: u32,
        face_index: i32,
        face_out: *mut u32,
    ) -> u32 {
        record_dfont_open(DfontOpenEvent::Post {
            offsets: offsets as usize,
            count,
            face_index,
            face_out: face_out as usize,
        });
        POST_DRIVER_RESULT
    }

    unsafe extern "C" fn recording_sfnt_driver(
        _library: *mut u32,
        _stream: *mut u32,
        offsets: *mut u32,
        count: u32,
        face_index: i32,
        face_out: *mut u32,
    ) -> u32 {
        record_dfont_open(DfontOpenEvent::Sfnt {
            offsets: offsets as usize,
            count,
            face_index,
            face_out: face_out as usize,
        });
        SFNT_DRIVER_RESULT
    }

    unsafe extern "C" fn recording_dfont_free(
        memory: *mut crate::ft::memory::FtMemory,
        block: *mut u8,
    ) {
        DFONT_OPEN_FREE_MEMORY = memory as usize;
        DFONT_OPEN_FREE_BLOCK = block as usize;
    }

    unsafe extern "C" fn dfont_unused_alloc(
        _memory: *mut crate::ft::memory::FtMemory,
        _size: i32,
    ) -> *mut u8 {
        core::ptr::null_mut()
    }

    unsafe extern "C" fn dfont_unused_realloc(
        _memory: *mut crate::ft::memory::FtMemory,
        _current_size: i32,
        _new_size: i32,
        _block: *mut u8,
    ) -> *mut u8 {
        core::ptr::null_mut()
    }

    fn dfont_recording_memory() -> crate::ft::memory::FtMemory {
        crate::ft::memory::FtMemory {
            user: core::ptr::null_mut(),
            alloc: dfont_unused_alloc,
            free: recording_dfont_free,
            realloc: dfont_unused_realloc,
        }
    }

    fn install_recording_dfont_open(
        header: u32,
        post_lookup: u32,
        sfnt_lookup: u32,
        post_driver: u32,
        sfnt_driver: u32,
    ) -> StdMutexGuard<'static, ()> {
        let guard = DFONT_OPEN_TEST_LOCK.lock().unwrap();
        unsafe {
            HEADER_RESULT = header;
            POST_LOOKUP_RESULT = post_lookup;
            SFNT_LOOKUP_RESULT = sfnt_lookup;
            POST_DRIVER_RESULT = post_driver;
            SFNT_DRIVER_RESULT = sfnt_driver;
            DFONT_OPEN_EVENT_COUNT = 0;
            DFONT_OPEN_FREE_MEMORY = 0;
            DFONT_OPEN_FREE_BLOCK = 0;
            DFONT_OPEN_OPS = DfontOpenOps {
                read_resource_header: recording_resource_header,
                find_resource_type: recording_resource_type_lookup,
                open_post: recording_post_driver,
                open_sfnt: recording_sfnt_driver,
            };
        }
        guard
    }

    fn uninstall_recording_dfont_open() {
        unsafe {
            DFONT_OPEN_OPS = DfontOpenOps {
                read_resource_header: missing_dfont_resource_header,
                find_resource_type: missing_dfont_resource_type,
                open_post: missing_dfont_driver,
                open_sfnt: missing_dfont_driver,
            };
        }
    }

    fn invoke_dfont_open(offset: u32) -> (u32, usize, [DfontOpenEvent; 8], usize, usize, usize) {
        let mut memory = dfont_recording_memory();
        // The firmware library's first word is an FT_Memory pointer. This
        // pointer-sized host fixture keeps that target word representable.
        let mut library = [core::ptr::addr_of_mut!(memory)];
        let result = unsafe {
            dfont_open(
                library.as_mut_ptr().cast(),
                STREAM as *mut u32,
                offset,
                DFONT_FACE_INDEX,
                DFONT_FACE_OUT as *mut u32,
            )
        };
        unsafe {
            (
                result,
                DFONT_OPEN_EVENT_COUNT,
                DFONT_OPEN_EVENTS,
                DFONT_OPEN_FREE_MEMORY,
                DFONT_OPEN_FREE_BLOCK,
                (&mut memory as *mut crate::ft::memory::FtMemory) as usize,
            )
        }
    }

    #[test]
    fn dfont_open_dispatches_post_at_header_offsets_and_releases_after_driver_error() {
        let _guard = install_recording_dfont_open(0, 0, 0, 0x55, 0);
        let (result, count, events, free_memory, free_block, memory) = invoke_dfont_open(0x180);
        assert_eq!(result, 0x55, "POST driver status is propagated unchanged");
        assert_eq!(count, 3);
        assert_eq!(events[0], DfontOpenEvent::Header { offset: 0x180 });
        assert_eq!(
            events[1],
            DfontOpenEvent::Lookup {
                tag: RESOURCE_TAG_POST,
                resource_map: DFONT_RESOURCE_MAP_OFFSET,
                resource_data: DFONT_RESOURCE_DATA_OFFSET,
            }
        );
        assert_eq!(
            events[2],
            DfontOpenEvent::Post {
                offsets: core::ptr::addr_of_mut!(POST_RESOURCE_OFFSETS).cast::<u32>() as usize,
                count: 2,
                face_index: DFONT_FACE_INDEX,
                face_out: DFONT_FACE_OUT,
            }
        );
        assert_eq!(free_memory, memory, "offset array uses library FT_Memory");
        assert_eq!(
            free_block,
            core::ptr::addr_of_mut!(POST_RESOURCE_OFFSETS).cast::<u8>() as usize
        );
        uninstall_recording_dfont_open();
    }

    #[test]
    fn dfont_open_tries_sfnt_only_after_post_lookup_error() {
        let _guard = install_recording_dfont_open(0, 2, 0, 0, 0xdead_beef);
        let (result, count, events, _free_memory, free_block, _memory) = invoke_dfont_open(0);
        assert_eq!(result, 0xdead_beef, "sfnt driver status is propagated unchanged");
        assert_eq!(count, 4);
        assert_eq!(events[0], DfontOpenEvent::Header { offset: 0 });
        assert_eq!(events[1], DfontOpenEvent::Lookup {
            tag: RESOURCE_TAG_POST,
            resource_map: DFONT_RESOURCE_MAP_OFFSET,
            resource_data: DFONT_RESOURCE_DATA_OFFSET,
        });
        assert_eq!(events[2], DfontOpenEvent::Lookup {
            tag: RESOURCE_TAG_SFNT,
            resource_map: DFONT_RESOURCE_MAP_OFFSET,
            resource_data: DFONT_RESOURCE_DATA_OFFSET,
        });
        assert_eq!(
            events[3],
            DfontOpenEvent::Sfnt {
                offsets: core::ptr::addr_of_mut!(SFNT_RESOURCE_OFFSETS).cast::<u32>() as usize,
                count: 3,
                face_index: DFONT_FACE_INDEX,
                face_out: DFONT_FACE_OUT,
            }
        );
        assert_eq!(
            free_block,
            core::ptr::addr_of_mut!(SFNT_RESOURCE_OFFSETS).cast::<u8>() as usize
        );
        uninstall_recording_dfont_open();
    }

    #[test]
    fn dfont_open_propagates_header_and_second_lookup_errors_without_freeing() {
        for (header, post_lookup, sfnt_lookup, expected, expected_events) in [
            (0x23, 0, 0, 0x23, 1),
            (0, 2, 0x57, 0x57, 3),
        ] {
            let _guard = install_recording_dfont_open(header, post_lookup, sfnt_lookup, 0, 0);
            let (result, count, _events, free_memory, free_block, _memory) = invoke_dfont_open(0x77);
            assert_eq!(result, expected);
            assert_eq!(count, expected_events);
            assert_eq!(free_memory, 0, "no offset array exists on lookup failure");
            assert_eq!(free_block, 0, "no offset array exists on lookup failure");
            uninstall_recording_dfont_open();
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

    /// Drives the real dfont port through its header-error path for
    /// nonzero scripted outcomes; zero continues through the harmless
    /// null-offset `POST` path below. The fallback caller observes exactly
    /// the same status and ordering either way.
    unsafe extern "C" fn recording_fallback_dfont_header(
        library: *mut u32,
        stream: *mut u32,
        offset: u32,
        resource_map_offset: *mut u32,
        resource_data_offset: *mut u32,
    ) -> u32 {
        record(FallbackEvent::Dfont {
            library: library as usize,
            stream: stream as usize,
            offset,
            face_index: FACE_INDEX,
            face_out: FACE_OUT,
        });
        if DFONT_RESULT != 0 {
            return DFONT_RESULT;
        }
        resource_map_offset.write(0);
        resource_data_offset.write(0);
        0
    }

    unsafe extern "C" fn recording_fallback_dfont_lookup(
        _library: *mut u32,
        _stream: *mut u32,
        _resource_map_offset: u32,
        _resource_data_offset: u32,
        _tag: u32,
        resource_offsets_out: *mut *mut u32,
        resource_count_out: *mut u32,
    ) -> u32 {
        resource_offsets_out.write(core::ptr::null_mut());
        resource_count_out.write(0);
        0
    }

    unsafe extern "C" fn recording_fallback_dfont_driver(
        _library: *mut u32,
        _stream: *mut u32,
        _resource_offsets: *mut u32,
        _resource_count: u32,
        _face_index: i32,
        _face_out: *mut u32,
    ) -> u32 {
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

    /// Installs recording seams with scripted results, seeds the host trace
    /// level, and optionally hooks the trace sink. The real dfont port is
    /// driven through its dependency seams; guards serialize the fallback,
    /// dfont, and trace swaps in that order.
    fn install_recording_fallback(
        probe: u32,
        dfont: u32,
        rules: u32,
        level: i32,
        trace: bool,
    ) -> (
        StdMutexGuard<'static, ()>,
        StdMutexGuard<'static, ()>,
        Option<StdMutexGuard<'static, ()>>,
    ) {
        let guard = DFONT_FALLBACK_TEST_LOCK.lock().unwrap();
        let dfont_guard = DFONT_OPEN_TEST_LOCK.lock().unwrap();
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
                run_fallback_rules: recording_rules,
            };
            DFONT_OPEN_OPS = DfontOpenOps {
                read_resource_header: recording_fallback_dfont_header,
                find_resource_type: recording_fallback_dfont_lookup,
                open_post: recording_fallback_dfont_driver,
                open_sfnt: recording_fallback_dfont_driver,
            };
        }
        (guard, dfont_guard, trace_guard)
    }

    fn uninstall_recording_fallback(trace: bool) {
        unsafe {
            DFONT_FALLBACK_OPS = DfontFallbackOps {
                probe_resource_fork: resource_fork_probe,
                run_fallback_rules: missing_fallback_rule_chain,
            };
            DFONT_OPEN_OPS = DfontOpenOps {
                read_resource_header: missing_dfont_resource_header,
                find_resource_type: missing_dfont_resource_type,
                open_post: missing_dfont_driver,
                open_sfnt: missing_dfont_driver,
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

    fn macbinary_header(data_fork_length: u32) -> [u8; 128] {
        let mut header = [0u8; 128];
        header[1] = 1;
        header[83..87].copy_from_slice(&data_fork_length.to_be_bytes());
        header
    }

    fn memory_stream(bytes: &mut [u8]) -> crate::ft::stream::FtStream {
        crate::ft::stream::FtStream {
            base: bytes.as_mut_ptr(),
            size: bytes.len() as u32,
            pos: 0,
            descriptor: core::ptr::null_mut(),
            pathname: core::ptr::null_mut(),
            read: None,
            close: None,
            memory: core::ptr::null_mut(),
            cursor: core::ptr::null_mut(),
            limit: core::ptr::null_mut(),
        }
    }

    #[test]
    fn resource_fork_probe_rejects_malformed_macbinary_headers() {
        let _guards = install_recording_fallback(0, 0xdead_beef, 0, 0, false);
        for (byte, value) in [(0, 1), (1, 0), (1, 34), (63, 1), (74, 1), (82, 1), (3, 1)] {
            let mut header = macbinary_header(0);
            header[byte] = value;
            let mut stream = memory_stream(&mut header);
            let result = unsafe {
                resource_fork_probe(
                    LIBRARY as *mut u32,
                    (&mut stream as *mut crate::ft::stream::FtStream).cast(),
                    FACE_INDEX,
                    FACE_OUT as *mut u32,
                )
            };
            assert_eq!(result, STATUS_UNKNOWN_FILE_FORMAT, "header[{byte}]={value}");
            assert_eq!(unsafe { FALLBACK_EVENT_COUNT }, 0, "header[{byte}]={value}");
        }
        uninstall_recording_fallback(false);
    }

    #[test]
    fn resource_fork_probe_propagates_stream_read_failure() {
        let _guards = install_recording_fallback(0, 0xdead_beef, 0, 0, false);
        let mut bytes = [0u8; 127];
        let mut stream = memory_stream(&mut bytes);
        let result = unsafe {
            resource_fork_probe(
                LIBRARY as *mut u32,
                (&mut stream as *mut crate::ft::stream::FtStream).cast(),
                FACE_INDEX,
                FACE_OUT as *mut u32,
            )
        };
        assert_eq!(result, STATUS_FALLBACK_RULE_CLASS);
        assert_eq!(unsafe { FALLBACK_EVENT_COUNT }, 0);
        uninstall_recording_fallback(false);
    }

    #[test]
    fn resource_fork_probe_aligns_data_fork_and_propagates_dfont_result() {
        let _guards = install_recording_fallback(0, 0xdead_beef, 0, 0, false);
        let mut header = macbinary_header(0x101);
        let mut stream = memory_stream(&mut header);
        let stream_ptr = (&mut stream as *mut crate::ft::stream::FtStream).cast::<u32>();
        let result = unsafe {
            resource_fork_probe(LIBRARY as *mut u32, stream_ptr, FACE_INDEX, FACE_OUT as *mut u32)
        };
        assert_eq!(result, 0xdead_beef);
        assert_eq!(unsafe { FALLBACK_EVENT_COUNT }, 1);
        assert_eq!(
            unsafe { FALLBACK_EVENTS[0] },
            FallbackEvent::Dfont {
                library: LIBRARY,
                stream: stream_ptr as usize,
                offset: 0x200,
                face_index: FACE_INDEX,
                face_out: FACE_OUT,
            }
        );
        uninstall_recording_fallback(false);
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

    // --- PFR physical-font and face teardown ---

    /// Serializes the tests using the recording allocator below.
    static PFR_FACE_DONE_TEST_LOCK: StdMutex<()> = StdMutex::new(());

    /// Target-word count sufficient for every pfr_phy_font_done field through
    /// `kern_items_tail` at +0x8c.
    const PFR_PHY_FONT_WORDS: usize = 0x90 / 4;
    /// The physical-font record is embedded at face word 0x48.
    const FACE_WORDS: usize = FACE_PHY_FONT_WORD + PFR_PHY_FONT_WORDS;

    static mut FREE_CALLS: usize = 0;
    static mut FREE_MEMORY_ARG: *mut crate::ft::memory::FtMemory = core::ptr::null_mut();
    static mut FREE_BLOCK_ARG: *mut u8 = core::ptr::null_mut();
    /// Complete ordered callback trace; every test here has at most ten calls.
    static mut FREE_BLOCKS: [usize; 12] = [0; 12];
    static mut FREE_MEMORIES: [usize; 12] = [0; 12];

    unsafe extern "C" fn recording_free(
        memory: *mut crate::ft::memory::FtMemory,
        block: *mut u8,
    ) {
        let slot = FREE_CALLS;
        FREE_MEMORY_ARG = memory;
        FREE_BLOCK_ARG = block;
        FREE_BLOCKS[slot] = block as usize;
        FREE_MEMORIES[slot] = memory as usize;
        FREE_CALLS += 1;
    }

    unsafe extern "C" fn unused_alloc(
        _memory: *mut crate::ft::memory::FtMemory,
        _size: i32,
    ) -> *mut u8 {
        panic!("PFR teardown never allocates")
    }

    unsafe extern "C" fn unused_realloc(
        _memory: *mut crate::ft::memory::FtMemory,
        _cur: i32,
        _new: i32,
        _block: *mut u8,
    ) -> *mut u8 {
        panic!("PFR teardown never reallocates")
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

    /// Clears the callback trace and returns the lock which makes the shared
    /// recording allocator safe for this module's parallel tests.
    fn install_recording_teardown() -> StdMutexGuard<'static, ()> {
        let guard = PFR_FACE_DONE_TEST_LOCK.lock().unwrap();
        unsafe {
            FREE_CALLS = 0;
            FREE_MEMORY_ARG = core::ptr::null_mut();
            FREE_BLOCK_ARG = core::ptr::null_mut();
            FREE_BLOCKS = [0; 12];
            FREE_MEMORIES = [0; 12];
        }
        guard
    }

    #[test]
    fn pfr_phy_font_done_skips_null_blocks_and_zeros_teardown_fields() {
        let _guard = install_recording_teardown();
        let mut memory = recording_memory();
        let sentinel = 0x5a5a_5a5ausize as *mut u8;
        let mut phys = [sentinel; PFR_PHY_FONT_WORDS];
        for word in [
            PFR_FONT_ID_WORD,
            PFR_FAMILY_NAME_WORD,
            PFR_STYLE_NAME_WORD,
            PFR_VERTICAL_STEM_SNAPS_WORD,
            PFR_STRIKES_WORD,
            PFR_CHARS_WORD,
            PFR_BLUE_VALUES_WORD,
            PFR_KERN_ITEMS_WORD,
        ] {
            phys[word] = core::ptr::null_mut();
        }

        unsafe { pfr_phy_font_done(phys.as_mut_ptr(), &mut memory) };

        assert_eq!(unsafe { FREE_CALLS }, 0, "null FT_FREE slots do not call free");
        for word in [
            PFR_HORIZONTAL_STEM_COUNT_WORD,
            PFR_HORIZONTAL_STEM_SNAPS_WORD,
            PFR_VERTICAL_STEM_COUNT_WORD,
            PFR_VERTICAL_STEM_SNAPS_WORD,
            PFR_FONT_ID_WORD,
            PFR_FAMILY_NAME_WORD,
            PFR_STYLE_NAME_WORD,
            PFR_NUM_STRIKES_WORD,
            PFR_MAX_STRIKES_WORD,
            PFR_STRIKES_WORD,
            PFR_NUM_BLUE_VALUES_WORD,
            PFR_BLUE_VALUES_WORD,
            PFR_NUM_CHARS_WORD,
            PFR_CHARS_OFFSET_WORD,
            PFR_CHARS_WORD,
            PFR_NUM_KERN_PAIRS_WORD,
            PFR_KERN_ITEMS_WORD,
            PFR_KERN_ITEMS_TAIL_WORD,
        ] {
            assert!(phys[word].is_null(), "target field +{:#x}", word * 4);
        }
        assert_eq!(phys[0x70 / 4], sentinel, "blue_fuzz is not cleared");
        assert_eq!(phys[0x74 / 4], sentinel, "blue_scale is not cleared");
    }

    #[test]
    fn pfr_phy_font_done_frees_owned_fields_and_kerning_list_in_retail_order() {
        let _guard = install_recording_teardown();
        let mut memory = recording_memory();
        let mut owned = [0u8; 7];
        let mut first_kern: [*mut u8; 1] = [core::ptr::null_mut(); 1];
        let mut second_kern: [*mut u8; 1] = [core::ptr::null_mut(); 1];
        let first = first_kern.as_mut_ptr().cast::<u8>();
        let second = second_kern.as_mut_ptr().cast::<u8>();
        first_kern[0] = second;
        let mut phys = [core::ptr::null_mut(); PFR_PHY_FONT_WORDS];
        let fields = [
            PFR_FONT_ID_WORD,
            PFR_FAMILY_NAME_WORD,
            PFR_STYLE_NAME_WORD,
            PFR_VERTICAL_STEM_SNAPS_WORD,
            PFR_STRIKES_WORD,
            PFR_CHARS_WORD,
            PFR_BLUE_VALUES_WORD,
        ];
        for (index, field) in fields.into_iter().enumerate() {
            phys[field] = unsafe { owned.as_mut_ptr().add(index) };
        }
        phys[PFR_KERN_ITEMS_WORD] = first;

        unsafe { pfr_phy_font_done(phys.as_mut_ptr(), &mut memory) };

        let expected = [
            owned.as_mut_ptr() as usize,
            unsafe { owned.as_mut_ptr().add(1) as usize },
            unsafe { owned.as_mut_ptr().add(2) as usize },
            unsafe { owned.as_mut_ptr().add(3) as usize },
            unsafe { owned.as_mut_ptr().add(4) as usize },
            unsafe { owned.as_mut_ptr().add(5) as usize },
            unsafe { owned.as_mut_ptr().add(6) as usize },
            first as usize,
            second as usize,
        ];
        assert_eq!(unsafe { FREE_CALLS }, expected.len());
        assert_eq!(unsafe { &FREE_BLOCKS[..expected.len()] }, expected);
        assert!(
            unsafe { FREE_MEMORIES[..expected.len()].iter().all(|&seen| seen == &mut memory as *mut _ as usize) },
            "every allocation uses the supplied FT_Memory"
        );
        for word in [
            PFR_HORIZONTAL_STEM_COUNT_WORD,
            PFR_HORIZONTAL_STEM_SNAPS_WORD,
            PFR_VERTICAL_STEM_COUNT_WORD,
            PFR_VERTICAL_STEM_SNAPS_WORD,
            PFR_FONT_ID_WORD,
            PFR_FAMILY_NAME_WORD,
            PFR_STYLE_NAME_WORD,
            PFR_NUM_STRIKES_WORD,
            PFR_MAX_STRIKES_WORD,
            PFR_STRIKES_WORD,
            PFR_NUM_BLUE_VALUES_WORD,
            PFR_BLUE_VALUES_WORD,
            PFR_NUM_CHARS_WORD,
            PFR_CHARS_OFFSET_WORD,
            PFR_CHARS_WORD,
            PFR_NUM_KERN_PAIRS_WORD,
            PFR_KERN_ITEMS_WORD,
            PFR_KERN_ITEMS_TAIL_WORD,
        ] {
            assert!(phys[word].is_null(), "target field +{:#x}", word * 4);
        }
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
    }

    #[test]
    fn pfr_face_done_uses_face_memory_for_embedded_physical_font() {
        let _guard = install_recording_teardown();
        let mut mock = mock_face();
        mock.wire();
        let mut physical_block = 0u8;
        let phys = unsafe { mock.words.as_mut_ptr().add(FACE_PHY_FONT_WORD) };
        unsafe { phys.add(PFR_FONT_ID_WORD).write(core::ptr::addr_of_mut!(physical_block)) };
        let face_memory = core::ptr::addr_of_mut!(mock.face_memory) as usize;
        unsafe { pfr_face_done(mock.words.as_mut_ptr()) };
        assert_eq!(unsafe { FREE_BLOCKS[0] }, core::ptr::addr_of_mut!(physical_block) as usize);
        assert_eq!(unsafe { FREE_MEMORIES[0] }, face_memory);
    }

    #[test]
    fn physical_font_teardown_precedes_available_sizes_free() {
        let _guard = install_recording_teardown();
        let mut mock = mock_face();
        mock.wire();
        let mut physical_block = 0u8;
        let phys = unsafe { mock.words.as_mut_ptr().add(FACE_PHY_FONT_WORD) };
        unsafe { phys.add(PFR_FONT_ID_WORD).write(core::ptr::addr_of_mut!(physical_block)) };
        let available = mock.words[FACE_AVAILABLE_SIZES_WORD];
        unsafe { pfr_face_done(mock.words.as_mut_ptr()) };
        assert_eq!(unsafe { FREE_CALLS }, 2);
        assert_eq!(unsafe { FREE_BLOCKS[1] }, available as usize);
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
        assert!(mock.words[FACE_FAMILY_NAME_WORD].is_null());
        assert!(mock.words[FACE_STYLE_NAME_WORD].is_null());
    }
    // --- registry_key_hash ---

    /// Serializes tests that replace the host singleton's providers word and
    /// exercise a provider vtable override.
    static REGISTRY_KEY_HASH_TEST_LOCK: StdMutex<()> = StdMutex::new(());

    /// One recorded provider-vtable invocation. The default hash is now a
    /// direct port, so fallback paths deliberately produce no event.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum RegistryEvent {
        VtableHash { name: usize },
    }

    static mut REGISTRY_EVENTS: [Option<RegistryEvent>; 8] = [None; 8];
    static mut REGISTRY_EVENT_COUNT: usize = 0;
    static mut VTABLE_HASH_RESULT: u32 = 0;
    /// When non-null, the provider override rewrites the key's index word
    /// through this alias before returning — pins the `ldr r1,[r4,#0x0]`
    /// reload @ 0x080855e8.
    static mut KEY_INDEX_ALIAS: *mut usize = core::ptr::null_mut();
    static mut KEY_INDEX_REWRITE: usize = 0;

    /// Vtable slot +0x00 of the mock provider object.
    static mut PROVIDER_VTABLE_SLOT: RegistryNameHash = recording_vtable_hash;

    fn record_registry_event(event: RegistryEvent) {
        unsafe {
            let count = REGISTRY_EVENT_COUNT;
            assert!(count < 8, "registry vtable called more than 8 times");
            REGISTRY_EVENTS[count] = Some(event);
            REGISTRY_EVENT_COUNT = count + 1;
        }
    }

    unsafe extern "C" fn recording_vtable_hash(name: *const u8) -> u32 {
        record_registry_event(RegistryEvent::VtableHash { name: name as usize });
        let alias = KEY_INDEX_ALIAS;
        if !alias.is_null() {
            alias.write_volatile(KEY_INDEX_REWRITE);
        }
        VTABLE_HASH_RESULT
    }

    fn registry_events() -> (usize, [Option<RegistryEvent>; 8]) {
        unsafe { (REGISTRY_EVENT_COUNT, REGISTRY_EVENTS) }
    }

    /// Points the host singleton's providers word at `providers`, zeroes the
    /// recorders, and returns the guard serializing the test state.
    fn install_registry_context(providers: *const u32) -> StdMutexGuard<'static, ()> {
        let guard = REGISTRY_KEY_HASH_TEST_LOCK.lock().unwrap();
        unsafe {
            REGISTRY_EVENT_COUNT = 0;
            VTABLE_HASH_RESULT = 0;
            KEY_INDEX_ALIAS = core::ptr::null_mut();
            registry_providers_word().write_volatile(providers);
        }
        guard
    }

    fn uninstall_registry_context() {
        unsafe { registry_providers_word().write_volatile(core::ptr::null()) };
    }

    /// A three-word registry key: index, unused, name pointer.
    fn mock_key(index: usize, name: &[u8]) -> [usize; 3] {
        [index, 0, name.as_ptr() as usize]
    }

    /// Target-layout namespace providers: count at byte +0x00 and its table
    /// pointer at byte +0x04. The 8-byte alignment makes the base stable;
    /// the pointer field is deliberately unaligned on a 64-bit host.
    #[repr(align(8))]
    struct NamespaceProviders([u8; 4 + core::mem::size_of::<*const u32>()]);

    impl NamespaceProviders {
        fn new(entry_count: u32, table: *const u32) -> Self {
            let mut providers = Self([0; 4 + core::mem::size_of::<*const u32>()]);
            unsafe {
                providers.0.as_mut_ptr().cast::<u32>().write_unaligned(entry_count);
                providers
                    .0
                    .as_mut_ptr()
                    .add(4)
                    .cast::<*const u32>()
                    .write_unaligned(table);
            }
            providers
        }

        fn ptr(&self) -> *const u32 {
            self.0.as_ptr().cast()
        }
    }

    #[test]
    fn namespace_provider_count_returns_minus_one_for_null() {
        assert_eq!(unsafe { namespace_provider_count(core::ptr::null()) }, -1);
    }

    #[test]
    fn namespace_provider_count_reads_the_signed_entry_count_word() {
        let empty = NamespaceProviders::new(0, core::ptr::null());
        let populated = NamespaceProviders::new(7, core::ptr::null());
        let negative = NamespaceProviders::new(u32::MAX, core::ptr::null());

        assert_eq!(unsafe { namespace_provider_count(empty.ptr()) }, 0);
        assert_eq!(unsafe { namespace_provider_count(populated.ptr()) }, 7);
        assert_eq!(unsafe { namespace_provider_count(negative.ptr()) }, -1);
    }

    #[test]
    fn namespace_provider_at_returns_null_for_null_providers() {
        assert!(unsafe { namespace_provider_at(core::ptr::null(), 3) }.is_null());
    }

    #[test]
    fn namespace_provider_at_reads_multiple_table_indices_and_null_entries() {
        let first = 0x1111_1111u32;
        let second = 0x2222_2222u32;
        let third = 0x3333_3333u32;
        let table = [
            core::ptr::addr_of!(first),
            core::ptr::null(),
            core::ptr::addr_of!(second),
            core::ptr::addr_of!(third),
        ];
        let providers = NamespaceProviders::new(4, table.as_ptr().cast());

        assert_eq!(unsafe { namespace_provider_at(providers.ptr(), 0) }, table[0]);
        assert!(
            unsafe { namespace_provider_at(providers.ptr(), 1) }.is_null(),
            "a null table entry returns null verbatim"
        );
        assert_eq!(unsafe { namespace_provider_at(providers.ptr(), 2) }, table[2]);
        assert_eq!(unsafe { namespace_provider_at(providers.ptr(), 3) }, table[3]);
    }

    #[test]
    fn default_name_hash_handles_null_empty_and_terminators() {
        assert_eq!(unsafe { registry_default_name_hash(core::ptr::null()) }, 0);
        for name in [&b"\0"[..], &b"\0ignored"[..], &b"a\0trailing"[..]] {
            let expected = if name.first() == Some(&b'a') {
                0x0001_e6c0
            } else {
                0
            };
            assert_eq!(
                unsafe { registry_default_name_hash(name.as_ptr()) },
                expected,
                "name={name:?}"
            );
        }
    }

    #[test]
    fn default_name_hash_salts_each_byte_position() {
        for (name, expected) in [
            (&b"a\0"[..], 0x0001_e6c0),
            (&b"aZ\0"[..], 0x1e69_89cd),
            (&b"abc\0"[..], 0xf547_ad32),
            (&[0x80, 0xff, 0][..], 0x000a_ba0b),
            (&b"abcdefgh\0"[..], 0x9ffa_53e2),
        ] {
            assert_eq!(
                unsafe { registry_default_name_hash(name.as_ptr()) },
                expected,
                "name={name:?}"
            );
        }
    }

    #[test]
    fn null_providers_uses_direct_default_name_hash() {
        let _guard = install_registry_context(core::ptr::null());
        let name = b"settings\0";
        let key = mock_key(7, name);
        let result = unsafe { registry_key_hash(key.as_ptr()) };
        assert_eq!(result, 7 ^ 0xf041_70c8, "index XOR default name hash");
        assert_eq!(registry_events().0, 0, "no provider vtable runs for a null array");
        uninstall_registry_context();
    }

    #[test]
    fn count_not_above_index_uses_direct_default_name_hash() {
        for (provider_count, index) in [(-1i32, 0usize), (0, 0), (1, 1), (2, 7)] {
            let providers_layout =
                NamespaceProviders::new(provider_count as u32, core::ptr::null());
            let _guard = install_registry_context(providers_layout.ptr());
            let name = b"boot\0";
            let key = mock_key(index, name);
            let result = unsafe { registry_key_hash(key.as_ptr()) };
            assert_eq!(
                result,
                index as u32 ^ 0x790b_cf98,
                "count={provider_count} index={index:#x}: the signed ble gate fell back"
            );
            assert_eq!(
                registry_events().0,
                0,
                "namespace_provider_at is never reached when count <= index"
            );
            uninstall_registry_context();
        }
    }

    #[test]
    fn count_above_index_uses_the_direct_provider_table_accessor() {
        for index in [0usize, 1, 7] {
            let provider_count = index as u32 + 1;
            let table = [core::ptr::addr_of!(PROVIDER_VTABLE_SLOT).cast::<u32>(); 8];
            let providers_layout = NamespaceProviders::new(provider_count, table.as_ptr().cast());
            let _guard = install_registry_context(providers_layout.ptr());
            let vtable_hash = 0x5555_0000 | index as u32;
            unsafe {
                VTABLE_HASH_RESULT = vtable_hash;
            }
            let name = b"diag\0";
            let key = mock_key(index, name);
            let result = unsafe { registry_key_hash(key.as_ptr()) };
            assert_eq!(result, index as u32 ^ vtable_hash, "index={index:#x}");
            let (count, events) = registry_events();
            assert_eq!(count, 1, "index={index:#x}");
            assert_eq!(
                events[0],
                Some(RegistryEvent::VtableHash { name: name.as_ptr() as usize }),
                "vtable slot +0x00 of the directly indexed provider hashes the name"
            );
            uninstall_registry_context();
        }
    }



    #[test]
    fn final_xor_reloads_the_index_word() {
        let table = [core::ptr::addr_of!(PROVIDER_VTABLE_SLOT).cast::<u32>(); 8];
        let providers_layout = NamespaceProviders::new(5, table.as_ptr().cast());
        let _guard = install_registry_context(providers_layout.ptr());
        let name = b"k\0";
        let mut key = mock_key(4, name);
        unsafe {
            VTABLE_HASH_RESULT = 0xffff_00ff;
            KEY_INDEX_ALIAS = key.as_mut_ptr();
            KEY_INDEX_REWRITE = 9;
        }
        let result = unsafe { registry_key_hash(key.as_ptr()) };
        assert_eq!(
            result,
            9 ^ 0xffff_00ff,
            "the ldr r1,[r4,#0x0] @ 0x080855e8 reloads the index after the hash call"
        );
        uninstall_registry_context();
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
