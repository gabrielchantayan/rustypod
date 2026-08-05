//! Accessor for an unidentified UI object's state word.

/// object_state_word — original: `FUN_08055e80` @ `0x08055e80` (12 bytes).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/003/08055e80_FUN_08055e80.c`.
/// The ARM leaf loads and returns the little-endian 32-bit state word at
/// offset `0xe38` in an otherwise unidentified UI object. It performs no
/// null or alignment checks, matching the original `ldr` ABI.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_state_word(object: *const u8) -> u32 {
    (object.add(0xe38) as *const u32).read()
}

/// object_state_kind — original: `FUN_08055e00` @ `0x08055e00` (128 bytes).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/003/08055e00_FUN_08055e00.c`;
/// assembly: `decomp/osos.asm` @ `0x08055e00..0x08055e7c`.
///
/// Loads the 32-bit state word at object offset `0xe38` (the same word
/// [`object_state_word`] exposes) and maps it through a ten-entry branch
/// table (`addls pc,pc,r0,lsl #2` after `cmp r0,#9`) to a small kind code:
/// state 0 -> 9, 2 -> 0x18, 3 -> 6, 4 -> 5, 5 -> 1, 6 -> 0x24, 7 -> 0x28,
/// 9 -> 0x2a. States 1 and 8, plus any state word above 9 (the `addls`
/// guard makes the comparison unsigned), fall through to the default code
/// 7. The meaning of the individual kind codes is not recovered; the nine
/// stock call sites forward the code to other UI helpers. Like the original
/// `ldr` at entry, there is no null or alignment guard on `object`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_state_kind(object: *const u8) -> u32 {
    match object_state_word(object) {
        0 => 0x09,
        2 => 0x18,
        3 => 0x06,
        4 => 0x05,
        5 => 0x01,
        6 => 0x24,
        7 => 0x28,
        9 => 0x2a,
        _ => 0x07,
    }
}
/// Byte offset of the nested object pointer (`ldr r0, [r0, #0xf00]`).
const NESTED_OBJECT_POINTER_OFFSET: usize = 0xf00;

/// Byte offset of the flag inside the nested object (`ldrb r0, [r0, #0xb88]`).
const NESTED_OBJECT_FLAG_OFFSET: usize = 0xb88;

/// Byte offset of the property byte inside the nested object
/// (`ldrb r0, [r0, #0xb51]`).
const NESTED_OBJECT_PROPERTY_OFFSET: usize = 0xb51;

/// Byte offset of the attribute byte inside the nested object
/// (`ldrb r0, [r0, #0xb66]`).
const NESTED_OBJECT_ATTRIBUTE_OFFSET: usize = 0xb66;

/// object_nested_flag — original: `FUN_08055f90` @ `0x08055f90` (12 bytes).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/003/08055f90_FUN_08055f90.c`;
/// raw ARM: `ldr r0, [r0, #0xf00]; ldrb r0, [r0, #0xb88]; bx lr`.
/// The leaf follows the pointer at `object + 0xf00`, then loads and returns
/// that nested object's byte at `+0xb88`. `ldrb` zero-extends the returned
/// byte in `r0`; the port exposes that unsigned ABI result as `u8`. Neither
/// pointer is null-checked, matching the original.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_nested_flag(object: *const u8) -> u8 {
    let nested_object = (object.add(NESTED_OBJECT_POINTER_OFFSET) as *const *const u8).read();
    nested_object.add(NESTED_OBJECT_FLAG_OFFSET).read()
}

/// object_nested_property — original: `FUN_08055f9c` @ `0x08055f9c` (12
/// bytes).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/003/08055f9c_FUN_08055f9c.c`;
/// raw ARM: `ldr r0, [r0, #0xf00]; ldrb r0, [r0, #0xb51]; bx lr`.
/// The leaf follows the pointer at `object + 0xf00` (the same nested object
/// [`object_nested_flag`] dereferences), then loads and returns that nested
/// object's byte at `+0xb51`. `ldrb` zero-extends the returned byte in `r0`;
/// the port exposes that unsigned ABI result as `u8`. Neither pointer is
/// null-checked, matching the original. Both stock call sites (in the
/// change-notification routine at 0x081732b0/0x081732c4) cache the byte and
/// fire a virtual callback when it changes, so it behaves as a polled
/// property of the nested object; the property's concrete meaning remains
/// unidentified. The adjacent 0x08055fa8 is the same shape with offset
/// `0xb66` and is a separate function, not a duplicate.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_nested_property(object: *const u8) -> u8 {
    let nested_object = (object.add(NESTED_OBJECT_POINTER_OFFSET) as *const *const u8).read();
    nested_object.add(NESTED_OBJECT_PROPERTY_OFFSET).read()
}

/// object_nested_attribute — original: `FUN_08055fa8` @ `0x08055fa8` (12
/// bytes).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/003/08055fa8_FUN_08055fa8.c`;
/// raw ARM: `ldr r0, [r0, #0xf00]; ldrb r0, [r0, #0xb66]; bx lr`.
/// The leaf follows the pointer at `object + 0xf00` (the same nested object
/// [`object_nested_flag`] and [`object_nested_property`] dereference), then
/// loads and returns that nested object's byte at `+0xb66`. `ldrb`
/// zero-extends the returned byte in `r0`; the port exposes that unsigned
/// ABI result as `u8`. Neither pointer is null-checked, matching the
/// original. Both stock call sites (at 0x081a3890 and 0x081a4d60) store the
/// byte into caller state at `+0xa1` — the second then gates a virtual
/// dispatch on the adjacent byte at `+0xa0` — so it behaves as a cached
/// attribute of the nested object; the attribute's concrete meaning remains
/// unidentified. This is a distinct accessor from the adjacent
/// [`object_nested_property`] @ 0x08055f9c, which reads offset `0xb51`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_nested_attribute(object: *const u8) -> u8 {
    let nested_object = (object.add(NESTED_OBJECT_POINTER_OFFSET) as *const *const u8).read();
    nested_object.add(NESTED_OBJECT_ATTRIBUTE_OFFSET).read()
}


/// The UI sequence identifier state (original global @ `0x089c_fcc4`).
///
/// The firmware reaches this runtime-initialized word through the literal at
/// `0x0805_5ecc`; this static models that target-side state.
pub static mut SEQUENCE_ID: u32 = 0;

/// sequence_id_next — original: `FUN_08055eb8` @ `0x08055eb8` (16 bytes).
///
/// Sources: `/home/gabe/Programming/ipod-decomp/decomp/c/003/08055eb8_FUN_08055eb8.c`
/// and `decomp/osos.asm` @ `0x08055eb8..0x08055ec8`. The decompilation
/// incorrectly declares `void`; the ARM leaf leaves the loaded word in `r0`.
/// It loads the sequence word at `0x089c_fcc4` through its `0x0805_5ecc`
/// literal, stores that word plus one with wrapping 32-bit arithmetic, and
/// returns the pre-increment value. The runtime global is modeled by
/// [`SEQUENCE_ID`] rather than its fixed device address.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sequence_id_next() -> u32 {
    let state = core::ptr::addr_of_mut!(SEQUENCE_ID);
    let sequence_id = core::ptr::read_volatile(state);
    core::ptr::write_volatile(state, sequence_id.wrapping_add(1));
    sequence_id
}

/// The three words inspected by [`indexed_object_offset`], followed by the
/// storage word consumed by its unported base-address callee.
///
/// Call sites at 0x08066bb8, 0x080e2d70, and 0x080e2dc8 pass this header and
/// use a one-based index to address fixed-size records. The callee at
/// 0x080aa828 verifies the same tag and reads `storage` at byte offset 24.
#[repr(C)]
pub struct IndexedObject {
    /// Fixed object-format tag: the literal at 0x08055f20 is `0x6172_6179`.
    pub type_tag: u32,
    /// Byte stride of one stored record.
    pub element_size: u32,
    /// Number of addressable records.
    pub element_count: u32,
    /// Header words not inspected by this helper.
    pub reserved: [u32; 3],
    /// Storage pointer read by the unported 0x080aa828 base-address helper.
    pub storage: *mut u8,
}

/// Object tag loaded from the literal pool at 0x08055f20.
pub const INDEXED_OBJECT_TAG: u32 = 0x6172_6179;

type IndexedObjectStorageBase = unsafe extern "C" fn(*const IndexedObject) -> *mut u8;

/// Calls the stock object-storage-base helper, which remains in retailOS.
///
/// This is deliberately a boundary rather than a port of 0x080aa828. Host
/// tests replace the one function pointer below; ARM builds call its fixed
/// firmware load address.
unsafe extern "C" fn firmware_indexed_object_storage_base(
    object: *const IndexedObject,
) -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        let storage_base: IndexedObjectStorageBase =
            core::mem::transmute(0x080a_a828usize);
        storage_base(object)
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = object;
        core::ptr::null_mut()
    }
}

/// Narrow boundary for the unported 0x080aa828 dependency.
static mut INDEXED_OBJECT_STORAGE_BASE: IndexedObjectStorageBase =
    firmware_indexed_object_storage_base;

#[inline(always)]
unsafe fn indexed_object_storage_base() -> IndexedObjectStorageBase {
    core::ptr::read_volatile(core::ptr::addr_of!(INDEXED_OBJECT_STORAGE_BASE))
}

/// indexed_object_offset — original: `FUN_08055ed0` @ `0x08055ed0` (80
/// bytes).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/003/08055ed0_FUN_08055ed0.c`;
/// assembly: `decomp/osos.asm` @ `0x08055ed0..0x08055f1c`.
///
/// Addresses one-based fixed-size records in an [`IndexedObject`]. It first
/// requires the literal [`INDEXED_OBJECT_TAG`], a nonzero index, and
/// `index <= element_count`; only then does it call retailOS helper
/// 0x080aa828 for the storage base and add `element_size * (index - 1)`.
///
/// # Safety
///
/// `object` must be readable as an aligned [`IndexedObject`]. Like the ARM
/// `ldr` at entry, this function has no null or alignment guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn indexed_object_offset(
    object: *const IndexedObject,
    index: u32,
) -> *mut u8 {
    if (*object).type_tag != INDEXED_OBJECT_TAG
        || index == 0
        || index > (*object).element_count
    {
        return core::ptr::null_mut();
    }

    let storage_base = indexed_object_storage_base()(object);
    storage_base.wrapping_add(
        (*object)
            .element_size
            .wrapping_mul(index.wrapping_sub(1)) as usize,
    )
}

/// Calls the stock 64-bit multiply-accumulate helper, which remains in
/// retailOS.
///
/// This is deliberately a boundary rather than a port of 0x08064980. Host
/// tests replace the one function pointer below; ARM builds call its fixed
/// firmware load address. The original null-guards `fields`, then reads
/// three consecutive little-endian doublewords `base = fields[0]`,
/// `count = fields[1]`, `scale = fields[2]` and returns `base` when
/// `count` is zero, otherwise the wrapping 64-bit product-sum
/// `base + count * scale` (`umull`/`mla`/`mla` for the product, then
/// `adds`/`adc` for the accumulate).
type ScaledFieldTotal = unsafe extern "C" fn(*const u8) -> i64;

unsafe extern "C" fn firmware_scaled_field_total(fields: *const u8) -> i64 {
    #[cfg(target_os = "none")]
    {
        let scaled_field_total: ScaledFieldTotal = core::mem::transmute(0x0806_4980usize);
        scaled_field_total(fields)
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = fields;
        0
    }
}

/// Narrow boundary for the unported 0x08064980 dependency.
static mut SCALED_FIELD_TOTAL: ScaledFieldTotal = firmware_scaled_field_total;

#[inline(always)]
unsafe fn scaled_field_total_fn() -> ScaledFieldTotal {
    core::ptr::read_volatile(core::ptr::addr_of!(SCALED_FIELD_TOTAL))
}

/// object_scaled_total — original: `FUN_08055f24` @ `0x08055f24` (24
/// bytes).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/003/08055f24_FUN_08055f24.c`;
/// assembly: `decomp/osos.asm` @ `0x08055f24..0x08055f38`.
///
/// Null-guarded thunk over the retailOS multiply-accumulate helper
/// 0x08064980: with a null `object` it returns 0 in r0:r1
/// (`moveq r0,#0x0; moveq r1,#0x0`); otherwise it tail-calls the helper
/// with `object + 0x18` (`addne r0,r0,#0x18; bne 0x08064980`), which folds
/// the three doublewords at object offsets 0x18/0x20/0x28 into
/// `base + count * scale` (plain `base` when `count` is zero). The
/// degenerate `object + 0x18 == 0` wraparound also returns 0, matching the
/// flags the `addne` leaves for the `bne`. Ghidra decompiles the thunk
/// with the callee body inlined, which is why the reference C shows the
/// full arithmetic; the callee itself stays in retailOS behind the
/// [`SCALED_FIELD_TOTAL`] boundary. The adjacent 0x08055f3c is the same
/// thunk without the +0x18 offset and is a separate function. The single
/// stock call site (0x080aaf44) applies it to a 0x44-byte descriptor
/// copied by 0x08054d28 and forwards the result together with the
/// sibling's to 0x08045174; the concrete meaning of the field triple is
/// not recovered.
///
/// # Safety
///
/// With a non-null `object`, the firmware helper reads the three
/// doublewords at `object + 0x18..0x30`; `object` must stay readable for
/// at least 0x30 bytes, as at the single stock call site.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_scaled_total(object: *const u8) -> i64 {
    if object.is_null() {
        return 0;
    }
    let fields = object.wrapping_add(0x18);
    if fields.is_null() {
        return 0;
    }
    scaled_field_total_fn()(fields)
}

/// object_scaled_total_base — original: `FUN_08055f3c` @ `0x08055f3c`
/// (20 bytes; functions.csv's 168 counts the fall-through tail Ghidra
/// merged from the following thunks — the original's `bx lr` is at
/// 0x08055f4c).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/003/08055f3c_FUN_08055f3c.c`;
/// assembly: `decomp/osos.asm` @ `0x08055f3c..0x08055f50`.
///
/// Null-guarded thunk over the same retailOS multiply-accumulate helper
/// 0x08064980 that [`object_scaled_total`] uses: with a null `object` it
/// returns 0 in r0:r1 (`moveq r0,#0x0; moveq r1,#0x0`); otherwise it
/// tail-calls the helper with `object` itself (`cmp r0,#0x0;
/// bne 0x08064980`), which folds the three doublewords at object offsets
/// 0/8/0x10 into `base + count * scale` (plain `base` when `count` is
/// zero). Ghidra decompiles the thunk with the callee body inlined, which
/// is why the reference C shows the full arithmetic; the callee itself
/// stays in retailOS behind the [`SCALED_FIELD_TOTAL`] boundary. This is
/// the sibling [`object_scaled_total`] @ 0x08055f24 without the +0x18
/// offset. The single stock call site (0x080aaf54) applies it to the same
/// 0x44-byte descriptor copied by 0x08054d28 as [`object_scaled_total`]
/// and forwards both results together to 0x08045174; the concrete meaning
/// of the field triple is not recovered.
///
/// # Safety
///
/// With a non-null `object`, the firmware helper reads the three
/// doublewords at `object..0x18`; `object` must stay readable for at
/// least 0x18 bytes, as at the single stock call site.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_scaled_total_base(object: *const u8) -> i64 {
    if object.is_null() {
        return 0;
    }
    scaled_field_total_fn()(object)
}

/// Byte offset of the version word inside the retailOS shared context
/// (`ldr r0,[r0,#0x48]` on the context getter's result).
const CONTEXT_VERSION_WORD_OFFSET: usize = 0x48;

/// Counted-payload limit handed to [`crate::libc::counted_copy::cstr_to_counted_u8`]
/// (`mov r2,#0xff`).
const COUNTED_TEXT_LIMIT: u32 = 0xff;

type SharedContext = unsafe extern "C" fn() -> *mut u8;

/// Calls the stock lazy shared-context getter, which remains in retailOS.
///
/// This is deliberately a boundary rather than a port of 0x08369bec. Host
/// tests replace the one function pointer below; ARM builds call its fixed
/// firmware load address. The original publishes a default context pointer
/// into its slot when zero, then returns the slot's context base.
unsafe extern "C" fn firmware_shared_context() -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        let shared_context: SharedContext = core::mem::transmute(0x0836_9becusize);
        shared_context()
    }

    #[cfg(not(target_os = "none"))]
    {
        core::ptr::null_mut()
    }
}

/// Narrow boundary for the unported 0x08369bec dependency.
static mut SHARED_CONTEXT: SharedContext = firmware_shared_context;

#[inline(always)]
unsafe fn shared_context_fn() -> SharedContext {
    core::ptr::read_volatile(core::ptr::addr_of!(SHARED_CONTEXT))
}

type FormatDottedTriple = unsafe extern "C" fn(u32, *mut u8);

/// Calls the stock dotted-triple formatter, which remains in retailOS.
///
/// This is deliberately a boundary rather than a port of 0x0806e0a4. Host
/// tests replace the one function pointer below; ARM builds call its fixed
/// firmware load address. The original splits `word` into `(word >> 24)`,
/// `((word >> 16) & 0xff)` and `(word & 0xffff)` and `sprintf`s them into
/// `dst` through the format string at 0x0806e0d4, `"%d.%d.%d"`.
unsafe extern "C" fn firmware_format_dotted_triple(word: u32, dst: *mut u8) {
    #[cfg(target_os = "none")]
    {
        let format_dotted_triple: FormatDottedTriple =
            core::mem::transmute(0x0806_e0a4usize);
        format_dotted_triple(word, dst)
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = (word, dst);
    }
}

/// Narrow boundary for the unported 0x0806e0a4 dependency.
static mut FORMAT_DOTTED_TRIPLE: FormatDottedTriple = firmware_format_dotted_triple;

#[inline(always)]
unsafe fn format_dotted_triple_fn() -> FormatDottedTriple {
    core::ptr::read_volatile(core::ptr::addr_of!(FORMAT_DOTTED_TRIPLE))
}

type ObjectCountedText = unsafe extern "C" fn(*const u8, *mut u8);

/// Calls the stock counted-text setter, which remains in retailOS.
///
/// This is deliberately a boundary rather than a port of 0x08046a88. Host
/// tests replace the one function pointer below; ARM builds call its fixed
/// firmware load address. The original clears the halfword at `object + 0`,
/// expands the counted string's payload bytes into halfwords at `object + 2`
/// through 0x08046b44, then stores the resulting halfword count at
/// `object + 0`; a null object (or null counted string with a non-null
/// object) makes it return -0x31 after the clear.
unsafe extern "C" fn firmware_object_counted_text(counted: *const u8, object: *mut u8) {
    #[cfg(target_os = "none")]
    {
        let object_counted_text: ObjectCountedText =
            core::mem::transmute(0x0804_6a88usize);
        object_counted_text(counted, object)
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = (counted, object);
    }
}

/// Narrow boundary for the unported 0x08046a88 dependency.
static mut OBJECT_COUNTED_TEXT: ObjectCountedText = firmware_object_counted_text;

#[inline(always)]
unsafe fn object_counted_text_fn() -> ObjectCountedText {
    core::ptr::read_volatile(core::ptr::addr_of!(OBJECT_COUNTED_TEXT))
}

/// object_set_version_text — original: `FUN_08055f50` @ `0x08055f50` (64
/// bytes).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/003/08055f50_FUN_08055f50.c`;
/// assembly: `decomp/osos.asm` @ `0x08055f50..0x08055f8c`.
///
/// Installs the shared context's dotted-triple word as an object's counted
/// text. It fetches the process-wide context through the retailOS lazy
/// getter 0x08369bec, reads the word at `context + 0x48`, and formats it
/// through stock helper 0x0806e0a4 — a `sprintf(dst, "%d.%d.%d", word >> 24,
/// (word >> 16) & 0xff, word & 0xffff)` wrapper over the format string at
/// 0x0806e0d4 — into the upper of two uninitialized 256-byte stack buffers
/// (`sub sp,sp,#0x200`). The ported
/// [`crate::libc::counted_copy::cstr_to_counted_u8`] (0x08045f14) then
/// converts that NUL-terminated text into a byte-counted string in the lower
/// buffer with limit [`COUNTED_TEXT_LIMIT`], and stock setter 0x08046a88
/// installs the counted text on `object` (halfword count at `object + 0`,
/// expanded halfword payload at `object + 2`). The context word's identity
/// as a version is inferred from the dotted-triple format and from the
/// byte-identical sibling 0x08052228, which reads `context + 0x4c` and is a
/// separate function. The single stock call site (0x08112800) sits in a
/// dispatch chain of field setters (0x08052228, 0x08054d78, 0x08054ea0,
/// 0x080539f0) that fill a stack object at `sp + 0x5c` before 0x081131a8
/// merges it into the record at `r5 + 0xf8` — an about/diagnostics-style
/// text field; the concrete field is not recovered. Ghidra declares the
/// original `void`; its r0 residue is 0x08046a88's return, which the call
/// site ignores, so the port returns nothing. The original's `mov r4,r0`
/// keeps `object` in a callee-saved register across the calls — a register
/// allocation detail, not observable state. The three stock helpers stay in
/// retailOS behind the [`SHARED_CONTEXT`], [`FORMAT_DOTTED_TRIPLE`] and
/// [`OBJECT_COUNTED_TEXT`] boundaries.
///
/// # Safety
///
/// Like the original, there is no null guard: the context getter must return
/// a pointer readable at `+0x48`, and `object` must be valid for the stock
/// setter's halfword writes (the setter itself tolerates a null `object` by
/// returning -0x31 after no write).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_set_version_text(object: *mut u8) {
    let context = shared_context_fn()();
    let version_word =
        (context.add(CONTEXT_VERSION_WORD_OFFSET) as *const u32).read();

    // The original reserves two uninitialized 256-byte stack buffers
    // (`sub sp,sp,#0x200`) and never clears them.
    let mut formatted = core::mem::MaybeUninit::<[u8; 256]>::uninit();
    let mut counted = core::mem::MaybeUninit::<[u8; 256]>::uninit();

    format_dotted_triple_fn()(version_word, formatted.as_mut_ptr() as *mut u8);
    crate::libc::counted_copy::cstr_to_counted_u8(
        formatted.as_ptr() as *const u8,
        counted.as_mut_ptr() as *mut u8,
        COUNTED_TEXT_LIMIT,
    );
    object_counted_text_fn()(counted.as_ptr() as *const u8, object);
}

/// Sampled-clock interface index the original passes to 0x0809b60c
/// (`mov r0,#0x0` before the `bl`).
const TIMESTAMP_INTERFACE: u32 = 0;

/// Fixed-point scale applied to the raw sample: a 64-bit left shift by 10
/// (`mov r1,r1,lsl #0xa; orr r1,r1,r0,lsr #0x16; mov r0,r0,lsl #0xa`).
const TIMESTAMP_SCALE_SHIFT: u32 = 10;

type ClockSample = unsafe extern "C" fn(u32) -> i64;

/// Calls the stock sampled-clock getter, which remains in retailOS.
///
/// This is deliberately a boundary rather than a port of 0x0809b60c. Host
/// tests replace the one function pointer below; ARM builds call its fixed
/// firmware load address. The original constructs a temporary stack object
/// around interface `interface` (0x08206e40), reads its current sample via
/// 0x08296f18, destroys the object (0x08206e6c), and returns the sample
/// zero-extended to 64 bits in r0:r1.
unsafe extern "C" fn firmware_clock_sample(interface: u32) -> i64 {
    #[cfg(target_os = "none")]
    {
        let clock_sample: ClockSample = core::mem::transmute(0x0809_b60cusize);
        clock_sample(interface)
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = interface;
        0
    }
}

/// Narrow boundary for the unported 0x0809b60c dependency.
static mut CLOCK_SAMPLE: ClockSample = firmware_clock_sample;

#[inline(always)]
unsafe fn clock_sample_fn() -> ClockSample {
    core::ptr::read_volatile(core::ptr::addr_of!(CLOCK_SAMPLE))
}

/// scaled_timestamp_now — original: `FUN_08055fb4` @ `0x08055fb4` (28
/// bytes).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/003/08055fb4_FUN_08055fb4.c`;
/// assembly: `decomp/osos.asm` @ `0x08055fb4..0x08055fcc`.
///
/// Calls retailOS sampled-clock getter 0x0809b60c with interface index
/// [`TIMESTAMP_INTERFACE`] and returns its 64-bit sample shifted left by
/// [`TIMESTAMP_SCALE_SHIFT`] bits in r0:r1 — a fixed-point timestamp 2^10
/// times finer than the raw getter's unit (the concrete unit is not
/// recovered). All three stock call sites (0x08141640, 0x081417a8,
/// 0x081eb42c) subtract a lazily snapshotted baseline from the result:
/// 0x08055ff8 returns the doubleword at global 0x089c_a5e0 + 0x20, first
/// populated by 0x08055fd0, which stores the identically scaled sample of
/// sibling getter 0x08090b88; the callers then convert the 64-bit delta to
/// `double`, so the function behaves as the "now" half of an elapsed-time
/// measurement. The original's `push {r4,lr}` never uses r4 — an ADS frame
/// artifact not reproduced here.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn scaled_timestamp_now() -> i64 {
    clock_sample_fn()(TIMESTAMP_INTERFACE) << TIMESTAMP_SCALE_SHIFT
}

/// The elapsed-time baseline slot at global 0x089c_a5e0 + 0x20.
///
/// The firmware reaches this doubleword through the literals at
/// `0x0805_5ff4` (0x08055fd0's `strd` store) and `0x0805_6024`
/// (0x08055ff8's lazy `ldrd` load), both holding 0x089c_a5e0; this static
/// models that target-side state. To the lazy getter 0x08055ff8, a zero
/// doubleword means "not yet snapshotted".
pub static mut TIMESTAMP_BASELINE: i64 = 0;

/// Calls the stock baseline-clock getter, which remains in retailOS.
///
/// This is deliberately a boundary rather than a port of 0x08090b88. Host
/// tests replace the one function pointer below; ARM builds call its fixed
/// firmware load address. Like its sibling 0x0809b60c (see
/// [`firmware_clock_sample`]), the original constructs a temporary stack
/// object around interface `interface` (0x08206e40) and destroys it
/// (0x08206e6c), but reads through the sibling accessor 0x08296ea4 instead
/// of 0x08296f18 and returns that 32-bit result zero-extended to 64 bits
/// in r0:r1 (`mov r1,r5` with r5 zeroed at 0x08090b9c).
unsafe extern "C" fn firmware_baseline_clock_sample(interface: u32) -> i64 {
    #[cfg(target_os = "none")]
    {
        let clock_sample: ClockSample = core::mem::transmute(0x0809_0b88usize);
        clock_sample(interface)
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = interface;
        0
    }
}

/// Narrow boundary for the unported 0x08090b88 dependency.
static mut BASELINE_CLOCK_SAMPLE: ClockSample = firmware_baseline_clock_sample;

#[inline(always)]
unsafe fn baseline_clock_sample_fn() -> ClockSample {
    core::ptr::read_volatile(core::ptr::addr_of!(BASELINE_CLOCK_SAMPLE))
}

/// snapshot_timestamp_baseline — original: `FUN_08055fd0` @ `0x08055fd0`
/// (36 bytes).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/003/08055fd0_FUN_08055fd0.c`;
/// assembly: `decomp/osos.asm` @ `0x08055fd0..0x08055ff0`.
///
/// Calls retailOS baseline-clock getter 0x08090b88 with interface index
/// [`TIMESTAMP_INTERFACE`], shifts its 64-bit sample left by
/// [`TIMESTAMP_SCALE_SHIFT`] bits (the same fixed-point scale
/// [`scaled_timestamp_now`] applies to sibling getter 0x0809b60c), and
/// stores the result as the doubleword at global 0x089c_a5e0 + 0x20
/// (`strd r0,r1,[r2,#0x20]`, modeled by [`TIMESTAMP_BASELINE`]). This is
/// the "snapshot" half of the firmware's elapsed-time measurement: the
/// lazy getter 0x08055ff8 calls it to populate a zero baseline, and all
/// three [`scaled_timestamp_now`] call sites subtract that baseline from
/// the current sample. Ghidra declares the original `void`, but it leaves
/// the scaled sample in r0:r1 and both non-trivial call sites rely on the
/// residue — 0x08055ff8 re-stores r0:r1 right after its `bl`, and
/// 0x081eb420 moves them into r6/r8 as the subtrahend for the following
/// `scaled_timestamp_now` delta — so the port returns the stored value.
/// The original's `push {r4,lr}` never uses r4 — an ADS frame artifact not
/// reproduced here.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn snapshot_timestamp_baseline() -> i64 {
    let scaled_sample =
        baseline_clock_sample_fn()(TIMESTAMP_INTERFACE) << TIMESTAMP_SCALE_SHIFT;
    core::ptr::addr_of_mut!(TIMESTAMP_BASELINE).write_volatile(scaled_sample);
    scaled_sample
}

/// timestamp_baseline — original: `FUN_08055ff8` @ `0x08055ff8` (44
/// bytes).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/003/08055ff8_FUN_08055ff8.c`;
/// assembly: `decomp/osos.asm` @ `0x08055ff8..0x08056020`.
///
/// Lazily initializes and returns the elapsed-time baseline doubleword at
/// global 0x089c_a5e0 + 0x20 (modeled by [`TIMESTAMP_BASELINE`]). It loads
/// the slot (`ldrd r0,r1,[r4,#0x20]`), treats a zero doubleword as "not
/// yet snapshotted" (`cmp r1,#0; cmpeq r0,r2`), and only then calls
/// [`snapshot_timestamp_baseline`] (0x08055fd0), storing its r0:r1 result
/// back into the slot (`strd r0,r1,[r4,#0x20]`) before returning it
/// (`ldrd` again). A nonzero slot is returned untouched, so the baseline
/// is sampled exactly once over the device's uptime. All three stock call
/// sites (0x0814164c, 0x081417b4, 0x081eb418) subtract the result from a
/// following [`scaled_timestamp_now`] sample and convert the 64-bit delta
/// to `double`, so this is the "zero point" half of the firmware's
/// elapsed-time measurement. The original's `push {r4,lr}` holds the
/// global pointer in r4 across the call — a register-allocation detail,
/// not observable state — and is not reproduced here.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn timestamp_baseline() -> i64 {
    if core::ptr::addr_of!(TIMESTAMP_BASELINE).read_volatile() == 0 {
        let scaled_sample = snapshot_timestamp_baseline();
        core::ptr::addr_of_mut!(TIMESTAMP_BASELINE).write_volatile(scaled_sample);
    }
    core::ptr::addr_of!(TIMESTAMP_BASELINE).read_volatile()
}

/// Byte offset of the mode flag word inside the retailOS shared context
/// (`ldr r0,[r0,#0x94]` on the context getter's result).
const CONTEXT_MODE_FLAG_OFFSET: usize = 0x94;

/// context_mode_flag — original: `FUN_08056028` @ `0x08056028` (20 bytes).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/003/08056028_FUN_08056028.c`;
/// assembly: `decomp/osos.asm` @ `0x08056028..0x08056038`.
///
/// Fetches the process-wide shared context through the retailOS lazy getter
/// 0x08369bec (the same [`SHARED_CONTEXT`] boundary [`object_set_version_text`]
/// uses), loads the word at `context + 0x94`, and returns its low bit
/// (`and r0,r0,#0x1`) — a boolean flag of the shared context. The single
/// stock call site (0x081602b0, grep -c on `decomp/osos.asm`) lazily caches
/// a record size selected by the flag into a global slot: 0x100 when the
/// bit is clear, 0xd8 when set (`moveq r0,#0x100; movne r0,#0xd8`), so the
/// bit behaves as a two-state layout/capacity mode selector; the concrete
/// mode is not recovered. The context getter stays in retailOS behind the
/// [`SHARED_CONTEXT`] boundary. The original's `push {r4,lr}` never uses
/// r4 — an ADS frame artifact not reproduced here.
///
/// # Safety
///
/// Like the original, there is no null guard: the context getter must
/// return a pointer readable at `+0x94`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn context_mode_flag() -> u32 {
    (shared_context_fn()().add(CONTEXT_MODE_FLAG_OFFSET) as *const u32).read() & 1
}

/// Byte offset of the companion word inside the nested object
/// (`ldr r0, [r0, #0xb54]`).
const NESTED_OBJECT_COMPANION_WORD_OFFSET: usize = 0xb54;

/// object_nested_companion_word — original: `FUN_0805603c` @ `0x0805603c`
/// (12 bytes).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/003/0805603c_FUN_0805603c.c`;
/// raw ARM: `ldr r0, [r0, #0xf00]; ldr r0, [r0, #0xb54]; bx lr`.
/// The leaf follows the pointer at `object + 0xf00` (the same nested object
/// [`object_nested_flag`], [`object_nested_property`] and
/// [`object_nested_attribute`] dereference), then loads and returns that
/// nested object's full 32-bit word at `+0xb54` — a word `ldr`, unlike the
/// zero-extending `ldrb` of the byte accessors. Neither pointer is
/// null-checked, matching the original. The single stock call site
/// (0x08160278, in the tail-dispatch setup at 0x08160254) obtains the owner
/// through 0x08289690()->+0x28->+0x30, stores the sibling
/// `rtc_context_handle` @ 0x08056124 (the nested object's `+0x0c` handle
/// word) result at its `+0x54`, then passes this `+0xb54` companion word as
/// `r1` to its vtable `+0x84` method; the word's concrete meaning remains
/// unidentified.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_nested_companion_word(object: *const u8) -> u32 {
    let nested_object = (object.add(NESTED_OBJECT_POINTER_OFFSET) as *const *const u8).read();
    (nested_object.add(NESTED_OBJECT_COMPANION_WORD_OFFSET) as *const u32).read()
}

/// Byte offset of the object's inline text buffer (`add r1,r4,#0x1c`).
const OBJECT_TEXT_OFFSET: usize = 0x1c;

/// Text-length clamp applied to the query result's length halfword
/// (`cmp r2,#0xff; movhi r2,#0xff`): the inline buffer at
/// [`OBJECT_TEXT_OFFSET`] holds at most 0xff bytes plus the NUL
/// terminator the function stores itself.
const OBJECT_TEXT_LIMIT: u16 = 0xff;

/// Byte offset of the object's field word (`str r0,[r4,#0x188]`).
const OBJECT_FIELD_WORD_OFFSET: usize = 0x188;

/// Byte offset of the object's tag halfword (`ldrh r0,[r4,#0x2]`).
const OBJECT_TAG_OFFSET: usize = 0x2;

/// Tag halfword selecting the extended object layout — the same value the
/// query helper 0x08051600 tests (`*(short *)(param_1 + 2) == 0x482b`) to
/// pick its larger inline capacity.
const OBJECT_TAG_EXTENDED: u16 = 0x482b;

/// Byte offset of the tagged-layout-only word (`streq r0,[r4,#0x4]`).
const OBJECT_TAGGED_WORD_OFFSET: usize = 0x4;

/// Query kind passed to the stock helper in r1 (`mov r1,#0x2`).
const FIELD_QUERY_KIND: u32 = 2;

/// Result-flags bit marking the text pointer as heap-owned (`tst r0,#0x1`).
const FIELD_RESULT_HEAP_TEXT: u16 = 0x1;

/// Result block filled by the stock field-query helper 0x08051600.
///
/// The original reserves the block at `sp + 0x10` inside its 0x248-byte
/// frame and zeroes only the 0x2c-byte tail at block offset `+0x208`
/// (flags, length, pointer and the head of the inline text buffer)
/// through the IRAM memzero veneer 0x08037db8. Only the fields this
/// caller consumes are named; the gaps are the helper's private scratch
/// (its decompilation shows field-type tags and a sub-query header living
/// there). The layout extends to `+0x238`, the end of the original frame.
#[repr(C)]
struct FieldQueryResult {
    _head: [u8; 0xc],
    /// Block `+0x0c`: stored into a tagged object's `+0x4` word.
    tagged_word: u32,
    _middle: [u8; 0x40],
    /// Block `+0x50`: stored into the object's `+0x188` word.
    field_word: u32,
    _scratch: [u8; 0x1b4],
    /// Block `+0x208`: result flags; bit 0 = heap-owned text pointer.
    flags: u16,
    /// Block `+0x20a`: text length in bytes.
    text_len: u16,
    _reserved: [u8; 4],
    /// Block `+0x210`: the text bytes — the helper's inline buffer at
    /// `+0x214`, or a heap allocation when [`FIELD_RESULT_HEAP_TEXT`] is
    /// set.
    text: *mut u8,
    /// Block `+0x214`: head of the helper's inline text buffer, out to
    /// the end of the original's stack frame.
    _inline_text: [u8; 0x24],
}

type FieldQuery = unsafe extern "C" fn(
    object: *mut u8,
    kind: u32,
    key: u32,
    key_len: u32,
    reserved: u32,
    result: *mut FieldQueryResult,
    query_word: *mut u32,
) -> i32;

/// Calls the stock record field-query helper, which remains in retailOS.
///
/// This is deliberately a boundary rather than a port of 0x08051600. Host
/// tests replace the one function pointer below; ARM builds call its fixed
/// firmware load address. The original resolves field `kind` of `object`'s
/// record (0x08043444), reads the typed value (0x08041d48) — chasing
/// sub-record lookups through 0x0805bfd0/0x0805be98 depending on the
/// `0x482b` object tag — and fills `result`: field-type tags and a
/// sub-query header in the scratch gaps, flags at `+0x208`, the text
/// length at `+0x20a`, and the text pointer at `+0x210` (its inline
/// buffer at `+0x214`, or a heap allocation marked with flags bit 0).
/// `key`/`key_len` select an optional named sub-field (both zero at this
/// call site); `query_word` is an in/out detail word. The return is a
/// status code: 0 on success, with 0x20 remapped to 0x30.
unsafe extern "C" fn firmware_field_query(
    object: *mut u8,
    kind: u32,
    key: u32,
    key_len: u32,
    reserved: u32,
    result: *mut FieldQueryResult,
    query_word: *mut u32,
) -> i32 {
    #[cfg(target_os = "none")]
    {
        let field_query: FieldQuery = core::mem::transmute(0x0805_1600usize);
        field_query(object, kind, key, key_len, reserved, result, query_word)
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = (object, kind, key, key_len, reserved, result, query_word);
        // A nonzero status keeps host callers on the untouched failure path.
        -1
    }
}

/// Narrow boundary for the unported 0x08051600 dependency.
static mut FIELD_QUERY: FieldQuery = firmware_field_query;

#[inline(always)]
unsafe fn field_query_fn() -> FieldQuery {
    core::ptr::read_volatile(core::ptr::addr_of!(FIELD_QUERY))
}

type HeapFree = unsafe extern "C" fn(*mut u8);

/// Calls the stock heap free, which remains in retailOS.
///
/// This is deliberately a boundary rather than a port of 0x08049398. Host
/// tests replace the one function pointer below; ARM builds call its fixed
/// firmware load address. The original is the retailOS allocator's free:
/// it returns immediately on a null pointer, validates the eight-byte
/// allocation header, decrements the pool accounting, and returns the
/// block to its pool. This caller invokes it only for query-result text
/// the helper flagged heap-owned.
unsafe extern "C" fn firmware_heap_free(pointer: *mut u8) {
    #[cfg(target_os = "none")]
    {
        let heap_free: HeapFree = core::mem::transmute(0x0804_9398usize);
        heap_free(pointer)
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = pointer;
    }
}

/// Narrow boundary for the unported 0x08049398 dependency.
static mut HEAP_FREE: HeapFree = firmware_heap_free;

#[inline(always)]
unsafe fn heap_free_fn() -> HeapFree {
    core::ptr::read_volatile(core::ptr::addr_of!(HEAP_FREE))
}

/// object_install_field_text — original: `FUN_08056048` @ `0x08056048`
/// (220 bytes).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/003/08056048_FUN_08056048.c`;
/// assembly: `decomp/osos.asm` @ `0x08056048..0x08056120`.
///
/// Fetches field kind [`FIELD_QUERY_KIND`] of the object's record through
/// the retailOS query helper 0x08051600 and installs the returned text on
/// the object. It zeroes the 0x2c-byte tail of a 0x238-byte stack result
/// block (the flags/length/pointer head at `+0x208`, through the IRAM
/// memzero veneer 0x08037db8) and a separate query word, then calls the
/// helper with `(object, 2, 0, 0, 0, &block, &word)` — Ghidra's 12-byte
/// `auStack_248` is an artifact: the helper's own decompilation writes
/// the block out to `param_6 + 0x214`, so the sixth argument is the whole
/// 0x238-byte block. On a zero status it clamps the block's length
/// halfword (`+0x20a`) to [`OBJECT_TEXT_LIMIT`], copies that many bytes
/// from the block's text pointer (`+0x210`) into the object's inline
/// buffer at `+0x1c` through the ported [`crate::libc::bcopy::bcopy`]
/// (0x08042cbc), stores a NUL terminator at `object + 0x1c + len`, stores
/// the block's `+0x50` word into `object + 0x188`, and — only when the
/// object's tag halfword at `+2` is [`OBJECT_TAG_EXTENDED`] (`sub
/// r12,r0,#0x4800; subs r12,r12,#0x2b`) — stores the block's `+0x0c` word
/// into `object + 4`. Then, regardless of status, if bit 0 of the block's
/// flags halfword is set it frees the text pointer through the retailOS
/// heap free 0x08049398. The helper's status is returned in r0. The
/// single stock call site (0x08161fb8, grep -c on `decomp/osos.asm`)
/// applies it to the sub-record at `r4 + 0x208` after building three
/// sibling records and running 0x08058150, and discards the result — an
/// init-time text/field population step; the fetched field's concrete
/// meaning is not recovered.
///
/// Deviations: the port zero-initializes the entire result block instead
/// of memset-ing only its `+0x208..+0x234` tail — the head fields are
/// only read after the helper writes them on the success path — and it
/// skips the original's dead post-free cleanup (clearing the flag bit and
/// nulling the pointer in the dying stack frame) and the redundant
/// `strh` re-zeroing the flags right after the memset. The original's
/// reload-and-reclamp of the length for the terminator store recomputes
/// the same value and is folded into one clamp here. The query helper
/// and heap free stay in retailOS behind the [`FIELD_QUERY`] and
/// [`HEAP_FREE`] boundaries; the copy runs the ported bcopy directly.
///
/// # Safety
///
/// Like the original, there is no null guard on `object`: it must be
/// writable for at least 0x18c bytes (text buffer at `+0x1c`, tag at
/// `+2`, words at `+4` and `+0x188`), as at the single stock call site.
/// The stock helper must fill the block's flags/length/pointer on its
/// success path, and a flagged text pointer must be a live allocation of
/// the retailOS heap.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_install_field_text(object: *mut u8) -> i32 {
    let mut result: FieldQueryResult = core::mem::zeroed();
    let mut query_word: u32 = 0;
    let status = field_query_fn()(
        object,
        FIELD_QUERY_KIND,
        0,
        0,
        0,
        &mut result,
        &mut query_word,
    );
    if status == 0 {
        let text_len = result.text_len.min(OBJECT_TEXT_LIMIT) as usize;
        crate::libc::bcopy::bcopy(result.text, object.add(OBJECT_TEXT_OFFSET), text_len);
        object.add(OBJECT_TEXT_OFFSET + text_len).write(0);
        (object.add(OBJECT_FIELD_WORD_OFFSET) as *mut u32).write(result.field_word);
        if (object.add(OBJECT_TAG_OFFSET) as *const u16).read() == OBJECT_TAG_EXTENDED {
            (object.add(OBJECT_TAGGED_WORD_OFFSET) as *mut u32).write(result.tagged_word);
        }
    }
    if result.flags & FIELD_RESULT_HEAP_TEXT != 0 {
        heap_free_fn()(result.text);
    }
    status
}

type ObjectKindTable = unsafe extern "C" fn(*const u8, u32) -> *const u64;

/// Calls the stock kind-indexed mask-table getter, which remains in
/// retailOS.
///
/// This is deliberately a boundary rather than a port of 0x080e4e64. Host
/// tests replace the one function pointer below; ARM builds call its fixed
/// firmware load address. The original takes `(object, kind)`: for `kind ==
/// 1` with bit 0 of the byte at `object + 0x18c` set it returns the override
/// table pointer at literal 0x080e4e84; otherwise it tail-calls the kind
/// switch 0x080d8948, which returns one of the per-kind table pointers
/// 0x080d8b68..0x080d8c10 (null for kinds 0, 1 without the flag, and any
/// kind above 0x2c).
unsafe extern "C" fn firmware_object_kind_table(
    object: *const u8,
    kind: u32,
) -> *const u64 {
    #[cfg(target_os = "none")]
    {
        let object_kind_table: ObjectKindTable =
            core::mem::transmute(0x080e_4e64usize);
        object_kind_table(object, kind)
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = (object, kind);
        core::ptr::null()
    }
}

/// Narrow boundary for the unported 0x080e4e64 dependency.
static mut OBJECT_KIND_TABLE: ObjectKindTable = firmware_object_kind_table;

#[inline(always)]
unsafe fn object_kind_table_fn() -> ObjectKindTable {
    core::ptr::read_volatile(core::ptr::addr_of!(OBJECT_KIND_TABLE))
}

/// object_kind_mask_union — original: `FUN_08055db8` @ `0x08055db8` (72
/// bytes).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/003/08055db8_FUN_08055db8.c`;
/// assembly: `decomp/osos.asm` @ `0x08055db8..0x08055dfc`.
///
/// Folds the per-kind mask table into a 64-bit union. The original forwards
/// `(object, kind)` untouched in r0/r1 to the retailOS table getter
/// 0x080e4e64 (`bl 0x080e4e64` with no argument setup — Ghidra's
/// zero-argument `FUN_08055db8(void)` decompilation is an artifact; the
/// single stock call site at 0x08067968 passes its record owner in r0 and
/// the word at `record + 0x14` in r1). With a null table it returns 0 in
/// r0:r1; otherwise it walks the table of 64-bit entries with `ldrd`,
/// OR-ing each entry's low word into one accumulator and its high word into
/// another (`orr r5,r5,r0` / `orr r6,r6,r1`), advancing eight bytes at a
/// time until a zero doubleword terminator, and returns the two
/// accumulators in r0:r1 — modeled here as one `u64`. The call site ORs
/// the result into the 64-bit field at `object + 0x1d0`, alongside a
/// sibling fold through 0x08054b0c, so the function aggregates the table's
/// entries into a combined mask; the masks' concrete meaning is not
/// recovered. The redundant `ldrdne r0,r1,[r4,#0x0]` reload inside the
/// loop is an ADS artifact — the zero test clobbers no register — and is
/// not reproduced. The table getter stays in retailOS behind the
/// [`OBJECT_KIND_TABLE`] boundary.
///
/// # Safety
///
/// Like the original, there is no null guard on `object`: the stock getter
/// may dereference it (`ldrb r0,[r0,#0x18c]` for `kind == 1`). A non-null
/// table must be a readable, 8-byte-aligned run of 64-bit entries ending in
/// a zero doubleword, as every stock table is.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_kind_mask_union(object: *const u8, kind: u32) -> u64 {
    let mut union: u64 = 0;
    let mut entry = object_kind_table_fn()(object, kind);
    if !entry.is_null() {
        loop {
            let mask = entry.read();
            if mask == 0 {
                break;
            }
            union |= mask;
            entry = entry.add(1);
        }
    }
    union
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    use std::sync::{Mutex, MutexGuard};

    static SEQUENCE_ID_LOCK: Mutex<()> = Mutex::new(());
    static INDEXED_OBJECT_STORAGE_BASE_LOCK: Mutex<()> = Mutex::new(());
    static SCALED_FIELD_TOTAL_LOCK: Mutex<()> = Mutex::new(());
    static CLOCK_SAMPLE_LOCK: Mutex<()> = Mutex::new(());
    static BASELINE_CLOCK_SAMPLE_LOCK: Mutex<()> = Mutex::new(());
    static mut CLOCK_SAMPLE_CALLS: u32 = 0;
    static mut CLOCK_SAMPLE_INTERFACE: u32 = u32::MAX;
    static mut MOCK_SAMPLE: i64 = 0;
    static mut BASELINE_SAMPLE_CALLS: u32 = 0;
    static mut BASELINE_SAMPLE_INTERFACE: u32 = u32::MAX;
    static mut MOCK_BASELINE_SAMPLE: i64 = 0;

    unsafe extern "C" fn recording_baseline_clock_sample(interface: u32) -> i64 {
        BASELINE_SAMPLE_CALLS += 1;
        BASELINE_SAMPLE_INTERFACE = interface;
        MOCK_BASELINE_SAMPLE
    }

    /// Restores the stock-call boundary before another test uses it.
    struct BaselineClockSampleReset;

    impl Drop for BaselineClockSampleReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(BASELINE_CLOCK_SAMPLE)
                    .write(firmware_baseline_clock_sample);
                core::ptr::addr_of_mut!(TIMESTAMP_BASELINE).write(0);
            }
        }
    }

    fn install_recording_baseline_clock_sample(sample: i64) -> MutexGuard<'static, ()> {
        let guard = BASELINE_CLOCK_SAMPLE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            BASELINE_SAMPLE_CALLS = 0;
            BASELINE_SAMPLE_INTERFACE = u32::MAX;
            MOCK_BASELINE_SAMPLE = sample;
            core::ptr::addr_of_mut!(TIMESTAMP_BASELINE).write(i64::MIN);
            core::ptr::addr_of_mut!(BASELINE_CLOCK_SAMPLE)
                .write(recording_baseline_clock_sample);
        }
        guard
    }

    unsafe extern "C" fn recording_clock_sample(interface: u32) -> i64 {
        CLOCK_SAMPLE_CALLS += 1;
        CLOCK_SAMPLE_INTERFACE = interface;
        MOCK_SAMPLE
    }

    /// Restores the stock-call boundary before another test uses it.
    struct ClockSampleReset;

    impl Drop for ClockSampleReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(CLOCK_SAMPLE).write(firmware_clock_sample);
            }
        }
    }

    fn install_recording_clock_sample(sample: i64) -> MutexGuard<'static, ()> {
        let guard = CLOCK_SAMPLE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            CLOCK_SAMPLE_CALLS = 0;
            CLOCK_SAMPLE_INTERFACE = u32::MAX;
            MOCK_SAMPLE = sample;
            core::ptr::addr_of_mut!(CLOCK_SAMPLE).write(recording_clock_sample);
        }
        guard
    }
    static mut STORAGE_BASE_CALLS: u32 = 0;
    static mut STORAGE_BASE_OBJECT: usize = 0;
    static mut MOCK_STORAGE_BASE: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_storage_base(object: *const IndexedObject) -> *mut u8 {
        STORAGE_BASE_CALLS += 1;
        STORAGE_BASE_OBJECT = object as usize;
        MOCK_STORAGE_BASE
    }

    /// Restores the stock-call boundary before another test uses it.
    struct StorageBaseReset;

    impl Drop for StorageBaseReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(INDEXED_OBJECT_STORAGE_BASE)
                    .write(firmware_indexed_object_storage_base);
            }
        }
    }

    fn install_recording_storage_base(storage_base: *mut u8) -> MutexGuard<'static, ()> {
        let guard = INDEXED_OBJECT_STORAGE_BASE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            STORAGE_BASE_CALLS = 0;
            STORAGE_BASE_OBJECT = 0;
            MOCK_STORAGE_BASE = storage_base;
            core::ptr::addr_of_mut!(INDEXED_OBJECT_STORAGE_BASE).write(recording_storage_base);
        }
        guard
    }

    static mut SCALED_TOTAL_CALLS: u32 = 0;
    static mut SCALED_TOTAL_FIELDS: usize = 0;
    static mut MOCK_SCALED_TOTAL: i64 = 0;

    unsafe extern "C" fn recording_scaled_field_total(fields: *const u8) -> i64 {
        SCALED_TOTAL_CALLS += 1;
        SCALED_TOTAL_FIELDS = fields as usize;
        MOCK_SCALED_TOTAL
    }

    /// Restores the stock-call boundary before another test uses it.
    struct ScaledFieldTotalReset;

    impl Drop for ScaledFieldTotalReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(SCALED_FIELD_TOTAL).write(firmware_scaled_field_total);
            }
        }
    }

    fn install_recording_scaled_field_total(total: i64) -> MutexGuard<'static, ()> {
        let guard = SCALED_FIELD_TOTAL_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            SCALED_TOTAL_CALLS = 0;
            SCALED_TOTAL_FIELDS = 0;
            MOCK_SCALED_TOTAL = total;
            core::ptr::addr_of_mut!(SCALED_FIELD_TOTAL).write(recording_scaled_field_total);
        }
        guard
    }

    fn indexed_object(
        type_tag: u32,
        element_size: u32,
        element_count: u32,
    ) -> IndexedObject {
        IndexedObject {
            type_tag,
            element_size,
            element_count,
            reserved: [0; 3],
            storage: core::ptr::null_mut(),
        }
    }

    fn seed_sequence_id(value: u32) {
        unsafe {
            core::ptr::write_volatile(core::ptr::addr_of_mut!(SEQUENCE_ID), value);
        }
    }

    fn sequence_id() -> u32 {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SEQUENCE_ID)) }
    }

    #[test]
    fn returns_the_word_at_offset_e38() {
        let mut object = [0u8; 0xe3c];
        object[0xe38..0xe3c].copy_from_slice(&0x89ab_cdefu32.to_le_bytes());

        assert_eq!(unsafe { object_state_word(object.as_ptr()) }, 0x89ab_cdef);
    }

    #[test]
    fn maps_every_jump_table_state_to_its_kind_code() {
        let mut object = [0u8; 0xe3c];
        let expected = [
            (0u32, 0x09u32),
            (1, 0x07),
            (2, 0x18),
            (3, 0x06),
            (4, 0x05),
            (5, 0x01),
            (6, 0x24),
            (7, 0x28),
            (8, 0x07),
            (9, 0x2a),
        ];

        for (state, kind) in expected {
            object[0xe38..0xe3c].copy_from_slice(&state.to_le_bytes());
            assert_eq!(unsafe { object_state_kind(object.as_ptr()) }, kind);
        }
    }

    #[test]
    fn out_of_range_states_fall_through_to_the_default_kind() {
        let mut object = [0u8; 0xe3c];

        for state in [10u32, 11, 0xffff, 0x8000_0000, u32::MAX] {
            object[0xe38..0xe3c].copy_from_slice(&state.to_le_bytes());
            assert_eq!(unsafe { object_state_kind(object.as_ptr()) }, 0x07);
        }
    }

    #[test]
    fn ignores_adjacent_object_bytes() {
        let mut object = [0xa5u8; 0xe40];
        object[0xe34..0xe38].copy_from_slice(&0x1122_3344u32.to_le_bytes());
        object[0xe38..0xe3c].copy_from_slice(&0x5566_7788u32.to_le_bytes());
        object[0xe3c..0xe40].copy_from_slice(&0x99aa_bbccu32.to_le_bytes());

        assert_eq!(unsafe { object_state_word(object.as_ptr()) }, 0x5566_7788);
    }

    #[test]
    fn returns_then_advances_the_sequence_state() {
        let _guard = SEQUENCE_ID_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        for initial in [0, 1, 0x2468_ace0, 0xffff_fffe] {
            seed_sequence_id(initial);
            assert_eq!(unsafe { sequence_id_next() }, initial);
            assert_eq!(sequence_id(), initial.wrapping_add(1));
        }
    }

    #[test]
    fn wraps_after_returning_the_maximum_sequence_id() {
        let _guard = SEQUENCE_ID_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        seed_sequence_id(u32::MAX);
        assert_eq!(unsafe { sequence_id_next() }, u32::MAX);
        assert_eq!(sequence_id(), 0);
        assert_eq!(unsafe { sequence_id_next() }, 0);
        assert_eq!(sequence_id(), 1);
    }
    #[test]
    fn wrong_type_tag_returns_null_without_querying_storage() {
        let mut storage = [0u8; 32];
        let _guard = install_recording_storage_base(storage.as_mut_ptr());
        let _reset = StorageBaseReset;
        let object = indexed_object(INDEXED_OBJECT_TAG ^ 1, 4, 1);

        assert_eq!(
            unsafe { indexed_object_offset(&object, 1) },
            core::ptr::null_mut()
        );
        assert_eq!(unsafe { STORAGE_BASE_CALLS }, 0);
    }

    #[test]
    fn zero_index_returns_null_without_querying_storage() {
        let mut storage = [0u8; 32];
        let _guard = install_recording_storage_base(storage.as_mut_ptr());
        let _reset = StorageBaseReset;
        let object = indexed_object(INDEXED_OBJECT_TAG, 4, 1);

        assert_eq!(
            unsafe { indexed_object_offset(&object, 0) },
            core::ptr::null_mut()
        );
        assert_eq!(unsafe { STORAGE_BASE_CALLS }, 0);
    }

    #[test]
    fn index_above_count_returns_null_without_querying_storage() {
        let mut storage = [0u8; 32];
        let _guard = install_recording_storage_base(storage.as_mut_ptr());
        let _reset = StorageBaseReset;
        let object = indexed_object(INDEXED_OBJECT_TAG, 4, 2);

        assert_eq!(
            unsafe { indexed_object_offset(&object, 3) },
            core::ptr::null_mut()
        );
        assert_eq!(unsafe { STORAGE_BASE_CALLS }, 0);
    }

    #[test]
    fn valid_one_based_indices_call_storage_base_and_scale_by_stride() {
        let mut storage = [0u8; 32];
        let _guard = install_recording_storage_base(storage.as_mut_ptr());
        let _reset = StorageBaseReset;
        let object = indexed_object(INDEXED_OBJECT_TAG, 12, 3);

        assert_eq!(
            unsafe { indexed_object_offset(&object, 1) },
            storage.as_mut_ptr(),
            "the first one-based record begins at the base"
        );
        assert_eq!(
            unsafe { indexed_object_offset(&object, 3) },
            unsafe { storage.as_mut_ptr().add(24) },
            "the upper inclusive index uses stride * (index - 1)"
        );
        assert_eq!(unsafe { STORAGE_BASE_CALLS }, 2);
        assert_eq!(unsafe { STORAGE_BASE_OBJECT }, &object as *const IndexedObject as usize);
    }

    #[test]
    fn null_object_returns_zero_without_querying_the_field_triple() {
        let _guard = install_recording_scaled_field_total(0x1122_3344_5566_7788);
        let _reset = ScaledFieldTotalReset;

        assert_eq!(unsafe { object_scaled_total(core::ptr::null()) }, 0);
        assert_eq!(unsafe { SCALED_TOTAL_CALLS }, 0);
    }

    #[test]
    fn wrapped_field_pointer_returns_zero_without_querying_the_field_triple() {
        let _guard = install_recording_scaled_field_total(0x1122_3344_5566_7788);
        let _reset = ScaledFieldTotalReset;
        // The degenerate `addne`/`bne` case: a non-null object whose
        // object + 0x18 wraps to null also yields 0 in r0:r1.
        let object = 0usize.wrapping_sub(0x18) as *const u8;

        assert_eq!(unsafe { object_scaled_total(object) }, 0);
        assert_eq!(unsafe { SCALED_TOTAL_CALLS }, 0);
    }

    #[test]
    fn forwards_the_shifted_field_pointer_and_the_helper_result() {
        let _guard = install_recording_scaled_field_total(0);
        let _reset = ScaledFieldTotalReset;
        let object = [0xa5u8; 0x30];

        for total in [
            0i64,
            1,
            -1,
            i64::MIN,
            i64::MAX,
            0x1122_3344_5566_7788,
            -0x1122_3344_5566_7788,
        ] {
            unsafe {
                MOCK_SCALED_TOTAL = total;
            }
            assert_eq!(unsafe { object_scaled_total(object.as_ptr()) }, total);
            assert_eq!(
                unsafe { SCALED_TOTAL_FIELDS },
                object.as_ptr() as usize + 0x18,
                "the helper must receive object + 0x18"
            );
        }
        assert_eq!(unsafe { SCALED_TOTAL_CALLS }, 7);
    }

    #[test]
    fn base_null_object_returns_zero_without_querying_the_field_triple() {
        let _guard = install_recording_scaled_field_total(0x1122_3344_5566_7788);
        let _reset = ScaledFieldTotalReset;

        assert_eq!(unsafe { object_scaled_total_base(core::ptr::null()) }, 0);
        assert_eq!(unsafe { SCALED_TOTAL_CALLS }, 0);
    }

    #[test]
    fn base_forwards_the_object_pointer_unshifted_and_the_helper_result() {
        let _guard = install_recording_scaled_field_total(0);
        let _reset = ScaledFieldTotalReset;
        let object = [0xa5u8; 0x18];

        for total in [
            0i64,
            1,
            -1,
            i64::MIN,
            i64::MAX,
            0x1122_3344_5566_7788,
            -0x1122_3344_5566_7788,
        ] {
            unsafe {
                MOCK_SCALED_TOTAL = total;
            }
            assert_eq!(unsafe { object_scaled_total_base(object.as_ptr()) }, total);
            assert_eq!(
                unsafe { SCALED_TOTAL_FIELDS },
                object.as_ptr() as usize,
                "the helper must receive object itself, with no +0x18 shift"
            );
        }
        assert_eq!(unsafe { SCALED_TOTAL_CALLS }, 7);
    }
    #[test]
    fn follows_the_object_pointer_to_the_nested_flag() {
        #[repr(align(8))]
        struct OuterObject(
            [u8; NESTED_OBJECT_POINTER_OFFSET + core::mem::size_of::<*const u8>()],
        );
        #[repr(align(8))]
        struct NestedObject([u8; NESTED_OBJECT_FLAG_OFFSET + 2]);

        let mut outer = OuterObject([0xa5; NESTED_OBJECT_POINTER_OFFSET + core::mem::size_of::<*const u8>()]);
        let mut nested = NestedObject([0xa5; NESTED_OBJECT_FLAG_OFFSET + 2]);
        nested.0[NESTED_OBJECT_FLAG_OFFSET - 1] = 0x11;
        nested.0[NESTED_OBJECT_FLAG_OFFSET] = 0x5a;
        nested.0[NESTED_OBJECT_FLAG_OFFSET + 1] = 0xe2;

        unsafe {
            (outer.0.as_mut_ptr().add(NESTED_OBJECT_POINTER_OFFSET) as *mut *const u8)
                .write(nested.0.as_ptr());
            assert_eq!(object_nested_flag(outer.0.as_ptr()), 0x5a);
        }
    }

    #[test]
    fn returns_an_unsigned_byte() {
        #[repr(align(8))]
        struct OuterObject(
            [u8; NESTED_OBJECT_POINTER_OFFSET + core::mem::size_of::<*const u8>()],
        );
        #[repr(align(8))]
        struct NestedObject([u8; NESTED_OBJECT_FLAG_OFFSET + 1]);

        let mut outer = OuterObject([0; NESTED_OBJECT_POINTER_OFFSET + core::mem::size_of::<*const u8>()]);
        let mut nested = NestedObject([0; NESTED_OBJECT_FLAG_OFFSET + 1]);

        unsafe {
            (outer.0.as_mut_ptr().add(NESTED_OBJECT_POINTER_OFFSET) as *mut *const u8)
                .write(nested.0.as_ptr());
            for byte in [0x00, 0x01, 0x7f, 0x80, 0xff] {
                nested.0[NESTED_OBJECT_FLAG_OFFSET] = byte;
                assert_eq!(
                    u32::from(object_nested_flag(outer.0.as_ptr())),
                    u32::from(byte),
                    "the ldrb result must be zero-extended for {byte:#04x}"
                );
            }
        }
    }

    #[test]
    fn follows_the_object_pointer_to_the_nested_property() {
        #[repr(align(8))]
        struct OuterObject(
            [u8; NESTED_OBJECT_POINTER_OFFSET + core::mem::size_of::<*const u8>()],
        );
        #[repr(align(8))]
        struct NestedObject([u8; NESTED_OBJECT_PROPERTY_OFFSET + 2]);

        let mut outer = OuterObject([0xa5; NESTED_OBJECT_POINTER_OFFSET + core::mem::size_of::<*const u8>()]);
        let mut nested = NestedObject([0xa5; NESTED_OBJECT_PROPERTY_OFFSET + 2]);
        nested.0[NESTED_OBJECT_PROPERTY_OFFSET - 1] = 0x11;
        nested.0[NESTED_OBJECT_PROPERTY_OFFSET] = 0x3c;
        nested.0[NESTED_OBJECT_PROPERTY_OFFSET + 1] = 0xe2;

        unsafe {
            (outer.0.as_mut_ptr().add(NESTED_OBJECT_POINTER_OFFSET) as *mut *const u8)
                .write(nested.0.as_ptr());
            assert_eq!(object_nested_property(outer.0.as_ptr()), 0x3c);
        }
    }

    #[test]
    fn nested_property_is_an_unsigned_byte() {
        #[repr(align(8))]
        struct OuterObject(
            [u8; NESTED_OBJECT_POINTER_OFFSET + core::mem::size_of::<*const u8>()],
        );
        #[repr(align(8))]
        struct NestedObject([u8; NESTED_OBJECT_PROPERTY_OFFSET + 1]);

        let mut outer = OuterObject([0; NESTED_OBJECT_POINTER_OFFSET + core::mem::size_of::<*const u8>()]);
        let mut nested = NestedObject([0; NESTED_OBJECT_PROPERTY_OFFSET + 1]);

        unsafe {
            (outer.0.as_mut_ptr().add(NESTED_OBJECT_POINTER_OFFSET) as *mut *const u8)
                .write(nested.0.as_ptr());
            for byte in [0x00, 0x01, 0x7f, 0x80, 0xff] {
                nested.0[NESTED_OBJECT_PROPERTY_OFFSET] = byte;
                assert_eq!(
                    u32::from(object_nested_property(outer.0.as_ptr())),
                    u32::from(byte),
                    "the ldrb result must be zero-extended for {byte:#04x}"
                );
            }
        }
    }

    #[test]
    fn follows_the_object_pointer_to_the_nested_attribute() {
        #[repr(align(8))]
        struct OuterObject(
            [u8; NESTED_OBJECT_POINTER_OFFSET + core::mem::size_of::<*const u8>()],
        );
        #[repr(align(8))]
        struct NestedObject([u8; NESTED_OBJECT_ATTRIBUTE_OFFSET + 2]);

        let mut outer = OuterObject([0xa5; NESTED_OBJECT_POINTER_OFFSET + core::mem::size_of::<*const u8>()]);
        let mut nested = NestedObject([0xa5; NESTED_OBJECT_ATTRIBUTE_OFFSET + 2]);
        nested.0[NESTED_OBJECT_ATTRIBUTE_OFFSET - 1] = 0x11;
        nested.0[NESTED_OBJECT_ATTRIBUTE_OFFSET] = 0x3c;
        nested.0[NESTED_OBJECT_ATTRIBUTE_OFFSET + 1] = 0xe2;

        unsafe {
            (outer.0.as_mut_ptr().add(NESTED_OBJECT_POINTER_OFFSET) as *mut *const u8)
                .write(nested.0.as_ptr());
            assert_eq!(object_nested_attribute(outer.0.as_ptr()), 0x3c);
        }
    }

    #[test]
    fn nested_attribute_is_an_unsigned_byte() {
        #[repr(align(8))]
        struct OuterObject(
            [u8; NESTED_OBJECT_POINTER_OFFSET + core::mem::size_of::<*const u8>()],
        );
        #[repr(align(8))]
        struct NestedObject([u8; NESTED_OBJECT_ATTRIBUTE_OFFSET + 1]);

        let mut outer = OuterObject([0; NESTED_OBJECT_POINTER_OFFSET + core::mem::size_of::<*const u8>()]);
        let mut nested = NestedObject([0; NESTED_OBJECT_ATTRIBUTE_OFFSET + 1]);

        unsafe {
            (outer.0.as_mut_ptr().add(NESTED_OBJECT_POINTER_OFFSET) as *mut *const u8)
                .write(nested.0.as_ptr());
            for byte in [0x00, 0x01, 0x7f, 0x80, 0xff] {
                nested.0[NESTED_OBJECT_ATTRIBUTE_OFFSET] = byte;
                assert_eq!(
                    u32::from(object_nested_attribute(outer.0.as_ptr())),
                    u32::from(byte),
                    "the ldrb result must be zero-extended for {byte:#04x}"
                );
            }
        }
    }

    #[test]
    fn follows_the_object_pointer_to_the_nested_companion_word() {
        #[repr(align(8))]
        struct OuterObject(
            [u8; NESTED_OBJECT_POINTER_OFFSET + core::mem::size_of::<*const u8>()],
        );
        #[repr(align(8))]
        struct NestedObject([u8; NESTED_OBJECT_COMPANION_WORD_OFFSET + 8]);

        let mut outer = OuterObject([0xa5; NESTED_OBJECT_POINTER_OFFSET + core::mem::size_of::<*const u8>()]);
        let mut nested = NestedObject([0xa5; NESTED_OBJECT_COMPANION_WORD_OFFSET + 8]);
        let neighbors = [0x1122_3344u32, 0x5566_7788, 0x99aa_bbcc];
        for (slot, word) in neighbors.iter().enumerate() {
            unsafe {
                (nested.0.as_mut_ptr().add(NESTED_OBJECT_COMPANION_WORD_OFFSET - 4 + slot * 4)
                    as *mut u32)
                    .write_unaligned(word.to_le());
            }
        }

        unsafe {
            (outer.0.as_mut_ptr().add(NESTED_OBJECT_POINTER_OFFSET) as *mut *const u8)
                .write(nested.0.as_ptr());
            assert_eq!(
                object_nested_companion_word(outer.0.as_ptr()),
                neighbors[1],
                "the ldr must read the word at +0xb54, little-endian"
            );
        }
    }

    #[test]
    fn nested_companion_word_is_a_full_word() {
        #[repr(align(8))]
        struct OuterObject(
            [u8; NESTED_OBJECT_POINTER_OFFSET + core::mem::size_of::<*const u8>()],
        );
        #[repr(align(8))]
        struct NestedObject([u8; NESTED_OBJECT_COMPANION_WORD_OFFSET + 4]);

        let mut outer = OuterObject([0; NESTED_OBJECT_POINTER_OFFSET + core::mem::size_of::<*const u8>()]);
        let mut nested = NestedObject([0; NESTED_OBJECT_COMPANION_WORD_OFFSET + 4]);

        unsafe {
            (outer.0.as_mut_ptr().add(NESTED_OBJECT_POINTER_OFFSET) as *mut *const u8)
                .write(nested.0.as_ptr());
            for word in [0x0000_0000u32, 0x0000_0001, 0x8000_0000, 0xffff_ffff, 0xdead_beef] {
                (nested.0.as_mut_ptr().add(NESTED_OBJECT_COMPANION_WORD_OFFSET) as *mut u32)
                    .write_unaligned(word.to_le());
                assert_eq!(
                    object_nested_companion_word(outer.0.as_ptr()),
                    word,
                    "the ldr result must keep all 32 bits for {word:#010x}"
                );
            }
        }
    }

    #[test]
    fn queries_interface_zero_and_scales_the_sample_by_two_to_the_tenth() {
        let _guard = install_recording_clock_sample(0x0012_3456_789a_bcde);
        let _reset = ClockSampleReset;

        assert_eq!(
            unsafe { scaled_timestamp_now() },
            0x0012_3456_789a_bcdei64 << 10
        );
        assert_eq!(unsafe { CLOCK_SAMPLE_CALLS }, 1);
        assert_eq!(
            unsafe { CLOCK_SAMPLE_INTERFACE },
            0,
            "the original passes interface index 0 (`mov r0,#0x0`)"
        );
    }

    #[test]
    fn scale_shift_carries_across_the_word_boundary() {
        let _guard = install_recording_clock_sample(0x003f_ffff_ffff_ffff);
        let _reset = ClockSampleReset;

        assert_eq!(
            unsafe { scaled_timestamp_now() },
            0x003f_ffff_ffff_ffffi64 << 10,
            "the top ten bits of r0 must shift into r1 (`orr r1,r1,r0,lsr #0x16`)"
        );
    }

    #[test]
    fn scale_shift_drops_bits_above_sixty_four() {
        let _guard = install_recording_clock_sample(-1);
        let _reset = ClockSampleReset;

        assert_eq!(unsafe { scaled_timestamp_now() }, -1i64 << 10);
    }

    #[test]
    fn baseline_snapshot_stores_the_scaled_sample_and_returns_it() {
        let _guard = install_recording_baseline_clock_sample(0x0012_3456_789a_bcde);
        let _reset = BaselineClockSampleReset;

        let returned = unsafe { snapshot_timestamp_baseline() };

        assert_eq!(
            returned,
            0x0012_3456_789a_bcdei64 << 10,
            "call sites 0x08055ff8 and 0x081eb420 consume the r0:r1 residue"
        );
        assert_eq!(
            unsafe { core::ptr::addr_of!(TIMESTAMP_BASELINE).read() },
            0x0012_3456_789a_bcdei64 << 10,
            "the scaled sample replaces the baseline slot (`strd r0,r1,[r2,#0x20]`)"
        );
        assert_eq!(unsafe { BASELINE_SAMPLE_CALLS }, 1);
        assert_eq!(
            unsafe { BASELINE_SAMPLE_INTERFACE },
            0,
            "the original passes interface index 0 (`mov r0,#0x0`)"
        );
    }

    #[test]
    fn baseline_snapshot_shift_carries_across_the_word_boundary() {
        let _guard = install_recording_baseline_clock_sample(0x003f_ffff_ffff_ffff);
        let _reset = BaselineClockSampleReset;

        assert_eq!(
            unsafe { snapshot_timestamp_baseline() },
            0x003f_ffff_ffff_ffffi64 << 10,
            "the top ten bits of r0 must shift into r1 (`orr r1,r1,r0,lsr #0x16`)"
        );
        assert_eq!(
            unsafe { core::ptr::addr_of!(TIMESTAMP_BASELINE).read() },
            0x003f_ffff_ffff_ffffi64 << 10
        );
    }

    #[test]
    fn baseline_snapshot_overwrites_a_previous_baseline() {
        let _guard = install_recording_baseline_clock_sample(7);
        let _reset = BaselineClockSampleReset;

        assert_eq!(unsafe { snapshot_timestamp_baseline() }, 7 << 10);
        assert_eq!(unsafe { snapshot_timestamp_baseline() }, 7 << 10);
        assert_eq!(unsafe { BASELINE_SAMPLE_CALLS }, 2);
    }

    #[test]
    fn zero_baseline_is_snapshotted_once_then_reused() {
        let _guard = install_recording_baseline_clock_sample(0x0012_3456_789a_bcde);
        let _reset = BaselineClockSampleReset;
        unsafe { core::ptr::addr_of_mut!(TIMESTAMP_BASELINE).write(0) };

        assert_eq!(
            unsafe { timestamp_baseline() },
            0x0012_3456_789a_bcdei64 << 10,
            "a zero slot triggers the snapshot call (`cmpeq r0,r2` after `cmp r1,#0`)"
        );
        assert_eq!(unsafe { BASELINE_SAMPLE_CALLS }, 1);
        assert_eq!(
            unsafe { core::ptr::addr_of!(TIMESTAMP_BASELINE).read() },
            0x0012_3456_789a_bcdei64 << 10,
            "the snapshot result is stored back into the slot (`strd r0,r1,[r4,#0x20]`)"
        );

        assert_eq!(
            unsafe { timestamp_baseline() },
            0x0012_3456_789a_bcdei64 << 10,
            "the populated slot is returned without resampling"
        );
        assert_eq!(
            unsafe { BASELINE_SAMPLE_CALLS },
            1,
            "the baseline is lazily sampled exactly once"
        );
    }

    #[test]
    fn nonzero_baseline_returns_without_sampling() {
        let _guard = install_recording_baseline_clock_sample(0x0012_3456_789a_bcde);
        let _reset = BaselineClockSampleReset;

        for baseline in [1, -1, i64::MIN, i64::MAX] {
            unsafe { core::ptr::addr_of_mut!(TIMESTAMP_BASELINE).write(baseline) };

            assert_eq!(
                unsafe { timestamp_baseline() },
                baseline,
                "any nonzero doubleword short-circuits the lazy snapshot"
            );
        }
        assert_eq!(unsafe { BASELINE_SAMPLE_CALLS }, 0);
    }

    #[test]
    fn resampling_after_zeroing_replaces_the_baseline() {
        let _guard = install_recording_baseline_clock_sample(3);
        let _reset = BaselineClockSampleReset;
        unsafe { core::ptr::addr_of_mut!(TIMESTAMP_BASELINE).write(0) };

        assert_eq!(unsafe { timestamp_baseline() }, 3 << 10);

        unsafe {
            core::ptr::addr_of_mut!(TIMESTAMP_BASELINE).write(0);
            core::ptr::addr_of_mut!(MOCK_BASELINE_SAMPLE).write(9);
        }

        assert_eq!(unsafe { timestamp_baseline() }, 9 << 10);
        assert_eq!(unsafe { BASELINE_SAMPLE_CALLS }, 2);
    }

    static VERSION_TEXT_LOCK: Mutex<()> = Mutex::new(());
    static mut MOCK_CONTEXT: *mut u8 = core::ptr::null_mut();
    static mut SHARED_CONTEXT_CALLS: u32 = 0;
    static mut FORMAT_CALLS: u32 = 0;
    static mut FORMAT_WORD: u32 = 0;
    static mut FORMAT_PAYLOAD: [u8; 512] = [0; 512];
    static mut FORMAT_PAYLOAD_LEN: usize = 0;
    static mut SET_TEXT_CALLS: u32 = 0;
    static mut SET_TEXT_OBJECT: usize = 0;
    static mut SET_TEXT_COUNTED: [u8; 300] = [0; 300];

    unsafe extern "C" fn recording_shared_context() -> *mut u8 {
        SHARED_CONTEXT_CALLS += 1;
        MOCK_CONTEXT
    }

    unsafe extern "C" fn recording_format_dotted_triple(word: u32, dst: *mut u8) {
        FORMAT_CALLS += 1;
        FORMAT_WORD = word;
        core::ptr::copy_nonoverlapping(FORMAT_PAYLOAD.as_ptr(), dst, FORMAT_PAYLOAD_LEN);
    }

    unsafe extern "C" fn recording_object_counted_text(counted: *const u8, object: *mut u8) {
        SET_TEXT_CALLS += 1;
        SET_TEXT_OBJECT = object as usize;
        let len = usize::from(counted.read());
        core::ptr::copy_nonoverlapping(counted, SET_TEXT_COUNTED.as_mut_ptr(), len + 1);
    }

    /// Restores the stock-call boundaries before another test uses them.
    struct VersionTextReset;

    impl Drop for VersionTextReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(SHARED_CONTEXT).write(firmware_shared_context);
                core::ptr::addr_of_mut!(FORMAT_DOTTED_TRIPLE)
                    .write(firmware_format_dotted_triple);
                core::ptr::addr_of_mut!(OBJECT_COUNTED_TEXT)
                    .write(firmware_object_counted_text);
            }
        }
    }

    fn install_version_text_mocks(
        context: *mut u8,
        payload: &[u8],
    ) -> MutexGuard<'static, ()> {
        let guard = VERSION_TEXT_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            MOCK_CONTEXT = context;
            SHARED_CONTEXT_CALLS = 0;
            FORMAT_CALLS = 0;
            FORMAT_WORD = 0;
            FORMAT_PAYLOAD = [0; 512];
            FORMAT_PAYLOAD[..payload.len()].copy_from_slice(payload);
            FORMAT_PAYLOAD_LEN = payload.len();
            SET_TEXT_CALLS = 0;
            SET_TEXT_OBJECT = 0;
            SET_TEXT_COUNTED = [0; 300];
            core::ptr::addr_of_mut!(SHARED_CONTEXT).write(recording_shared_context);
            core::ptr::addr_of_mut!(FORMAT_DOTTED_TRIPLE)
                .write(recording_format_dotted_triple);
            core::ptr::addr_of_mut!(OBJECT_COUNTED_TEXT)
                .write(recording_object_counted_text);
        }
        guard
    }

    #[test]
    fn reads_the_context_version_word_and_installs_the_counted_text() {
        let mut context = [0xa5u8; 0x50];
        context[0x44..0x48].copy_from_slice(&0x1122_3344u32.to_le_bytes());
        context[0x48..0x4c].copy_from_slice(&0x0200_0004u32.to_le_bytes());
        context[0x4c..0x50].copy_from_slice(&0x5566_7788u32.to_le_bytes());
        let _guard = install_version_text_mocks(context.as_mut_ptr(), b"2.0.4\0");
        let _reset = VersionTextReset;
        let mut object = [0u8; 0x5c];

        unsafe { object_set_version_text(object.as_mut_ptr()) };

        assert_eq!(unsafe { SHARED_CONTEXT_CALLS }, 1);
        assert_eq!(unsafe { FORMAT_CALLS }, 1);
        assert_eq!(
            unsafe { FORMAT_WORD },
            0x0200_0004,
            "the formatter must receive the word at context + 0x48 (`ldr r0,[r0,#0x48]`)"
        );
        assert_eq!(unsafe { SET_TEXT_CALLS }, 1);
        assert_eq!(
            unsafe { SET_TEXT_OBJECT },
            object.as_mut_ptr() as usize,
            "the setter must receive the caller's object unchanged (`mov r1,r4`)"
        );
        assert_eq!(
            &unsafe { SET_TEXT_COUNTED }[..6],
            b"\x052.0.4",
            "the counted text is the formatted string with a length byte"
        );
    }

    #[test]
    fn counted_conversion_stops_at_the_ff_limit() {
        let mut context = [0u8; 0x4c];
        let mut payload = std::vec::Vec::from([0x61u8; 300]);
        payload.push(0);
        let _guard = install_version_text_mocks(context.as_mut_ptr(), &payload);
        let _reset = VersionTextReset;
        let mut object = [0u8; 0x5c];

        unsafe { object_set_version_text(object.as_mut_ptr()) };

        let counted = unsafe { SET_TEXT_COUNTED };
        assert_eq!(
            counted[0], 0xff,
            "the 0xff limit caps the counted length (`mov r2,#0xff`)"
        );
        assert!(
            counted[1..=0xff].iter().all(|&byte| byte == 0x61),
            "exactly 255 payload bytes survive the limit"
        );
    }

    #[test]
    fn empty_formatted_text_installs_a_zero_length_counted_text() {
        let mut context = [0u8; 0x4c];
        let _guard = install_version_text_mocks(context.as_mut_ptr(), b"\0");
        let _reset = VersionTextReset;
        let mut object = [0u8; 0x5c];

        unsafe { object_set_version_text(object.as_mut_ptr()) };

        assert_eq!(unsafe { SET_TEXT_CALLS }, 1);
        assert_eq!(
            unsafe { SET_TEXT_COUNTED }[0],
            0,
            "an immediate source NUL leaves the counted length at zero"
        );
    }

    /// Installs the recording context getter for [`context_mode_flag`].
    ///
    /// Shares `VERSION_TEXT_LOCK` with the version-text tests because both
    /// suites overwrite the `SHARED_CONTEXT` boundary.
    fn install_mode_flag_mock(context: *mut u8) -> MutexGuard<'static, ()> {
        let guard = VERSION_TEXT_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            MOCK_CONTEXT = context;
            SHARED_CONTEXT_CALLS = 0;
            core::ptr::addr_of_mut!(SHARED_CONTEXT).write(recording_shared_context);
        }
        guard
    }

    #[test]
    fn returns_the_low_bit_of_the_context_word_at_0x94() {
        let mut context = [0u8; 0x9c];
        // Neighboring words stay all-ones so a wrong offset reads 1 here.
        context[0x90..0x94].copy_from_slice(&u32::MAX.to_le_bytes());
        context[0x94..0x98].copy_from_slice(&0x5a5a_5a5bu32.to_le_bytes());
        context[0x98..0x9c].copy_from_slice(&u32::MAX.to_le_bytes());
        let _guard = install_mode_flag_mock(context.as_mut_ptr());
        let _reset = VersionTextReset;

        assert_eq!(unsafe { context_mode_flag() }, 1);
        assert_eq!(
            unsafe { SHARED_CONTEXT_CALLS },
            1,
            "the context is fetched once (`bl 0x08369bec`)"
        );
    }

    #[test]
    fn masks_everything_but_the_low_bit() {
        let mut context = [0u8; 0x98];
        context[0x94..0x98].copy_from_slice(&0xffff_fffeu32.to_le_bytes());
        let _guard = install_mode_flag_mock(context.as_mut_ptr());
        let _reset = VersionTextReset;

        assert_eq!(
            unsafe { context_mode_flag() },
            0,
            "a set word with bit 0 clear yields 0 (`and r0,r0,#0x1`)"
        );
    }

    static KIND_TABLE_LOCK: Mutex<()> = Mutex::new(());
    static mut KIND_TABLE_CALLS: u32 = 0;
    static mut KIND_TABLE_OBJECT: usize = 0;
    static mut KIND_TABLE_KIND: u32 = u32::MAX;
    static mut MOCK_KIND_TABLE: *const u64 = core::ptr::null();

    unsafe extern "C" fn recording_object_kind_table(
        object: *const u8,
        kind: u32,
    ) -> *const u64 {
        KIND_TABLE_CALLS += 1;
        KIND_TABLE_OBJECT = object as usize;
        KIND_TABLE_KIND = kind;
        MOCK_KIND_TABLE
    }

    /// Restores the stock-call boundary before another test uses it.
    struct KindTableReset;

    impl Drop for KindTableReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(OBJECT_KIND_TABLE)
                    .write(firmware_object_kind_table);
            }
        }
    }

    fn install_recording_kind_table(table: *const u64) -> MutexGuard<'static, ()> {
        let guard = KIND_TABLE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            KIND_TABLE_CALLS = 0;
            KIND_TABLE_OBJECT = 0;
            KIND_TABLE_KIND = u32::MAX;
            MOCK_KIND_TABLE = table;
            core::ptr::addr_of_mut!(OBJECT_KIND_TABLE).write(recording_object_kind_table);
        }
        guard
    }

    #[test]
    fn null_table_returns_zero_and_forwards_both_arguments() {
        let _guard = install_recording_kind_table(core::ptr::null());
        let _reset = KindTableReset;
        let mut object = [0u8; 0x1a0];

        assert_eq!(unsafe { object_kind_mask_union(object.as_mut_ptr(), 7) }, 0);
        assert_eq!(unsafe { KIND_TABLE_CALLS }, 1, "the getter is called once");
        assert_eq!(
            unsafe { KIND_TABLE_OBJECT },
            object.as_mut_ptr() as usize,
            "r0 is forwarded untouched to the getter"
        );
        assert_eq!(
            unsafe { KIND_TABLE_KIND },
            7,
            "r1 is forwarded untouched to the getter"
        );
    }

    #[test]
    fn immediate_terminator_returns_zero() {
        let table = [0u64; 1];
        let _guard = install_recording_kind_table(table.as_ptr());
        let _reset = KindTableReset;
        let mut object = [0u8; 0x1a0];

        assert_eq!(
            unsafe { object_kind_mask_union(object.as_mut_ptr(), 1) },
            0,
            "a zero first doubleword ends the walk before any OR"
        );
    }

    #[test]
    fn unions_every_entry_until_the_zero_doubleword() {
        let table = [
            0x0000_0001_0000_0002u64,
            0x0000_0004_0000_0008,
            0xffff_0000_0000_0000,
            0,
            // Past the terminator: must never be read.
            0xdead_beef_dead_beef,
        ];
        let _guard = install_recording_kind_table(table.as_ptr());
        let _reset = KindTableReset;
        let mut object = [0u8; 0x1a0];

        assert_eq!(
            unsafe { object_kind_mask_union(object.as_mut_ptr(), 0x2c) },
            0xffff_0005_0000_000a,
            "the result is the bitwise OR of all entries up to the terminator"
        );
    }

    static FIELD_QUERY_LOCK: Mutex<()> = Mutex::new(());
    static HEAP_FREE_LOCK: Mutex<()> = Mutex::new(());
    static mut FIELD_QUERY_CALLS: u32 = 0;
    static mut FIELD_QUERY_OBJECT: usize = 0;
    static mut FIELD_QUERY_KIND_SEEN: u32 = u32::MAX;
    static mut FIELD_QUERY_KEY: u32 = u32::MAX;
    static mut FIELD_QUERY_KEY_LEN: u32 = u32::MAX;
    static mut FIELD_QUERY_RESERVED: u32 = u32::MAX;
    static mut FIELD_QUERY_WORD_SEEN: u32 = u32::MAX;
    static mut MOCK_QUERY_STATUS: i32 = 0;
    static mut MOCK_QUERY_FLAGS: u16 = 0;
    static mut MOCK_QUERY_TEXT_LEN: u16 = 0;
    static mut MOCK_QUERY_TEXT: *mut u8 = core::ptr::null_mut();
    static mut MOCK_QUERY_FIELD_WORD: u32 = 0;
    static mut MOCK_QUERY_TAGGED_WORD: u32 = 0;
    static mut HEAP_FREE_CALLS: u32 = 0;
    static mut HEAP_FREE_POINTER: usize = usize::MAX;

    unsafe extern "C" fn recording_field_query(
        object: *mut u8,
        kind: u32,
        key: u32,
        key_len: u32,
        reserved: u32,
        result: *mut FieldQueryResult,
        query_word: *mut u32,
    ) -> i32 {
        FIELD_QUERY_CALLS += 1;
        FIELD_QUERY_OBJECT = object as usize;
        FIELD_QUERY_KIND_SEEN = kind;
        FIELD_QUERY_KEY = key;
        FIELD_QUERY_KEY_LEN = key_len;
        FIELD_QUERY_RESERVED = reserved;
        FIELD_QUERY_WORD_SEEN = query_word.read();
        let result = &mut *result;
        result.flags = MOCK_QUERY_FLAGS;
        result.text_len = MOCK_QUERY_TEXT_LEN;
        result.text = MOCK_QUERY_TEXT;
        result.field_word = MOCK_QUERY_FIELD_WORD;
        result.tagged_word = MOCK_QUERY_TAGGED_WORD;
        MOCK_QUERY_STATUS
    }

    unsafe extern "C" fn recording_heap_free(pointer: *mut u8) {
        HEAP_FREE_CALLS += 1;
        HEAP_FREE_POINTER = pointer as usize;
    }

    /// Restores both stock-call boundaries before another test uses them.
    struct FieldQueryReset;

    impl Drop for FieldQueryReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(FIELD_QUERY).write(firmware_field_query);
                core::ptr::addr_of_mut!(HEAP_FREE).write(firmware_heap_free);
            }
        }
    }

    struct FieldQueryMocks {
        _query_guard: MutexGuard<'static, ()>,
        _free_guard: MutexGuard<'static, ()>,
        _reset: FieldQueryReset,
    }

    fn install_field_query_mocks(status: i32, flags: u16, text_len: u16) -> FieldQueryMocks {
        let query_guard = FIELD_QUERY_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let free_guard = HEAP_FREE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            FIELD_QUERY_CALLS = 0;
            FIELD_QUERY_OBJECT = 0;
            FIELD_QUERY_KIND_SEEN = u32::MAX;
            FIELD_QUERY_KEY = u32::MAX;
            FIELD_QUERY_KEY_LEN = u32::MAX;
            FIELD_QUERY_RESERVED = u32::MAX;
            FIELD_QUERY_WORD_SEEN = u32::MAX;
            MOCK_QUERY_STATUS = status;
            MOCK_QUERY_FLAGS = flags;
            MOCK_QUERY_TEXT_LEN = text_len;
            MOCK_QUERY_TEXT = core::ptr::null_mut();
            MOCK_QUERY_FIELD_WORD = 0;
            MOCK_QUERY_TAGGED_WORD = 0;
            HEAP_FREE_CALLS = 0;
            HEAP_FREE_POINTER = usize::MAX;
            core::ptr::addr_of_mut!(FIELD_QUERY).write(recording_field_query);
            core::ptr::addr_of_mut!(HEAP_FREE).write(recording_heap_free);
        }
        FieldQueryMocks {
            _query_guard: query_guard,
            _free_guard: free_guard,
            _reset: FieldQueryReset,
        }
    }

    /// Sentinel-filled object buffer with its tag halfword set.
    fn field_text_object(tag: u16) -> [u8; 0x200] {
        let mut object = [0xaau8; 0x200];
        object[OBJECT_TAG_OFFSET..OBJECT_TAG_OFFSET + 2].copy_from_slice(&tag.to_le_bytes());
        object
    }

    #[test]
    fn forwards_the_query_tuple_and_returns_status_verbatim() {
        let _mocks = install_field_query_mocks(0x30, 0, 0);
        let mut object = field_text_object(0x1234);

        assert_eq!(
            unsafe { object_install_field_text(object.as_mut_ptr()) },
            0x30,
            "the helper's status is returned in r0"
        );
        assert_eq!(unsafe { FIELD_QUERY_CALLS }, 1, "the helper is called once");
        assert_eq!(
            unsafe { FIELD_QUERY_OBJECT },
            object.as_mut_ptr() as usize,
            "r0 is forwarded untouched"
        );
        assert_eq!(
            unsafe { FIELD_QUERY_KIND_SEEN },
            FIELD_QUERY_KIND,
            "r1 is the hardcoded query kind (`mov r1,#0x2`)"
        );
        assert_eq!(
            unsafe { (FIELD_QUERY_KEY, FIELD_QUERY_KEY_LEN, FIELD_QUERY_RESERVED) },
            (0, 0, 0),
            "the remaining arguments are the original's three zeros"
        );
        assert_eq!(
            unsafe { FIELD_QUERY_WORD_SEEN },
            0,
            "the query word is zero-initialized (`str r5,[sp,#0xc]`)"
        );
        assert!(
            object.iter().skip(4).all(|&byte| byte == 0xaa),
            "a nonzero status leaves the object untouched"
        );
        assert_eq!(
            unsafe { HEAP_FREE_CALLS },
            0,
            "flags bit 0 clear: nothing is freed"
        );
    }

    #[test]
    fn installs_text_and_both_words_on_success_for_tagged_objects() {
        let _mocks = install_field_query_mocks(0, 0, 5);
        let mut text = *b"hello";
        unsafe {
            MOCK_QUERY_TEXT = text.as_mut_ptr();
            MOCK_QUERY_FIELD_WORD = 0xcafe_f00d;
            MOCK_QUERY_TAGGED_WORD = 0x1234_5678;
        }
        let mut object = field_text_object(OBJECT_TAG_EXTENDED);

        assert_eq!(unsafe { object_install_field_text(object.as_mut_ptr()) }, 0);
        assert_eq!(
            &object[OBJECT_TEXT_OFFSET..OBJECT_TEXT_OFFSET + 6],
            b"hello\0",
            "the text is copied to object+0x1c and NUL-terminated"
        );
        assert_eq!(
            u32::from_le_bytes(
                object[OBJECT_FIELD_WORD_OFFSET..OBJECT_FIELD_WORD_OFFSET + 4]
                    .try_into()
                    .unwrap()
            ),
            0xcafe_f00d,
            "the block's +0x50 word lands at object+0x188"
        );
        assert_eq!(
            u32::from_le_bytes(
                object[OBJECT_TAGGED_WORD_OFFSET..OBJECT_TAGGED_WORD_OFFSET + 4]
                    .try_into()
                    .unwrap()
            ),
            0x1234_5678,
            "a 0x482b-tagged object also receives the block's +0x0c word at +4"
        );
        assert_eq!(
            unsafe { HEAP_FREE_CALLS },
            0,
            "inline (flags bit 0 clear) text is never freed"
        );
    }

    #[test]
    fn skips_the_tagged_word_for_other_tags() {
        let _mocks = install_field_query_mocks(0, 0, 1);
        let mut text = [b'x'];
        unsafe {
            MOCK_QUERY_TEXT = text.as_mut_ptr();
            MOCK_QUERY_TAGGED_WORD = 0xdead_beef;
        }
        let mut object = field_text_object(0x1234);

        assert_eq!(unsafe { object_install_field_text(object.as_mut_ptr()) }, 0);
        assert_eq!(
            u32::from_le_bytes(
                object[OBJECT_TAGGED_WORD_OFFSET..OBJECT_TAGGED_WORD_OFFSET + 4]
                    .try_into()
                    .unwrap()
            ),
            0xaaaa_aaaa,
            "without the 0x482b tag the +4 word keeps its prior bytes"
        );
    }

    #[test]
    fn clamps_the_text_length_and_terminates_at_the_clamped_index() {
        let _mocks = install_field_query_mocks(0, 0, 0x1ff);
        let mut text = [0x5au8; 0x200];
        unsafe {
            MOCK_QUERY_TEXT = text.as_mut_ptr();
        }
        let mut object = field_text_object(0x1234);

        assert_eq!(unsafe { object_install_field_text(object.as_mut_ptr()) }, 0);
        assert!(
            object[OBJECT_TEXT_OFFSET..OBJECT_TEXT_OFFSET + 0xff]
                .iter()
                .all(|&byte| byte == 0x5a),
            "exactly 0xff bytes are copied (`cmp r2,#0xff; movhi r2,#0xff`)"
        );
        assert_eq!(
            object[OBJECT_TEXT_OFFSET + 0xff],
            0,
            "the terminator lands at object+0x1c+0xff"
        );
        assert_eq!(
            object[OBJECT_TEXT_OFFSET + 0x100],
            0xaa,
            "nothing past the terminator is touched"
        );
    }

    #[test]
    fn frees_heap_owned_text_even_when_the_query_failed() {
        let _mocks = install_field_query_mocks(0x30, FIELD_RESULT_HEAP_TEXT, 0);
        let mut heap_text = [0u8; 16];
        unsafe {
            MOCK_QUERY_TEXT = heap_text.as_mut_ptr();
        }
        let mut object = field_text_object(0x1234);

        assert_eq!(
            unsafe { object_install_field_text(object.as_mut_ptr()) },
            0x30,
            "the failure status is still returned"
        );
        assert_eq!(
            unsafe { HEAP_FREE_CALLS },
            1,
            "the free runs outside the success branch (`tst r0,#0x1` after it)"
        );
        assert_eq!(
            unsafe { HEAP_FREE_POINTER },
            heap_text.as_mut_ptr() as usize,
            "the block's text pointer is handed to the heap free"
        );
        assert!(
            object.iter().skip(4).all(|&byte| byte == 0xaa),
            "the object is untouched on the failure path"
        );
    }
}
