//! Ports of the ARM ADS 1.0.1 locale machinery — setlocale, the
//! per-category C-locale getters, localeconv and their data blocks:
//!
//! - `setlocale_core` — original: `FUN_080307bc` @ 0x080307bc (448 bytes;
//!   the install path @ 0x08030860 referenced by runtime/errno.rs is the
//!   second half of this function). Full setlocale engine, see below.
//! - `locale_name_for_mask` — original: `FUN_080306cc` @ 0x080306cc
//!   (240 bytes; sole caller: setlocale_core). Renders the current locale
//!   name for a category mask: single category -> the installed block's
//!   own name ("C" when the slot is still empty), several categories ->
//!   the `*`-prefixed hex encoding of all five slot words.
//! - `get_lc_ctype` / `get_lc_monetary` / `get_lc_numeric` — originals:
//!   `FUN_0803350c` @ 0x0803350c / `FUN_08036b80` @ 0x08036b80 /
//!   `FUN_080355f8` @ 0x080355f8 (52 bytes each, instruction-identical
//!   modulo literals; moved here from assert_rt.rs, where the category
//!   identities were not yet known). Each returns its compiled-in
//!   C-locale block for `name` NULL/""/"C", NULL for any other name.
//! - `localeconv_fill` — original: `FUN_080354b8` @ 0x080354b8
//!   (208 bytes). Fills an `Lconv` from the installed LC_MONETARY and
//!   LC_NUMERIC blocks, resolving their block-relative string offsets.
//! - `localeconv` — original: `FUN_080334dc` @ 0x080334dc (20 bytes).
//!   Refills and returns the static `lconv` (device: @ 0x08b317d4, via
//!   the pointer literal @ 0x080334f0).
//! - `ptr_or_deref_is_null` — original: `FUN_080334f4` @ 0x080334f4
//!   (24 bytes). `p == NULL || *p == NULL` — locale-block presence check
//!   (caller @ 0x083d8dec).
//!
//! ## The ADS category model
//!
//! Categories are bit masks (ADS locale.h values): LC_COLLATE 0x01,
//! LC_CTYPE 0x02, LC_MONETARY 0x04, LC_NUMERIC 0x08, LC_TIME 0x10,
//! LC_ALL 0x1f. The installed state is five pointer words at
//! libspace+0x20 + 4*i (i = bit index): collate, ctype, monetary,
//! numeric, time. The LC_CTYPE slot is stored biased +1 (so index -1/EOF
//! reads the guard byte before the flag table — see ctype.rs); readers
//! unbias with `& ~3`. Every category block carries a self-relative i32
//! at block-4 pointing at its NUL-terminated name ("C").
//!
//! The compiled-in C-locale data (extracted byte-exact from osos rodata):
//! - LC_CTYPE block @ 0x08985f00: guard byte 0x00 + the 256 ctype flags
//!   (0x08985f01, `ctype::CTYPE_FLAGS`); name "C" @ 0x08985ef8.
//! - LC_NUMERIC block @ 0x08986254 (16 bytes): three block-relative
//!   string offsets {0x0c, 0x0e, 0x0f} -> decimal_point ".",
//!   thousands_sep "", grouping "".
//! - LC_MONETARY block @ 0x0898654c (0x2b bytes): 8 char fields, all
//!   0xff (CHAR_MAX = "not available"), then seven block-relative string
//!   offsets {0x24..0x2a}, all pointing at empty strings.
//! - LC_COLLATE and LC_TIME have no per-category getter: setlocale
//!   installs the locale directory pointer 0x08985c06 itself (the word
//!   the five `add rX, pc` literals at 0x08030984..0x08030994 all
//!   resolve to; it is also passed to — and ignored by — the three
//!   getters). 0x08985c06 is NOT ~3-aligned and is not preceded by a
//!   name offset: querying the name of an installed LC_COLLATE/LC_TIME
//!   slot makes the original compute `*(0x08985c00) + 0x08985c04` =
//!   0x45444342 ('BCDE', the tail of the digit string "0123...F") +
//!   base — a garbage pointer that is returned but never dereferenced
//!   inside the locale code. The replica reproduces the surrounding
//!   bytes so the port computes the equivalent (never-dereferenced)
//!   value.
//!
//! ## setlocale_core algorithm
//!
//! 1. mask 0 or with bits outside 0x1f -> NULL.
//! 2. `name == NULL` -> pure query: `locale_name_for_mask(mask)`.
//! 3. `name[0] == '*'` -> restore path: parse five 8-digit lowercase-hex
//!    groups from name+1 (no validation, exactly 40 chars) and store
//!    group i raw into slot i when bit i is in the mask; then query.
//! 4. otherwise -> install path (@ 0x08030860): run every selected
//!    category's getter first (LC_COLLATE/LC_TIME "get" the directory
//!    pointer, which never fails — so e.g. setlocale(LC_COLLATE, "FR")
//!    succeeds, a faithful quirk); if ANY getter returns NULL, return
//!    NULL with NO slots written (no partial install). Then store all
//!    selected blocks (ctype biased +1) and query.
//!
//! ## Deviations
//!
//! - The five libspace+0x20..+0x34 words are modeled as `LC_SLOTS`
//!   (`[usize; 5]`, zero = empty like the device BSS) instead of the
//!   u32 words in `errno::Libspace` — host pointers do not fit in u32
//!   (same deviation as mbrtowc.rs's `LOCALE_CTYPE_PTR`). On the 32-bit
//!   target the two views are the same words in spirit; hooking the
//!   stock firmware readers of libspace+0x24 will need them unified.
//! - The `*` encode/restore round-trip carries the low 32 bits of each
//!   slot (8 hex digits, exactly like the original); on a 64-bit host
//!   restored slot values are therefore only meaningful for testing the
//!   parse/print logic, not as live pointers.
//! - Slot reads/writes are volatile so LLVM cannot fold the
//!   "never-written" default state into callers (mbrtowc.rs precedent).
//! - `localeconv_fill` dereferences the installed monetary/numeric
//!   blocks unconditionally, exactly like the original (which crashes if
//!   nothing was ever installed — on device `__rt_lib_init` seeds the
//!   slots at startup). Callers/tests must install a locale first.
//! - The static name buffer (device: BSS @ 0x08b2f8ec via the literal
//!   @ 0x08030980) and static lconv (@ 0x08b317d4) are `static mut`s at
//!   linker-chosen addresses.

use crate::runtime::ctype::CTYPE_FLAGS;

/// LC_COLLATE category bit (ADS locale.h).
pub const LC_COLLATE: u32 = 0x01;
/// LC_CTYPE category bit.
pub const LC_CTYPE: u32 = 0x02;
/// LC_MONETARY category bit.
pub const LC_MONETARY: u32 = 0x04;
/// LC_NUMERIC category bit.
pub const LC_NUMERIC: u32 = 0x08;
/// LC_TIME category bit.
pub const LC_TIME: u32 = 0x10;
/// All five categories.
pub const LC_ALL: u32 = 0x1f;

/// Number of category slots (bit index == slot index).
const LC_SLOT_COUNT: usize = 5;

/// A compiled-in C-locale category block with its name record, laid out
/// exactly like the osos rodata: name string, then the self-relative i32
/// name offset at block-4, then the block itself.
#[repr(C, align(4))]
struct NamedLcBlock<const N: usize> {
    /// The locale name ("C"), at block-8 like the original rodata.
    name: [u8; 4],
    /// Self-relative offset block -> name (-8), read by
    /// `locale_name_for_mask` at block-4.
    name_offset: i32,
    /// The category block itself.
    block: [u8; N],
}

impl<const N: usize> NamedLcBlock<N> {
    const fn c_locale(block: [u8; N]) -> Self {
        Self { name: *b"C\0\0\0", name_offset: -8, block }
    }

    fn block_ptr(&self) -> *const u8 {
        self.block.as_ptr()
    }
}

/// The LC_CTYPE block: guard byte 0x00 (index -1/EOF) + the 256 ctype
/// flags. Original @ 0x08985f00 (flags @ 0x08985f01, see ctype.rs).
const fn ctype_block_bytes() -> [u8; 257] {
    let mut block = [0u8; 257];
    let mut i = 0;
    while i < 256 {
        block[i + 1] = CTYPE_FLAGS[i];
        i += 1;
    }
    block
}

/// C-locale LC_CTYPE block replica (original @ 0x08985f00).
static LC_CTYPE_BLOCK: NamedLcBlock<257> = NamedLcBlock::c_locale(ctype_block_bytes());

/// C-locale LC_NUMERIC block replica (original @ 0x08986254, 16 bytes):
/// offsets {0x0c, 0x0e, 0x0f} -> ".", "", "".
static LC_NUMERIC_BLOCK: NamedLcBlock<16> = NamedLcBlock::c_locale([
    0x0c, 0x00, 0x00, 0x00, // decimal_point offset
    0x0e, 0x00, 0x00, 0x00, // thousands_sep offset
    0x0f, 0x00, 0x00, 0x00, // grouping offset
    b'.', 0x00, 0x00, 0x00, // "." @ +0xc, "" @ +0xe, "" @ +0xf
]);

/// C-locale LC_MONETARY block replica (original @ 0x0898654c, 0x2b
/// bytes): 8 CHAR_MAX char fields, 7 string offsets {0x24..0x2a}, then
/// the 7 empty strings they point at.
static LC_MONETARY_BLOCK: NamedLcBlock<0x2b> = NamedLcBlock::c_locale([
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // char fields
    0x24, 0x00, 0x00, 0x00, // int_curr_symbol offset
    0x25, 0x00, 0x00, 0x00, // currency_symbol offset
    0x26, 0x00, 0x00, 0x00, // mon_decimal_point offset
    0x27, 0x00, 0x00, 0x00, // mon_thousands_sep offset
    0x28, 0x00, 0x00, 0x00, // mon_grouping offset
    0x29, 0x00, 0x00, 0x00, // positive_sign offset
    0x2a, 0x00, 0x00, 0x00, // negative_sign offset
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // the empty strings
]);

/// Replica of the rodata around the locale directory pointer 0x08985c06
/// (bytes 0x08985c00..0x08985c30 of osos, byte-exact): the tail
/// "...BCDEF\0" of the digit string, then the u16 table the directory
/// pointer lands in. The directory pointer is `base + 6`, reproducing
/// the original's `≡ 2 (mod 4)` bias and the garbage word 0x45444342
/// that `locale_name_for_mask` reads at `(ptr & ~3) - 4` (see module
/// docs — computed, never dereferenced).
#[repr(C, align(4))]
struct LocaleDirectoryReplica([u8; 48]);

static LOCALE_DIRECTORY: LocaleDirectoryReplica = LocaleDirectoryReplica([
    0x42, 0x43, 0x44, 0x45, 0x46, 0x00, 0x00, 0x00, // "BCDEF\0" tail
    0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, //
    0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, //
    0x04, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, //
    0x05, 0x00, 0x05, 0x00, 0x04, 0x00, 0x04, 0x00, //
    0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, //
]);

/// The locale directory pointer (original: 0x08985c06). Installed
/// verbatim as the LC_COLLATE / LC_TIME "block" and passed to (and
/// ignored by) the three getters.
fn locale_directory_ptr() -> *const u8 {
    LOCALE_DIRECTORY.0.as_ptr().wrapping_add(6)
}

/// The five installed category words — model of libspace+0x20..+0x34
/// (see module docs for the u32-vs-pointer deviation). Zero = empty,
/// like the zero-initialized device BSS before `__rt_lib_init` seeds it.
static mut LC_SLOTS: [usize; LC_SLOT_COUNT] = [0; LC_SLOT_COUNT];

/// Volatile slot read (see module docs). Crate-visible for
/// runtime/lib_init.rs, whose `__rt_lib_init` port seeds the slots at
/// library init exactly like the device startup.
pub(crate) unsafe fn lc_slot_read(i: usize) -> usize {
    core::ptr::addr_of!(LC_SLOTS[i]).read_volatile()
}

/// Volatile slot write (crate-visible like [`lc_slot_read`]).
pub(crate) unsafe fn lc_slot_write(i: usize, value: usize) {
    core::ptr::addr_of_mut!(LC_SLOTS[i]).write_volatile(value);
}

/// The installed LC_NUMERIC block — the runtime model of the
/// libspace+0x2c word (slot 3). In-crate accessor for the original's
/// direct libspace readers (printf's decimal-point fetch @ 0x080359xx
/// does `ldr r0, [libspace, #0x2c]`). NULL until a locale is installed,
/// like the device BSS.
pub unsafe fn installed_lc_numeric_block() -> *const u8 {
    lc_slot_read(3) as *const u8
}

/// "C" — the default name returned for an empty slot (original: rodata
/// @ 0x0803097c, `adr r0, 0x803097c`).
static C_LOCALE_NAME: [u8; 2] = *b"C\0";

/// The `*`-encoded locale name buffer: '*' + 5 x 8 hex digits + the NUL
/// that survives from zero initialization (original: 42-byte BSS block
/// @ 0x08b2f8ec, reached through the pointer literal @ 0x08030980).
static mut ENCODED_NAME_BUFFER: [u8; 42] = [0; 42];

/// strcmp — original: `thunk_FUN_08391e44`/`FUN_08391e44` @ 0x08391e38
/// (72 bytes). ADS byte-compare loop: walks while bytes are equal and
/// nonzero, then returns 1 / 0 / -1 from an unsigned comparison of the
/// first differing byte. (Crate-private: osos has no public strcmp — see
/// AGENTS.md.)
#[inline]
unsafe fn strcmp_ads(mut a: *const u8, mut b: *const u8) -> i32 {
    while *a == *b && *a != 0 {
        a = a.add(1);
        b = b.add(1);
    }
    let (x, y) = (*a, *b);
    if x > y {
        1
    } else if x == y {
        0
    } else {
        -1
    }
}

/// Shared body of the three getters: NULL when `name` is a nonempty
/// string other than "C", otherwise the compiled-in C-locale block.
#[inline(always)]
unsafe fn select_c_locale_block(name: *const u8, c_block: *const u8) -> *const u8 {
    if !name.is_null() && *name != 0 && strcmp_ads(name, C_LOCALE_NAME.as_ptr()) != 0 {
        return core::ptr::null();
    }
    c_block
}

/// get_lc_ctype — original: `FUN_0803350c` @ 0x0803350c (52 bytes).
///
/// `locale_dir` (r0, the directory pointer 0x08985c06 at every call
/// site) is ignored by the original (`movs r0, r1`). Returns the
/// C-locale LC_CTYPE block (original @ 0x08985f00; guard byte + flags,
/// UNbiased — setlocale adds the +1) for NULL/empty/"C" `name`, NULL
/// for anything else.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn get_lc_ctype(_locale_dir: *const u8, name: *const u8) -> *const u8 {
    select_c_locale_block(name, LC_CTYPE_BLOCK.block_ptr())
}

/// get_lc_monetary — original: `FUN_08036b80` @ 0x08036b80 (52 bytes;
/// scouted as `get_lc_c_block_08036b80` before the category was known).
///
/// Same selection as `get_lc_ctype`; the block is the C-locale
/// LC_MONETARY data (original @ 0x0898654c).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn get_lc_monetary(_locale_dir: *const u8, name: *const u8) -> *const u8 {
    select_c_locale_block(name, LC_MONETARY_BLOCK.block_ptr())
}

/// get_lc_numeric — original: `FUN_080355f8` @ 0x080355f8 (52 bytes;
/// scouted as `get_lc_c_block_080355f8` before the category was known).
///
/// Same selection as `get_lc_ctype`; the block is the C-locale
/// LC_NUMERIC data (original @ 0x08986254).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn get_lc_numeric(_locale_dir: *const u8, name: *const u8) -> *const u8 {
    select_c_locale_block(name, LC_NUMERIC_BLOCK.block_ptr())
}

/// locale_name_for_mask — original: `FUN_080306cc` @ 0x080306cc
/// (240 bytes; sole caller: setlocale_core).
///
/// Multi-category mask: renders '*' + all five slot words as 8 lowercase
/// hex digits each into the static buffer and returns it (slots are
/// rendered whether selected or not — the encoding is a full snapshot).
/// Single category: an empty slot names "C"; an installed slot resolves
/// the block's own name via the self-relative offset at
/// `(block & ~3) - 4` (the `& ~3` unbiases the +1 LC_CTYPE slot). An
/// unknown single-bit value returns NULL (dead for masks setlocale_core
/// validates).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn locale_name_for_mask(mask: u32) -> *const u8 {
    if mask & mask.wrapping_sub(1) != 0 {
        // More than one category: '*' + 5 x 8 hex digits.
        let buf = core::ptr::addr_of_mut!(ENCODED_NAME_BUFFER) as *mut u8;
        *buf = b'*';
        let mut out = buf.add(1);
        for slot in 0..LC_SLOT_COUNT {
            // The original stores/loads 32-bit words; render the low 32
            // bits (see the module-docs deviation note).
            let mut word = lc_slot_read(slot) as u32;
            for _ in 0..8 {
                let nibble = (word >> 28) as u8;
                *out = if nibble < 10 { b'0' + nibble } else { 0x57 + nibble };
                word <<= 4;
                out = out.add(1);
            }
        }
        return buf;
    }
    let slot = match mask {
        LC_COLLATE => 0,
        LC_CTYPE => 1,
        LC_MONETARY => 2,
        LC_NUMERIC => 3,
        LC_TIME => 4,
        _ => return core::ptr::null(),
    };
    let installed = lc_slot_read(slot);
    if installed == 0 {
        return C_LOCALE_NAME.as_ptr();
    }
    // bic block, #3; ldr off, [block, #-4]; add name, off, block
    let block = installed & !3usize;
    let name_offset = ((block - 4) as *const i32).read();
    block.wrapping_add(name_offset as isize as usize) as *const u8
}

/// The install path of setlocale_core (the second half of the original,
/// branch target 0x08030860 — the address runtime/errno.rs documents as
/// "setlocale"). All selected getters run before any slot is written:
/// one failed name lookup means NO partial install.
unsafe fn setlocale_install(mask: u32, name: *const u8) -> *const u8 {
    let dir = locale_directory_ptr();
    let mut ctype = core::ptr::null();
    let mut monetary = core::ptr::null();
    let mut numeric = core::ptr::null();
    if mask & LC_CTYPE != 0 {
        ctype = get_lc_ctype(dir, name);
        if ctype.is_null() {
            return core::ptr::null();
        }
    }
    // LC_COLLATE and LC_TIME have no getter: the original loads the
    // directory pointer itself (never NULL, so any name "succeeds").
    if mask & LC_MONETARY != 0 {
        monetary = get_lc_monetary(dir, name);
        if monetary.is_null() {
            return core::ptr::null();
        }
    }
    if mask & LC_NUMERIC != 0 {
        numeric = get_lc_numeric(dir, name);
        if numeric.is_null() {
            return core::ptr::null();
        }
    }
    if mask & LC_CTYPE != 0 {
        // Stored biased +1: index -1/EOF lands on the guard byte.
        lc_slot_write(1, ctype as usize + 1);
    }
    if mask & LC_COLLATE != 0 {
        lc_slot_write(0, dir as usize);
    }
    if mask & LC_MONETARY != 0 {
        lc_slot_write(2, monetary as usize);
    }
    if mask & LC_NUMERIC != 0 {
        lc_slot_write(3, numeric as usize);
    }
    if mask & LC_TIME != 0 {
        lc_slot_write(4, dir as usize);
    }
    locale_name_for_mask(mask)
}

/// setlocale_core — original: `FUN_080307bc` @ 0x080307bc (448 bytes;
/// call sites: the C++ locale layer @ 0x082670fc/0x08267130/0x08267154).
///
/// The setlocale engine — see the module docs for the full algorithm
/// (validate mask; NULL name = query; '*' name = raw-slot restore;
/// otherwise all-or-nothing install). Returns the new/current locale
/// name, or NULL on a bad mask or unknown locale name.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn setlocale_core(mask: u32, name: *const u8) -> *const u8 {
    if mask == 0 || mask & !LC_ALL != 0 {
        return core::ptr::null();
    }
    if !name.is_null() {
        if *name != b'*' {
            return setlocale_install(mask, name);
        }
        // Restore path: five 8-digit hex groups, parsed with the
        // original's unvalidated `c > '9' ? c - 0x57 : c - '0'`.
        let mut p = name.add(1);
        for slot in 0..LC_SLOT_COUNT {
            let mut word: u32 = 0;
            for _ in 0..8 {
                let c = *p;
                p = p.add(1);
                let digit = if c > 0x39 { c.wrapping_sub(0x57) } else { c.wrapping_sub(0x30) };
                word = (word << 4) | digit as u32;
            }
            if mask & (1 << slot) != 0 {
                lc_slot_write(slot, word as usize);
            }
        }
    }
    locale_name_for_mask(mask)
}

/// The C89 lconv record filled by `localeconv_fill`. Device layout:
/// ten 4-byte string pointers + eight char fields = 0x30 bytes (host
/// pointers are wider; fields correspond one-to-one).
#[repr(C)]
pub struct Lconv {
    pub decimal_point: *const u8,
    pub thousands_sep: *const u8,
    pub grouping: *const u8,
    pub int_curr_symbol: *const u8,
    pub currency_symbol: *const u8,
    pub mon_decimal_point: *const u8,
    pub mon_thousands_sep: *const u8,
    pub mon_grouping: *const u8,
    pub positive_sign: *const u8,
    pub negative_sign: *const u8,
    pub int_frac_digits: u8,
    pub frac_digits: u8,
    pub p_cs_precedes: u8,
    pub p_sep_by_space: u8,
    pub n_cs_precedes: u8,
    pub n_sep_by_space: u8,
    pub p_sign_posn: u8,
    pub n_sign_posn: u8,
}

/// localeconv_fill — original: `FUN_080354b8` @ 0x080354b8 (208 bytes).
///
/// Fills `lconv` from the installed LC_MONETARY (libspace+0x28, slot 2)
/// and LC_NUMERIC (libspace+0x2c, slot 3) blocks: the three numeric
/// string pointers resolve the block-relative offsets at numeric+0/4/8,
/// the seven monetary string pointers the offsets at monetary+8..0x24,
/// and the eight char fields copy monetary bytes 0..8 verbatim.
///
/// # Safety
/// Dereferences both installed blocks unconditionally, exactly like the
/// original — a locale must have been installed (see module docs).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn localeconv_fill(lconv: *mut Lconv) {
    let monetary = lc_slot_read(2) as *const u8;
    let numeric = lc_slot_read(3) as *const u8;
    // Resolves the self-relative i32 at `block + at` to a pointer.
    let resolve = |block: *const u8, at: usize| -> *const u8 {
        let offset = (block.add(at) as *const i32).read();
        block.wrapping_offset(offset as isize)
    };
    (*lconv).decimal_point = resolve(numeric, 0);
    (*lconv).thousands_sep = resolve(numeric, 4);
    (*lconv).grouping = resolve(numeric, 8);
    (*lconv).int_curr_symbol = resolve(monetary, 0x08);
    (*lconv).currency_symbol = resolve(monetary, 0x0c);
    (*lconv).mon_decimal_point = resolve(monetary, 0x10);
    (*lconv).mon_thousands_sep = resolve(monetary, 0x14);
    (*lconv).mon_grouping = resolve(monetary, 0x18);
    (*lconv).positive_sign = resolve(monetary, 0x1c);
    (*lconv).negative_sign = resolve(monetary, 0x20);
    (*lconv).int_frac_digits = *monetary.add(0);
    (*lconv).frac_digits = *monetary.add(1);
    (*lconv).p_cs_precedes = *monetary.add(2);
    (*lconv).p_sep_by_space = *monetary.add(3);
    (*lconv).n_cs_precedes = *monetary.add(4);
    (*lconv).n_sep_by_space = *monetary.add(5);
    (*lconv).p_sign_posn = *monetary.add(6);
    (*lconv).n_sign_posn = *monetary.add(7);
}

/// The static lconv `localeconv` returns (original: BSS @ 0x08b317d4,
/// via the pointer literal @ 0x080334f0).
static mut LCONV_STATIC: Lconv = Lconv {
    decimal_point: core::ptr::null(),
    thousands_sep: core::ptr::null(),
    grouping: core::ptr::null(),
    int_curr_symbol: core::ptr::null(),
    currency_symbol: core::ptr::null(),
    mon_decimal_point: core::ptr::null(),
    mon_thousands_sep: core::ptr::null(),
    mon_grouping: core::ptr::null(),
    positive_sign: core::ptr::null(),
    negative_sign: core::ptr::null(),
    int_frac_digits: 0,
    frac_digits: 0,
    p_cs_precedes: 0,
    p_sep_by_space: 0,
    n_cs_precedes: 0,
    n_sep_by_space: 0,
    p_sign_posn: 0,
    n_sign_posn: 0,
};

/// localeconv — original: `FUN_080334dc` @ 0x080334dc (20 bytes; caller
/// @ 0x082673f8 in the C++ locale layer).
///
/// Refills the static lconv from the installed blocks and returns it.
///
/// # Safety
/// Same as `localeconv_fill`: a locale must have been installed.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn localeconv() -> *mut Lconv {
    let lconv = core::ptr::addr_of_mut!(LCONV_STATIC);
    localeconv_fill(lconv);
    lconv
}

/// ptr_or_deref_is_null — original: `FUN_080334f4` @ 0x080334f4
/// (24 bytes; caller @ 0x083d8dec).
///
/// Returns 1 when `p` is NULL or `*p` is NULL, 0 otherwise —
/// locale-block presence check.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ptr_or_deref_is_null(p: *const *const u8) -> u32 {
    (p.is_null() || (*p).is_null()) as u32
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;
    use super::*;
    use std::ffi::CStr;
    use std::string::String;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes tests: LC_SLOTS / the name buffer / LCONV_STATIC are
    /// global state. Also resets the slots to the empty (device-boot)
    /// state. Crate-visible: lib_init.rs's full-init test seeds the same
    /// slots.
    pub(crate) fn locale_state() -> MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        let guard = LOCK.lock().unwrap();
        unsafe {
            for i in 0..LC_SLOT_COUNT {
                lc_slot_write(i, 0);
            }
        }
        guard
    }

    fn cstr(p: *const u8) -> &'static str {
        assert!(!p.is_null());
        unsafe { CStr::from_ptr(p as *const _) }.to_str().unwrap()
    }

    /// Independent hex render of the expected '*' encoding.
    fn encoded(slots: [u32; 5]) -> String {
        let mut s = String::from("*");
        for w in slots {
            s.push_str(&std::format!("{w:08x}"));
        }
        s
    }

    #[test]
    fn rejects_invalid_masks() {
        let _lock = locale_state();
        unsafe {
            for mask in [0u32, 0x20, 0x3f, 0x100, 0xffffffff] {
                assert!(setlocale_core(mask, core::ptr::null()).is_null(), "mask={mask:#x}");
                assert!(setlocale_core(mask, b"C\0".as_ptr()).is_null(), "mask={mask:#x}");
            }
        }
    }

    #[test]
    fn query_before_any_install_names_c() {
        let _lock = locale_state();
        unsafe {
            for mask in [LC_COLLATE, LC_CTYPE, LC_MONETARY, LC_NUMERIC, LC_TIME] {
                assert_eq!(cstr(setlocale_core(mask, core::ptr::null())), "C");
            }
            // Multi-category query: full '*' snapshot of the zero slots.
            let name = setlocale_core(LC_ALL, core::ptr::null());
            assert_eq!(cstr(name), encoded([0; 5]));
        }
    }

    #[test]
    fn install_c_by_every_spelling() {
        for name in [b"C\0".as_ptr(), b"\0".as_ptr()] {
            let _lock = locale_state();
            unsafe {
                let ret = setlocale_core(LC_ALL, name);
                // Multi-category install returns the '*' snapshot.
                let expect = encoded([
                    locale_directory_ptr() as u32,
                    LC_CTYPE_BLOCK.block_ptr() as u32 + 1,
                    LC_MONETARY_BLOCK.block_ptr() as u32,
                    LC_NUMERIC_BLOCK.block_ptr() as u32,
                    locale_directory_ptr() as u32,
                ]);
                assert_eq!(cstr(ret), expect);
                // Slots hold the real (full-width) block addresses.
                assert_eq!(lc_slot_read(0), locale_directory_ptr() as usize);
                assert_eq!(lc_slot_read(1), LC_CTYPE_BLOCK.block_ptr() as usize + 1);
                assert_eq!(lc_slot_read(2), LC_MONETARY_BLOCK.block_ptr() as usize);
                assert_eq!(lc_slot_read(3), LC_NUMERIC_BLOCK.block_ptr() as usize);
                assert_eq!(lc_slot_read(4), locale_directory_ptr() as usize);
            }
        }
    }

    #[test]
    fn installed_blocks_resolve_their_own_name() {
        let _lock = locale_state();
        unsafe {
            setlocale_core(LC_CTYPE | LC_MONETARY | LC_NUMERIC, b"C\0".as_ptr());
            // Single-category queries resolve the name through the
            // self-relative offset at (block & ~3) - 4 (the & ~3
            // unbiases the ctype slot's +1).
            assert_eq!(cstr(setlocale_core(LC_CTYPE, core::ptr::null())), "C");
            assert_eq!(cstr(setlocale_core(LC_MONETARY, core::ptr::null())), "C");
            assert_eq!(cstr(setlocale_core(LC_NUMERIC, core::ptr::null())), "C");
        }
    }

    #[test]
    fn unknown_name_fails_without_partial_install() {
        let _lock = locale_state();
        unsafe {
            assert!(setlocale_core(LC_ALL, b"fr_FR\0".as_ptr()).is_null());
            for i in 0..LC_SLOT_COUNT {
                assert_eq!(lc_slot_read(i), 0, "slot {i} must stay empty");
            }
            // Even with a passing category ordered before the failing
            // one, nothing may be written (all getters run first).
            assert!(setlocale_core(LC_CTYPE | LC_NUMERIC, b"xx\0".as_ptr()).is_null());
            assert_eq!(lc_slot_read(1), 0);
            assert_eq!(lc_slot_read(3), 0);
        }
    }

    /// Faithful quirk: LC_COLLATE/LC_TIME have no getter, so any name
    /// "succeeds" for a mask containing only those categories, and the
    /// directory pointer is installed.
    #[test]
    fn collate_and_time_accept_any_name() {
        let _lock = locale_state();
        unsafe {
            let ret = setlocale_core(LC_COLLATE, b"fr_FR\0".as_ptr());
            assert!(!ret.is_null());
            assert_eq!(lc_slot_read(0), locale_directory_ptr() as usize);
            setlocale_core(LC_TIME, b"whatever\0".as_ptr());
            assert_eq!(lc_slot_read(4), locale_directory_ptr() as usize);
        }
    }

    /// The name of an installed LC_COLLATE/LC_TIME slot is the original's
    /// garbage pointer: `(dir & ~3)` + the word 0x45444342 ('BCDE') read
    /// at `(dir & ~3) - 4`. Never dereferenced — assert the value only.
    #[test]
    fn collate_name_reproduces_the_originals_garbage_pointer() {
        let _lock = locale_state();
        unsafe {
            setlocale_core(LC_COLLATE, b"C\0".as_ptr());
            let aligned = locale_directory_ptr() as usize & !3;
            let expect = aligned.wrapping_add(0x45444342);
            let got = setlocale_core(LC_COLLATE, core::ptr::null());
            assert_eq!(got as usize, expect);
        }
    }

    #[test]
    fn star_restore_writes_only_selected_slots() {
        let _lock = locale_state();
        unsafe {
            for i in 0..LC_SLOT_COUNT {
                lc_slot_write(i, 0x1111_0000 + i);
            }
            let name = b"*00000001deadbeef12345678cafef00d9abcdef0\0";
            // Restore only ctype (slot 1) and numeric (slot 3).
            let ret = setlocale_core(LC_CTYPE | LC_NUMERIC, name.as_ptr());
            assert_eq!(lc_slot_read(0), 0x1111_0000);
            assert_eq!(lc_slot_read(1), 0xdead_beef);
            assert_eq!(lc_slot_read(2), 0x1111_0002);
            assert_eq!(lc_slot_read(3), 0xcafe_f00d);
            assert_eq!(lc_slot_read(4), 0x1111_0004);
            // The returned name is the post-restore snapshot.
            let expect = encoded([0x1111_0000, 0xdead_beef, 0x1111_0002, 0xcafe_f00d, 0x1111_0004]);
            assert_eq!(cstr(ret), expect);
        }
    }

    /// Encode -> restore -> encode round-trips exactly (lowercase hex,
    /// 8 digits per slot).
    #[test]
    fn star_encoding_round_trips() {
        let _lock = locale_state();
        unsafe {
            let values = [0x00000001u32, 0xdeadbeef, 0x12345678, 0xcafef00d, 0x9abcdef0];
            for (i, v) in values.iter().enumerate() {
                lc_slot_write(i, *v as usize);
            }
            let first: Vec<u8> = {
                let p = setlocale_core(LC_ALL, core::ptr::null());
                cstr(p).as_bytes().to_vec()
            };
            assert_eq!(first, encoded(values).as_bytes());
            // Wipe, restore from the snapshot, re-encode.
            for i in 0..LC_SLOT_COUNT {
                lc_slot_write(i, 0);
            }
            let mut snapshot = first.clone();
            snapshot.push(0);
            let again = setlocale_core(LC_ALL, snapshot.as_ptr());
            assert_eq!(cstr(again).as_bytes(), &first[..]);
            for (i, v) in values.iter().enumerate() {
                assert_eq!(lc_slot_read(i), *v as usize);
            }
        }
    }

    #[test]
    fn localeconv_returns_the_c_locale_lconv() {
        let _lock = locale_state();
        unsafe {
            setlocale_core(LC_ALL, b"C\0".as_ptr());
            let lc = localeconv();
            // ISO C: the C locale has "." / "" everywhere and CHAR_MAX
            // (0xff on this unsigned-char target) in every char field.
            assert_eq!(cstr((*lc).decimal_point), ".");
            assert_eq!(cstr((*lc).thousands_sep), "");
            assert_eq!(cstr((*lc).grouping), "");
            assert_eq!(cstr((*lc).int_curr_symbol), "");
            assert_eq!(cstr((*lc).currency_symbol), "");
            assert_eq!(cstr((*lc).mon_decimal_point), "");
            assert_eq!(cstr((*lc).mon_thousands_sep), "");
            assert_eq!(cstr((*lc).mon_grouping), "");
            assert_eq!(cstr((*lc).positive_sign), "");
            assert_eq!(cstr((*lc).negative_sign), "");
            for (name, v) in [
                ("int_frac_digits", (*lc).int_frac_digits),
                ("frac_digits", (*lc).frac_digits),
                ("p_cs_precedes", (*lc).p_cs_precedes),
                ("p_sep_by_space", (*lc).p_sep_by_space),
                ("n_cs_precedes", (*lc).n_cs_precedes),
                ("n_sep_by_space", (*lc).n_sep_by_space),
                ("p_sign_posn", (*lc).p_sign_posn),
                ("n_sign_posn", (*lc).n_sign_posn),
            ] {
                assert_eq!(v, 0xff, "{name} must be CHAR_MAX");
            }
            // The same static is returned every time.
            assert_eq!(localeconv(), lc);
        }
    }

    /// localeconv_fill resolves arbitrary crafted blocks (proves the
    /// self-relative offset arithmetic, including negative offsets).
    #[test]
    fn localeconv_fill_resolves_crafted_blocks() {
        let _lock = locale_state();
        // Numeric block: strings placed BEFORE the offset table.
        #[repr(C, align(4))]
        struct FakeNumeric {
            strings: [u8; 4], // ",\0#\0" at block-4
            offsets: [i32; 3],
        }
        let numeric = FakeNumeric { strings: *b",\0#\0", offsets: [-4, -2, -3] };
        let numeric_base = numeric.offsets.as_ptr() as *const u8;
        // Monetary block: chars 0..8 then 7 offsets pointing at a tail.
        #[repr(C, align(4))]
        struct FakeMonetary {
            chars: [u8; 8],
            offsets: [i32; 7],
            tail: [u8; 8],
        }
        let monetary = FakeMonetary {
            chars: [1, 2, 3, 4, 5, 6, 7, 8],
            offsets: [0x24, 0x26, 0x24, 0x26, 0x24, 0x26, 0x24],
            tail: *b"$\0\xa4\0\0\0\0\0",
        };
        let monetary_base = &monetary as *const FakeMonetary as *const u8;
        unsafe {
            lc_slot_write(2, monetary_base as usize);
            lc_slot_write(3, numeric_base as usize);
            let mut out: Lconv = core::mem::zeroed();
            localeconv_fill(&mut out);
            assert_eq!(cstr(out.decimal_point), ",");
            assert_eq!(cstr(out.thousands_sep), "#");
            assert_eq!(out.grouping, numeric_base.wrapping_offset(-3));
            assert_eq!(cstr(out.int_curr_symbol), "$");
            assert_eq!(out.currency_symbol, monetary_base.wrapping_add(0x26));
            assert_eq!(cstr(out.mon_decimal_point), "$");
            assert_eq!(out.int_frac_digits, 1);
            assert_eq!(out.n_sign_posn, 8);
        }
    }

    #[test]
    fn ptr_or_deref_is_null_truth_table() {
        unsafe {
            assert_eq!(ptr_or_deref_is_null(core::ptr::null()), 1);
            let null_inner: *const u8 = core::ptr::null();
            assert_eq!(ptr_or_deref_is_null(&null_inner), 1);
            let byte = 7u8;
            let live: *const u8 = &byte;
            assert_eq!(ptr_or_deref_is_null(&live), 0);
        }
    }

    // --- getter behavior (moved with the getters from assert_rt.rs) ---

    const NULLP: *const u8 = core::ptr::null();

    #[test]
    fn getters_select_their_blocks_for_default_names() {
        unsafe {
            for name in [NULLP, b"\0".as_ptr(), b"C\0".as_ptr()] {
                assert_eq!(get_lc_ctype(NULLP, name), LC_CTYPE_BLOCK.block_ptr());
                assert_eq!(get_lc_monetary(NULLP, name), LC_MONETARY_BLOCK.block_ptr());
                assert_eq!(get_lc_numeric(NULLP, name), LC_NUMERIC_BLOCK.block_ptr());
            }
        }
    }

    #[test]
    fn getters_reject_other_names_and_ignore_the_directory_arg() {
        unsafe {
            let garbage = 0xdeadbeefusize as *const u8;
            for name in [&b"x\0"[..], &b"c\0"[..], &b"CC\0"[..], &b"C \0"[..], &b"POSIX\0"[..]] {
                assert!(get_lc_ctype(garbage, name.as_ptr()).is_null(), "{name:?}");
                assert!(get_lc_monetary(garbage, name.as_ptr()).is_null(), "{name:?}");
                assert!(get_lc_numeric(garbage, name.as_ptr()).is_null(), "{name:?}");
            }
            assert_eq!(get_lc_ctype(garbage, b"C\0".as_ptr()), LC_CTYPE_BLOCK.block_ptr());
        }
    }

    /// The ctype block replica must be the guard byte + the ctype.rs
    /// flag table, and carry the "C" name record at block-8/-4.
    #[test]
    fn ctype_block_layout_is_guard_plus_flags_with_name_record() {
        assert_eq!(LC_CTYPE_BLOCK.block[0], 0, "guard byte");
        assert_eq!(&LC_CTYPE_BLOCK.block[1..], &CTYPE_FLAGS[..]);
        let block = LC_CTYPE_BLOCK.block_ptr();
        unsafe {
            let off = (block.sub(4) as *const i32).read();
            assert_eq!(off, -8);
            assert_eq!(cstr(block.wrapping_offset(off as isize)), "C");
        }
        // The directory pointer keeps the original's alignment bias.
        assert_eq!(locale_directory_ptr() as usize & 3, 2);
    }

    /// Mirror of ADS strcmp @ 0x08391e38: -1/0/1, unsigned byte compare.
    #[test]
    fn strcmp_ads_matches_ads_semantics() {
        unsafe {
            assert_eq!(strcmp_ads(b"C\0".as_ptr(), b"C\0".as_ptr()), 0);
            assert_eq!(strcmp_ads(b"\0".as_ptr(), b"\0".as_ptr()), 0);
            assert_eq!(strcmp_ads(b"a\0".as_ptr(), b"b\0".as_ptr()), -1);
            assert_eq!(strcmp_ads(b"b\0".as_ptr(), b"a\0".as_ptr()), 1);
            assert_eq!(strcmp_ads(b"ab\0".as_ptr(), b"abc\0".as_ptr()), -1);
            assert_eq!(strcmp_ads(b"abc\0".as_ptr(), b"ab\0".as_ptr()), 1);
            assert_eq!(strcmp_ads(b"\xff\0".as_ptr(), b"a\0".as_ptr()), 1);
            assert_eq!(strcmp_ads(b"a\0".as_ptr(), b"\xff\0".as_ptr()), -1);
        }
    }
}
