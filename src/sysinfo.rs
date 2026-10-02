//! System-info accessors — the lazily cached board-version word.
//!
//! retailOS keeps a system-info struct in RAM at 0x089caaac (referenced
//! only from the literal pools of `board_version` @ 0x080e624c and its two
//! neighbors in the 0x082bcxxx diagnostics cluster, binary-scanned); its
//! word at +0x8 caches the board/firmware revision word behind a
//! 0x7fffffff sentinel. The authoritative copy lives at +0x84 of the
//! process-wide shared-context object returned by
//! [`crate::ui::object_state::shared_context`] @ 0x08369bec. The cached
//! word's HIGH halfword 0x10 with LOW halfword >= 6 marks the board
//! generation whose timer channel 3
//! [`crate::codegen::timer_wait`](crate::codegen::timer_wait) waits on.

use crate::ui::object_state::shared_context;

#[cfg(test)]
extern crate std;

/// System-info struct base the query's literal-pool word at 0x080e6278
/// holds (binary-verified: `ac aa 9c 08`); field +0x8 is the lazily
/// cached board-version word.
#[cfg(target_os = "none")]
const SYSTEM_INFO_BASE: usize = 0x089c_aaac;

/// Offset of the lazily cached board-version word in the system-info
/// struct (`ldr r0,[r4,#0x8]` / `strne r0,[r4,#0x8]`).
#[cfg(target_os = "none")]
const CACHED_BOARD_VERSION_OFFSET: usize = 0x8;

/// Offset of the authoritative board-version word in the shared-context
/// object (`ldrne r0,[r0,#0x84]`).
const CONTEXT_BOARD_VERSION_OFFSET: usize = 0x84;

/// Not-yet-cached marker for the board-version word. The original tests
/// it with `cmn r0,#0x80000001` / `bne` — a compare against
/// 0x7fffffff spelled as an add-with-negative.
const BOARD_VERSION_SENTINEL: u32 = 0x7fff_ffff;

/// Host builds substitute this static for the fixed RAM struct field so
/// tests can drive both cache states without mapping retailOS RAM.
#[cfg(not(target_os = "none"))]
static mut HOST_CACHED_BOARD_VERSION: u32 = BOARD_VERSION_SENTINEL;
/// Diagnostics cluster's cached board-generation classification byte. The
/// original's literal-pool word at 0x082bc668 holds this address.
#[cfg(target_os = "none")]
const DIAGNOSTICS_BOARD_GENERATION_CACHE: usize = 0x089c_ae8c;

/// Sentinel used by the diagnostics board-generation cache.
const DIAGNOSTICS_BOARD_GENERATION_UNINITIALIZED: i8 = -1;

/// Host replacement for the diagnostics cache byte at 0x089cae8c.
#[cfg(not(target_os = "none"))]
static mut HOST_DIAGNOSTICS_BOARD_GENERATION_CACHE: i8 =
    DIAGNOSTICS_BOARD_GENERATION_UNINITIALIZED;

#[cfg(test)]
static HOST_DIAGNOSTICS_BOARD_GENERATION_CACHE_LOCK: std::sync::Mutex<()> =
    std::sync::Mutex::new(());

/// Serializes test-only writes to the host board-version cache so other
/// modules can exercise callers of [`board_version`] without racing this
/// module's cache tests.
#[cfg(test)]
pub(crate) static HOST_CACHED_BOARD_VERSION_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

use crate::drivers::storage_backend_pin_89_status::storage_backend_pin_89_status;


/// Restores the host board-version cache to its sentinel on drop.
#[cfg(test)]
pub(crate) struct HostCachedBoardVersion {
    _guard: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
impl Drop for HostCachedBoardVersion {
    fn drop(&mut self) {
        unsafe {
            core::ptr::addr_of_mut!(HOST_CACHED_BOARD_VERSION).write(BOARD_VERSION_SENTINEL);
        }
    }
}

/// Installs a non-sentinel board version for a host caller test.
#[cfg(test)]
pub(crate) fn install_host_cached_board_version(version: u32) -> HostCachedBoardVersion {
    let guard = HOST_CACHED_BOARD_VERSION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    unsafe {
        core::ptr::addr_of_mut!(HOST_CACHED_BOARD_VERSION).write(version);
    }
    HostCachedBoardVersion {
        _guard: guard,
    }
}


#[inline(always)]
unsafe fn cached_board_version_slot() -> *mut u32 {
    #[cfg(target_os = "none")]
    {
        (SYSTEM_INFO_BASE + CACHED_BOARD_VERSION_OFFSET) as *mut u32
    }

    #[cfg(not(target_os = "none"))]
    {
        core::ptr::addr_of_mut!(HOST_CACHED_BOARD_VERSION)
    }
}

/// board_version — original: `FUN_080e624c` @ 0x080e624c (44 code bytes
/// plus the 4-byte literal-pool word at 0x080e6278 Ghidra's 44-byte
/// extent excludes; the next function's `stmdb sp!,{r0-r11,lr}` prologue
/// starts at 0x080e627c, so the true occupied range is 48 bytes).
///
/// Binary-verified call sites: **13 direct `bl` callers**, all
/// unconditional (cond=e — no predicated forms), plus one 4-byte branch
/// veneer `b 0x080e624c` @ 0x080515e4 that the ported
/// [`board_version_halves`](crate::fp::fp_misc) diagnostics splitter
/// calls through. No word in osos.dec holds the value 0x080e624c
/// (binary-scanned), so the function is not dispatched virtually.
///
/// The whole body is:
///
/// ```text
/// stmdb sp!,{r4,lr}
/// ldr   r4,[0x080e6278]      ; r4 = 0x089caaac (system-info struct)
/// ldr   r0,[r4,#0x8]         ; cached word
/// cmn   r0,#0x80000001       ; cached == 0x7fffffff ?
/// bne   0x080e6270
/// bl    0x08369bec           ; shared_context()
/// cmp   r0,#0
/// ldrne r0,[r0,#0x84]        ; context's authoritative word
/// strne r0,[r4,#0x8]         ; cache it
/// ldr   r0,[r4,#0x8]         ; reload and return the cache
/// ldmia sp!,{r4,pc}
/// ```
///
/// Answers the lazily cached board-version word: while the cache still
/// holds the 0x7fffffff sentinel the authoritative word is fetched from
/// +0x84 of the shared-context object and republished into the cache —
/// but only when the context getter returned non-NULL (`cmp r0,#0` /
/// `ldrne` / `strne` guard the refresh; with a NULL context the sentinel
/// is left in place and returned as-is). Once cached, the context is
/// never consulted again. The final `ldr` reloads the cache word rather
/// than keeping it in a register, so a NULL context on the refresh path
/// still returns the (sentinel) cache content; the port reproduces that
/// double read with volatile accesses.
///
/// Deviations:
/// - The `stmdb sp!,{r4,lr}` / `ldmia sp!,{r4,pc}` frame only keeps the
///   struct base alive across the `bl`; the port rematerializes the
///   address instead and keeps no frame (an ADS artifact).
/// - The refresh callee is the already-ported
///   [`shared_context`](crate::ui::object_state::shared_context), called
///   directly; on target the link resolves it to the Rust port in
///   librustypod.a.
/// - Host builds read and write a static in place of the fixed RAM field
///   (this module's version of the object_state host-storage pattern);
///   target behavior is unchanged.
///
/// # Safety
///
/// On target the fixed RAM field must be writable; like the original,
/// the context pointer is trusted to be readable at +0x84 whenever the
/// getter returns non-NULL.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn board_version() -> u32 {
    let cache = cached_board_version_slot();
    if cache.read_volatile() == BOARD_VERSION_SENTINEL {
        let context = shared_context();
        if !context.is_null() {
            let word = (context.add(CONTEXT_BOARD_VERSION_OFFSET) as *const u32).read_volatile();
            cache.write_volatile(word);
        }
    }
    cache.read_volatile()
}

/// iram_copy_start_offset — retailOS `FUN_082bc600` at `0x082bc600`.
///
/// True extent: 8 bytes, ending before the independent literal-load getter
/// at `0x082bc608`. Raw words `e3a00906 e12fff1e` decode to
/// `mov r0,#0x18000; bx lr`. Whole-image aligned A32 decoding verifies
/// two inbound plain BLs (`0x080a6c84`, `0x080b5210`), zero predicated
/// BLs, and no outbound calls.
///
/// Return the fixed start offset subtracted from [`iram_copy_end_offset`]
/// by both callers to obtain the byte count copied from IRAM mirror
/// `0x22000000`. No memory access, arguments, or deliberate deviations.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn iram_copy_start_offset() -> u32 {
    0x0001_8000
}

#[cfg(test)]
mod iram_copy_start_offset_tests {
    use super::iram_copy_start_offset;

    #[test]
    fn caller_byte_count_preserves_zero_and_unsigned_wraparound() {
        // The callers use ARM SUB without saturating or validating the end.
        for (end, expected) in [
            (0x18000u32, 0),
            (0x18001, 1),
            (0x24000, 0xc000),
            (0x17fff, u32::MAX),
            (0, 0xfffe_8000),
            (u32::MAX, 0xfffe_7fff),
        ] {
            assert_eq!(end.wrapping_sub(iram_copy_start_offset()), expected);
        }
    }
}

#[cfg(not(target_os = "none"))]
static mut HOST_IRAM_COPY_END_OFFSET: u32 = u32::MAX;

/// iram_copy_end_offset — retailOS `FUN_082bc794` at `0x082bc794`.
///
/// True occupied extent: 48 bytes through `0x082bc7c3`, including the
/// literal at `0x082bc7c0`; the instruction body is 44 bytes. The next
/// independent function starts at `0x082bc7c4`. Raw A32 decoding verifies
/// two inbound plain BLs (`0x080a6c7c`, `0x080b5208`), one outbound plain
/// BL to shared_context (`0x08369bec`), and zero predicated BLs.
///
/// Read system-info word +0xc at `0x089caaac`. If it is `u32::MAX`, fetch
/// the shared context and, only when non-NULL, cache its aligned word +0xe8.
/// Reload and return the cache. A sentinel-valued source remains retryable;
/// zero and every other word are valid cached values. Both stock callers
/// subtract 0x18000 to obtain the byte count copied from IRAM mirror
/// 0x22000000, hence this is the copy's exclusive end offset.
///
/// Deviations: host builds substitute a static for fixed RAM; target calls
/// the existing Rust shared_context port. No target behavioral deviations.
///
/// # Safety
/// Fixed target RAM must be writable, and a non-NULL shared context must
/// contain a readable, word-aligned u32 at +0xe8. Access is externally serialized.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn iram_copy_end_offset() -> u32 {
    #[cfg(target_os = "none")]
    let cache = (SYSTEM_INFO_BASE + 0xc) as *mut u32;
    #[cfg(not(target_os = "none"))]
    let cache = core::ptr::addr_of_mut!(HOST_IRAM_COPY_END_OFFSET);

    if cache.read_volatile() == u32::MAX {
        let context = shared_context();
        if !context.is_null() {
            cache.write_volatile(context.add(0xe8).cast::<u32>().read_volatile());
        }
    }
    cache.read_volatile()
}

/// board_version_is_11_19_or_20 — retailOS `FUN_082964dc` at `0x082964dc`.
///
/// True size: 40 bytes, ending at `0x08296500` with pop {r4,pc}; the next
/// function starts at `0x08296504`. Raw A32 decoding verifies two inbound
/// plain BLs (`0x081042b8`, `0x08104604`), zero predicated inbound BLs,
/// and one outbound plain BL to shared_context (`0x08369bec`).
///
/// Read the aligned board-version word at shared-context +0x84, shift right
/// by 16, and return exactly 1 for codes 11, 19, or 20, otherwise 0. The
/// low halfword is ignored. Both callers pass this predicate to the same
/// resource-selection routine at `0x082a1df8`; the code meanings are unknown.
///
/// Deviations: reuse the existing Rust shared_context port and its host
/// backing storage. No target behavioral deviations or added NULL guard.
///
/// # Safety
/// The shared context must be non-NULL and contain a readable, word-aligned
/// u32 at +0x84. Access to the shared-context slot is externally serialized.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn board_version_is_11_19_or_20() -> u32 {
    let code = shared_context().add(0x84).cast::<u32>().read_volatile() >> 16;
    matches!(code, 11 | 19 | 20) as u32
}

#[cfg(test)]
mod board_version_code_tests {
    use super::*;

    struct ContextReset;

    impl Drop for ContextReset {
        fn drop(&mut self) {
            unsafe {
                crate::ui::object_state::host_install_shared_context(core::ptr::null_mut());
            }
        }
    }

    #[test]
    fn classifies_every_high_halfword_independently_of_low_halfword() {
        let _guard = crate::ui::object_state::SHARED_CONTEXT_TEST_LOCK
            .lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = ContextReset;
        let mut context = [0xa5a5_a5a5u32; 0x88 / 4];
        unsafe {
            crate::ui::object_state::host_install_shared_context(context.as_mut_ptr().cast());
            for high in 0..=u16::MAX as u32 {
                for low in [0, 1, 0x8000, 0xffff] {
                    context[0x84 / 4] = (high << 16) | low;
                    let expected = if high == 11 || high == 19 || high == 20 { 1 } else { 0 };
                    assert_eq!(board_version_is_11_19_or_20(), expected,
                        "board word {:#010x}", context[0x84 / 4]);
                    assert_eq!(context[0x84 / 4], (high << 16) | low);
                    assert_eq!(context[0x80 / 4], 0xa5a5_a5a5);
                }
            }
        }
    }
}

#[cfg(test)]
mod iram_copy_end_offset_tests {
    use super::*;
    use std::sync::MutexGuard;

    struct Fixture(MutexGuard<'static, ()>);

    impl Fixture {
        fn install(cache: u32, context: *mut u8) -> Self {
            let guard = crate::ui::object_state::SHARED_CONTEXT_TEST_LOCK
                .lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            unsafe {
                core::ptr::addr_of_mut!(HOST_IRAM_COPY_END_OFFSET).write(cache);
                crate::ui::object_state::host_install_shared_context(context);
            }
            Self(guard)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(HOST_IRAM_COPY_END_OFFSET).write(u32::MAX);
                crate::ui::object_state::host_install_shared_context(core::ptr::null_mut());
            }
        }
    }

    #[test]
    fn null_context_leaves_cache_retryable() {
        let _fixture = Fixture::install(u32::MAX, core::ptr::null_mut());
        unsafe {
            assert_eq!(iram_copy_end_offset(), u32::MAX);
            let mut context = [0u32; 0xec / 4];
            context[0xe8 / 4] = 0x24000;
            crate::ui::object_state::host_install_shared_context(context.as_mut_ptr().cast());
            assert_eq!(iram_copy_end_offset(), 0x24000);
        }
    }

    #[test]
    fn every_non_sentinel_value_is_cached_without_refresh() {
        let mut context = [0u32; 0xec / 4];
        context[0xe8 / 4] = 0x12345678;
        for value in [0, 1, 0x18000, 0x80000000, u32::MAX - 1] {
            let _fixture = Fixture::install(value, context.as_mut_ptr().cast());
            assert_eq!(unsafe { iram_copy_end_offset() }, value);
        }
    }

    #[test]
    fn refresh_uses_field_e8_and_sticks_except_for_sentinel() {
        for value in [0, 0x24000, 0x80000000, u32::MAX] {
            let mut context = [0xa5a5a5a5u32; 0xec / 4];
            context[0xe8 / 4] = value;
            let _fixture = Fixture::install(u32::MAX, context.as_mut_ptr().cast());
            assert_eq!(unsafe { iram_copy_end_offset() }, value);
            context[0xe8 / 4] = 0x34567;
            assert_eq!(unsafe { iram_copy_end_offset() },
                if value == u32::MAX { 0x34567 } else { value });
        }
    }
}

/// storage_backend_status — retailOS `FUN_082bc7c4` at `0x082bc7c4`.
///
/// Raw ARM runs from `push {r4,lr}` through `pop {r4,pc}` at `0x082bc844`:
/// **132 bytes** (33 words); the distinct `push {r4,r5,r6,lr}` at
/// `0x082bc848` is the next function boundary. Binary decoding finds **three
/// direct inbound `bl` callers**, all plain unconditional instructions at
/// `0x080e4b80`, `0x080e706c`, and `0x082bcb80; no predicated `bl` callers.
/// The body has one unconditional `bl` to [`board_version`] and tail-branches
/// to `0x082bc488` for the remaining cases.
///
/// It classifies `board_version() >> 16`: 0, 14, and out-of-range values
/// return 0; 13, 15 through 18, and 20 return 4; all other in-range values
/// (1 through 12, 19, and 21) tail-call the pin-89 status target, which
/// returns 2 or 3 after reading GPIO pin 0x59.
///
/// # Deliberate deviation
///
/// Both `board_version` and the pin-89 tail-call target are now called through
/// their Rust ports rather than fixed firmware addresses.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn storage_backend_status() -> u32 {
    match board_version() >> 16 {
        1..=12 | 19 | 21 => storage_backend_pin_89_status(),
        13 | 15..=18 | 20 => 4,
        _ => 0,
    }
}

#[inline(always)]
unsafe fn diagnostics_board_generation_cache_slot() -> *mut i8 {
    #[cfg(target_os = "none")]
    {
        DIAGNOSTICS_BOARD_GENERATION_CACHE as *mut i8
    }

    #[cfg(not(target_os = "none"))]
    {
        core::ptr::addr_of_mut!(HOST_DIAGNOSTICS_BOARD_GENERATION_CACHE)
    }
}

/// diagnostics_board_generation — original: `FUN_082bc614` @ 0x082bc614
/// (84 code bytes plus its 4-byte literal-pool word at 0x082bc668; the
/// next function starts at 0x082bc66c, so the true occupied range is
/// 88 bytes).
///
/// Binary-verified call sites: **2 plain, unconditional `bl` instructions**
/// (`bl 0x080e624c` at 0x082bc628 and 0x082bc630); no predicated `bl`
/// instructions. The function has four direct callers.
///
/// Reads a signed cache byte at 0x089cae8c. If it is -1, obtains the
/// board-version word twice: the first read supplies its high halfword,
/// and the second supplies its low halfword. It stores and returns 1 only
/// for high halfword 0x13 and low halfword 0x10 through 0xff inclusive;
/// every other pair stores and returns 2. A non-sentinel cache byte is
/// returned unchanged.
///
/// Deliberate deviations: `board_version` is the existing Rust seam for
/// `FUN_080e624c`; host builds substitute a static for the fixed cache
/// address. Volatile byte accesses retain the original's separate signed
/// `ldrsb` reads and byte store.
///
/// # Safety
///
/// On target, 0x089cae8c must be a readable and writable cache byte.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn diagnostics_board_generation() -> i32 {
    let cache = diagnostics_board_generation_cache_slot();
    let cached_generation = cache.read_volatile();
    if cached_generation != DIAGNOSTICS_BOARD_GENERATION_UNINITIALIZED {
        return cached_generation as i32;
    }

    let version_high = board_version() >> 16;
    let version_low = board_version() as u16;
    let generation = if version_high == 0x13 && (0x10..0x100).contains(&version_low) {
        1
    } else {
        2
    };
    cache.write_volatile(generation);
    cache.read_volatile() as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    use std::sync::MutexGuard;

    /// Serializes access to this module's host cache static; acquired
    /// before the shared-context lock so the two modules' lock order is
    /// consistent (object_state's own tests take VERSION_TEXT_LOCK, then
    /// SHARED_CONTEXT_TEST_LOCK, and never this one).

    /// Holds both locks for the fixture's lifetime and restores the
    /// sentinel cache / NULL context on drop.
    struct Fixture {
        _cache_guard: MutexGuard<'static, ()>,
        _context_guard: MutexGuard<'static, ()>,
    }

    impl Fixture {
        fn install(cache: u32, context: *mut u8) -> Fixture {
            let cache_guard = HOST_CACHED_BOARD_VERSION_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let context_guard = crate::ui::object_state::SHARED_CONTEXT_TEST_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            unsafe {
                core::ptr::addr_of_mut!(HOST_CACHED_BOARD_VERSION).write(cache);
                crate::ui::object_state::host_install_shared_context(context);
            }
            Fixture {
                _cache_guard: cache_guard,
                _context_guard: context_guard,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(HOST_CACHED_BOARD_VERSION).write(BOARD_VERSION_SENTINEL);
                crate::ui::object_state::host_install_shared_context(core::ptr::null_mut());
            }
        }
    }

    /// A shared-context stand-in large enough to hold the word at +0x84
    /// (0x88 bytes, word-aligned so the port's aligned `u32` read models
    /// the original's `ldr`).
    struct Context([u32; 0x88 / 4]);

    impl Context {
        fn with_version_word(word: u32) -> Context {
            let mut context = Context([0u32; 0x88 / 4]);
            context.0[CONTEXT_BOARD_VERSION_OFFSET / 4] = word;
            context
        }

        fn as_ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr() as *mut u8
        }

        fn write_version_word(&mut self, word: u32) {
            self.0[CONTEXT_BOARD_VERSION_OFFSET / 4] = word;
        }
    }

    #[test]
    fn returns_the_cached_word_without_consulting_the_context() {
        // No context installed: any refresh attempt would observe NULL
        // and leave the cache untouched, so a changed return value could
        // only come from the cache itself.
        let _fixture = Fixture::install(0x0010_0006, core::ptr::null_mut());

        assert_eq!(unsafe { board_version() }, 0x0010_0006);
        assert_eq!(
            unsafe { core::ptr::addr_of!(HOST_CACHED_BOARD_VERSION).read() },
            0x0010_0006,
            "a non-sentinel cache is returned verbatim and never refreshed"
        );
    }

    #[test]
    fn keeps_the_sentinel_when_the_context_is_null() {
        let _fixture = Fixture::install(BOARD_VERSION_SENTINEL, core::ptr::null_mut());

        assert_eq!(unsafe { board_version() }, BOARD_VERSION_SENTINEL);
        assert_eq!(
            unsafe { core::ptr::addr_of!(HOST_CACHED_BOARD_VERSION).read() },
            BOARD_VERSION_SENTINEL,
            "the cmp r0,#0 / strne guard blocks the refresh on a NULL context"
        );
    }

    #[test]
    fn refreshes_once_from_context_field_84_then_sticks() {
        let mut context = Context::with_version_word(0x0010_0006);
        let _fixture = Fixture::install(BOARD_VERSION_SENTINEL, context.as_ptr());

        assert_eq!(
            unsafe { board_version() },
            0x0010_0006,
            "the sentinel triggers one refresh from context +0x84"
        );
        assert_eq!(
            unsafe { core::ptr::addr_of!(HOST_CACHED_BOARD_VERSION).read() },
            0x0010_0006,
            "the refreshed word is republished into the cache"
        );

        context.write_version_word(0xdead_beef);
        assert_eq!(
            unsafe { board_version() },
            0x0010_0006,
            "once cached, the context is never consulted again"
        );
    }

    #[test]
    fn caches_a_zero_context_word_as_a_valid_value() {
        // Zero is a legitimate refreshed word: only 0x7fffffff is the
        // sentinel, so a zero field +0x84 must replace the cache and end
        // the refresh path for good.
        let mut context = Context::with_version_word(0);
        let _fixture = Fixture::install(BOARD_VERSION_SENTINEL, context.as_ptr());

        assert_eq!(unsafe { board_version() }, 0);
        assert_eq!(unsafe { core::ptr::addr_of!(HOST_CACHED_BOARD_VERSION).read() }, 0);


        context.write_version_word(0x0010_0006);
        assert_eq!(
            unsafe { board_version() },
            0,
            "a cached zero is not mistaken for the sentinel"
        );
    }

    #[test]
    fn storage_backend_status_classifies_all_board_generation_edges() {
        use crate::drivers::gpio_pin_read::host_gpio_data;
        let _guard = host_gpio_data::LOCK.lock();
        for (version_high, expected) in [
            (0, 0),
            (1, 3),
            (12, 3),
            (13, 4),
            (14, 0),
            (15, 4),
            (18, 4),
            (20, 4),
            (19, 3),
            (21, 3),
            (22, 0),
            (u32::MAX, 0),
        ] {
            let _fixture = install_host_cached_board_version(version_high << 16);
            unsafe {
                core::ptr::write_volatile(core::ptr::addr_of_mut!(host_gpio_data::DATA_WORD), 2);
            }
            assert_eq!(unsafe { storage_backend_status() }, expected, "{version_high}");
            if matches!(version_high, 1..=12 | 19 | 21) {
                unsafe {
                    core::ptr::write_volatile(core::ptr::addr_of_mut!(host_gpio_data::DATA_WORD), !2);
                    assert_eq!(storage_backend_status(), 2, "{version_high}: GPIO low");
                }
            }
        }
    }

    struct DiagnosticsFixture {
        _generation_guard: MutexGuard<'static, ()>,
        _board_version: HostCachedBoardVersion,
    }

    impl DiagnosticsFixture {
        fn install(version: u32) -> DiagnosticsFixture {
            let generation_guard = HOST_DIAGNOSTICS_BOARD_GENERATION_CACHE_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            unsafe {
                core::ptr::addr_of_mut!(HOST_DIAGNOSTICS_BOARD_GENERATION_CACHE)
                    .write(DIAGNOSTICS_BOARD_GENERATION_UNINITIALIZED);
            }
            DiagnosticsFixture {
                _generation_guard: generation_guard,
                _board_version: install_host_cached_board_version(version),
            }
        }
    }

    impl Drop for DiagnosticsFixture {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(HOST_DIAGNOSTICS_BOARD_GENERATION_CACHE)
                    .write(DIAGNOSTICS_BOARD_GENERATION_UNINITIALIZED);
            }
        }
    }

    #[test]
    fn diagnostics_board_generation_accepts_only_the_verified_version_window() {
        for (version, expected) in [
            (0x0013_0010, 1),
            (0x0013_00ff, 1),
            (0x0013_000f, 2),
            (0x0013_0100, 2),
            (0x0012_0010, 2),
        ] {
            let _fixture = DiagnosticsFixture::install(version);
            assert_eq!(unsafe { diagnostics_board_generation() }, expected, "{version:#010x}");
        }
    }

    #[test]
    fn diagnostics_board_generation_returns_a_non_sentinel_cached_byte() {
        let _fixture = DiagnosticsFixture::install(0x0013_0010);
        unsafe {
            core::ptr::addr_of_mut!(HOST_DIAGNOSTICS_BOARD_GENERATION_CACHE).write(-7);
        }

        assert_eq!(unsafe { diagnostics_board_generation() }, -7);
    }
}
