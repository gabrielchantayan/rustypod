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
/// Serializes test-only writes to the host board-version cache so other
/// modules can exercise callers of [`board_version`] without racing this
/// module's cache tests.
#[cfg(test)]
pub(crate) static HOST_CACHED_BOARD_VERSION_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
}
