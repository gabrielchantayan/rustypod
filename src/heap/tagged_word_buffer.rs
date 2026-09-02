//! `tagged_word_buffer_destroy` — destructor for the 20-byte tagged u32
//! buffer object.
//!
//! Original: `FUN_0803e5e4` @ 0x0803e5e4 (92 bytes exactly,
//! 0x0803e5e4..0x0803e640; the next independent body — the sibling key
//! comparator `FUN_0803e640` — starts immediately at 0x0803e640, so no
//! trailing literal pool is dropped). A full decode of every ARM B/BL word
//! in `osos.dec` finds 22 direct call sites, matching Ghidra's count: 14
//! unconditional `bl` plus 8 `blne` (all 8 at 0x080623cc..0x08062420, each
//! immediately preceded by `cmp r0, #0` — those callers NULL-check even
//! though the destructor has its own `movs`/`popeq` NULL guard). No `b`
//! tail calls target it.
//!
//! The object is five target words `{data, len, capacity, tag, flags}` —
//! the first three are exactly [`crate::heap::word_buffer::WordBuffer`];
//! the sibling comparator @ 0x0803e640 orders two objects by `tag` (a zero
//! tag sorts above any nonzero one), then by `len` (signed), then by an
//! unsigned lexicographic walk of the `data` u32 elements, which pins the
//! field layout. Destruction order:
//!
//! 1. NULL `this` returns immediately.
//! 2. If `data != NULL`: poison the buffer with the unported heap-poison
//!    helper `FUN_0805f440(data, capacity << 2)`, then, unless
//!    `flags & FLAG_BUFFER_BORROWED`, release it through the ported
//!    `traced_free` @ 0x08043994. `FLAG_BUFFER_BORROWED` marks a buffer
//!    the object does not own.
//! 3. `flags` is RELOADED from the object (the original re-reads +0x10 at
//!    0x0803e618, after the buffer poison/free — a later flag store by
//!    either call is honored), bit 0 (`FLAG_DELETE_THIS`) is latched, and
//!    the object itself is poisoned (`FUN_0805f440(this, 20)`).
//! 4. If the latched bit was set, `this` is released through `traced_free`
//!    — the scalar-deleting-destructor bit. The original tail-branches
//!    (`bne 0x08043994`); the port makes an ordinary returning call, the
//!    same documented deviation as `traced_free`'s own post-trace branch.
//!
//! Deliberate deviation: `FUN_0805f440` is not in `names.yaml` as ported,
//! so both direct calls go through the indirect, volatile
//! [`TAGGED_WORD_BUFFER_POISON`] hook (the `WORD_BUFFER_GROW` pattern).
//! Firmware builds default it to the stock address 0x0805f440; host builds
//! default to a no-op — the scrub is a debug fill with no effect on the
//! destructor's ownership contract. The helper itself (for whoever ports
//! it): 0x0805f440..0x0805f4a0, 19 unconditional `bl` sites, fills
//! `dst[0..len]` from a rolling state byte @ 0x08a0ea04 (the traced_alloc
//! large-allocation tag byte; state = `(addr & 15) + state + 17` per byte,
//! wrapping), then runs the ported `memchr` @ 0x08031180 over the fill for
//! the final state value and bumps the state by 63 on a hit.

use crate::drivers::ata_cmd::traced_free;

/// `flags` bit 0: release `this` itself through `traced_free` after the
/// object has been poisoned (scalar deleting destructor behavior).
pub const FLAG_DELETE_THIS: u32 = 1;
/// `flags` bit 1: the `data` buffer is borrowed — poison it but do not
/// release it.
pub const FLAG_BUFFER_BORROWED: u32 = 2;

/// Object size in bytes — the original poisons `this` with a literal 20
/// (0x0803e61c: `mov r1, #20`).
pub const TAGGED_WORD_BUFFER_SIZE: u32 = 20;

/// Target-layout tagged u32 buffer. Every field stays a target word so the
/// layout is 20 bytes on host and target alike; `data` is a target pointer
/// word, not a host pointer.
#[repr(C)]
pub struct TaggedWordBuffer {
    /// +0x00: element storage (target pointer word), NULL when empty.
    pub data: u32,
    /// +0x04: live element count (the comparator's signed length key).
    pub len: u32,
    /// +0x08: allocated element capacity; the destructor poisons
    /// `capacity << 2` bytes of `data`.
    pub capacity: u32,
    /// +0x0c: ordering tag (the comparator's primary key).
    pub tag: u32,
    /// +0x10: [`FLAG_DELETE_THIS`] / [`FLAG_BUFFER_BORROWED`].
    pub flags: u32,
}

/// The unported `FUN_0805f440` heap-poison helper: fills `dst[0..len]` with
/// the rolling debug pattern described in the module header.
pub type HeapPoison = unsafe extern "C" fn(dst: *mut u8, len: u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn stock_heap_poison(dst: *mut u8, len: u32) {
    let poison: HeapPoison = unsafe { core::mem::transmute(0x0805_f440usize) };
    unsafe { poison(dst, len) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_heap_poison(_dst: *mut u8, _len: u32) {}

/// Hook for `FUN_0805f440`. It is volatile-read at the call sites so LLVM
/// cannot fold the host no-op stub into `tagged_word_buffer_destroy`.
#[cfg(target_os = "none")]
pub static mut TAGGED_WORD_BUFFER_POISON: HeapPoison = stock_heap_poison;
#[cfg(not(target_os = "none"))]
pub static mut TAGGED_WORD_BUFFER_POISON: HeapPoison = missing_heap_poison;

#[inline(always)]
unsafe fn heap_poison() -> HeapPoison {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(TAGGED_WORD_BUFFER_POISON)) }
}

/// tagged_word_buffer_destroy — original: `FUN_0803e5e4` @ 0x0803e5e4
/// (92 bytes; 14 `bl` + 8 `blne` call sites, all predicated sites
/// caller-side NULL checks).
///
/// Destroys the object as described in the module header. `this` must be
/// NULL or point at the five aligned writable target words above; a nonzero
/// `data` word released here (without [`FLAG_BUFFER_BORROWED`]) must be
/// owned by the allocation family paired with `traced_free`, as must `this`
/// itself when [`FLAG_DELETE_THIS`] is set.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tagged_word_buffer_destroy(this: *mut TaggedWordBuffer) {
    if this.is_null() {
        return;
    }
    let data = unsafe { core::ptr::addr_of!((*this).data).read_volatile() };
    if data != 0 {
        let capacity = unsafe { core::ptr::addr_of!((*this).capacity).read_volatile() };
        unsafe { heap_poison()(data as usize as *mut u8, capacity << 2) };
        let flags = unsafe { core::ptr::addr_of!((*this).flags).read_volatile() };
        if flags & FLAG_BUFFER_BORROWED == 0 {
            unsafe { traced_free(data as usize as *mut u8) };
        }
    }
    // Re-read, not a reuse of the +0x10 load above: the original reloads
    // the flags word after the buffer poison/free (0x0803e618).
    let flags = unsafe { core::ptr::addr_of!((*this).flags).read_volatile() };
    let delete = flags & FLAG_DELETE_THIS;
    unsafe { heap_poison()(this as *mut u8, TAGGED_WORD_BUFFER_SIZE) };
    if delete != 0 {
        unsafe { traced_free(this as *mut u8) };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::ata_cmd::{TracedFreeHooks, TRACED_FREE_HOOKS};
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Ordered event log: (b'p', dst, len) for the poison seam, (b'f', ptr, 0)
    /// for traced_free. The poison mock also scribbles 0xAA over the range,
    /// like the original's fill, so a poison of `this` provably runs before
    /// the self free (the free recorder re-reads the scrubbed object fine).
    static mut EVENTS: Vec<(u8, usize, u32)> = Vec::new();
    /// When set, the buffer-release mock ORs this into `this.flags`,
    /// modelling a free-side flag store the destructor's reload must honor.
    static mut FREE_SET_FLAGS: u32 = 0;
    static mut FLAG_TARGET: *mut u32 = core::ptr::null_mut();

    unsafe extern "C" fn mock_poison(dst: *mut u8, len: u32) {
        unsafe {
            (*core::ptr::addr_of_mut!(EVENTS)).push((b'p', dst as usize, len));
            core::ptr::write_bytes(dst, 0xAA, len as usize);
        }
    }

    unsafe extern "C" fn mock_free(block: *mut u8) {
        unsafe {
            (*core::ptr::addr_of_mut!(EVENTS)).push((b'f', block as usize, 0));
            let set = FREE_SET_FLAGS;
            if set != 0 {
                *FLAG_TARGET |= set;
            }
        }
    }

    fn install() -> (MutexGuard<'static, ()>, HeapPoison, TracedFreeHooks) {
        let guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            let old_poison = core::ptr::read_volatile(core::ptr::addr_of!(TAGGED_WORD_BUFFER_POISON));
            let old_free = core::ptr::read_volatile(core::ptr::addr_of!(TRACED_FREE_HOOKS));
            TAGGED_WORD_BUFFER_POISON = mock_poison;
            TRACED_FREE_HOOKS = TracedFreeHooks { free: mock_free, trace: None };
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            FREE_SET_FLAGS = 0;
            FLAG_TARGET = core::ptr::null_mut();
            (guard, old_poison, old_free)
        }
    }

    unsafe fn restore(guard: MutexGuard<'static, ()>, old_poison: HeapPoison, old_free: TracedFreeHooks) {
        unsafe {
            TAGGED_WORD_BUFFER_POISON = old_poison;
            TRACED_FREE_HOOKS = old_free;
        }
        drop(guard);
    }

    fn events() -> Vec<(u8, usize, u32)> {
        unsafe { (*core::ptr::addr_of!(EVENTS)).clone() }
    }

    /// Writable buffer below 4 GiB so the u32 `data` word round-trips on
    /// host. Distinct hint; the mapper never unmaps, so no other module may
    /// reuse it.
    fn try_buffer() -> Option<*mut u8> {
        static SLAB: std::sync::LazyLock<Option<usize>> = std::sync::LazyLock::new(|| {
            crate::testing::try_map_u32_slab(crate::testing::hints::TAGGED_WORD_BUFFER, 0x1000)
                .map(|p| p as usize)
        });
        (*SLAB).map(|p| p as *mut u8)
    }

    fn fixture_unavailable() -> bool {
        try_buffer().is_none()
            && crate::testing::note_missing_u32_fixture("heap::tagged_word_buffer")
    }

    #[test]
    fn null_this_is_a_no_op() {
        let (guard, old_poison, old_free) = install();
        unsafe { tagged_word_buffer_destroy(core::ptr::null_mut()) };
        assert!(events().is_empty());
        unsafe { restore(guard, old_poison, old_free) };
    }

    #[test]
    fn null_data_skips_buffer_release_but_still_poison_self_and_deletes() {
        let (guard, old_poison, old_free) = install();
        let mut object = TaggedWordBuffer { data: 0, len: 7, capacity: 9, tag: 3, flags: FLAG_DELETE_THIS };
        let this = &mut object as *mut TaggedWordBuffer;

        unsafe { tagged_word_buffer_destroy(this) };

        assert_eq!(
            events(),
            std::vec![(b'p', this as usize, 20), (b'f', this as usize, 0)],
            "no buffer poison/free; self poisoned with the literal 20, then freed"
        );
        unsafe { restore(guard, old_poison, old_free) };
    }

    #[test]
    fn null_data_without_delete_bit_only_poison_self() {
        let (guard, old_poison, old_free) = install();
        let mut object = TaggedWordBuffer { data: 0, len: 0, capacity: 0, tag: 0, flags: 0 };
        let this = &mut object as *mut TaggedWordBuffer;

        unsafe { tagged_word_buffer_destroy(this) };

        assert_eq!(events(), std::vec![(b'p', this as usize, 20)]);
        unsafe { restore(guard, old_poison, old_free) };
    }

    #[test]
    fn owned_buffer_is_poisoned_capacity_words_then_freed_then_self_poisoned() {
        if fixture_unavailable() {
            return;
        }
        let (guard, old_poison, old_free) = install();
        let data = try_buffer().unwrap();
        unsafe { core::ptr::write_bytes(data, 0x11, 0x40) };
        let mut object = TaggedWordBuffer {
            data: data as usize as u32,
            len: 2,
            capacity: 3,
            tag: 0xdead,
            flags: 0,
        };
        let this = &mut object as *mut TaggedWordBuffer;

        unsafe { tagged_word_buffer_destroy(this) };

        assert_eq!(
            events(),
            std::vec![
                (b'p', data as usize, 12),
                (b'f', data as usize, 0),
                (b'p', this as usize, 20),
            ],
            "buffer poisoned with capacity << 2 and released before the self poison"
        );
        assert_eq!(
            unsafe { core::ptr::read_volatile(data) },
            0xAA,
            "the poison seam really scrubbed the buffer"
        );
        unsafe { restore(guard, old_poison, old_free) };
    }

    #[test]
    fn borrowed_buffer_is_poisoned_but_never_freed() {
        if fixture_unavailable() {
            return;
        }
        let (guard, old_poison, old_free) = install();
        let data = try_buffer().unwrap();
        let mut object = TaggedWordBuffer {
            data: data as usize as u32,
            len: 1,
            capacity: 4,
            tag: 0,
            flags: FLAG_BUFFER_BORROWED,
        };
        let this = &mut object as *mut TaggedWordBuffer;

        unsafe { tagged_word_buffer_destroy(this) };

        assert_eq!(
            events(),
            std::vec![(b'p', data as usize, 16), (b'p', this as usize, 20)],
            "FLAG_BUFFER_BORROWED suppresses the data release only"
        );
        unsafe { restore(guard, old_poison, old_free) };
    }

    #[test]
    fn flags_reloaded_after_buffer_release_honors_a_late_delete_bit() {
        if fixture_unavailable() {
            return;
        }
        let (guard, old_poison, old_free) = install();
        let data = try_buffer().unwrap();
        let mut object = TaggedWordBuffer {
            data: data as usize as u32,
            len: 0,
            capacity: 1,
            tag: 0,
            flags: 0,
        };
        let this = &mut object as *mut TaggedWordBuffer;
        unsafe {
            FREE_SET_FLAGS = FLAG_DELETE_THIS;
            FLAG_TARGET = core::ptr::addr_of_mut!((*this).flags);
        }

        unsafe { tagged_word_buffer_destroy(this) };

        assert_eq!(
            events(),
            std::vec![
                (b'p', data as usize, 4),
                (b'f', data as usize, 0),
                (b'p', this as usize, 20),
                (b'f', this as usize, 0),
            ],
            "the delete bit stored by the buffer free is seen: flags reload at 0x0803e618"
        );
        unsafe { restore(guard, old_poison, old_free) };
    }
}
