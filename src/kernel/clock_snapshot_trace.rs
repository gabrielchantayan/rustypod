//! Emitting the remaining tick delta for matching kernel clock snapshots.
//!
//! `trace_matching_clock_snapshot_delta_ms` — original: `FUN_08369110` @
//! 0x08369110 (144 bytes, 0x08369110..0x083691a0). Ghidra's 116-byte
//! extent contains the 29 ARM instructions through `pop {r3,r4,r5,r6,r7,r8,
//! r9,pc}` at 0x08369180, but omits the three literal words at
//! 0x08369184..0x0836918c and the 16-byte `(L10,H' ms',N)` format string at
//! 0x08369190..0x0836919f; the next function begins at 0x083691a0.
//!
//! A binary scan of every ARM B/BL word in osos.dec finds seven direct call
//! sites, all unconditional `bl` (0x082bfd58, 0x082c0408, 0x082c0418,
//! 0x082c0694, 0x082c0730, 0x082c0780, and 0x082c0800); there are no
//! predicated call sites. Each caller is a clock-snapshot diagnostic path.
//!
//! The function walks the singly linked snapshot list rooted at 0x22008a68.
//! A node matches only when its kind (+0x18), object (+0x1c), and name token
//! (+0x10) equal the three arguments, in that order. For every match it
//! traces `(deadline (+0x08) - current_tick @ 0x2200acfc) * tick_scale @
//! 0x083e30e8` through the already ported `trace_printf` @ 0x082dcf7c.
//! Arithmetic deliberately wraps at 32 bits, exactly as the ARM `sub`/`mul`
//! pair does; it does not clamp an expired deadline to zero.
//!
//! On target the globals and format are their retailOS addresses. Host tests
//! replace only those fixed RAM words and the trace emission with local
//! backing so they can exercise target-width next pointers; production host
//! builds still call `trace_printf` normally.

use core::ptr::{addr_of, read_volatile};
#[cfg(test)]
use core::ptr::addr_of_mut;
#[cfg(not(all(test, not(target_os = "none"))))]
use crate::stdio::trace_printf::trace_printf;

/// One 32-byte node in the clock-snapshot list at 0x22008a68.
///
/// All link-like fields are u32 target addresses/handles, never host-width
/// pointers. The unnamed words are retained so the decoded offsets remain
/// exact on both ARM and x86-64 hosts.
#[repr(C)]
struct ClockSnapshot {
    next: u32,
    _word_04: u32,
    deadline: u32,
    _word_0c: u32,
    name_token: u32,
    _word_14: u32,
    kind: u32,
    object: u32,
}

/// Head word for the clock-snapshot list.
#[cfg(target_os = "none")]
const CLOCK_SNAPSHOT_LIST_HEAD: *const u32 = 0x2200_8a68 as *const u32;
#[cfg(not(target_os = "none"))]
static mut CLOCK_SNAPSHOT_LIST_HEAD: u32 = 0;

/// Scale multiplying a tick delta into the unit the trace labels `ms`.
#[cfg(target_os = "none")]
const CLOCK_TICK_SCALE: *const u32 = 0x083e_30e8 as *const u32;
#[cfg(not(target_os = "none"))]
static mut CLOCK_TICK_SCALE: u32 = 0;

/// Current kernel tick sampled once for each matching snapshot.
#[cfg(target_os = "none")]
const CLOCK_CURRENT_TICK: *const u32 = 0x2200_acfc as *const u32;
#[cfg(not(target_os = "none"))]
static mut CLOCK_CURRENT_TICK: u32 = 0;

#[inline(always)]
unsafe fn snapshot_head() -> *mut ClockSnapshot {
    #[cfg(target_os = "none")]
    let head = unsafe { read_volatile(CLOCK_SNAPSHOT_LIST_HEAD) };
    #[cfg(not(target_os = "none"))]
    let head = unsafe { read_volatile(addr_of!(CLOCK_SNAPSHOT_LIST_HEAD)) };
    head as usize as *mut ClockSnapshot
}

#[inline(always)]
unsafe fn current_tick() -> u32 {
    #[cfg(target_os = "none")]
    unsafe { read_volatile(CLOCK_CURRENT_TICK) }
    #[cfg(not(target_os = "none"))]
    unsafe { read_volatile(addr_of!(CLOCK_CURRENT_TICK)) }
}

#[inline(always)]
unsafe fn tick_scale() -> u32 {
    #[cfg(target_os = "none")]
    unsafe { read_volatile(CLOCK_TICK_SCALE) }
    #[cfg(not(target_os = "none"))]
    unsafe { read_volatile(addr_of!(CLOCK_TICK_SCALE)) }
}

#[cfg(all(test, not(target_os = "none")))]
extern crate std;

#[cfg(all(test, not(target_os = "none")))]
static EMITTED_DELTAS: parking_lot::Mutex<std::vec::Vec<u32>> =
    parking_lot::Mutex::new(std::vec::Vec::new());

/// Emits the one-word varargs frame the ARM builds on its stack.
#[cfg(not(all(test, not(target_os = "none"))))]
#[inline(always)]
unsafe fn emit_snapshot_delta_ms(delta_ms: u32) {
    #[cfg(target_os = "none")]
    let format = 0x0836_9190usize as *const u8;
    #[cfg(not(target_os = "none"))]
    let format = b"(L10,H' ms',N)\0".as_ptr();
    unsafe { trace_printf(format, addr_of!(delta_ms)) };
}

/// Test-only observer avoids changing the shared `trace_printf` formatter
/// slot while the crate's parallel host suite is running.
#[cfg(all(test, not(target_os = "none")))]
#[inline(always)]
unsafe fn emit_snapshot_delta_ms(delta_ms: u32) {
    EMITTED_DELTAS.lock().push(delta_ms);
}

/// trace_matching_clock_snapshot_delta_ms — original: `FUN_08369110` @
/// 0x08369110 (144 bytes; 7 unconditional `bl` call sites).
///
/// Walks the global clock-snapshot list and traces the wrapping tick delta in
/// milliseconds for each node whose `kind`, `object`, and `name_token` match
/// the supplied selectors. It makes no NULL or cycle check beyond the list
/// head/node link check in the original; callers own a valid acyclic list.
///
/// # Safety
///
/// On target, the fixed firmware globals and every reachable list node must
/// be readable. `kind`, `object`, and `name_token` are raw retailOS selector
/// words, not Rust object references.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn trace_matching_clock_snapshot_delta_ms(
    kind: u32,
    name_token: u32,
    object: u32,
) {
    let mut snapshot = unsafe { snapshot_head() };
    while !snapshot.is_null() {
        if unsafe { read_volatile(addr_of!((*snapshot).kind)) } == kind
            && unsafe { read_volatile(addr_of!((*snapshot).object)) } == object
            && unsafe { read_volatile(addr_of!((*snapshot).name_token)) } == name_token
        {
            let deadline = unsafe { read_volatile(addr_of!((*snapshot).deadline)) };
            let delta_ms = deadline
                .wrapping_sub(unsafe { current_tick() })
                .wrapping_mul(unsafe { tick_scale() });
            unsafe { emit_snapshot_delta_ms(delta_ms) };
        }
        snapshot = unsafe {
            read_volatile(addr_of!((*snapshot).next)) as usize as *mut ClockSnapshot
        };
    }
}

#[cfg(all(test, not(target_os = "none")))]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use core::mem::size_of;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    unsafe fn set_host_state(head: u32, tick: u32, scale: u32) {
        unsafe {
            addr_of_mut!(CLOCK_SNAPSHOT_LIST_HEAD).write_volatile(head);
            addr_of_mut!(CLOCK_CURRENT_TICK).write_volatile(tick);
            addr_of_mut!(CLOCK_TICK_SCALE).write_volatile(scale);
        }
    }

    #[test]
    fn traces_only_full_matches_with_arm_wrapping_arithmetic() {
        let _guard = TEST_LOCK.lock();
        assert_eq!(size_of::<ClockSnapshot>(), 0x20);

        // The fixture carries raw u32 next pointers, as the firmware does.
        // It maps once: try_map_u32_slab never unmaps a hint.
        let Some(raw_nodes) = try_map_u32_slab(hints::CLOCK_SNAPSHOT_TRACE, 4 * size_of::<ClockSnapshot>()) else {
            return;
        };
        let nodes = raw_nodes.cast::<ClockSnapshot>();
        assert!((nodes as usize) <= u32::MAX as usize);

        unsafe {
            nodes.add(0).write(ClockSnapshot {
                next: nodes.add(1) as usize as u32,
                _word_04: 0,
                deadline: 0,
                _word_0c: 0,
                name_token: 0x1111,
                _word_14: 0,
                kind: 6,
                object: 0x2222,
            });
            nodes.add(1).write(ClockSnapshot {
                next: nodes.add(2) as usize as u32,
                _word_04: 0,
                deadline: 10,
                _word_0c: 0,
                name_token: 0x1111,
                _word_14: 0,
                kind: 7,
                object: 0x2222,
            });
            nodes.add(2).write(ClockSnapshot {
                next: nodes.add(3) as usize as u32,
                _word_04: 0,
                deadline: 99,
                _word_0c: 0,
                name_token: 0x3333,
                _word_14: 0,
                kind: 7,
                object: 0x2222,
            });
            nodes.add(3).write(ClockSnapshot {
                next: 0,
                _word_04: 0,
                deadline: 1,
                _word_0c: 0,
                name_token: 0x1111,
                _word_14: 0,
                kind: 7,
                object: 0x2222,
            });
            EMITTED_DELTAS.lock().clear();
            set_host_state(nodes as usize as u32, 3, 4);
            trace_matching_clock_snapshot_delta_ms(7, 0x1111, 0x2222);
        }

        let seen = EMITTED_DELTAS.lock();
        assert_eq!(seen.as_slice(), &[28, 0xffff_fff8]);
        drop(seen);

        // A null head is the original's only list guard and must emit nothing.
        unsafe {
            EMITTED_DELTAS.lock().clear();
            set_host_state(0, 0, 0);
            trace_matching_clock_snapshot_delta_ms(7, 0x1111, 0x2222);
        }
        assert!(EMITTED_DELTAS.lock().is_empty());
    }
}
