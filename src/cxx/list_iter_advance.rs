//! Checked `std::list` iterator increment.
//!
//! `list_iter_advance` — original: `FUN_083d5e88` @ 0x083d5e88 (24 bytes;
//! 5 direct inbound calls, all unconditional plain `bl` at 0x0818a580,
//! 0x0818ae00, 0x0818b14c, 0x0818b1f4, and 0x083d5db8, verified by decoding
//! every ARM B/BL immediate in `osos.dec`; no predicated calls or tail
//! branches).
//!
//! Raw ARM is `ldr r1,[r0]; cmp r1,#0; bleq 0x08030f44; ldr r1,[r1,#4];
//! str r1,[r0]; bx lr`. It advances the single target-pointer word at `it`
//! to the current node's `next` word at +0x4. A NULL current node invokes the
//! non-returning `heap_panic`; a NULL next pointer is valid and is stored.
//!
//! Deviation: none. The pointer word remains a `u32` at the opaque node
//! layout's exact aligned offset; host fixtures use a below-4-GiB mapping.

use crate::heap::veneers::heap_panic;

/// Byte offset of the next target-pointer word in a checked-list node.
const NODE_NEXT_OFFSET: usize = 0x4;

/// list_iter_advance — original: `FUN_083d5e88` @ 0x083d5e88 (24 bytes;
/// 5 direct inbound plain `bl` calls, binary-verified).
///
/// Replaces `*it` with the current node's next target pointer. A NULL current
/// node never returns: it enters [`heap_panic`].
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.list_iter_advance")]
#[inline(never)]
pub unsafe extern "C" fn list_iter_advance(it: *mut *mut u8) {
    let node = unsafe { it.read() };
    if node.is_null() {
        unsafe { heap_panic() };
    }
    let next = unsafe { node.add(NODE_NEXT_OFFSET).cast::<u32>().read() } as usize as *mut u8;
    unsafe { it.write(next) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex, MutexGuard};

    const FIXTURE_LEN: usize = 0x1000;
    const FIRST_NODE_OFFSET: usize = 0x100;
    const SECOND_NODE_OFFSET: usize = 0x200;

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::LIST_ITER_ADVANCE, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    fn fixture() -> Option<*mut u8> {
        let base = (*FIXTURE)? as *mut u8;
        unsafe { core::ptr::write_bytes(base, 0, FIXTURE_LEN) };
        Some(base)
    }

    fn lock() -> MutexGuard<'static, ()> {
        match FIXTURE_LOCK.lock() {
            Ok(lock) => lock,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    #[test]
    fn advances_to_the_exact_next_word_and_accepts_a_null_successor() {
        let _lock = lock();
        let Some(base) = fixture() else {
            note_missing_u32_fixture("cxx::list_iter_advance");
            return;
        };
        let first = unsafe { base.add(FIRST_NODE_OFFSET) };
        let second = unsafe { base.add(SECOND_NODE_OFFSET) };

        unsafe {
            first.add(NODE_NEXT_OFFSET).cast::<u32>().write(second as usize as u32);
            second.add(NODE_NEXT_OFFSET).cast::<u32>().write(0);
        }

        let mut it = first;
        unsafe { list_iter_advance(&mut it) };
        assert_eq!(it, second);

        unsafe { list_iter_advance(&mut it) };
        assert!(it.is_null());
    }
}
