//! Selects an indexed context item and tail-dispatches it.
//!
//! `context_select_item_and_dispatch` — retailOS `FUN_080e4f80` @
//! `0x080e4f80` (88 bytes, `0x080e4f80..0x080e4fd8`). Raw ARM establishes
//! the next real function at `0x080e4fd8` (`push {r4-r8,lr}`). It has no
//! outbound plain or predicated `bl`; it ends in an indirect `bx r3`. Whole-
//! image decoding finds three inbound plain `bl` calls (`0x08069d24`,
//! `0x0808032c`, and `0x080c74e0`) and no predicated inbound `bl` calls.
//!
//! # Algorithm
//!
//! Copies six metadata words from the context's target-width owner into
//! context offsets `+0x570..+0x584`, selects one word from each owner table at
//! `+0x1a4` and `+0x1a8`, stores the pair to `output`, then dispatches the pair
//! through the context callback at `+0x5dc`.
//!
//! # Deliberate deviation
//!
//! ARM tail-branches to the callback and therefore returns its value directly.
//! Rust calls and returns normally. The callback has no recovered concrete
//! identity: target builds dispatch the physical target-width function pointer;
//! host builds use a typed seam.

#[cfg(target_os = "none")]
use core::mem;

const OWNER_WORD: usize = 1;
const FIRST_TABLE_WORD: usize = 0x1a4 / 4;
const SECOND_TABLE_WORD: usize = 0x1a8 / 4;
const FIRST_METADATA_WORD: usize = 0x1b0 / 4;
const CONTEXT_METADATA_WORD: usize = 0x570 / 4;
const CONTEXT_DISPATCH_WORD: usize = 0x5dc / 4;

type ContextItemDispatch = unsafe extern "C" fn(*mut u32, u32, u32) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_context_item_dispatch(_context: *mut u32, _first: u32, _second: u32) -> u32 {
    panic!("context_select_item_and_dispatch requires the context +0x5dc callback")
}

#[cfg(not(target_os = "none"))]
pub static mut CONTEXT_SELECT_ITEM_DISPATCH: ContextItemDispatch = missing_context_item_dispatch;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn context_item_dispatch(context: *mut u32) -> ContextItemDispatch {
    unsafe { mem::transmute(context.add(CONTEXT_DISPATCH_WORD).read_volatile() as usize) }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn context_item_dispatch(_context: *mut u32) -> ContextItemDispatch {
    unsafe { core::ptr::addr_of!(CONTEXT_SELECT_ITEM_DISPATCH).read_volatile() }
}

/// Selects an indexed pair from the context owner, copies owner metadata, and
/// dispatches the pair — original: `FUN_080e4f80` @ `0x080e4f80` (88 bytes;
/// three inbound direct plain `bl` sites, no predicated inbound `bl` sites; no
/// outbound `bl`, terminal indirect `bx`). See the module header for raw
/// evidence and algorithm.
///
/// # Safety
///
/// `context` must be valid for writes through target offset `+0x584` and a
/// callback pointer at `+0x5dc`. Its word at `+4` is a valid target-width owner
/// pointer with readable metadata and table pointers; `output` is valid for two
/// aligned `u32` writes. RetailOS performs no bounds or NULL checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.context_select_item_and_dispatch")]
#[inline(never)]
pub unsafe extern "C" fn context_select_item_and_dispatch(
    context: *mut u32,
    item_index: u32,
    output: *mut u32,
) -> u32 {
    let owner = unsafe { context.add(OWNER_WORD).read_volatile() as *const u32 };
    unsafe {
        for word in 0..6 {
            context.add(CONTEXT_METADATA_WORD + word).write_volatile(owner.add(FIRST_METADATA_WORD + word).read_volatile());
        }
        let first_table = owner.add(FIRST_TABLE_WORD).read_volatile() as *const u32;
        let second_table = owner.add(SECOND_TABLE_WORD).read_volatile() as *const u32;
        let first = first_table.add(item_index as usize).read_volatile();
        let second = second_table.add(item_index as usize).read_volatile();
        output.write_volatile(first);
        output.add(1).write_volatile(second);
        context_item_dispatch(context)(context, first, second)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut DISPATCH_ARGUMENTS: (usize, u32, u32) = (0, 0, 0);

    unsafe extern "C" fn recording_dispatch(context: *mut u32, first: u32, second: u32) -> u32 {
        unsafe { DISPATCH_ARGUMENTS = (context as usize, first, second); }
        first ^ second
    }

    struct DispatchGuard(ContextItemDispatch);
    impl Drop for DispatchGuard {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(CONTEXT_SELECT_ITEM_DISPATCH).write_volatile(self.0) }
        }
    }

    unsafe fn install_dispatch() -> DispatchGuard {
        let seam = core::ptr::addr_of_mut!(CONTEXT_SELECT_ITEM_DISPATCH);
        let previous = unsafe { seam.read_volatile() };
        unsafe {
            seam.write_volatile(recording_dispatch);
            DISPATCH_ARGUMENTS = (0, 0, 0);
        }
        DispatchGuard(previous)
    }

    #[test]
    fn copies_metadata_selects_the_indexed_pair_and_dispatches_it() {
        let _lock = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::CONTEXT_SELECT_ITEM_AND_DISPATCH, 160) else {
            assert!(note_missing_u32_fixture("app/context_select_item_and_dispatch"));
            return;
        };
        let owner = slab.cast::<u32>();
        let first_table = unsafe { owner.add(128) };
        let second_table = unsafe { owner.add(136) };
        let mut context = [0u32; CONTEXT_DISPATCH_WORD + 1];
        let mut output = [0u32; 2];
        unsafe {
            for word in 0..6 {
                owner.add(FIRST_METADATA_WORD + word).write(0x1100_0000 + word as u32);
            }
            owner.add(FIRST_TABLE_WORD).write(first_table as u32);
            owner.add(SECOND_TABLE_WORD).write(second_table as u32);
            first_table.add(0).write(0xaaaa_0000);
            first_table.add(3).write(0xaaaa_0003);
            second_table.add(0).write(0xbbbb_0000);
            second_table.add(3).write(0xbbbb_0003);
            context[OWNER_WORD] = owner as u32;
            let _dispatch = install_dispatch();

            assert_eq!(context_select_item_and_dispatch(context.as_mut_ptr(), 0, output.as_mut_ptr()), 0x1111_0000);
            assert_eq!(output, [0xaaaa_0000, 0xbbbb_0000]);
            assert_eq!(DISPATCH_ARGUMENTS, (context.as_mut_ptr() as usize, 0xaaaa_0000, 0xbbbb_0000));

            assert_eq!(context_select_item_and_dispatch(context.as_mut_ptr(), 3, output.as_mut_ptr()), 0x1111_0000);
            assert_eq!(&context[CONTEXT_METADATA_WORD..CONTEXT_METADATA_WORD + 6], &[0x1100_0000, 0x1100_0001, 0x1100_0002, 0x1100_0003, 0x1100_0004, 0x1100_0005]);
            assert_eq!(output, [0xaaaa_0003, 0xbbbb_0003]);
            assert_eq!(DISPATCH_ARGUMENTS, (context.as_mut_ptr() as usize, 0xaaaa_0003, 0xbbbb_0003));
        }
    }
}
