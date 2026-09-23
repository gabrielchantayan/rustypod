//! Refcounted-handle three-slot vtable dispatcher.
//!
//! `handle_vtable_sequence_dispatch` — original: `FUN_081317dc` @
//! **0x081317dc** (96 bytes, `0x081317dc..0x0813183c`). Raw `osos.dec`
//! decoding establishes the final tail `bx r2` at 0x08131838 and the next
//! separately linked entry at 0x0813183c. The body contains three plain,
//! unconditional direct `bl` instructions, all to
//! `handle_deref_or_null_alias_6190` @ 0x083d6190, and zero predicated `bl`
//! instructions. There are three inbound plain direct `bl` call sites and no
//! predicated inbound forms.
//!
//! # Algorithm
//!
//! Dereferences the refcounted handle at `owner+0x28` before each operation.
//! It invokes unrecovered vtable slots +0xec with the implementation, +0x138
//! with `(output, implementation, argument)`, and +0x40 with
//! `(implementation, output)`. The final operation is a tail dispatch in ARM.
//!
//! # Deliberate deviations
//!
//! The three vtable-slot identities and return values are not inferred. Rust
//! expresses the final tail dispatch as a normal void call, and host vtables
//! use pointer-width entries instead of the target's four-byte words.

use crate::cxx::handle::handle_deref_or_null;

const HANDLE_OFFSET: usize = 0x28;
const FINISH_SLOT: usize = 0xec / 4;
const POPULATE_SLOT: usize = 0x138 / 4;
const COMPLETE_SLOT: usize = 0x40 / 4;

type Finish = unsafe extern "C" fn(*mut u8);
type Populate = unsafe extern "C" fn(*mut u8, *mut u8, u32);
type Complete = unsafe extern "C" fn(*mut u8, *mut u8);

#[inline(always)]
unsafe fn implementation(owner: *mut u8) -> *mut u8 {
    unsafe { handle_deref_or_null(owner.add(HANDLE_OFFSET).cast::<*const *mut u8>()) }
}

/// Performs the three recovered virtual operations of the implementation held
/// by `owner`.
///
/// # Safety
///
/// `owner+0x28` must be a readable handle slot. Each dereferenced implementation
/// must have a valid vtable and the three slots must accept these recovered ABIs.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.handle_vtable_sequence_dispatch")]
#[inline(never)]
pub unsafe extern "C" fn handle_vtable_sequence_dispatch(output: *mut u8, owner: *mut u8, argument: u32) {
    let first = unsafe { implementation(owner) };
    let first_vtable = unsafe { first.cast::<*const usize>().read() };
    let finish: Finish = unsafe { core::mem::transmute(first_vtable.add(FINISH_SLOT).read()) };
    unsafe { finish(first) };

    let second = unsafe { implementation(owner) };
    let second_vtable = unsafe { second.cast::<*const usize>().read() };
    let populate: Populate = unsafe { core::mem::transmute(second_vtable.add(POPULATE_SLOT).read()) };
    unsafe { populate(output, second, argument) };

    let third = unsafe { implementation(owner) };
    let third_vtable = unsafe { third.cast::<*const usize>().read() };
    let complete: Complete = unsafe { core::mem::transmute(third_vtable.add(COMPLETE_SLOT).read()) };
    unsafe { complete(third, output) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

    static HANDLE_BODY: AtomicUsize = AtomicUsize::new(0);
    static SECOND: AtomicUsize = AtomicUsize::new(0);
    static THIRD: AtomicUsize = AtomicUsize::new(0);
    static OUTPUT: AtomicUsize = AtomicUsize::new(0);
    static ARGUMENT: AtomicU32 = AtomicU32::new(0);
    static ORDER: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn finish(implementation: *mut u8) {
        assert_eq!(ORDER.fetch_add(1, Ordering::SeqCst), 0);
        HANDLE_BODY.store(SECOND.load(Ordering::SeqCst), Ordering::SeqCst);
        assert!(!implementation.is_null());
    }

    unsafe extern "C" fn populate(output: *mut u8, implementation: *mut u8, argument: u32) {
        assert_eq!(ORDER.fetch_add(1, Ordering::SeqCst), 1);
        assert_eq!(implementation as usize, SECOND.load(Ordering::SeqCst));
        OUTPUT.store(output as usize, Ordering::SeqCst);
        ARGUMENT.store(argument, Ordering::SeqCst);
        HANDLE_BODY.store(THIRD.load(Ordering::SeqCst), Ordering::SeqCst);
    }

    unsafe extern "C" fn complete(implementation: *mut u8, output: *mut u8) {
        assert_eq!(ORDER.fetch_add(1, Ordering::SeqCst), 2);
        assert_eq!(implementation as usize, THIRD.load(Ordering::SeqCst));
        assert_eq!(output as usize, OUTPUT.load(Ordering::SeqCst));
    }

    #[test]
    fn re_dereferences_the_handle_before_each_recovered_vtable_slot() {
        let mut vtable = [0usize; POPULATE_SLOT + 1];
        vtable[COMPLETE_SLOT] = complete as usize;
        vtable[FINISH_SLOT] = finish as usize;
        vtable[POPULATE_SLOT] = populate as usize;
        let mut first = [vtable.as_ptr() as usize];
        let mut second = [vtable.as_ptr() as usize];
        let mut third = [vtable.as_ptr() as usize];
        let mut owner = [0usize; HANDLE_OFFSET / core::mem::size_of::<usize>() + 1];
        let mut output = 0u8;

        SECOND.store(second.as_mut_ptr() as usize, Ordering::SeqCst);
        THIRD.store(third.as_mut_ptr() as usize, Ordering::SeqCst);
        HANDLE_BODY.store(first.as_mut_ptr() as usize, Ordering::SeqCst);
        owner[HANDLE_OFFSET / core::mem::size_of::<usize>()] = HANDLE_BODY.as_ptr() as usize;
        OUTPUT.store(0, Ordering::SeqCst);
        ARGUMENT.store(0, Ordering::SeqCst);
        ORDER.store(0, Ordering::SeqCst);

        unsafe { handle_vtable_sequence_dispatch(&mut output, owner.as_mut_ptr().cast(), 0xa5a5_5a5a) };

        assert_eq!(ORDER.load(Ordering::SeqCst), 3);
        assert_eq!(OUTPUT.load(Ordering::SeqCst), &mut output as *mut u8 as usize);
        assert_eq!(ARGUMENT.load(Ordering::SeqCst), 0xa5a5_5a5a);
    }
}
