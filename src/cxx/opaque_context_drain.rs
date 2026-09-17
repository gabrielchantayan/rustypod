//! `drain_opaque_context` — original: `thunk_FUN_082e7d4c` @ **0x08262918**,
//! a 4-byte `b 0x082e7d4c` veneer.
//!
//! # Extent and calls, binary-verified
//!
//! The veneer word is `ea02150b`; its target begins at 0x082e7d4c with
//! `push {r4,lr}`. The literal magic word at 0x082e7dcc belongs to this body,
//! and the next independently linked prologue begins at 0x082e7dd0, making
//! the true target extent 132 bytes (0x082e7d4c..0x082e7dcf). Decoding ARM
//! branch-immediate words in the raw image finds four plain unconditional
//! `bl` callers of the veneer (0x0818ac90, 0x0839e83c, 0x0839e9a8, and
//! 0x0839f384), with no predicated `bl` callers.
//!
//! # Algorithm
//!
//! A NULL context returns 0x1a. A context marked `0x434e4453` is initialized
//! through the opaque 0x082e7e54 routine; a nonzero initialization status
//! returns immediately. Then, while the word at context+8 names a deque with
//! a nonzero count at +0x20, copy its front object word, pop that four-byte
//! deque element, and signal the object through the 0x080860c0 wrapper. The
//! final signal status is returned (or zero when no element is processed).
//!
//! # Deliberate deviations
//!
//! The initializer is unported: target builds call its fixed retailOS address
//! and host builds use a zero-status boundary. The retail body calls direct
//! `bl` targets for the iterator copy, deque pop, and signal wrapper; this
//! port calls their existing Rust ports, preserving their effects and result.

use core::ptr;

use crate::cxx::templates::deque_pop_front_elem4;
use crate::heap::block_deque::BlockDeque;
use crate::kernel::gateway_signal::gateway_signal_object;

const CONTEXT_MAGIC: u32 = 0x434e_4453;
const INVALID_CONTEXT: u32 = 0x1a;
const RETAIL_OPAQUE_CONTEXT_INITIALIZE: usize = 0x082e_7e54;

type OpaqueContextInitialize = unsafe extern "C" fn(*mut u32, *const u32) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn opaque_context_initialize(context: *mut u32, selector: *const u32) -> u32 {
    let initialize: OpaqueContextInitialize = core::mem::transmute(RETAIL_OPAQUE_CONTEXT_INITIALIZE);
    initialize(context, selector)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn opaque_context_initialize(_context: *mut u32, _selector: *const u32) -> u32 {
    0
}

unsafe fn drain_opaque_context_with<Initialize, Pop, Signal>(
    context: *mut u32,
    mut initialize: Initialize,
    mut pop_front: Pop,
    mut signal_object: Signal,
) -> u32
where
    Initialize: FnMut(*mut u32, *const u32) -> u32,
    Pop: FnMut(*mut u32),
    Signal: FnMut(u32) -> u32,
{
    if context.is_null() {
        return INVALID_CONTEXT;
    }

    if context.read() == CONTEXT_MAGIC {
        let status = initialize(context, ptr::null());
        if status != 0 {
            return status;
        }
    }

    let mut status = 0;
    loop {
        let deque = context.add(2).read() as *mut u32;
        if deque.is_null() || deque.add(8).read() == 0 {
            return status;
        }

        let object = deque.read();
        pop_front(deque);
        status = signal_object(object);
    }
}

/// Drains and signals every queued opaque-context object.
///
/// # Safety
///
/// `context` must be NULL or point to three readable `u32` words. Its third
/// word must be NULL or a valid four-byte-element [`BlockDeque`] whose front
/// object words can be signalled and whose ownership meets
/// [`deque_pop_front_elem4`]'s contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn drain_opaque_context(context: *mut u32) -> u32 {
    drain_opaque_context_with(
        context,
        |context, selector| opaque_context_initialize(context, selector),
        |deque| deque_pop_front_elem4(deque.cast::<BlockDeque>()),
        |object| gateway_signal_object(object),
    )
}

#[cfg(test)]
mod tests {
    extern crate std;

    use crate::testing::{hints, try_map_u32_slab};
    use super::*;

    #[test]
    fn rejects_null_context() {
        unsafe {
            assert_eq!(drain_opaque_context_with(ptr::null_mut(), |_, _| 0, |_| {}, |_| 0), 0x1a);
        }
    }

    #[test]
    fn propagates_nonzero_initializer_status() {
        let mut context = [CONTEXT_MAGIC, 0, 0];
        let mut initialized = 0;
        unsafe {
            assert_eq!(
                drain_opaque_context_with(
                    context.as_mut_ptr(),
                    |seen, selector| {
                        assert_eq!(seen, context.as_mut_ptr());
                        assert!(selector.is_null());
                        initialized += 1;
                        7
                    },
                    |_| panic!("must not pop after failed initialization"),
                    |_| panic!("must not signal after failed initialization"),
                ),
                7,
            );
        }
        assert_eq!(initialized, 1);
    }

    #[test]
    fn skips_initializer_for_unmarked_context_and_returns_final_signal_status() {
        let Some(slab) = try_map_u32_slab(hints::OPAQUE_CONTEXT_DRAIN, 4096) else {
            return;
        };
        let (deque, context) = unsafe {
            let deque = slab.cast::<u32>();
            let context = deque.add(16);
            deque.write(0x1234_5678);
            for word in 1..8 {
                deque.add(word).write(0);
            }
            deque.add(8).write(1);
            context.write(0);
            context.add(1).write(0);
            context.add(2).write(deque as usize as u32);
            (deque, context)
        };
        let mut initialized = 0;
        let mut popped = 0;
        let mut signalled = 0;
        unsafe {
            assert_eq!(
                drain_opaque_context_with(
                    context,
                    |_, _| {
                        initialized += 1;
                        0
                    },
                    |seen| {
                        assert_eq!(seen, deque);
                        popped += 1;
                        unsafe { context.add(2).write(0) };
                    },
                    |object| {
                        assert_eq!(object, 0x1234_5678);
                        signalled += 1;
                        0x27
                    },
                ),
                0x27,
            );
        }
        assert_eq!((initialized, popped, signalled), (0, 1, 1));
    }

    #[test]
    fn empty_deque_returns_zero_without_operations() {
        let mut context = [0, 0, 0];
        unsafe {
            assert_eq!(
                drain_opaque_context_with(
                    context.as_mut_ptr(),
                    |_, _| panic!("unmarked context must not initialize"),
                    |_| panic!("empty deque must not pop"),
                    |_| panic!("empty deque must not signal"),
                ),
                0,
            );
        }
    }
}
