//! RetailOS SHA-1 initialization and post-finalization reset.
//!
//! `sha1_init` — original: `FUN_080ec1bc` @ 0x080ec1bc. True extent
//! [0x080ec1bc, 0x080ec224): 84 instruction bytes and 20 literal bytes
//! containing the SHA-1 initial state. The next real function starts with
//! PUSH at 0x080ec224. Whole-image A32 decoding finds two inbound plain BLs
//! (0x080efcac and 0x083691b8), zero predicated BLs, and no outgoing BLs.
//!
//! Clears buffered-byte count (word 85), low/high bit counts (87/86), writes
//! the five standard SHA-1 state words, and clears all 80 schedule words.
//! SHA1_Final uses this same operation to reset a consumed context.
//! Deliberate deviation: volatile aligned word stores prevent LLVM replacing
//! the clear loop with a libc builtin; the firmware store order is retained.

use super::sha1_update::Sha1Context;

/// Initializes all 352 bytes of a retailOS SHA-1 context.
///
/// # Safety
/// `context` must be aligned and writable for a complete `Sha1Context`.
/// Its previous contents need not be initialized. NULL is not accepted.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sha1_init(context: *mut Sha1Context) {
    let words = context.cast::<u32>();
    unsafe {
        words.add(85).write_volatile(0);
        words.add(87).write_volatile(0);
        words.add(86).write_volatile(0);
        words.add(0).write_volatile(0x6745_2301);
        words.add(1).write_volatile(0xefcd_ab89);
        words.add(2).write_volatile(0x98ba_dcfe);
        words.add(3).write_volatile(0x1032_5476);
        words.add(4).write_volatile(0xc3d2_e1f0);
        for index in 5..85 {
            words.add(index).write_volatile(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INITIAL: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe,
        0x10325476, 0xc3d2e1f0];

    #[test]
    fn resets_dirty_context_without_touching_neighbors() {
        #[repr(C)]
        struct Guarded {
            before: [u32; 3],
            context: Sha1Context,
            after: [u32; 3],
        }
        for fill in [0, u32::MAX, 0xdead_beef, 0x8000_0000] {
            let mut fixture = Guarded {
                before: [0xa55a_1234; 3],
                context: Sha1Context { words: [fill; 88] },
                after: [0x5aa5_4321; 3],
            };
            unsafe { sha1_init(&mut fixture.context) };
            assert_eq!(&fixture.context.words[..5], &INITIAL);
            assert_eq!(&fixture.context.words[5..], &[0; 83]);
            assert_eq!(fixture.before, [0xa55a_1234; 3]);
            assert_eq!(fixture.after, [0x5aa5_4321; 3]);
        }
    }

    #[test]
    fn initializes_uninitialized_storage_and_resets_after_update() {
        let mut storage = core::mem::MaybeUninit::<Sha1Context>::uninit();
        unsafe { sha1_init(storage.as_mut_ptr()) };
        let mut context = unsafe { storage.assume_init() };
        let bytes = [0xff, 0x80, 0x01, 0x00, 0x42];
        unsafe { super::super::sha1_update::sha1_update(&mut context, bytes.as_ptr(), 5) };
        assert_eq!(context.words[85], 5);
        assert_eq!(context.words[87], 40);
        unsafe { sha1_init(&mut context) };
        assert_eq!(&context.words[..5], &INITIAL);
        assert_eq!(&context.words[5..], &[0; 83]);
    }
}
