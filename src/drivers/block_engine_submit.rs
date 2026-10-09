//! `block_engine_submit` — `FUN_080d8cdc` @ 0x080d8cdc.
//! True extent [0x080d8cdc, 0x080d8d14): 56 bytes, 14 A32 words;
//! the next function starts with PUSH. Whole-image aligned BL decoding finds
//! two plain inbound calls (0x080861c0, 0x08086268), zero predicated calls,
//! and zero outgoing calls.
//!
//! Write 1 to engine +0x80, the supplied block address to +0x84, and 64 to
//! +0x8c. Submit the context word +0x48 to +0, poll bit 0 until clear, then
//! replace the context word with 10. The caller pads a digest block; the
//! peripheral's exact identity is not established. Raw words, unlike Ghidra
//! C, put the block-address write BEFORE the submission and polling.
//!
//! Deliberate deviations: none in target behavior. An inlined register-access
//! helper permits deterministic host tests of busy transitions and write order;
//! production accesses remain aligned volatile MMIO, with no timeout.

const ENGINE_BASE: *mut u32 = 0x3800_0000 as *mut u32;
const CONTEXT_COMMAND_WORD: usize = 0x48 / 4;

#[inline(always)]
unsafe fn submit_with_io(
    context: *mut u32,
    block_address: u32,
    mut write: impl FnMut(usize, u32),
    mut read: impl FnMut(usize) -> u32,
) {
    write(0x80 / 4, 1);
    write(0x84 / 4, block_address);
    write(0x8c / 4, 64);
    write(0, unsafe { context.add(CONTEXT_COMMAND_WORD).read() });
    while read(0) & 1 != 0 {}
    unsafe { context.add(CONTEXT_COMMAND_WORD).write(10) };
}

/// Submit one 64-byte block and wait for the engine's busy bit to clear.
///
/// # Safety
/// `context` must be aligned and readable/writable through word +0x48.
/// `block_address` must be a valid device-visible block address. The caller
/// must own the engine registers and ensure the hardware eventually completes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn block_engine_submit(context: *mut u32, block_address: u32) {
    unsafe {
        submit_with_io(context, block_address,
            |word, value| ENGINE_BASE.add(word).write_volatile(value),
            |word| ENGINE_BASE.add(word).read_volatile());
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::cell::RefCell;
    use std::vec::Vec;

    #[derive(Debug, PartialEq)]
    enum Event { Write(usize, u32), Read(usize, u32) }

    #[test]
    fn preserves_submission_order_and_waits_only_on_bit_zero() {
        for (command, address, samples) in [
            (0, 0, &[0u32][..]),
            (0x8000_0000, u32::MAX, &[0xffff_fffe][..]),
            (u32::MAX, 0x0800_1000, &[1, 0x8000_0001, 3, 2][..]),
        ] {
            let mut context = [0xa5a5_a5a5u32; 20];
            context[CONTEXT_COMMAND_WORD] = command;
            let before = context;
            let ptr = context.as_mut_ptr();
            let events = RefCell::new(Vec::new());
            let mut samples_iter = samples.iter();
            unsafe {
                submit_with_io(ptr, address,
                    |word, value| events.borrow_mut().push(Event::Write(word, value)),
                    |word| {
                        // The cached command must remain intact until completion.
                        assert_eq!(ptr.add(CONTEXT_COMMAND_WORD).read(), command);
                        let sample = *samples_iter.next().expect("unexpected extra poll");
                        events.borrow_mut().push(Event::Read(word, sample));
                        sample
                    });
            }
            assert!(samples_iter.next().is_none());
            let mut expected = std::vec![Event::Write(32, 1), Event::Write(33, address),
                Event::Write(35, 64), Event::Write(0, command)];
            expected.extend(samples.iter().map(|&value| Event::Read(0, value)));
            assert_eq!(events.into_inner(), expected);
            let mut expected_context = before;
            expected_context[CONTEXT_COMMAND_WORD] = 10;
            assert_eq!(context, expected_context);
        }
    }
}
