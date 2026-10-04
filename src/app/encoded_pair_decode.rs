//! Encoded-pair reader — `FUN_0820b074` @ `0x0820b074`.
//! True extent: 200 bytes (196 instruction bytes plus lookup pointer at
//! 0x0820b138), next function 0x0820b13c. Whole-image ARM-word decoding:
//! two inbound plain BLs (0x0820b1d8, 0x082201b0), zero predicated BLs;
//! two outbound plain BLs, zero predicated BLs, one virtual BLX site.
//!
//! Read two low-halfword characters through virtual slot +0x24. On the
//! first character only, delegate CR/LF handling to the retained retail
//! helpers. Otherwise index the byte table at 0x088ff91e, reject 0xff,
//! accumulate radix-16, and translate decoded LF/CR to 0x1d/0x1c.
//! Exhaustion or an invalid table byte sets the receiver's +4 byte to one
//! without touching output. No target behavioral deviations. Host fixtures
//! widen pointer fields and substitute the table and two unported helpers.
//! The raw table is not assumed to be a conventional ASCII hex table.

use core::ptr;

#[repr(C)]
pub struct EncodedPairReader {
    pub vtable: *const usize,
    pub failed: u8,
}

pub type ReadCharacter = unsafe extern "C" fn(*mut EncodedPairReader, *mut u16) -> u32;
pub type IsLineBreak = unsafe extern "C" fn(*mut EncodedPairReader, u32) -> u32;
pub type ReadAfterLineBreak = unsafe extern "C" fn(*mut EncodedPairReader, u32, *mut u16) -> u32;

#[derive(Clone, Copy)]
pub struct EncodedPairOps {
    pub is_line_break: IsLineBreak,
    pub read_after_line_break: ReadAfterLineBreak,
    pub table: *const u8,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_is_line_break(reader: *mut EncodedPairReader, character: u32) -> u32 {
    let helper: IsLineBreak = core::mem::transmute(0x0820_b1e0usize);
    helper(reader, character)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_read_after_line_break(
    reader: *mut EncodedPairReader, character: u32, output: *mut u16,
) -> u32 {
    let helper: ReadAfterLineBreak = core::mem::transmute(0x0820_b13cusize);
    helper(reader, character, output)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_is_line_break(_: *mut EncodedPairReader, _: u32) -> u32 {
    panic!("encoded_pair_decode requires retail helper 0x0820b1e0");
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_read_after_line_break(_: *mut EncodedPairReader, _: u32, _: *mut u16) -> u32 {
    panic!("encoded_pair_decode requires retail helper 0x0820b13c");
}

#[cfg(target_os = "none")]
pub static mut ENCODED_PAIR_OPS: EncodedPairOps = EncodedPairOps {
    is_line_break: firmware_is_line_break,
    read_after_line_break: firmware_read_after_line_break,
    table: 0x088f_f91e as *const u8,
};
#[cfg(not(target_os = "none"))]
pub static mut ENCODED_PAIR_OPS: EncodedPairOps = EncodedPairOps {
    is_line_break: missing_is_line_break,
    read_after_line_break: missing_read_after_line_break,
    table: ptr::null(),
};

/// Decode one encoded pair. Receiver, virtual table, callbacks and the selected
/// table entries must be valid; output must be writable on successful decoding.
/// Helpers retain their retail ABI: r2/r3 are not inputs to this function.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn encoded_pair_decode(reader: *mut EncodedPairReader, output: *mut u16) -> u32 {
    let ops = ptr::read_volatile(ptr::addr_of!(ENCODED_PAIR_OPS));
    let mut value = 0u16;
    for digit_index in 0..2 {
        let read: ReadCharacter = core::mem::transmute((*reader).vtable.add(9).read());
        let mut character = 0u16;
        if read(reader, &mut character) == 0 {
            (*reader).failed = 1;
            return 0;
        }
        if digit_index == 0 && (ops.is_line_break)(reader, character as u32) != 0 {
            return (ops.read_after_line_break)(reader, character as u32, output);
        }
        let digit = ops.table.add(character as usize).read();
        if digit == 0xff {
            (*reader).failed = 1;
            return 0;
        }
        value = value.wrapping_mul(16).wrapping_add(digit as u16);
    }
    output.write(match value { 10 => 0x1d, 13 => 0x1c, _ => value });
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    #[repr(C)]
    struct Fixture {
        reader: EncodedPairReader,
        input: [u16; 2],
        available: usize,
        consumed: usize,
        line_checks: usize,
        delegated: u32,
        helper_result: u32,
    }

    unsafe extern "C" fn read(reader: *mut EncodedPairReader, output: *mut u16) -> u32 {
        let fixture = &mut *(reader as *mut Fixture);
        if fixture.consumed == fixture.available { return 0; }
        output.write(fixture.input[fixture.consumed]);
        fixture.consumed += 1;
        7
    }
    unsafe extern "C" fn line_check(reader: *mut EncodedPairReader, character: u32) -> u32 {
        (*(reader as *mut Fixture)).line_checks += 1;
        (character == 10 || character == 13) as u32
    }
    unsafe extern "C" fn after_line(reader: *mut EncodedPairReader, character: u32, output: *mut u16) -> u32 {
        let fixture = &mut *(reader as *mut Fixture);
        fixture.delegated = character;
        if fixture.helper_result != 0 { output.write(0x4321); }
        fixture.helper_result
    }

    #[test]
    fn pair_boundaries_failure_and_line_break_delegation() {
        let _lock = LOCK.lock();
        let mut table = [0xffu8; 65536];
        table[0x1234] = 0;
        table[0x5678] = 10;
        table[0x5679] = 13;
        table[0xabcd] = 254;
        table[10] = 3;
        table[13] = 4;
        let mut vtable = [0usize; 10];
        vtable[9] = read as *const () as usize;
        unsafe {
            let previous = ENCODED_PAIR_OPS;
            ENCODED_PAIR_OPS = EncodedPairOps { is_line_break: line_check, read_after_line_break: after_line, table: table.as_ptr() };
            for (input, available, helper_result, expected_result, expected_output, expected_failed, consumed, delegated) in [
                ([0x1234, 0x5678], 2, 1, 1, 0x1d, 0x5a, 2, 0),
                ([0x1234, 0x5679], 2, 1, 1, 0x1c, 0x5a, 2, 0),
                ([0xabcd, 0xabcd], 2, 1, 1, 4318, 0x5a, 2, 0),
                ([0x1234, 10], 2, 1, 1, 3, 0x5a, 2, 0),
                ([0x1234, 13], 2, 1, 1, 4, 0x5a, 2, 0),
                ([0xffff, 0x5678], 2, 1, 0, 0xbeef, 1, 1, 0),
                ([0x1234, 0xffff], 2, 1, 0, 0xbeef, 1, 2, 0),
                ([0x1234, 0x5678], 0, 1, 0, 0xbeef, 1, 0, 0),
                ([0x1234, 0x5678], 1, 1, 0, 0xbeef, 1, 1, 0),
                ([10, 0xffff], 2, 9, 9, 0x4321, 0x5a, 1, 10),
                ([13, 0xffff], 2, 0, 0, 0xbeef, 0x5a, 1, 13),
            ] {
                let mut fixture = Fixture { reader: EncodedPairReader { vtable: vtable.as_ptr(), failed: 0x5a }, input, available, consumed: 0, line_checks: 0, delegated: 0, helper_result };
                let mut output = 0xbeef;
                assert_eq!(encoded_pair_decode(&mut fixture.reader, &mut output), expected_result);
                assert_eq!(output, expected_output);
                assert_eq!(fixture.reader.failed, expected_failed);
                assert_eq!(fixture.consumed, consumed);
                assert_eq!(fixture.delegated, delegated);
                assert_eq!(fixture.line_checks, (consumed != 0) as usize);
            }
            ENCODED_PAIR_OPS = previous;
        }
    }
}
