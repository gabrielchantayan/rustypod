//! `u16_code_dispatch` — original: `FUN_080dc92c` @ `0x080dc92c` (220 bytes;
//! 4 direct unconditional `bl` call sites, no predicated `bl`).
//!
//! Raw ARM establishes the exact extent `0x080dc92c..0x080dca08`; the next
//! separately entered function begins at `0x080dca10`, after the two literal
//! words at `0x080dca08` and `0x080dca0c`. It binary-searches a 12-byte primary
//! record table for the low sixteen bits of `code`, selects an indexed UTF-16
//! word, and dispatches that word through `receiver`'s vtable `+0x1c` slot. An
//! absent primary entry, an out-of-range index, or a null secondary lookup
//! dispatches `0x3f`. A primary word of `0xffff` instead looks up an 8-byte
//! secondary record and dispatches its zero-terminated word sequence followed
//! by the original `0xffff` sentinel.
//!
//! Deliberate deviations: the unrecovered binary-search helper at `0x080edb8c`
//! is represented by a host replacement seam; device builds call its verified
//! address. Rust passes the helper's saved/restored comparator register as the
//! vtable wrapper's fourth argument, preserving the retail forwarding.

use crate::cxx::vtable_word_callback::vtable_word_callback;

const PRIMARY_COMPARE: usize = 0x080b_f2bc;
const SECONDARY_COMPARE: usize = 0x080b_f29c;

/// The portions of an `0x080edb8c` result record observed by this dispatcher.
#[repr(C)]
pub struct CodeDispatchRecord {
    /// +0x00: first code covered by this record.
    pub first_code: u16,
    _padding_02: u16,
    /// +0x04: number of UTF-16 words in `codes`.
    pub code_count: u16,
    _padding_06: u16,
    /// +0x08: selected word array, or secondary zero-terminated sequence.
    pub codes: *const u16,
}

type CodeDispatchLookup = unsafe extern "C" fn(
    query: *mut u32,
    records: *mut u8,
    record_count: u32,
    record_size: u32,
    compare: usize,
) -> *mut CodeDispatchRecord;

#[cfg(target_os = "none")]
unsafe fn retail_code_dispatch_lookup(
    query: *mut u32,
    records: *mut u8,
    record_count: u32,
    record_size: u32,
    compare: usize,
) -> *mut CodeDispatchRecord {
    let lookup: CodeDispatchLookup = unsafe { core::mem::transmute(0x080e_db8cusize) };
    unsafe { lookup(query, records, record_count, record_size, compare) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_code_dispatch_lookup(
    _query: *mut u32,
    _records: *mut u8,
    _record_count: u32,
    _record_size: u32,
    _compare: usize,
) -> *mut CodeDispatchRecord {
    panic!("u16_code_dispatch requires lookup helper 0x080edb8c")
}

/// Host replacement for the unrecovered binary-search helper at `0x080edb8c`.
#[cfg(not(target_os = "none"))]
pub static mut CODE_DISPATCH_LOOKUP: CodeDispatchLookup = missing_code_dispatch_lookup;

unsafe fn code_dispatch_lookup(
    query: *mut u32,
    records: *mut u8,
    record_count: u32,
    record_size: u32,
    compare: usize,
) -> *mut CodeDispatchRecord {
    #[cfg(target_os = "none")]
    {
        unsafe { retail_code_dispatch_lookup(query, records, record_count, record_size, compare) }
    }
    #[cfg(not(target_os = "none"))]
    {
        let lookup = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CODE_DISPATCH_LOOKUP)) };
        unsafe { lookup(query, records, record_count, record_size, compare) }
    }
}

unsafe fn dispatch(receiver: *mut u8, word: u16, forwarded_r3: usize) {
    unsafe { vtable_word_callback(receiver, word as u32, 0, forwarded_r3) };
}

/// Dispatches the primary code mapped from `code`, including its optional
/// secondary zero-terminated sequence.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn u16_code_dispatch(
    code: u32,
    receiver: *mut u8,
    primary_records: *mut u8,
    primary_record_count: u32,
    secondary_records: *mut u8,
    secondary_record_count: u32,
) {
    let mut query = [code, receiver as usize as u32, primary_records as usize as u32, primary_record_count];
    let primary = unsafe {
        code_dispatch_lookup(query.as_mut_ptr(), primary_records, primary_record_count, 12, PRIMARY_COMPARE)
    };
    if primary.is_null() {
        unsafe { dispatch(receiver, 0x3f, PRIMARY_COMPARE) };
        return;
    }

    let key = code as u16;
    let index = key.wrapping_sub(unsafe { (*primary).first_code }) as usize;
    if index >= unsafe { (*primary).code_count as usize } {
        unsafe { dispatch(receiver, 0x3f, PRIMARY_COMPARE) };
        return;
    }
    let selected = unsafe { (*primary).codes.add(index).read() };
    if selected != u16::MAX {
        unsafe { dispatch(receiver, selected, PRIMARY_COMPARE) };
        return;
    }

    query[0] = key as u32;
    let secondary = unsafe {
        code_dispatch_lookup(query.as_mut_ptr(), secondary_records, secondary_record_count, 8, SECONDARY_COMPARE)
    };
    if secondary.is_null() {
        unsafe { dispatch(receiver, 0x3f, SECONDARY_COMPARE) };
        return;
    }
    let mut sequence = unsafe { (*secondary).codes };
    loop {
        let word = unsafe { sequence.read() };
        if word == 0 {
            break;
        }
        unsafe { dispatch(receiver, word, SECONDARY_COMPARE) };
        sequence = unsafe { sequence.add(1) };
    }
    unsafe { dispatch(receiver, selected, SECONDARY_COMPARE) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::Mutex;

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut PRIMARY: *mut CodeDispatchRecord = ptr::null_mut();
    static mut SECONDARY: *mut CodeDispatchRecord = ptr::null_mut();
    static mut LOOKUPS: [(u32, u32, usize); 2] = [(0, 0, 0); 2];
    static mut LOOKUP_COUNT: usize = 0;
    static mut WORDS: [u32; 8] = [0; 8];
    static mut WORD_COUNT: usize = 0;

    unsafe extern "C" fn lookup(
        query: *mut u32,
        _records: *mut u8,
        _record_count: u32,
        record_size: u32,
        compare: usize,
    ) -> *mut CodeDispatchRecord {
        unsafe {
            LOOKUPS[LOOKUP_COUNT] = (query.read(), record_size, compare);
            LOOKUP_COUNT += 1;
            if record_size == 12 { PRIMARY } else { SECONDARY }
        }
    }

    type WordCallback = unsafe extern "C" fn(*mut u8, *mut u32, usize, usize) -> usize;

    unsafe extern "C" fn record_word(
        _receiver: *mut u8,
        word: *mut u32,
        _callback: usize,
        _forwarded_r3: usize,
    ) -> usize {
        unsafe {
            WORDS[WORD_COUNT] = word.read();
            WORD_COUNT += 1;
        }
        0
    }

    #[repr(C)]
    struct Receiver {
        vtable: *const WordCallback,
    }

    fn reset(primary: *mut CodeDispatchRecord, secondary: *mut CodeDispatchRecord) {
        unsafe {
            PRIMARY = primary;
            SECONDARY = secondary;
            LOOKUP_COUNT = 0;
            WORD_COUNT = 0;
            CODE_DISPATCH_LOOKUP = lookup;
        }
    }

    fn run(code: u32, primary: *mut CodeDispatchRecord, secondary: *mut CodeDispatchRecord) {
        let mut vtable = [record_word as WordCallback; 8];
        let mut receiver = Receiver { vtable: vtable.as_mut_ptr() };
        reset(primary, secondary);
        unsafe { u16_code_dispatch(code, (&mut receiver as *mut Receiver).cast(), ptr::null_mut(), 7, ptr::null_mut(), 9) };
    }

    #[test]
    fn missing_or_out_of_range_primary_dispatches_question_mark() {
        let _guard = DISPATCH_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        run(0x1234, ptr::null_mut(), ptr::null_mut());
        unsafe {
            assert_eq!(&WORDS[..WORD_COUNT], &[0x3f]);
            assert_eq!(LOOKUPS[0], (0x1234, 12, PRIMARY_COMPARE));
        }

        let words = [0x44u16];
        let mut primary = CodeDispatchRecord { first_code: 0x1235, _padding_02: 0, code_count: 1, _padding_06: 0, codes: words.as_ptr() };
        run(0x1234, &mut primary, ptr::null_mut());
        unsafe { assert_eq!(&WORDS[..WORD_COUNT], &[0x3f]) };
    }

    #[test]
    fn selected_primary_word_dispatches_once() {
        let _guard = DISPATCH_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let words = [0x55u16, 0x66];
        let mut primary = CodeDispatchRecord { first_code: 0x40, _padding_02: 0, code_count: 2, _padding_06: 0, codes: words.as_ptr() };
        run(0x41, &mut primary, ptr::null_mut());
        unsafe {
            assert_eq!(&WORDS[..WORD_COUNT], &[0x66]);
            assert_eq!(LOOKUP_COUNT, 1);
        }
    }

    #[test]
    fn sentinel_dispatches_secondary_sequence_then_sentinel() {
        let _guard = DISPATCH_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let primary_words = [u16::MAX];
        let secondary_words = [7u16, 8, 0];
        let mut primary = CodeDispatchRecord { first_code: 0x99, _padding_02: 0, code_count: 1, _padding_06: 0, codes: primary_words.as_ptr() };
        let mut secondary = CodeDispatchRecord { first_code: 0, _padding_02: 0, code_count: 0, _padding_06: 0, codes: secondary_words.as_ptr() };
        run(0x1_0099, &mut primary, &mut secondary);
        unsafe {
            assert_eq!(&WORDS[..WORD_COUNT], &[7, 8, u16::MAX as u32]);
            assert_eq!(LOOKUPS[1], (0x99, 8, SECONDARY_COMPARE));
        }
    }
}
