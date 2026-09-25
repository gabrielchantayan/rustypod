//! Merge one bottom-up pass over twelve-byte string-and-word records.

use crate::runtime::rt_div::__rt_sdiv;

use super::string_object_word_merge::string_object_word_merge;
use super::templates::StringObjectWord;

/// `string_object_word_merge_pass` — original: `FUN_083e8814` @ `0x083e8814`
/// (**184 bytes**, raw extent `0x083e8814..0x083e88cc`; the next independently
/// linked function starts with `push {r4-r6,lr}` at `0x083e88cc`). Raw A32
/// decoding finds four unconditional plain body `bl` instructions—two to
/// `string_object_word_merge` @ `0x083ea788` and two to `__rt_sdiv` @
/// `0x08031568`—and no predicated `bl`. The only two inbound direct `bl` sites
/// are unconditional at `0x083e9ab8` and `0x083e9ad4`; none are predicated.
///
/// Merges consecutive pairs of sorted `run_records`-long runs from
/// `[first, last)` into `output`. A final incomplete pair merges a left run of
/// `min(run_records, remaining_records)` records with its remaining right run.
/// The original divides byte spans by twelve through the signed ADS runtime,
/// preserving truncation toward zero for malformed reversed or partial ranges.
///
/// Deliberate deviations: typed record cursors replace `+0xc` arithmetic, and
/// the stateless comparator argument passed by retail callers is accepted but
/// deliberately ignored: the downstream port verified that it is never
/// dereferenced.
///
/// # Safety
///
/// `first..last` must be a readable contiguous range of sorted
/// [`StringObjectWord`] records, and `output` must have writable capacity for
/// every record in that range. `run_records` must be positive for termination.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_object_word_merge_pass(
    mut first: *const StringObjectWord,
    last: *const StringObjectWord,
    mut output: *mut StringObjectWord,
    run_records: i32,
    _comparator: *const u8,
) {
    let record_bytes = core::mem::size_of::<StringObjectWord>() as i32;
    while __rt_sdiv((last as usize).wrapping_sub(first as usize) as i32, record_bytes) >= run_records.wrapping_mul(2) {
        let left_end = first.add(run_records as usize);
        let right_end = left_end.add(run_records as usize);
        output = string_object_word_merge(first, left_end, left_end, right_end, output);
        first = right_end;
    }

    let remaining_records = __rt_sdiv((last as usize).wrapping_sub(first as usize) as i32, record_bytes);
    let left_records = if run_records < remaining_records { run_records } else { remaining_records };
    let left_end = first.add(left_records as usize);
    string_object_word_merge(first, left_end, left_end, last, output);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::string_object::{
        StringObject, StringObjectAssignCstrOps, StringObjectVtable,
        DEFAULT_STRING_OBJECT_ASSIGN_CSTR_OPS, STRING_OBJECT_ASSIGN_CSTR_OPS,
    };
    use crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK;

    static mut POOL: [[u8; 8]; 8] = [[0; 8]; 8];
    static mut CURSOR: usize = 0;

    unsafe extern "C" fn allocate(this: *mut StringObject, _size: usize, _flags: u32) -> *mut u8 {
        let index = CURSOR;
        CURSOR += 1;
        let payload = core::ptr::addr_of_mut!(POOL[index]).cast();
        (*this).payload = payload;
        payload
    }

    unsafe extern "C" fn clear(_this: *mut StringObject) {}

    struct OpsGuard;
    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS).write_volatile(DEFAULT_STRING_OBJECT_ASSIGN_CSTR_OPS) }
        }
    }

    fn record(text: &mut [u8], trailing_word: u32) -> StringObjectWord {
        StringObjectWord { string: StringObject { vtable: 0xdead_beefusize as *const StringObjectVtable, payload: text.as_mut_ptr() }, trailing_word }
    }

    #[test]
    fn merges_complete_runs_and_a_short_final_pair() {
        let _lock = STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let _ops = OpsGuard;
        unsafe {
            CURSOR = 0;
            POOL = [[0; 8]; 8];
            core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS).write_volatile(StringObjectAssignCstrOps { allocate_payload: allocate, clear_payload: clear });
        }
        let mut a = *b"a\0";
        let mut d = *b"d\0";
        let mut b = *b"b\0";
        let mut c = *b"c\0";
        let mut e = *b"e\0";
        let input = [record(&mut a, 1), record(&mut d, 4), record(&mut b, 2), record(&mut c, 3), record(&mut e, 5)];
        let mut output = [record(&mut [], 0), record(&mut [], 0), record(&mut [], 0), record(&mut [], 0), record(&mut [], 0)];

        unsafe {
            string_object_word_merge_pass(input.as_ptr(), input.as_ptr().add(input.len()), output.as_mut_ptr(), 2, core::ptr::null());
            assert_eq!(output.map(|record| record.trailing_word), [1, 2, 3, 4, 5]);
        }
    }
}
