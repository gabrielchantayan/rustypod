use super::api_exit::sqlite_api_exit;
use super::prepare::{LockAndPrepareFn, PREPARE_OP};
use super::utf16_to_utf8::sqlite3_utf16_to_utf8;
use crate::cxx::opaque_type_tag_is_allowed::opaque_type_tag_is_allowed;
use crate::heap::tracked::tracked_free;

const SQLITE_MISUSE: i32 = 21;

pub type Utf16ToUtf8Fn = unsafe extern "C" fn(*mut u8, *mut u8, i32) -> *mut u8;
pub type Utf16PrefixByteLenFn = unsafe extern "C" fn(*const u8, i32) -> i32;
pub type FreeFn = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_utf16_prefix_byte_len(text: *const u8, utf8_byte_count: i32) -> i32 {
    let utf16_prefix_byte_len: Utf16PrefixByteLenFn = core::mem::transmute(0x0838_61e0usize);
    utf16_prefix_byte_len(text, utf8_byte_count)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_utf16_prefix_byte_len(_text: *const u8, _utf8_byte_count: i32) -> i32 {
    panic!("sqlite3_prepare16 requires UTF-16 prefix byte length operation @ 0x083861e0")
}

#[cfg(target_os = "none")]
const DEFAULT_UTF16_PREFIX_BYTE_LEN_OP: Utf16PrefixByteLenFn = retail_utf16_prefix_byte_len;
#[cfg(not(target_os = "none"))]
const DEFAULT_UTF16_PREFIX_BYTE_LEN_OP: Utf16PrefixByteLenFn = missing_utf16_prefix_byte_len;

pub static mut UTF16_TO_UTF8_OP: Utf16ToUtf8Fn = sqlite3_utf16_to_utf8;
pub static mut UTF16_PREFIX_BYTE_LEN_OP: Utf16PrefixByteLenFn = DEFAULT_UTF16_PREFIX_BYTE_LEN_OP;
pub static mut FREE_OP: FreeFn = tracked_free;

#[inline(always)]
unsafe fn utf16_to_utf8_op() -> Utf16ToUtf8Fn {
    core::ptr::read_volatile(core::ptr::addr_of!(UTF16_TO_UTF8_OP))
}

#[inline(always)]
unsafe fn utf16_prefix_byte_len_op() -> Utf16PrefixByteLenFn {
    core::ptr::read_volatile(core::ptr::addr_of!(UTF16_PREFIX_BYTE_LEN_OP))
}

#[inline(always)]
unsafe fn prepare_op() -> LockAndPrepareFn {
    core::ptr::read_volatile(core::ptr::addr_of!(PREPARE_OP))
}

#[inline(always)]
unsafe fn free_op() -> FreeFn {
    core::ptr::read_volatile(core::ptr::addr_of!(FREE_OP))
}

/// sqlite3Prepare16 — original `FUN_0838160c` at load address `0x0838160c`
/// (192 bytes, `0x0838160c..0x083816cc`; eight unconditional direct `bl`
/// instructions and no predicated `bl`).
///
/// Rejects an unrecognized database type tag with SQLITE_MISUSE. Otherwise,
/// converts UTF-16 SQL to UTF-8, prepares it with the requested source-retention
/// flag, maps the UTF-8 tail back to a UTF-16 byte offset, frees the conversion,
/// and filters the result through sqlite_api_exit. Deliberate deviations: the
/// unported UTF-16 prefix-byte-length helper at `0x083861e0` uses a volatile
/// host seam and its verified retailOS address on firmware; conversion and free
/// use replaceable host seams only for tests.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite3_prepare16_internal(
    db: *mut u8,
    utf16_sql: *mut u8,
    byte_count: i32,
    save_sql: i32,
    statement_out: *mut *mut u8,
    tail_out: *mut *mut u8,
) -> i32 {
    if opaque_type_tag_is_allowed(db.cast()) == 0 {
        return SQLITE_MISUSE;
    }

    let utf8_sql = utf16_to_utf8_op()(db, utf16_sql, byte_count);
    let mut result_code = 0;
    if !utf8_sql.is_null() {
        let mut utf8_tail = core::ptr::null();
        result_code = prepare_op()(db, utf8_sql, -1, save_sql, statement_out, core::ptr::addr_of_mut!(utf8_tail));
        if !utf8_tail.is_null() && !tail_out.is_null() {
            *tail_out = utf16_sql.add(utf16_prefix_byte_len_op()(utf16_sql, utf8_tail.offset_from(utf8_sql) as i32) as usize);
        }
    }
    free_op()(utf8_sql);
    sqlite_api_exit(db, result_code)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static CONVERSION_CALLS: AtomicUsize = AtomicUsize::new(0);
    static PREPARE_SAVE_SQL: AtomicI32 = AtomicI32::new(0);
    static PREPARE_SQL: AtomicUsize = AtomicUsize::new(0);
    static FREED: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn conversion(_db: *mut u8, _text: *mut u8, _length: i32) -> *mut u8 {
        CONVERSION_CALLS.fetch_add(1, Ordering::SeqCst);
        0x1000usize as *mut u8
    }
    #[repr(align(4))]
    struct Db([u8; 0x44]);


    unsafe extern "C" fn prepare(
        _db: *mut u8, sql: *const u8, _byte_count: i32, save_sql: i32,
        _statement_out: *mut *mut u8, tail_out: *mut *const u8,
    ) -> i32 {
        PREPARE_SQL.store(sql as usize, Ordering::SeqCst);
        PREPARE_SAVE_SQL.store(save_sql, Ordering::SeqCst);
        *tail_out = sql.add(4);
        17
    }

    unsafe extern "C" fn prefix_byte_len(_text: *const u8, utf8_byte_count: i32) -> i32 {
        assert_eq!(utf8_byte_count, 4);
        8
    }

    unsafe extern "C" fn free(pointer: *mut u8) {
        FREED.store(pointer as usize, Ordering::SeqCst);
    }

    unsafe fn with_ops(body: impl FnOnce()) {
        let _guard = OPS_LOCK.lock();
        let saved_conversion = core::ptr::read_volatile(core::ptr::addr_of!(UTF16_TO_UTF8_OP));
        let saved_prefix = core::ptr::read_volatile(core::ptr::addr_of!(UTF16_PREFIX_BYTE_LEN_OP));
        let saved_prepare = core::ptr::read_volatile(core::ptr::addr_of!(PREPARE_OP));
        let saved_free = core::ptr::read_volatile(core::ptr::addr_of!(FREE_OP));
        core::ptr::write_volatile(core::ptr::addr_of_mut!(UTF16_TO_UTF8_OP), conversion);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(UTF16_PREFIX_BYTE_LEN_OP), prefix_byte_len);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(PREPARE_OP), prepare);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(FREE_OP), free);
        body();
        core::ptr::write_volatile(core::ptr::addr_of_mut!(UTF16_TO_UTF8_OP), saved_conversion);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(UTF16_PREFIX_BYTE_LEN_OP), saved_prefix);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(PREPARE_OP), saved_prepare);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(FREE_OP), saved_free);
    }
    #[test]
    fn converts_prepares_maps_tail_frees_and_filters_result() { unsafe {
        let mut db = Db([0u8; 0x44]);
        db.0[0x18] = 0xff;
        core::ptr::write_unaligned(db.0.as_mut_ptr().add(0x40).cast(), 0xa029_a697u32);
        let mut sql = [0u8; 16];
        let mut tail = core::ptr::null_mut();
        CONVERSION_CALLS.store(0, Ordering::SeqCst);
        with_ops(|| assert_eq!(sqlite3_prepare16_internal(db.0.as_mut_ptr(), sql.as_mut_ptr(), 12, 1, core::ptr::null_mut(), &mut tail), 17));
        assert_eq!(CONVERSION_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(PREPARE_SQL.load(Ordering::SeqCst), 0x1000);
        assert_eq!(PREPARE_SAVE_SQL.load(Ordering::SeqCst), 1);
        assert_eq!(tail, sql.as_mut_ptr().add(8));
        assert_eq!(FREED.load(Ordering::SeqCst), 0x1000);
    }}

    #[test]
    fn rejected_type_skips_conversion_and_api_exit() { unsafe {
        let mut db = Db([0u8; 0x44]);
        CONVERSION_CALLS.store(0, Ordering::SeqCst);
        with_ops(|| assert_eq!(sqlite3_prepare16_internal(db.0.as_mut_ptr(), core::ptr::null_mut(), 0, 0, core::ptr::null_mut(), core::ptr::null_mut()), SQLITE_MISUSE));
        assert_eq!(CONVERSION_CALLS.load(Ordering::SeqCst), 0);
    }}
}
