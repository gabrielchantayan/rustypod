use super::error::SQLITE_UTF8;
use super::vdbe_mem_set_str::vdbe_mem_set_str;

/// sqlite3_result_text — original `FUN_08391220` at load address
/// `0x08391220` (24 bytes; six direct `bl` call sites, all unconditional;
/// four additional unconditional direct `b` tail entries).
///
/// Installs the caller-owned UTF-8 text in the embedded `Mem` result at
/// `context + 8`, forwarding the text pointer, length, and destructor without
/// validation. Deliberate deviations: none.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sqlite3_result_text(
    context: *mut u8,
    text: *mut u8,
    length: i32,
    destructor: *mut u8,
) {
    vdbe_mem_set_str(context.add(8), text, length, SQLITE_UTF8, destructor);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::mem_release::FLAG_DYN;
    use crate::sqlite::vdbe::{Mem, MEM_STATIC};
    use crate::sqlite::vdbe_mem_set_str::{MEM_STR, MEM_TERM};

    #[repr(C)]
    struct SqliteContext {
        reserved: [u32; 2],
        result: Mem,
    }

    fn empty_mem() -> Mem {
        Mem {
            u: 0,
            r: 0.0,
            db: core::ptr::null_mut(),
            z: core::ptr::null_mut(),
            n: 0,
            flags: 0,
            value_type: 0,
            enc: 0,
            x_del: core::ptr::null_mut(),
            z_malloc: core::ptr::null_mut(),
        }
    }

    fn context() -> SqliteContext {
        SqliteContext { reserved: [0; 2], result: empty_mem() }
    }

    #[test]
    fn negative_length_sets_the_embedded_result_as_terminated_utf8() {
        let mut context = context();
        let mut text = *b"iPod\0";

        assert_eq!(core::mem::offset_of!(SqliteContext, result), 8);
        unsafe {
            sqlite3_result_text(
                core::ptr::addr_of_mut!(context).cast(),
                text.as_mut_ptr(),
                -1,
                core::ptr::null_mut(),
            );
        }

        assert_eq!(context.result.z, text.as_mut_ptr());
        assert_eq!(context.result.n, 4);
        assert_eq!(context.result.flags, MEM_STR | MEM_TERM | MEM_STATIC);
        assert_eq!(context.result.enc, SQLITE_UTF8);
    }

    #[test]
    fn explicit_length_and_destructor_are_forwarded_without_text_scanning() {
        let mut context = context();
        let mut text = *b"a\0b\0";
        let destructor = 0x1234usize as *mut u8;

        unsafe {
            sqlite3_result_text(
                core::ptr::addr_of_mut!(context).cast(),
                text.as_mut_ptr(),
                3,
                destructor,
            );
        }

        assert_eq!(context.result.z, text.as_mut_ptr());
        assert_eq!(context.result.n, 3);
        assert_eq!(context.result.flags, MEM_STR | FLAG_DYN);
        assert_eq!(context.result.enc, SQLITE_UTF8);
        assert_eq!(context.result.x_del, destructor);
    }
}
