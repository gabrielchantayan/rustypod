#[cfg(target_pointer_width = "32")]
use super::mem_release::mem_release;
use super::strdup::db_str_dup;
use super::value_text::change_encoding_op;
use super::vdbe::Mem;
use super::vdbe_mem_set_str::vdbe_mem_set_str;

const SQLITE_UTF8: u8 = 1;
const SQLITE_UTF16LE: u8 = 2;
const MEM_DYN: u16 = 0x40;
const DB_MALLOC_FAILED_OFFSET: usize = 0x1e;

#[cfg(target_pointer_width = "32")]
#[inline(always)]
unsafe fn release_temporary(value: *mut Mem) {
    mem_release(value.cast());
}

#[cfg(not(target_pointer_width = "32"))]
#[inline(always)]
unsafe fn release_temporary(value: *mut Mem) {
    (*value).z = core::ptr::null_mut();
    (*value).z_malloc = core::ptr::null_mut();
    (*value).x_del = core::ptr::null_mut();
}

/// sqlite3Utf16to8 — original `FUN_083862e4` at load address `0x083862e4`
/// (156 bytes, `0x083862e4..0x08386380`; five unconditional direct `bl`
/// instructions and no predicated `bl`).
///
/// Installs a native UTF-16 string in a zeroed temporary `Mem`, converts it
/// to UTF-8, and returns the conversion-owned buffer directly or a
/// connection-owned duplicate of static storage. A pre-existing sticky
/// allocation failure releases the temporary and returns NULL. Deliberate
/// deviation: the firmware's runtime endian selector at `0x088fa948` is one
/// in the decrypted image, selecting UTF-16LE; this little-endian target
/// ports that observed path. `sqlite3VdbeChangeEncoding` remains unported,
/// so its existing volatile seam supplies its failure-shaped default. On
/// 64-bit host tests the temporary's pointer fields are wider than the
/// target's raw 0x28-byte layout, so the release stores are modeled through
/// typed fields rather than calling the target-offset release port.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite3_utf16_to_utf8(
    db: *mut u8,
    text: *mut u8,
    length: i32,
) -> *mut u8 {
    let mut value = Mem {
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
    };

    vdbe_mem_set_str(
        core::ptr::addr_of_mut!(value).cast(),
        text,
        length,
        SQLITE_UTF16LE,
        core::ptr::null_mut(),
    );
    (change_encoding_op())(core::ptr::addr_of_mut!(value).cast(), SQLITE_UTF8);

    if db.add(DB_MALLOC_FAILED_OFFSET).read() != 0 {
        release_temporary(core::ptr::addr_of_mut!(value));
        return core::ptr::null_mut();
    }
    if value.flags & MEM_DYN != 0 {
        return value.z;
    }
    db_str_dup(db, value.z)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn null_input_returns_null_without_allocating() {
        let mut db = [0u8; 0x20];

        assert!(unsafe { sqlite3_utf16_to_utf8(db.as_mut_ptr(), core::ptr::null_mut(), 0) }.is_null());
    }

    #[test]
    fn sticky_allocation_failure_releases_temporary_and_returns_null() {
        let mut db = [0u8; 0x20];
        db[DB_MALLOC_FAILED_OFFSET] = 1;
        assert!(unsafe {
            sqlite3_utf16_to_utf8(db.as_mut_ptr(), core::ptr::null_mut(), 0)
        }
        .is_null());
    }
}
