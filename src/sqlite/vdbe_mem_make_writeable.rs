//! Writable payload conversion — give a SQLite `Mem` cell an owned,
//! NUL-terminated string/blob buffer before a caller mutates it.
//!
//! - `vdbe_mem_make_writeable` — original: `FUN_0838bb30` @ 0x0838bb30
//!   (132 bytes, 0x0838bb30..0x0838bbb4; **7 `bl` call sites**, all
//!   unconditional, binary-scanned from osos.dec). It is SQLite 3.5.9's
//!   `sqlite3VdbeMemMakeWriteable` in `vdbemem.c`.
//!
//! ### Raw algorithm
//!
//! `MEM_Zero` (0x800) first materializes through
//! [`vdbe_mem_expand_blob`]. Any nonzero expansion result maps to
//! `SQLITE_NOMEM` (7). The flags are then reloaded: only a
//! `MEM_Str|MEM_Blob` (0x12) payload whose `z` differs from `zMalloc` is
//! grown to `n + 2` with preservation. A failed grow likewise returns 7.
//! On success the original writes two zero bytes at `z[n]` and `z[n + 1]`
//! and sets `MEM_Term` (0x20). A payload already at `zMalloc`, or one
//! without either type bit, is left untouched.
//!
//! The raw closing `ldmia sp!, {r4,pc}` is at 0x0838bbb0; 0x0838bbb4 is
//! the separate `sqlite3VdbeMemExpandBlob` entry, so there is no literal
//! pool. The seven direct calls are at 0x08386778, 0x083873e8,
//! 0x08387540, 0x0838855c, 0x0838bb20, 0x0838bef4, and 0x0838c43c;
//! every branch has condition `al` (no caller-side predicate).
//!
//! Deliberate deviation: typed `repr(C)` [`Mem`] fields replace the raw
//! target offsets, whose 32-bit layout is asserted in `sqlite/vdbe.rs`;
//! this keeps widened host pointers disjoint.

use super::value_set_str::SQLITE_NOMEM;
use super::vdbe::Mem;
#[cfg(test)]
use super::vdbe::MEM_STATIC;
use super::vdbe_mem_expand_blob::vdbe_mem_expand_blob;
use super::vdbe_mem_grow::vdbe_mem_grow;
use super::vdbe_mem_realify::SQLITE_OK;

/// `MEM_Str | MEM_Blob`: payload types requiring owned, terminated bytes.
const MEM_STR_OR_BLOB: u16 = 0x0012;
/// `MEM_Term`: `z[n]` and `z[n + 1]` hold zero bytes.
const MEM_TERM: u16 = 0x0020;
/// `MEM_Zero`: `u` is the implicit zero-tail byte count.
const MEM_ZERO: u16 = 0x0800;

/// vdbe_mem_make_writeable — original: `FUN_0838bb30` @ 0x0838bb30
/// (132 bytes; 7 unconditional `bl` call sites).
///
/// `sqlite3VdbeMemMakeWriteable`: materialize a zero-tail first, then copy
/// a borrowed string/blob into preserved `zMalloc` storage large enough for
/// its payload plus two terminators. The two trailing zero bytes and
/// `MEM_Term` are written only when storage changed from borrowed to owned.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_mem_make_writeable(p_mem: *mut Mem) -> i32 {
    if (*p_mem).flags & MEM_ZERO != 0 && vdbe_mem_expand_blob(p_mem) != SQLITE_OK {
        return SQLITE_NOMEM;
    }

    if (*p_mem).flags & MEM_STR_OR_BLOB != 0 && (*p_mem).z != (*p_mem).z_malloc {
        if vdbe_mem_grow(p_mem, (*p_mem).n.wrapping_add(2), 1) != SQLITE_OK {
            return SQLITE_NOMEM;
        }
        let terminator = (*p_mem).z.offset((*p_mem).n as isize);
        terminator.write(0);
        terminator.add(1).write(0);
        (*p_mem).flags |= MEM_TERM;
    }

    SQLITE_OK
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    /// Valid tag-57 tracked allocation shape for `vdbe_mem_grow`'s capacity
    /// probe. The word at payload - 4 is the pad; the signed capacity word
    /// lives at payload - pad - 8.
    #[repr(C, align(32))]
    struct FakeBlock {
        size: i32,
        _sign: i32,
        _pad_bytes: [u8; 20],
        pad: u32,
        payload: [u8; 32],
    }

    impl FakeBlock {
        fn new(capacity: i32) -> Self {
            FakeBlock { size: capacity, _sign: 0, _pad_bytes: [0; 20], pad: 24, payload: [0xa5; 32] }
        }

        fn payload(&mut self) -> *mut u8 {
            self.payload.as_mut_ptr()
        }
    }

    fn mem(flags: u16, n: i32, n_zero: i32, z: *mut u8, z_malloc: *mut u8) -> Mem {
        Mem {
            u: n_zero as u32 as u64,
            r: f64::from_bits(0x7ff8_0000_5a5a_5a5a),
            db: core::ptr::null_mut(),
            z,
            n,
            flags,
            value_type: 0x5b,
            enc: 1,
            x_del: core::ptr::null_mut(),
            z_malloc,
        }
    }

    #[test]
    fn unrelated_payload_types_return_without_dereferencing_pointers() {
        let mut cell = mem(MEM_TERM | MEM_STATIC, -7, 0, core::ptr::null_mut(), 1usize as *mut u8);
        let before = (cell.u, cell.n, cell.flags, cell.z, cell.z_malloc);

        assert_eq!(unsafe { vdbe_mem_make_writeable(&mut cell) }, SQLITE_OK);
        assert_eq!((cell.u, cell.n, cell.flags, cell.z, cell.z_malloc), before);
    }

    #[test]
    fn borrowed_string_becomes_owned_and_gets_double_terminator() {
        let mut block = FakeBlock::new(32);
        let z_malloc = block.payload();
        let mut borrowed = *b"song!!";
        let mut cell = mem(0x0002 | MEM_STATIC, 4, 0, borrowed.as_mut_ptr(), z_malloc);

        assert_eq!(unsafe { vdbe_mem_make_writeable(&mut cell) }, SQLITE_OK);
        assert_eq!(cell.z, z_malloc);
        assert_eq!(unsafe { core::slice::from_raw_parts(z_malloc, 6) }, b"song\0\0");
        assert_eq!(cell.flags, 0x0002 | MEM_TERM, "Grow clears MEM_Static before MakeWriteable sets MEM_Term");
    }

    #[test]
    fn zero_tail_is_expanded_before_the_post_expansion_ownership_check() {
        let mut block = FakeBlock::new(32);
        let z = block.payload();
        unsafe { z.copy_from_nonoverlapping(b"art".as_ptr(), 3) };
        let mut cell = mem(MEM_ZERO | MEM_TERM | MEM_STATIC | 0x0002, 3, 2, z, z);

        assert_eq!(unsafe { vdbe_mem_make_writeable(&mut cell) }, SQLITE_OK);
        assert_eq!(cell.n, 5);
        assert_eq!(unsafe { core::slice::from_raw_parts(z, 5) }, b"art\0\0");
        assert_eq!(cell.flags, 0x0002, "ExpandBlob clears MEM_Zero|MEM_Term; z == zMalloc prevents a new terminator write");
    }
}
