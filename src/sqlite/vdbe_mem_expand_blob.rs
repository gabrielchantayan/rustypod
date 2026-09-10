//! Zero-tail blob materialization — turn SQLite's compact `MEM_Zero`
//! representation into a physical payload before a consumer needs bytes.
//!
//! - `vdbe_mem_expand_blob` — original: `FUN_0838bbb4` @ 0x0838bbb4
//!   (132 bytes, 0x0838bbb4..0x0838bc38; **11 `bl` call sites**,
//!   binary-scanned from osos.dec: 3 unconditional, 7 `blne`, and 1
//!   `blgt`). Upstream SQLite 3.5.9's `sqlite3VdbeMemExpandBlob`
//!   (`int sqlite3VdbeMemExpandBlob(Mem *pMem)` in vdbemem.c), verified
//!   against the raw ARM listing below.
//!
//! ### Raw algorithm
//!
//! The function samples `Mem.flags`; unless `MEM_Zero` (0x800) is set,
//! it returns `SQLITE_OK` without touching the cell. Otherwise it adds
//! the low word of `u` (the zero-tail byte count) to `n`; a non-positive
//! signed low-word result becomes the one-byte minimum request. It calls
//! `sqlite3VdbeMemGrow(pMem, request, 1)`, maps every nonzero result to
//! `SQLITE_NOMEM` (7), and leaves the cell in Grow's failure state. On
//! success it zeroes `u` low-word bytes from the pre-expansion `n`,
//! stores the wrapped low-word sum in `n`, and clears `MEM_Zero|MEM_Term`
//! (`bic #0x820`).
//!
//! The raw function is entered at 0x0838bbb4 and closes with
//! `ldmia sp!, {r4,pc}` at 0x0838bc34; 0x0838bc38 begins the distinct
//! `FUN_0838bc38`. There is no literal pool. The predicated call mix is
//! meaningful: callers normally gate expansion with `MEM_Zero` themselves
//! (seven `blne`), while this callee still has its own unguarded flag test.
//!
//! Deliberate deviation: `Mem` is accessed through its typed `repr(C)`
//! representation, whose original 32-bit offsets are asserted in
//! `sqlite/vdbe.rs`; this avoids overlapping widened host pointers.

use crate::libc::iram_veneers::iram_memzero_veneer;
use super::value_set_str::SQLITE_NOMEM;
use super::vdbe::Mem;
use super::vdbe_mem_grow::vdbe_mem_grow;
use super::vdbe_mem_realify::SQLITE_OK;

/// `MEM_Term` (0x20), cleared after the physical tail is written.
const MEM_TERM: u16 = 0x0020;
/// `MEM_Zero` (0x800), the compact implicit-zero-tail representation.
const MEM_ZERO: u16 = 0x0800;

/// vdbe_mem_expand_blob — original: `FUN_0838bbb4` @ 0x0838bbb4
/// (132 bytes; 11 `bl` call sites: 3 unconditional, 7 `blne`, 1 `blgt`).
///
/// `sqlite3VdbeMemExpandBlob`: materialize a `MEM_Zero` cell by growing
/// its payload to `n + u.nZero`, zeroing its tail, recording the new `n`,
/// and clearing `MEM_Zero|MEM_Term`. A cell without `MEM_Zero` is untouched;
/// a failed grow returns `SQLITE_NOMEM` before tail writes or flag changes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_mem_expand_blob(p_mem: *mut Mem) -> i32 {
    if (*p_mem).flags & MEM_ZERO == 0 {
        return SQLITE_OK;
    }

    let n_zero = (*p_mem).u as i32;
    let expanded_n = (*p_mem).n.wrapping_add(n_zero);
    let request = if expanded_n <= 0 { 1 } else { expanded_n };
    if vdbe_mem_grow(p_mem, request, 1) != SQLITE_OK {
        return SQLITE_NOMEM;
    }

    iram_memzero_veneer((*p_mem).z.offset((*p_mem).n as isize), n_zero as u32 as usize);
    (*p_mem).n = expanded_n;
    (*p_mem).flags &= !(MEM_ZERO | MEM_TERM);
    SQLITE_OK
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use super::super::vdbe::MEM_STATIC;

    /// Valid tag-57 tracked allocation shape for `vdbe_mem_grow`'s
    /// capacity probe: payload - 4 holds its pad, and payload - pad - 8
    /// holds this signed capacity word.
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

    fn mem(flags: u16, n: i32, n_zero: i32, z: *mut u8) -> Mem {
        Mem {
            u: n_zero as u32 as u64,
            r: f64::from_bits(0x7ff8_0000_5a5a_5a5a),
            db: 0x0bad_1000usize as *mut u8,
            z,
            n,
            flags,
            value_type: 0x5b,
            enc: 0xa7,
            x_del: core::ptr::null_mut(),
            z_malloc: z,
        }
    }

    #[test]
    fn non_zero_cells_return_without_reading_their_payload() {
        let mut cell = mem(MEM_TERM | MEM_STATIC, 17, 9, 0x0bad_2000usize as *mut u8);
        let before = (cell.u, cell.n, cell.flags, cell.z, cell.z_malloc);

        assert_eq!(unsafe { vdbe_mem_expand_blob(&mut cell) }, SQLITE_OK);
        assert_eq!((cell.u, cell.n, cell.flags, cell.z, cell.z_malloc), before);
    }

    #[test]
    fn expansion_zeroes_exact_tail_updates_length_and_clears_attributes() {
        let mut block = FakeBlock::new(32);
        let z = block.payload();
        let mut cell = mem(MEM_ZERO | MEM_TERM | MEM_STATIC | 0x0002, 2, 4, z);

        assert_eq!(unsafe { vdbe_mem_expand_blob(&mut cell) }, SQLITE_OK);
        assert_eq!(unsafe { core::slice::from_raw_parts(z, 2) }, [0xa5, 0xa5]);
        assert_eq!(unsafe { core::slice::from_raw_parts(z.add(2), 4) }, [0, 0, 0, 0]);
        assert_eq!(cell.n, 6);
        assert_eq!(cell.flags, 0x0002, "Grow clears MEM_Static; ExpandBlob clears MEM_Zero|MEM_Term");
    }

    #[test]
    fn non_positive_expanded_length_still_requests_grow_and_commits_wrapped_n() {
        let mut block = FakeBlock::new(32);
        let z = block.payload();
        let mut cell = mem(MEM_ZERO | MEM_TERM | 0x0002, 0, 0, z);

        assert_eq!(unsafe { vdbe_mem_expand_blob(&mut cell) }, SQLITE_OK);
        assert_eq!(unsafe { core::slice::from_raw_parts(z, 8) }, [0xa5; 8]);
        assert_eq!(cell.n, 0);
        assert_eq!(cell.flags, 0x0002);
    }
}
