//! VDBE cursor allocation for OpenRead/OpenEphemeral.
//!
//! `allocate_cursor` — original: `FUN_082b38e0` @ `0x082b38e0` (216 bytes,
//! `0x082b38e0..0x082b39b8`; 4 direct callers: 3 plain `bl`, 1 `blne`,
//! decoded from every aligned ARM B/BL word in `osos.dec`).
//!
//! SQLite 3.5.9's private `allocateCursor` in `vdbe.c`: select cursor `i_cur`'s
//! backing Mem from the top of `aMem`, release an existing cursor, grow that Mem
//! to `sizeof(Cursor) + (is_btree_cursor ? 0x60 : 0) + 8*n_field`, and zero the
//! result. `OP_SetNumColumns` (0x62) and `OP_OpenEphemeral` (0x70) contribute
//! `p2` fields. On success it installs the cursor in `apCsr`, then records iDb,
//! nField, aType, and the Btree-cursor region. `sqlite3VdbeFreeCursor` is
//! ported directly in [`vdbe_free_cursor`]. Deliberate deviation: named
//! `repr(C)` fields preserve target pointer slots without assuming 32-bit
//! host-pointer byte offsets.

use super::vdbe_free_cursor::vdbe_free_cursor;
use super::vdbe::{Mem, Vdbe, VdbeOp};
use super::vdbe_mem_grow::vdbe_mem_grow;
use crate::libc::iram_veneers::iram_memzero_veneer;

const CURSOR_SIZE: usize = 0x80;
const BTREE_CURSOR_SIZE: usize = 0x60;
const FIELD_BYTES: usize = 8;
const OP_SET_NUM_COLUMNS: u8 = b'b';
const OP_OPEN_EPHEMERAL: u8 = b'p';

#[repr(C)]
pub struct VdbeCursor {
    pub p_cursor: *mut u8,
    pub n_field: i32,
    _gap_08: [u8; 0x48],
    pub i_db: i32,
    _gap_54: [u8; 0x1c],
    pub a_type: *mut u32,
}


/// `allocateCursor` — original: `FUN_082b38e0` @ `0x082b38e0` (216 bytes).
///
/// `p`, `p_op`, and the selected `a_mem` and `ap_csr` elements must be valid.
/// The original has no bounds or NULL checks after selecting `a_mem[n_mem-i_cur]`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn allocate_cursor(
    p: *mut Vdbe,
    i_cur: i32,
    p_op: *const VdbeOp,
    i_db: i32,
    is_btree_cursor: i32,
) -> *mut VdbeCursor {
    let n_mem = i32::from_le_bytes([(*p)._gap_48[0], (*p)._gap_48[1], (*p)._gap_48[2], (*p)._gap_48[3]]);
    let p_mem = (*p).a_mem.add(n_mem.wrapping_sub(i_cur) as usize);
    let n_field = if (*p_op).opcode == OP_SET_NUM_COLUMNS || (*p_op).opcode == OP_OPEN_EPHEMERAL {
        (*p_op).p2
    } else {
        0
    };
    let n_byte = CURSOR_SIZE
        .wrapping_add((is_btree_cursor != 0) as usize * BTREE_CURSOR_SIZE)
        .wrapping_add((n_field as usize).wrapping_mul(FIELD_BYTES));
    let ap_csr = (*p).ap_csr.cast::<*mut VdbeCursor>();

    if !(*ap_csr.add(i_cur as usize)).is_null() {
        vdbe_free_cursor(p, (*ap_csr.add(i_cur as usize)).cast());
        *ap_csr.add(i_cur as usize) = core::ptr::null_mut();
    }
    if vdbe_mem_grow(p_mem, n_byte as i32, 0) != 0 {
        return core::ptr::null_mut();
    }

    let cursor = (*p_mem).z.cast::<VdbeCursor>();
    *ap_csr.add(i_cur as usize) = cursor;
    iram_memzero_veneer(cursor.cast(), n_byte);
    (*cursor).n_field = n_field;
    (*cursor).i_db = i_db;
    if n_field != 0 {
        (*cursor).a_type = (*p_mem).z.add(CURSOR_SIZE).cast();
    }
    if is_btree_cursor != 0 {
        (*cursor).p_cursor = (*p_mem).z.add(CURSOR_SIZE + (n_field as usize).wrapping_mul(FIELD_BYTES));
    }
    cursor
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn replaces_old_cursor_and_lays_out_ephemeral_btree_cursor() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            let mut words = [0u32; 128];
            let payload = words.as_mut_ptr().cast::<u8>().add(8);
            (payload.sub(8).cast::<i32>()).write(512);
            (payload.sub(4).cast::<u32>()).write(0);
            let mut mems = [
                Mem { u: 0, r: 0.0, db: core::ptr::null_mut(), z: core::ptr::null_mut(), n: 0, flags: 0, value_type: 0, enc: 0, x_del: core::ptr::null_mut(), z_malloc: core::ptr::null_mut() },
                Mem { u: 0, r: 0.0, db: core::ptr::null_mut(), z: payload, n: 0, flags: 0, value_type: 0, enc: 0, x_del: core::ptr::null_mut(), z_malloc: payload },
            ];
            let mut cursors: [*mut VdbeCursor; 2] = [core::ptr::null_mut(); 2];
            let mut p: Vdbe = core::mem::zeroed();
            p.a_mem = mems.as_mut_ptr();
            p._gap_48[..4].copy_from_slice(&1i32.to_le_bytes());
            p.ap_csr = cursors.as_mut_ptr().cast();
            let old = words.as_mut_ptr().cast::<u8>().add(16).cast::<VdbeCursor>();
            old.cast::<u8>().add(0x1f).write(1);
            cursors[0] = old;
            let op = VdbeOp { opcode: OP_OPEN_EPHEMERAL, p4type: 0, p1: 0, p2: 3, p3: 0, p4: core::ptr::null_mut(), p5: 0, opflags: 0 };
            let cursor = allocate_cursor(&mut p, 0, &op, -1, 1);
            assert_eq!(cursors[0], cursor);
            assert_eq!((*cursor).n_field, 3);
            assert_eq!((*cursor).i_db, -1);
            assert_eq!((*cursor).a_type, mems[1].z.add(CURSOR_SIZE).cast());
            assert_eq!((*cursor).p_cursor, mems[1].z.add(CURSOR_SIZE + 3 * FIELD_BYTES));
        }
    }
}
