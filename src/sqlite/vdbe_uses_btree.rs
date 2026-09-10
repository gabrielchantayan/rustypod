//! Track a database b-tree used by a prepared statement.
//!
//! `vdbe_uses_btree` — original: `FUN_0838d100` @ `0x0838d100` (192 bytes;
//! **10 `bl` call sites, all unconditional**, verified by decoding every ARM
//! branch-with-link word in `osos.dec`: 0x0836fd24, 0x08378d6c, 0x08378ebc,
//! 0x0837913c, 0x0837d72c, 0x0837f374, 0x0837f938, 0x08381058, 0x083848bc,
//! and 0x0838f378). This is SQLite's `sqlite3VdbeUsesBtree`.
//!
//! The routine marks `database_index` in the statement's b-tree mask. It then
//! finds `db->aDb[database_index].pBt`; for a present, sharable b-tree it
//! inserts that b-tree into the statement's inline list ordered by its shared
//! b-tree pointer. Equal keys are inserted after existing equal keys. There is
//! no bounds or NULL check for the VDBE or connection, matching the firmware.
//!
//! Deliberate deviations: the unmodeled tail of [`VdbeBtreeUse`] is a typed
//! target-layout facade rather than extending the shared [`super::vdbe::Vdbe`]
//! with guessed intermediate fields. On 32-bit ARM its named fields have the
//! firmware offsets; on a 64-bit host they retain distinct pointer fields for
//! sound fixtures.

/// One database slot (`Db`) in the connection's `aDb` array (24 bytes on ARM).
#[repr(C)]
pub struct DbSlot {
    /// +0x00: unmodeled database name and safety flags.
    _gap_00: [u8; 4],
    /// +0x04: the associated b-tree.
    pub btree: *mut Btree,
    /// +0x08..+0x17: unmodeled schema and flags.
    _gap_08: [u8; 0x18 - 8],
}

/// The subset of a SQLite connection that this routine reads.
#[repr(C)]
pub struct ConnectionBtrees {
    /// +0x00..+0x07: unmodeled connection fields.
    _gap_00: [u8; 8],
    /// +0x08: array of per-database slots.
    pub databases: *mut DbSlot,
}

/// A b-tree handle. `shared` and `sharable` are the only fields used here.
#[repr(C)]
pub struct Btree {
    /// +0x00: owning connection.
    _db: *mut u8,
    /// +0x04: the shared b-tree object, used as the ordering key.
    pub shared: *mut u8,
    /// +0x08: transaction state.
    _in_transaction: u8,
    /// +0x09: nonzero when this handle participates in shared-cache locking.
    pub sharable: u8,
}

/// The VDBE fields reached by `sqlite3VdbeUsesBtree`.
///
/// The original's fixed b-tree list has room for `SQLITE_MAX_ATTACHED + 2`
/// handles; this build's attached-database bound is ten, so twelve entries
/// cover every valid firmware index plus the main and temporary databases.
#[repr(C)]
pub struct VdbeBtreeUse {
    /// +0x00: the owning connection.
    pub db: *mut ConnectionBtrees,
    /// +0x04..+0x10f: fields modeled by `sqlite::vdbe::Vdbe` or not needed.
    _gap_04: [u8; 0x110 - 4],
    /// +0x110: one bit for each database used by this statement.
    pub btree_mask: u32,
    /// +0x114: number of live entries in `btrees`.
    pub btree_count: u32,
    /// +0x118: b-tree handles sorted by their `shared` pointer.
    pub btrees: [*mut Btree; 12],
}

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::size_of::<DbSlot>() == 0x18);
    assert!(core::mem::offset_of!(ConnectionBtrees, databases) == 0x08);
    assert!(core::mem::offset_of!(Btree, shared) == 0x04);
    assert!(core::mem::offset_of!(Btree, sharable) == 0x09);
    assert!(core::mem::offset_of!(VdbeBtreeUse, btree_mask) == 0x110);
    assert!(core::mem::offset_of!(VdbeBtreeUse, btree_count) == 0x114);
    assert!(core::mem::offset_of!(VdbeBtreeUse, btrees) == 0x118);
};

/// sqlite3VdbeUsesBtree — original: `FUN_0838d100` @ `0x0838d100` (192 bytes;
/// 10 unconditional `bl` call sites).
///
/// Mark a database as used, then place its sharable b-tree in ascending shared
/// pointer order. ARM's register shift uses the argument's low byte and
/// produces zero for shift counts at least 32; preserve that behavior instead
/// of Rust's modulo-32 wrapping shift.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_uses_btree(vdbe: *mut VdbeBtreeUse, database_index: i32) {
    let shift = (database_index as u32) & 0xff;
    let bit = if shift < 32 { 1u32 << shift } else { 0 };
    if (*vdbe).btree_mask & bit != 0 {
        return;
    }
    (*vdbe).btree_mask |= bit;

    let btree = (*(*vdbe).db).databases.add(database_index as usize).read().btree;
    if btree.is_null() || (*btree).sharable == 0 {
        return;
    }

    let shared = (*btree).shared;
    let btrees = core::ptr::addr_of_mut!((*vdbe).btrees).cast::<*mut Btree>();
    let mut index = 0usize;
    let count = (*vdbe).btree_count as usize;
    while index < count {
        if ((*btrees.add(index).read()).shared as usize) > shared as usize {
            break;
        }
        index += 1;
    }

    let mut tail = count;
    while tail > index {
        btrees.add(tail).write(btrees.add(tail - 1).read());
        tail -= 1;
    }
    btrees.add(index).write(btree);
    (*vdbe).btree_count += 1;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blank_vdbe() -> VdbeBtreeUse {
        unsafe { core::mem::MaybeUninit::<VdbeBtreeUse>::zeroed().assume_init() }
    }

    fn blank_db_slot() -> DbSlot {
        unsafe { core::mem::MaybeUninit::<DbSlot>::zeroed().assume_init() }
    }

    #[test]
    fn already_marked_database_does_not_dereference_connection_or_mutate_list() {
        let mut vdbe = blank_vdbe();
        vdbe.btree_mask = 1 << 3;
        vdbe.btree_count = 1;
        let sentinel = 0x1000usize as *mut Btree;
        vdbe.btrees[0] = sentinel;

        unsafe { vdbe_uses_btree(&mut vdbe, 3) };

        assert_eq!(vdbe.btree_mask, 1 << 3);
        assert_eq!(vdbe.btree_count, 1);
        assert_eq!(vdbe.btrees[0], sentinel);
    }

    #[test]
    fn marks_null_and_unsharable_database_without_list_entry() {
        let mut slots = [blank_db_slot(), blank_db_slot()];
        let mut connection = ConnectionBtrees { _gap_00: [0; 8], databases: slots.as_mut_ptr() };
        let mut vdbe = blank_vdbe();
        vdbe.db = &mut connection;

        unsafe { vdbe_uses_btree(&mut vdbe, 0) };
        assert_eq!(vdbe.btree_mask, 1);
        assert_eq!(vdbe.btree_count, 0);

        let mut unsharable = Btree {
            _db: core::ptr::null_mut(), shared: 0x4000usize as *mut u8,
            _in_transaction: 0, sharable: 0,
        };
        slots[1].btree = &mut unsharable;
        unsafe { vdbe_uses_btree(&mut vdbe, 1) };
        assert_eq!(vdbe.btree_mask, 3);
        assert_eq!(vdbe.btree_count, 0);
    }

    #[test]
    fn inserts_by_shared_pointer_and_keeps_equal_keys_stable() {
        let mut btrees = [
            Btree { _db: core::ptr::null_mut(), shared: 0x3000usize as *mut u8, _in_transaction: 0, sharable: 1 },
            Btree { _db: core::ptr::null_mut(), shared: 0x1000usize as *mut u8, _in_transaction: 0, sharable: 1 },
            Btree { _db: core::ptr::null_mut(), shared: 0x2000usize as *mut u8, _in_transaction: 0, sharable: 1 },
            Btree { _db: core::ptr::null_mut(), shared: 0x2000usize as *mut u8, _in_transaction: 0, sharable: 1 },
        ];
        let mut slots = [blank_db_slot(), blank_db_slot(), blank_db_slot(), blank_db_slot()];
        for (slot, btree) in slots.iter_mut().zip(btrees.iter_mut()) {
            slot.btree = btree;
        }
        let mut connection = ConnectionBtrees { _gap_00: [0; 8], databases: slots.as_mut_ptr() };
        let mut vdbe = blank_vdbe();
        vdbe.db = &mut connection;

        for index in [0, 1, 2, 3] {
            unsafe { vdbe_uses_btree(&mut vdbe, index) };
        }

        assert_eq!(vdbe.btree_mask, 0b1111);
        assert_eq!(vdbe.btree_count, 4);
        let expected = unsafe {
            [
                btrees.as_mut_ptr().add(1),
                btrees.as_mut_ptr().add(2),
                btrees.as_mut_ptr().add(3),
                btrees.as_mut_ptr(),
            ]
        };
        assert_eq!(vdbe.btrees[..4], expected);
    }

    #[test]
    fn high_register_shift_sets_no_bit_but_still_performs_null_btree_path() {
        let mut slots: [DbSlot; 33] = core::array::from_fn(|_| blank_db_slot());
        let mut connection = ConnectionBtrees { _gap_00: [0; 8], databases: slots.as_mut_ptr() };
        let mut vdbe = blank_vdbe();
        vdbe.db = &mut connection;

        unsafe { vdbe_uses_btree(&mut vdbe, 32) };

        assert_eq!(vdbe.btree_mask, 0);
        assert_eq!(vdbe.btree_count, 0);
    }
}
