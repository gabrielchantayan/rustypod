//! SQLite database-fixer context initialization.
//!
//! - `sqlite_fix_init` — original: `FUN_08379654` @ `0x08379654` (64
//!   bytes, `0x08379654..0x08379694`; the independently linked
//!   `sqlite3FixSelect` prologue begins at `0x08379694`). Decoding every
//!   aligned ARM `B`/`BL` immediate in `osos.dec` finds four direct inbound
//!   `bl` calls, all unconditional: `0x0836fe2c` (inside `FUN_0836fd5c`),
//!   `0x08373de0` (inside `FUN_08373cfc`), `0x08374828`
//!   (`sqlite3FixTriggerStep`), and `0x08379368` (inside `FUN_083792f4`).
//!   There are no predicated call forms or tail `b` transfers. Ghidra's
//!   64-byte size and 4-`bl` report match the raw words exactly. This is
//!   SQLite 3.5.x's `sqlite3FixInit`.
//!
//! Algorithm: reject a negative database index or index 1 (the `temp`
//!   database never needs schema fixups) by returning zero. Otherwise fill
//!   the caller's 4-word `DbFixer`: word 0 is the `Parse*` itself, word 1
//!   is `db->aDb[iDb].pSchema` where `db` is `Parse.db` (+0x00), `aDb` is
//!   `sqlite3.aDb` (+0x08), and `sizeof(Db)` is `0x18` with `pSchema` at
//!   offset zero; words 2 and 3 store the `zType` and `pName` arguments
//!   verbatim. Returns one.
//!
//! The fifth argument arrives on the stack: the entry sequence is
//! `str lr,[sp,#-4]!` / `ldr lr,[sp,#4]`, so the pushed link register
//! slot doubles as the frame slot from which `pName` is reloaded before
//! the `stmib r0!,{r1,r3,lr}` store.
//!
//! The raw guard is `cmp r2,#0; blt fail` then `cmp r2,#1; bne body`,
//! i.e. exactly the upstream `iDb<0 || iDb==1` check: index 0 (`main`)
//! enters the body and records `aDb[0].pSchema`.

/// `sqlite3FixInit` — original: `FUN_08379654` @ `0x08379654` (64 bytes;
/// 4 unconditional direct `bl` call sites).
///
/// Initializes the `DbFixer` at `fixer` for database index `i_db` of the
/// connection referenced by `parse`, recording the object type string
/// `z_type` and the object's name token `name`. Returns zero for a
/// negative index or the `temp` index 1, and one otherwise.
///
/// All structure accesses are target-width: `Parse`, `sqlite3`, `Db` and
/// `DbFixer` fields are 4-byte words, so `parse` and the loaded `db`/
/// `aDb` pointers are handled as `u32` target-space addresses.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.sqlite_fix_init")]
#[inline(never)]
pub unsafe extern "C" fn sqlite_fix_init(
    fixer: *mut u32,
    parse: *const u32,
    i_db: i32,
    z_type: *const u8,
    name: *const u8,
) -> u32 {
    if i_db < 0 || i_db == 1 {
        return 0;
    }
    let db = core::ptr::read(parse);
    core::ptr::write(fixer, parse as u32);
    let a_db = core::ptr::read((db as *const u32).add(2));
    // sizeof(Db) = 0x18 = 6 words; Db.pSchema is at offset 0.
    let schema = core::ptr::read(
        (a_db as *const u32).add((i_db as u32).wrapping_mul(6) as usize),
    );
    core::ptr::write(fixer.add(1), schema);
    core::ptr::write(fixer.add(2), z_type as u32);
    core::ptr::write(fixer.add(3), name as u32);
    1
}

#[cfg(test)]
mod tests {
    use super::sqlite_fix_init;

    /// One page holds every fixture. Target-space u32 pointers index into
    /// the slab, so the fixtures keep the firmware's 4-byte field spacing
    /// on a 64-bit host.
    struct Slab(*mut u8);

    impl Slab {
        const PARSE: usize = 0x000;
        const DB: usize = 0x040;
        const A_DB: usize = 0x100;

        fn map() -> Option<Slab> {
            let p = crate::testing::try_map_u32_slab(crate::testing::hints::SQLITE_FIX_INIT, 0x1000)?;
            unsafe { core::ptr::write_bytes(p, 0, 0x1000) };
            Some(Slab(p))
        }

        fn w32(&self, off: usize, v: u32) {
            unsafe { core::ptr::write_unaligned(self.0.add(off) as *mut u32, v) };
        }

        fn r32(&self, off: usize) -> u32 {
            unsafe { core::ptr::read_unaligned(self.0.add(off) as *const u32) }
        }

        fn parse(&self) -> *const u32 {
            self.0 as *const u32
        }

        /// Distinct per-test fixer regions (tests run in parallel on the
        /// shared slab): pass 0x400, 0x410, 0x420, 0x430.
        fn fixer(&self, off: usize) -> *mut u32 {
            unsafe { self.0.add(off) as *mut u32 }
        }

        /// Wire `Parse.db -> DB`, `sqlite3.aDb -> A_DB`, and plant a
        /// distinct schema marker `0x5c0e_0000 | i` in `aDb[i].pSchema`
        /// for i in -2..8.
        fn wire(&self) {
            self.w32(Self::PARSE, (self.0 as usize + Self::DB) as u32);
            self.w32(Self::DB + 8, (self.0 as usize + Self::A_DB) as u32);
            for i in -2i32..8 {
                self.w32(
                    (Self::A_DB as i32 + i * 0x18) as usize,
                    0x5c0e_0000u32 | (i as u32 & 0xffff),
                );
            }
        }
    }

    #[test]
    fn rejects_negative_index_and_temp() {
        let Some(s) = Slab::map() else { return };
        s.wire();
        for i_db in [-2i32, -1, 1] {
            assert_eq!(
                unsafe { sqlite_fix_init(s.fixer(0x400), s.parse(), i_db, 0xaaaa as *const u8, 0xbbbb as *const u8) },
                0
            );
        }
        // The fixer must be untouched on the rejection path.
        for w in 0..4 {
            assert_eq!(s.r32(0x400 + w * 4), 0);
        }
    }

    #[test]
    fn fills_fixer_for_main_and_real_database() {
        let Some(s) = Slab::map() else { return };
        s.wire();
        // i_db = 0 (`main`) is NOT rejected: the raw guard is iDb<0 ||
        // iDb==1, so it records aDb[0].pSchema.
        for i_db in [0i32, 2] {
            let rc = unsafe {
                sqlite_fix_init(s.fixer(0x410), s.parse(), i_db, 0x1111_2222 as *const u8, 0x3333_4444 as *const u8)
            };
            assert_eq!(rc, 1);
            assert_eq!(s.r32(0x410 + 0), s.parse() as u32);
            assert_eq!(s.r32(0x410 + 4), 0x5c0e_0000 | (i_db as u32));
            assert_eq!(s.r32(0x410 + 8), 0x1111_2222);
            assert_eq!(s.r32(0x410 + 12), 0x3333_4444);
        }
    }

    #[test]
    fn schema_index_scales_by_db_stride() {
        let Some(s) = Slab::map() else { return };
        s.wire();
        for i_db in [3i32, 7] {
            let rc = unsafe {
                sqlite_fix_init(s.fixer(0x420), s.parse(), i_db, core::ptr::null(), core::ptr::null())
            };
            assert_eq!(rc, 1);
            assert_eq!(s.r32(0x420 + 4), 0x5c0e_0000 | (i_db as u32));
        }
    }

}
