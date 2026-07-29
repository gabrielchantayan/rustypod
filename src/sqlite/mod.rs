//! The embedded SQLite engine (retailOS' media database).
//!
//! Everything between roughly 0x08366000 and 0x0838ffff in osos is one
//! compilation unit family: an amalgamated SQLite ~3.5.x. The evidence is
//! the string pool in that range — `sqlite_master`, `sqlite_temp_master`,
//! `sqlite_sequence`, `sqlite_stat1`, `sqlite_autoindex_`, the full
//! `sqlite3ErrStr` message table (0x083763c4..0x083766e4: "database disk
//! image is malformed", "library routine called out of sequence", ...),
//! the `PRAGMA` name table (0x0837f5fc..0x083811ac: `default_cache_size`,
//! `journal_mode`, `auto_vacuum`, `incremental_vacuum`, `temp_store`,
//! `freelist_count`, ...), the parser diagnostics ("near \"%T\": syntax
//! error", "DISTINCT in aggregate must be followed by an expression") and
//! the VACUUM script `ATTACH '' AS vacuum_db;`.
//!
//! Two non-SQLite islands sit inside the address span and are *not* part
//! of this subsystem: the ATA/CE-ATA driver block around
//! 0x08369000..0x0836c000 (strings "IAD: failed to write ATA task file",
//! "RMS: data transfer ATA status error", "MMC init failed"), which is
//! where the already-ported `gpio_pin_configure` @ 0x0836b5b0 lives, and
//! the FreeType/UI fragments above 0x0838f000.
//!
//! Struct layouts recovered from the code and cross-checked against the
//! SQLite sources of that era:
//!
//! ```text
//! sqlite3 (db):  +0x1e mallocFailed (u8)
//! Vdbe:          +0x00 db,   +0x0c nOp,     +0x10 nOpAlloc, +0x14 aOp,
//!                +0x18 nLabel, +0x1c nLabelAlloc, +0x20 aLabel,
//!                +0xff expired
//! VdbeOp (20 B): +0 opcode, +1 p4type, +2 opflags, +3 p5,
//!                +4 p1, +8 p2, +12 p3, +16 p4
//! Btree:         +0x00 db, +0x04 pBt, +0x08 inTrans, +0x09 sharable,
//!                +0x0a locked, +0x0c wantToLock
//! Parse:         +0x00 db, +0x04 rc, +0x08 zErrMsg, +0x0c pVdbe,
//!                +0x40 nErr
//! Token:         +0x00 z, +0x04 (dyn:1 | n:31)
//! ```
//!
//! ### The image/runtime address skew (+0xaed8)
//!
//! Three functions here index a 256-byte byte map through the literal
//! pointer 0x088faa8b, and reading the decrypted image at that address
//! yields unrelated data (a 12-byte-record string index). That is *not*
//! runtime initialization: above the read-only image the decrypted body's
//! addresses are skewed, and the datum a firmware pointer `A` names lives
//! at image address `A + 0xaed8`. Two independent confirmations:
//!
//! - 0x088faa8b + 0xaed8 = 0x08905963, which holds the standard
//!   `sqlite3UpperToLower` table byte-for-byte (identity except
//!   `'A'..='Z'` -> `'a'..='z'`) — and that is its *only* occurrence in
//!   the whole image, referenced by no pointer literal.
//! - 0x089cb1bc + 0xaed8 = 0x089d6094, which holds the pool alignment
//!   table `{4,!3} {16,!15} {32,!31} {1024,!1023}` — the exact bytes
//!   `heap/pool.rs` documents as "recovered from a serialized copy @
//!   0x089d6094".
//!
//! So the "0x089cb1xx page is re-initialized at runtime" note in
//! `heap/pool.rs` and the "table is not in the image" warning about
//! 0x088faa8b describe the same skew, not two runtime-init phenomena.
//! Scanning every pointer literal into 0x088e0000..0x08920000 agrees:
//! their targets are readable C strings only at `+0xaed8`.

pub mod btree_lock;
pub mod mem;
pub mod parse;
pub mod stricmp;
pub mod strhash;
pub mod strdup;
pub mod vdbe;
