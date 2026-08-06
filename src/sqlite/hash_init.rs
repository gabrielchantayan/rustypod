//! Initializing SQLite's generic symbol-table hash — `sqlite3HashInit`
//! from hash.c, the constructor half of the `Hash` machinery the
//! dispatcher in [`super::hash_function`] selects key hashes for.
//!
//! - `hash_init` — original: `FUN_0837ade8` @ 0x0837ade8 (32 bytes; 9
//!   `bl` call sites in three functions, binary-scanned). SQLite
//!   3.4.x/3.5.x's `sqlite3HashInit`:
//!
//! ```c
//! void sqlite3HashInit(Hash *pNew, int keyClass, int copyKey){
//!   assert( pNew!=0 );
//!   assert( keyClass>=SQLITE_HASH_INT && keyClass<=SQLITE_HASH_BINARY );
//!   pNew->keyClass = keyClass;
//!   pNew->copyKey = copyKey &&
//!                   (keyClass==SQLITE_HASH_STRING || keyClass==SQLITE_HASH_BINARY);
//!   pNew->first = 0;
//!   pNew->count = 0;
//!   pNew->htsize = 0;
//!   pNew->ht = 0;
//! }
//! ```
//!
//! The body is eight stores and no prologue — the asserts are compiled
//! out (NDEBUG):
//!
//! ```text
//! 0837ade8:  strb r1,[r0,#0x0]    ; keyClass
//! 0837adec:  mov  r1,#0x0
//! 0837adf0:  strb r2,[r0,#0x1]    ; copyKey
//! 0837adf4:  str  r1,[r0,#0xc]    ; first   = 0
//! 0837adf8:  str  r1,[r0,#0x4]    ; count   = 0
//! 0837adfc:  str  r1,[r0,#0x8]    ; htsize  = 0
//! 0837ae00:  str  r1,[r0,#0x10]   ; ht      = 0
//! 0837ae04:  bx   lr
//! ```
//!
//! It pins this build's `Hash` layout (20 bytes, so a `Schema` packs
//! four of them at +0x04/+0x18/+0x2c/+0x40):
//!
//! ```text
//! +0x00 key_class (u8)   SQLITE_HASH_STRING (3) at every call site
//! +0x01 copy_key  (u8)   keys are strdup'd on insert / freed on delete
//! +0x04 count     (u32)  entries in the table
//! +0x08 htsize    (u32)  bucket count (sqlite3HashInsert @ 0x0837ae08
//! +0x0c first     (ptr)  insertion-order list head   doubles +0x08 and
//! +0x10 ht        (ptr)  bucket array of {count, chain} pairs)
//! ```
//!
//! The field order differs from upstream's `keyClass, copyKey, count,
//! first, htsize, ht`: here `htsize` sits at +0x08 and `first` at
//! +0x0c, proven by `sqlite3HashInsert` doubling the +0x08 word
//! (`*(int*)(param_1 + 8) << 1`) and walking the +0x0c list in
//! `sqlite3HashClear` @ 0x0837ad2c.
//!
//! Callers:
//!
//! - `openDatabase` @ 0x082dbda8 (3 sites): the fresh 0x180-byte
//!   `sqlite3` handle's three hashes at +0xf4 / +0x114 / +0x128
//!   (aModule / aFunc / aCollSeq family), all
//!   `(SQLITE_HASH_STRING, 0)`.
//! - `sqlite3SchemaClear` @ 0x08382c58 (2 sites): re-inits the
//!   schema's `trigHash` @ +0x2c and `tblHash` @ +0x04 after the
//!   delete loops, so the emptied `Schema` is back to pristine.
//! - `sqlite3SchemaGet` @ 0x08382d18 (4 sites): a new 100-byte
//!   `Schema` with `file_format == 0` gets all four hashes —
//!   tblHash @ +0x04, idxHash @ +0x18, trigHash @ +0x2c, fkeyHash
//!   @ +0x40 — the fkey hash alone with `copy_key = 1`.
//!
//! Deviation from upstream: `copy_key` is stored verbatim (`strb r2`)
//! where upstream ANDs it with `keyClass >= SQLITE_HASH_STRING`. Every
//! observed call site passes the final value already (0, or 1 with
//! `SQLITE_HASH_STRING` for fkeyHash), so the behaviors coincide.

/// Byte offset of `Hash.keyClass` (original: `strb r1, [r0, #0]`).
const KEY_CLASS_OFFSET: usize = 0x00;
/// Byte offset of `Hash.copyKey` (original: `strb r2, [r0, #1]`).
const COPY_KEY_OFFSET: usize = 0x01;
/// Word offset of `Hash.count` (entries; original: `str r1, [r0, #4]`).
const COUNT_OFFSET: usize = 0x04;
/// Word offset of `Hash.htsize` (buckets; original: `str r1, [r0, #8]`).
const HTSIZE_OFFSET: usize = 0x08;
/// Word offset of `Hash.first` (list head; original: `str r1, [r0, #0xc]`).
const FIRST_OFFSET: usize = 0x0c;
/// Word offset of `Hash.ht` (bucket array; original: `str r1, [r0, #0x10]`).
const HT_OFFSET: usize = 0x10;

/// hash_init — original: `FUN_0837ade8` @ 0x0837ade8 (32 bytes; 9 `bl`
/// call sites).
///
/// `sqlite3HashInit`: stamp `key_class` and `copy_key` into the two
/// flag bytes and clear the table proper — entry count, bucket count,
/// insertion-order list head and bucket array all become zero. The
/// hash must point at 20 bytes of word-aligned writable memory, as
/// every firmware caller's `Hash` is.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn hash_init(hash: *mut u8, key_class: u8, copy_key: u8) {
    hash.add(KEY_CLASS_OFFSET).write(key_class);
    hash.add(COPY_KEY_OFFSET).write(copy_key);
    (hash.add(COUNT_OFFSET) as *mut u32).write(0);
    (hash.add(HTSIZE_OFFSET) as *mut u32).write(0);
    (hash.add(FIRST_OFFSET) as *mut u32).write(0);
    (hash.add(HT_OFFSET) as *mut u32).write(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 20-byte `Hash` plus guard bytes on each side; word-aligned as
    /// every firmware `Hash` is (embedded at +0x04-aligned offsets of
    /// word-aligned structs).
    #[repr(align(4))]
    struct HashBytes([u8; 0x14 + 8]);

    impl HashBytes {
        fn dirty() -> Self {
            HashBytes([0xa5; 0x14 + 8])
        }
        fn ptr(&mut self) -> *mut u8 {
            self.0[4..].as_mut_ptr()
        }
        fn word(&self, offset: usize) -> u32 {
            u32::from_le_bytes(self.0[4 + offset..4 + offset + 4].try_into().unwrap())
        }
    }

    #[test]
    fn stamps_the_two_flag_bytes_and_clears_the_table() {
        let mut hash = HashBytes::dirty();
        unsafe { hash_init(hash.ptr(), 3, 1) };
        assert_eq!(hash.0[4 + KEY_CLASS_OFFSET], 3, "keyClass");
        assert_eq!(hash.0[4 + COPY_KEY_OFFSET], 1, "copyKey");
        assert_eq!(hash.word(COUNT_OFFSET), 0, "count");
        assert_eq!(hash.word(HTSIZE_OFFSET), 0, "htsize");
        assert_eq!(hash.word(FIRST_OFFSET), 0, "first");
        assert_eq!(hash.word(HT_OFFSET), 0, "ht");
    }

    #[test]
    fn copy_key_is_stored_verbatim() {
        // Deviation from upstream's `copyKey && keyClass >= STRING`:
        // the firmware stores r2 unchanged, whatever it is.
        let mut hash = HashBytes::dirty();
        unsafe { hash_init(hash.ptr(), 3, 0) };
        assert_eq!(hash.0[4 + COPY_KEY_OFFSET], 0);

        let mut hash = HashBytes::dirty();
        unsafe { hash_init(hash.ptr(), 1, 1) };
        assert_eq!(hash.0[4 + KEY_CLASS_OFFSET], 1);
        assert_eq!(
            hash.0[4 + COPY_KEY_OFFSET],
            1,
            "no keyClass>=STRING gate on copyKey"
        );
    }

    #[test]
    fn the_padding_and_everything_outside_the_struct_is_untouched() {
        let mut hash = HashBytes::dirty();
        unsafe { hash_init(hash.ptr(), 3, 0) };
        for (i, byte) in hash.0.iter().enumerate() {
            let in_struct = (4..4 + 0x14).contains(&i);
            let is_flag = i == 4 + KEY_CLASS_OFFSET || i == 4 + COPY_KEY_OFFSET;
            let is_word = (4 + COUNT_OFFSET..4 + COUNT_OFFSET + 4).contains(&i)
                || (4 + HTSIZE_OFFSET..4 + HTSIZE_OFFSET + 4).contains(&i)
                || (4 + FIRST_OFFSET..4 + FIRST_OFFSET + 4).contains(&i)
                || (4 + HT_OFFSET..4 + HT_OFFSET + 4).contains(&i);
            if !in_struct || (!is_flag && !is_word) {
                assert_eq!(
                    *byte, 0xa5,
                    "byte {i:#x} clobbered (padding +0x02/+0x03 included)"
                );
            }
        }
    }
}
