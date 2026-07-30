//! Find-or-insert on a red-black-tree map keyed by a single byte — the
//! `map<u8, V>::operator[]` shape the application layer uses to fetch the
//! mapped value for a one-byte key (26 `bl` call sites).
//!
//! - [`byte_key_map_find`] — original: `FUN_083db038` @ 0x083db038
//!   (88 bytes; 26 `bl` call sites, the only copy).
//!
//! Algorithm (from the disassembly): build a 16-byte key/value pair on
//! the stack — the key byte read from `*key` at +0, a zeroed 12-byte
//! mapped value at +4 (the original zeroes a separate 12-byte temporary
//! with `stmia` and block-copies it into the pair, the copy-construction
//! of a default-constructed value) — then run the tree insert-unique
//! operation @ 0x083b867c(&result, map, &pair) and return the resulting
//! node pointer plus 0x14, i.e. `&node->value`: the node header is
//! 0x10 bytes (color/flag at +0, parent +4, left +8, right +0xc) with
//! the key pair at +0x10, so +0x14 is the mapped value inside the pair.
//!
//! Scouted contract of the dependency @ 0x083b867c (NOT ported; the
//! [`BYTE_KEY_MAP_OPS`] dispatch boundary, house pattern — see
//! `cxx/pair_header.rs`):
//!
//! ```text
//! void insert_unique(result *r0, map *r1, const pair *r2)
//!   r0 +0  <- node pointer (existing or newly inserted)
//!   r0 +4  <- inserted flag byte (1 = newly linked, 0 = key present)
//!   r1     container: +0x10 header node (header+4 = root, header+8 =
//!          leftmost), +0x18 multi-insert flag byte (nonzero skips the
//!          uniqueness test — multimap semantics), +0x19 comparator
//!   r2     the 16-byte key pair above; node keys sit at node+0x10
//! ```
//!
//! The body is libstdc++'s `_Rb_tree::_M_insert_unique`: descend from
//! the root comparing keys through the comparator @ 0x083d73bc (nonzero
//! -> descend left at +8, else right at +0xc), remember the last node,
//! then — via the iterator-equality helper @ 0x083cf740 against the
//! leftmost header child and an inline predecessor/successor walk —
//! either return the existing node with the flag clear or link a fresh
//! node through 0x083b8844 (`_M_insert`, which allocates, copies the
//! pair and rebalances) and return it flagged. Every path stores the
//! node word at result+0 and the flag byte at result+4, which is the
//! whole contract this port relies on.
//!
//! Deviations:
//! - The pair's three padding bytes at +1..+4 are zeroed; the original
//!   leaves them as uninitialised stack. Nothing observes them (the
//!   comparator reads only the key byte; the node copy's pad word is
//!   never read back).
//! - 0x083b867c is dispatched through [`BYTE_KEY_MAP_OPS`], which
//!   defaults to a stub reporting a null node (see its doc); on real
//!   hardware the slot must be installed before this port runs.
//! - The final `node + 0x14` is a wrapping add (the original's plain
//!   `add r0, r0, #0x14`); with a real node installed the value is
//!   identical.

/// The 16-byte key/value pair the find builds on its stack frame and
/// hands to the tree operation: key byte at +0, padding at +1..+4,
/// default-constructed (zeroed) 12-byte mapped value at +4. Matches the
/// original's stack layout at sp+0x14..sp+0x24 exactly.
#[repr(C)]
pub struct ByteKeyPair {
    /// +0: the key byte, read from `*key`.
    pub key: u8,
    /// +1..+4: padding (zeroed here; stack garbage in the original).
    pub pad: [u8; 3],
    /// +4: the zeroed 12-byte mapped value.
    pub value: [u32; 3],
}

// The pair is all 4-byte-aligned members, so the original's offsets
// hold on every host — asserted unconditionally.
const _VALUE_OFFSET: [u8; 4] = [0; core::mem::offset_of!(ByteKeyPair, value)];
const _PAIR_SIZE: [u8; 16] = [0; core::mem::size_of::<ByteKeyPair>()];

/// The result the tree operation @ 0x083b867c writes through its first
/// argument: node pointer at +0, inserted-flag byte at +4. The find
/// consumes only the node word.
#[repr(C)]
pub struct ByteKeyInsertResult {
    /// +0: node pointer — the existing node for `key`, or the freshly
    /// linked one.
    pub node: *mut u8,
    /// +4: inserted flag byte (1 = newly linked, 0 = key was present).
    pub inserted: u8,
}

/// The byte-keyed map container. Opaque to this port — only its address
/// is forwarded to the insert hook. Scouted layout, from 0x083b867c's
/// reads: +0x10 header node (header+4 = root, header+8 = leftmost),
/// +0x18 multi-insert flag byte, +0x19 key-comparator object.
#[repr(C)]
pub struct ByteKeyMap {
    _opaque: [u8; 0],
}

/// Indirect dispatch for the not-yet-ported tree insert-unique
/// operation @ 0x083b867c (the `PairHeaderOps` precedent in
/// `cxx/pair_header.rs`).
#[derive(Clone, Copy)]
pub struct ByteKeyMapOps {
    /// The container operation @ 0x083b867c: writes the node pointer at
    /// `result + 0` and the inserted-flag byte at `result + 4`. See the
    /// module header for the full scouted contract.
    pub insert_unique: unsafe extern "C" fn(
        result: *mut ByteKeyInsertResult,
        map: *mut ByteKeyMap,
        key: *const ByteKeyPair,
    ),
}

/// Default stub: no tree wired, so report "not found, not inserted"
/// with a null node — the find then returns 0x14 (null + 0x14), an
/// obviously invalid value pointer. On real hardware BYTE_KEY_MAP_OPS
/// must be installed before this port runs; a null node can never come
/// out of the real operation (the header node always exists).
unsafe extern "C" fn missing_insert_unique(
    result: *mut ByteKeyInsertResult,
    _map: *mut ByteKeyMap,
    _key: *const ByteKeyPair,
) {
    (*result).node = core::ptr::null_mut();
    (*result).inserted = 0;
}

/// The active tree-operation slot. Defaults to the documented stub
/// above; replaced by host tests (mocks) and eventually by the ported
/// 0x083b867c. Written once at init on target; tests serialize access.
pub static mut BYTE_KEY_MAP_OPS: ByteKeyMapOps = ByteKeyMapOps {
    insert_unique: missing_insert_unique,
};

/// byte_key_map_find — original: `FUN_083db038` @ 0x083db038
/// (88 bytes; 26 `bl` call sites, the only copy).
///
/// Finds (or inserts) the node for the single byte at `*key` in `map`
/// and returns a pointer to its mapped value, `node + 0x14`. Builds the
/// 16-byte key pair (key byte + zeroed 12-byte value) on the stack and
/// runs the tree insert-unique operation @ 0x083b867c through
/// [`BYTE_KEY_MAP_OPS`]; only the result's node word is consumed, the
/// inserted-flag byte is dropped.
///
/// # Safety
/// `key` must point at a readable byte and `map` at a live container
/// whose layout matches the scouted one in the module header. The
/// installed `insert_unique` must honour the 0x083b867c contract (node
/// word at result+0, flag byte at result+4); with the default stub the
/// returned pointer is 0x14 and must not be dereferenced.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn byte_key_map_find(map: *mut ByteKeyMap, key: *const u8) -> *mut u8 {
    let pair = ByteKeyPair {
        key: key.read(),
        pad: [0; 3],
        value: [0; 3],
    };
    let mut result = ByteKeyInsertResult {
        node: core::ptr::null_mut(),
        inserted: 0,
    };
    // Reads the fn-pointer field directly rather than through a
    // whole-table read (the timer_schedule_shim gotcha).
    let insert_unique =
        core::ptr::addr_of!(BYTE_KEY_MAP_OPS.insert_unique).read_volatile();
    insert_unique(&mut result, map, &pair);
    result.node.wrapping_add(0x14)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex as StdMutex;
    use std::vec::Vec;

    /// Ops-table swaps are global; serialize the tests.
    static OPS_LOCK: StdMutex<()> = StdMutex::new(());

    struct OpsGuard;

    impl OpsGuard {
        fn install(ops: ByteKeyMapOps) -> Self {
            unsafe {
                core::ptr::addr_of_mut!(BYTE_KEY_MAP_OPS).write_volatile(ops);
            }
            OpsGuard
        }
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(BYTE_KEY_MAP_OPS).write_volatile(
                    ByteKeyMapOps {
                        insert_unique: missing_insert_unique,
                    },
                );
            }
        }
    }

    /// With the default stub the hook reports a null node and the find
    /// returns null + 0x14 — and the map/key pointers are never
    /// dereferenced beyond the key byte itself.
    #[test]
    fn default_stub_returns_null_plus_header() {
        let _lock = OPS_LOCK.lock().unwrap();
        let _guard = OpsGuard::install(ByteKeyMapOps {
            insert_unique: missing_insert_unique,
        });
        unsafe {
            let key: u8 = 0x42;
            let value = byte_key_map_find(core::ptr::null_mut(), &key);
            assert_eq!(value as usize, 0x14);
        }
    }

    /// The hook receives the map pointer unchanged and a pair carrying
    /// the key byte at +0 with a fully zeroed 12-byte value; the find
    /// returns the hook's node plus 0x14.
    #[test]
    fn pair_shape_and_return_offset() {
        let _lock = OPS_LOCK.lock().unwrap();

        static mut SEEN_MAP: usize = 0;
        static mut SEEN_KEY: u8 = 0;
        static mut SEEN_VALUE: [u32; 3] = [1; 3];
        /// Fake node storage; the hook hands out its base.
        static mut NODE: [u8; 0x20] = [0; 0x20];

        unsafe extern "C" fn recording_insert_unique(
            result: *mut ByteKeyInsertResult,
            map: *mut ByteKeyMap,
            key: *const ByteKeyPair,
        ) {
            core::ptr::addr_of_mut!(SEEN_MAP).write_volatile(map as usize);
            core::ptr::addr_of_mut!(SEEN_KEY).write_volatile((*key).key);
            core::ptr::addr_of_mut!(SEEN_VALUE).write_volatile((*key).value);
            (*result).node = core::ptr::addr_of_mut!(NODE).cast::<u8>();
            (*result).inserted = 1;
        }

        let _guard = OpsGuard::install(ByteKeyMapOps {
            insert_unique: recording_insert_unique,
        });
        unsafe {
            let mut map_storage = Vec::from([0u8; 0x20]);
            let map = map_storage.as_mut_ptr().cast::<ByteKeyMap>();
            let key: u8 = 0xa5;
            let value = byte_key_map_find(map, &key);

            assert_eq!(
                core::ptr::addr_of!(SEEN_MAP).read_volatile(),
                map as usize
            );
            assert_eq!(core::ptr::addr_of!(SEEN_KEY).read_volatile(), 0xa5);
            assert_eq!(core::ptr::addr_of!(SEEN_VALUE).read_volatile(), [0; 3]);
            let node = core::ptr::addr_of_mut!(NODE).cast::<u8>();
            assert_eq!(value, node.add(0x14));
        }
    }

    /// A found-not-inserted result (flag byte 0) still yields node +
    /// 0x14; the find never reads the flag.
    #[test]
    fn existing_node_ignores_inserted_flag() {
        let _lock = OPS_LOCK.lock().unwrap();

        static mut NODE: [u8; 0x20] = [0; 0x20];

        unsafe extern "C" fn found_insert_unique(
            result: *mut ByteKeyInsertResult,
            _map: *mut ByteKeyMap,
            _key: *const ByteKeyPair,
        ) {
            (*result).node = core::ptr::addr_of_mut!(NODE).cast::<u8>();
            (*result).inserted = 0;
        }

        let _guard = OpsGuard::install(ByteKeyMapOps {
            insert_unique: found_insert_unique,
        });
        unsafe {
            let key: u8 = 0x00;
            let value = byte_key_map_find(core::ptr::null_mut(), &key);
            let node = core::ptr::addr_of_mut!(NODE).cast::<u8>();
            assert_eq!(value, node.add(0x14));
        }
    }
}
