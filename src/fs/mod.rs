//! Filesystem-layer helpers (path handling, FAT-facing utilities,
//! HFS B-tree node access).
/// FAT directory-entry start-cluster extraction @ 0x082e1378.
pub mod fat_dirent;
pub mod path_limits;
/// Path-resolution node release @ 0x082e19cc.
pub mod path_node;
/// Cache-entry reference release @ 0x082e18bc.
pub mod cache_entry;
/// Cache lock semaphore release @ 0x082d7944.
pub mod cache_lock;
/// Platform C++ file-object read wrapper @ 0x082784b8.
pub mod file_read;
/// Exact-length resource-reader transfer @ 0x082a6aa4.
pub mod resource_reader_read_exact;
/// HFS B-tree node fetch and validation @ 0x08053d6c.
pub mod hfs_btree_get_node;
/// File-path layer failure-status accessor @ 0x0829dcf8.
pub mod error_status;
