//! Filesystem-layer helpers (path handling, FAT-facing utilities,
//! HFS B-tree node access).
/// FAT directory-entry start-cluster extraction @ 0x082e1378.
pub mod fat_dirent;
/// FAT data-cluster to cache-block-index conversion @ 0x082e01cc.
pub mod fat_cluster_to_block;
pub mod path_limits;
/// Path-resolution node release @ 0x082e19cc.
pub mod path_node;
/// Shared path-data reference release @ 0x082e1960.
pub mod shared_data;
/// Path-resolution child lookup with default continuation state @ 0x082e2004.
pub mod path_node_lookup;
/// Cache-entry reference release @ 0x082e18bc.
pub mod cache_entry;
/// Cache-backed disk-block acquisition @ 0x082e3f98.
pub mod cache_block;
/// Four-slot disk block-read gate and dispatch @ 0x082c6244.
pub mod disk_block;
/// Cache-entry slot preparation and writeback @ 0x082e48bc.
pub mod cache_block_prepare;
/// Cache-entry writeback through the storage-block writer @ 0x082e4b4c.
pub mod cache_entry_flush;
/// Cache-page halfword transfer through the page resolver @ 0x082e1a34.
pub mod cache_page;
/// Shared resident FAT-position value reader boundary at 0x082e0cac.
pub(crate) mod cache_position_value;
/// FAT next-cluster reader and reserved-value filter @ 0x082e0378.
pub mod fat_next_cluster;
/// FAT directory-cursor initialization and advancement @ 0x082b2014.
pub mod fat_cursor;
/// Searches a cache-position range for its first zero value @ 0x082e1098.
pub mod zero_cache_position;
/// Cache lock semaphore release @ 0x082d7944.
pub mod cache_lock;
/// Platform C++ file-object read wrapper @ 0x082784b8.
pub mod file_read;
/// Exact-length resource-reader transfer @ 0x082a6aa4.
pub mod resource_reader_read_exact;
/// Absolute resource-reader file seek @ 0x082a6ad8.
pub mod resource_reader_seek_absolute;
/// HFS B-tree node fetch and validation @ 0x08053d6c.
pub mod hfs_btree_get_node;
/// File-path layer failure-status accessor @ 0x0829dcf8.
pub mod error_status;
/// Mapped allocation-bitmap block completion @ 0x0806448c.
pub mod block_window;
/// Block-size alignment check and opaque storage-backend transfer @ 0x08077444.
pub mod storage_transfer;
/// Mounted-volume table slot lookup @ 0x082e0e1c.
pub mod volume_table;
/// Mounted-volume descriptor cursor seek wrapper @ 0x082e628c.
pub mod volume_seek;
/// Four-slot filesystem drive lookup @ 0x082e06f4.
pub mod drive_slot;
/// Path prefix drive-index resolver @ 0x082c3000.
pub mod path_drive_index;
