//! Filesystem-layer helpers (path handling, FAT-facing utilities,
//! HFS B-tree node access).
/// FAT directory-entry start-cluster extraction @ 0x082e1378.
pub mod fat_dirent;
/// FAT long-file-name fragment-state update @ 0x082dfdc0.
pub mod fat_lfn_fragment;
/// FAT long-file-name checksum for an 11-byte short name @ 0x082e0194.
pub mod fat_lfn_short_name_checksum;
/// FAT data-cluster to cache-block-index conversion @ 0x082e01cc.
pub mod fat_cluster_to_block;
/// FAT cache-block-index to data-cluster conversion @ 0x082e4358.
pub mod fat_cluster_for_offset;
/// FAT table size bias-and-division helper @ 0x080e75e4.
pub mod fat_table_sector_count;
pub mod path_limits;
/// Finder `.DS_Store` metadata-path substring predicate @ 0x0809e718.
pub mod ds_store_path;
/// Splits a path at its final configured delimiter @ 0x082e37d4.
pub mod path_component_split;
/// Optional `X:` drive-prefix parser @ 0x082e377c.
pub mod drive_prefix_parse;
/// Path-resolution node release @ 0x082e19cc.
pub mod path_node;
/// Shared path-data reference release @ 0x082e1960.
pub mod shared_data;
/// Path-resolution child lookup with default continuation state @ 0x082e2004.
pub mod path_node_lookup;
/// Cache-entry reference release @ 0x082e18bc.
pub mod cache_entry;
/// Sequential cache-entry allocation @ 0x082e4320.
pub mod cache_entry_next;
/// Bounded cache-entry allocation with a cleared 512-byte payload @ 0x082e254c.
pub mod cache_entry_allocate_cleared;
/// Cache-backed disk-block acquisition @ 0x082e3f98.
pub mod cache_block;
/// Four-slot disk block read/write gates and dispatch @ 0x082c6244 / 0x082c62f0.
pub mod disk_block;
/// Cache-entry slot preparation and writeback @ 0x082e48bc.
pub mod cache_block_prepare;
/// Flushes a pending cache request and its drive metadata @ 0x082b172c.
pub mod cache_request_flush;
/// Cache-entry writeback through the storage-block writer @ 0x082e4b4c.
pub mod cache_entry_flush;
/// Clears cache-entry transient fields while retaining its context link @ 0x082e4b84.
pub mod cache_entry_reset;
/// Cache-page halfword transfer through the page resolver @ 0x082e1a34.
pub mod cache_page;
/// Format-specific default cache-position value writer @ 0x082e3bcc.
pub mod cache_position_default_value;
/// Shared resident FAT-position value reader boundary at 0x082e0cac.
pub(crate) mod cache_position_value;
/// FAT next-cluster reader and reserved-value filter @ 0x082e0378.
pub mod fat_next_cluster;
/// Releases a FAT cluster chain through the shared cache-position writer @ 0x082e18f8.
pub mod fat_cluster_chain_release;
/// Clears an allocatable FAT cluster through the shared cache-position writer @ 0x082e03f4.
pub mod fat_cluster_clear;
/// FAT directory-cursor initialization and advancement @ 0x082b2014.
/// FAT directory cursor cache-block advancement @ 0x082e36c8.
pub mod fat_cursor_advance_block;
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
/// HFS B-tree node free-space probe @ 0x08053e14.
pub mod hfs_btree_free_space;
pub mod hfs_btree_get_record;
/// HFS B-tree key-length decoder @ 0x080537f8.
pub mod hfs_btree_key_length;
/// File-path layer failure-status accessor @ 0x0829dcf8.
pub mod error_status;
/// Mapped allocation-bitmap block completion @ 0x0806448c.
pub mod block_window;
/// Block-size alignment check and opaque storage-backend transfer @ 0x08077444.
pub mod storage_transfer;
/// Opaque storage-backend dispatch through vtable slot three @ 0x08149e10.
pub mod storage_backend_transfer;
/// Opaque storage-backend read dispatch through vtable slot two @ 0x08149de8.
pub mod storage_backend_read;
/// Extent-list read wrapper that selects operation one @ 0x08136920.
pub mod storage_extent_read;
/// Mounted-volume table slot lookup @ 0x082e0e1c.
pub mod volume_table;
/// Mounted-volume information query @ 0x082e19ec.
pub mod volume_info;
/// Mounted-volume descriptor cursor seek wrapper @ 0x082e628c.
pub mod volume_seek;
/// Four-slot filesystem drive lookup @ 0x082e06f4.
pub mod drive_slot;
/// Drive-slot cleanup and reference-count release @ 0x082e073c.
pub mod drive_slot_cleanup;
/// Four-slot filesystem drive-index validator @ 0x082e4b3c.
pub mod drive_slot_index;
/// Flushes a drive slot's pending metadata writes @ 0x082e149c.
pub mod drive_slot_flush;
/// Path prefix drive-index resolver @ 0x082c3000.
pub mod path_drive_index;
/// Volume-prefixed music-library path construction @ 0x0806b4a0.
pub mod music_path_resolve;
