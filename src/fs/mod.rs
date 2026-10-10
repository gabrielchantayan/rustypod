//! Filesystem-layer helpers (path handling, FAT-facing utilities,
//! HFS B-tree node access).
/// Constant storage memory-capacity gate @ 0x080b6bec.
pub mod storage_memory_capacity_enabled;
/// Volume-dependent default allocation-size selection @ 0x080d528c.
pub mod default_allocation_size;
/// ID3-prefixed word version reader @ 0x08120bdc.
pub mod id3_word_version;
/// Release and rebuild cached storage extents @ 0x08136954.
pub mod storage_extents_refresh;
/// Convert logical extent pairs to backend block ranges @ 0x08136d80.
pub mod storage_extents_translate;
/// Mode-selected two-word record setter @ 0x0814d91c.
pub mod mode_record_pair_set;
/// Mode-selected offset translation @ 0x0814da30.
pub mod mode_offset_translate;
/// Lazy aligned storage-transfer scratch buffer @ 0x0814da74.
pub mod storage_scratch_buffer_ensure;
/// Extent-backed storage buffer constructor @ 0x081c01e4.
pub mod storage_buffer_construct;
/// Extent-backed storage buffer initialization @ 0x081c0180.
pub mod storage_buffer_initialize;
/// FAT directory-entry start-cluster extraction @ 0x082e1378.
pub mod fat_dirent;
/// FAT directory-entry volume-information record writer @ 0x082e1390.
pub mod fat_dirent_volume_info;
/// FAT directory-entry cache-block index lookup @ 0x082e1448.
pub mod fat_dirent_block_index;
/// FAT 8.3 short-name renderer @ 0x082e2fe0.
pub mod fat_short_name_render;
/// FAT 8.3 short-name base/extension splitter @ 0x082e0e8c.
pub mod fat_short_name_split;
/// FAT directory-entry name and metadata population @ 0x082e4970.
pub mod fat_dirent_populate_names;
/// FAT long-file-name fragment-state update @ 0x082dfdc0.
pub mod fat_lfn_fragment;
/// FAT long-file-name reconstruction from accumulated directory entries @ 0x082e44b4.
pub mod fat_lfn_reconstruct;
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
/// Bounded ASCII-space predicate for path-component suffixes @ 0x082e0138.
pub mod remaining_path_bytes_are_spaces;
/// Current-directory path-component predicate @ 0x082e2a7c.
pub mod path_component_is_current_reference;
/// Parent-directory path-component predicate @ 0x082e2ad0.
pub mod path_component_is_parent_reference;
/// Optional `X:` drive-prefix parser @ 0x082e377c.
pub mod drive_prefix_parse;
/// Path-resolution node release @ 0x082e19cc.
pub mod path_node;
/// Releases a path-resolution context under its drive's ATA semaphore @ 0x082e1cd0.
pub mod path_context_release;
/// Path-node header attribute reader @ 0x082e1d2c.
pub mod path_attributes;
/// Creates a path-resolution node for a mounted volume @ 0x082e21dc.
pub mod path_node_create_for_volume;
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
/// Cache-operation accounting and resident list-head lookup @ 0x082e015c.
pub mod cache_operation_begin;
/// Allocates a cache position and initializes its format-specific default value @ 0x082e026c.
pub mod cache_position_allocate;
/// Flushes each cache entry for a FAT-cluster range @ 0x082e044c.
pub mod cache_blocks_flush;
/// Cache-backed disk-block acquisition @ 0x082e3f98.
pub mod cache_block;
/// Four-slot disk block read/write gates and dispatch @ 0x082c6244 / 0x082c62f0.
pub mod disk_block;
/// Cache-entry slot preparation and writeback @ 0x082e48bc.
pub mod cache_block_prepare;
/// Flushes a pending cache request and its drive metadata @ 0x082b172c.
pub mod cache_request_flush;
/// Updates a resolved path node's mode-preserving header attributes @ 0x082e4578.
pub mod path_attribute_update;
/// Cache-entry writeback through the storage-block writer @ 0x082e4b4c.
pub mod cache_entry_flush;
/// Clears cache-entry transient fields while retaining its context link @ 0x082e4b84.
pub mod cache_entry_reset;
/// Marks a backward cache-entry range with byte `0xe5` @ 0x082e4b9c.
pub mod cache_entry_set_marker_range;
/// Splits an opaque packed calendar timestamp into two target halfwords @ 0x082e2264.
pub mod timestamp_halves;
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
/// FAT12/FAT16/FAT32 entry writer @ 0x0818d69c.
pub mod fat_entry_write;
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
/// Bounded nonblank line reader @ 0x080eda58.
pub mod file_read_line;
/// Signed absolute seek through an outer file handle @ 0x08161a80.
pub mod file_seek_signed;
/// Exact-length resource-reader transfer @ 0x082a6aa4.
pub mod resource_reader_read_exact;
/// Absolute resource-reader file seek @ 0x082a6ad8.
pub mod resource_reader_seek_absolute;
/// Validated outer-handle cursor query wrapper @ 0x0805b73c.
pub mod validated_file_tell;
/// HFS B-tree node fetch and validation @ 0x08053d6c.
pub mod hfs_btree_get_node;
/// HFS B-tree node free-space probe @ 0x08053e14.
pub mod hfs_btree_free_space;
pub mod hfs_btree_get_record;
/// HFS B-tree record-request preparation and opaque consumer dispatch @ 0x080595c0.
pub mod hfs_btree_prepare_record_request;
/// HFS B-tree key-length decoder @ 0x080537f8.
pub mod hfs_btree_key_length;
/// Validated HFS B-tree key lookup wrapper with resident dispatch seams @ 0x08058ba4.
pub mod hfs_btree_lookup_key;
/// File-path layer failure-status accessor @ 0x0829dcf8.
pub mod error_status;
/// Mapped allocation-bitmap block completion @ 0x0806448c.
pub mod block_window;
/// Block-size alignment check and opaque storage-backend transfer @ 0x08077444.
pub mod storage_transfer;
/// Initializes and writes a chain of B-tree map nodes @ 0x080819d8.
pub mod btree_map_nodes;
/// Chunks a block transfer through a cleared, aligned temporary buffer @ 0x080f086c.
pub mod storage_transfer_chunked;
/// Opaque storage-backend dispatch through vtable slot three @ 0x08149e10.
pub mod storage_backend_transfer;
/// Opaque storage-backend read dispatch through vtable slot two @ 0x08149de8.
pub mod storage_backend_read;
/// Extent-list read wrapper that selects operation one @ 0x08136920.
pub mod storage_extent_read;
/// Write-enabled extent-list wrapper @ 0x08136a94.
pub mod storage_extent_write;
/// Mounted-volume table slot lookup @ 0x082e0e1c.
pub mod volume_table;
/// Releases and clears a mounted-volume table slot's owned buffer @ 0x082e04fc.
pub mod volume_table_release_buffer;
/// Mounted-volume information query @ 0x082e19ec.
pub mod volume_info;
/// Mounted-volume descriptor cursor seek wrapper @ 0x082e628c.
pub mod volume_seek;
/// Four-slot filesystem drive lookup @ 0x082e06f4.
pub mod drive_slot;
/// Drive-slot creation and dependent initialization phases @ 0x082e2458.
pub mod drive_slot_initialize;
/// Reads selected-drive total and data-area sector counts @ 0x082e172c.
pub mod drive_sector_counts;
/// Drive-slot cleanup and reference-count release @ 0x082e073c.
pub mod drive_slot_cleanup;
/// Four-slot filesystem drive-index validator @ 0x082e4b3c.
pub mod drive_slot_index;
/// Flushes a drive slot's pending metadata writes @ 0x082e149c.
pub mod drive_slot_flush;
/// Path prefix drive-index resolver @ 0x082c3000.
pub mod path_drive_index;
/// Disk-I/O readiness argument adapter @ 0x082c3174.
pub mod drive_ready;
/// Volume-prefixed music-library path construction @ 0x0806b4a0.
pub mod music_path_resolve;
/// Bounded file-prefix reader @ 0x080962f0.
pub mod file_read_prefix;
