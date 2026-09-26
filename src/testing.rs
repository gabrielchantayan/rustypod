//! Shared host-test fixtures.
//!
//! Several ported modules describe firmware objects whose pointer fields are
//! **u32 target pointers**: the port reads them with `word(..) as usize as
//! *mut u8` and dereferences the result. A host fixture backing such an
//! object must therefore live entirely below 4 GiB, or the address truncates
//! on store and the first dereference dies on SIGSEGV.
//!
//! This is a strictly stronger requirement than the one the heap slabs have
//! (`heap/pool.rs`, `heap/mod.rs`), where the only constraint is that bit 31
//! stay clear because `pool_alloc` uses it as the uncached mark. Conflating
//! the two is how `cxx/list_splice.rs`, `heap/block_mgr.rs` and
//! `heap/client_populate.rs` each shipped a bit-31 assertion that a
//! 0x1_xxxx_xxxx mapping passes happily before crashing.
//!
//! **Not every host can satisfy it.** Linux honours a low `mmap` hint. arm64
//! macOS reserves the whole low 4 GiB and refuses such a mapping even with
//! `MAP_FIXED`, so there the fixture cannot exist at all. Modules that need
//! one skip their tests on those hosts rather than crash — which is why this
//! returns an `Option` instead of asserting.

extern crate std;

/// Fixture base addresses, one per mapping site — not merely one per
/// module. [`try_map_u32_slab`] never unmaps, so two tests in the SAME
/// module that share a hint collide exactly like two modules would: the
/// second one to run finds the region occupied and skips.
///
/// These MUST be unique. A duplicate does not fail loudly — the second
/// module to map simply gets some other address, which on a 64-bit host is
/// usually above 4 GiB, so [`try_map_u32_slab`] returns `None` and that
/// module's tests quietly skip on EVERY host. That is exactly what happened
/// when `app/event_list` picked `0x0d00_0000`, already held by
/// `cxx/list_splice`: seven tests stopped running anywhere and the suite
/// still reported green.
///
/// Keep every fixture hint here rather than as a literal in the module, so
/// a collision is visible in one place instead of being invisible across
/// six files. Each region is at most 0x0100_0000 wide, so neighbours cannot
/// overlap.
pub mod hints {
    // 0x7010_0000: dedicated to crypto/sha1_managed_context_create's
    // target-width SHA-1 backing context fixture; mappings never unmap.
    pub const SHA1_MANAGED_CONTEXT_CREATE: usize = 0x7010_0000;
    // 0x6ef0_0000: dedicated to heap/fixa_resource's target-width FixA
    // owner, FixL range, and resource fixtures; mappings never unmap.
    pub const FIXA_RESOURCE_RELEASE: usize = 0x6ef0_0000;
    // 0x6ed0_0000: dedicated to cxx/descriptor_action_dispatch's raw-u32
    // owner and source fixture; mappings never unmap.
    pub const DESCRIPTOR_ACTION_DISPATCH: usize = 0x6ed0_0000;
    // 0x6ee0_0000: dedicated to util/key_descriptor_copy_eight's
    // target-width descriptor, source, and output fixture; mappings never unmap.
    pub const KEY_DESCRIPTOR_EIGHT_BYTE_COPY: usize = 0x6ee0_0000;
    // 0x7c20_0000: dedicated to crypto/pkcs7_set_detached's target-width
    // PKCS7 and ASN1_OBJECT fixture; mappings never unmap.
    pub const PKCS7_SET_DETACHED: usize = 0x7c20_0000;
    // 0x6f58_0000: dedicated to crypto/rsa_size's target-width RSA fixture;
    // mappings never unmap, so no other port may share this hint.
    pub const RSA_SIZE: usize = 0x6f58_0000;
    // 0x6f70_0000: dedicated to drivers/storage_backend_sector_size's
    // target-width validated-backend fixture; mappings never unmap.
    pub const STORAGE_BACKEND_SECTOR_SIZE: usize = 0x6f70_0000;
    // 0x6f80_0000: dedicated to util/binary_data_read's target-width input
    // fixture; mappings never unmap.
    pub const BINARY_DATA_READ: usize = 0x6f80_0000;
    // 0xfee0_0000 / 0xfee1_0000: dedicated to ft/pshinter's target-width
    // stem-record array fixtures; mappings never unmap.
    pub const PSH_DIMENSION_APPEND_STEM_RECORD: usize = 0xfee0_0000;
    pub const PSH_DIMENSION_APPEND_STEM_RECORD_CAPACITY: usize = 0xfee1_0000;
    // 0x6f50_0000: dedicated to util/video_engine's target-width controller,
    // engine, frame-table, and frame-record fixture; mappings never unmap.
    pub const VIDEO_ENGINE_PRESENT_DEFAULT_FRAME: usize = 0x6f50_0000;
    // 0x6f60_0000: dedicated to app/selection_state_refresh_if_count_changed's
    // target-width state, inner, context, and index-table fixture; mappings
    // never unmap, so no other port may share this hint.
    pub const SELECTION_STATE_COUNT_REFRESH: usize = 0x6f60_0000;
    // 0xe100_0000: dedicated to app/animation_property_pair_init's owner,
    // fixed-value endpoints, and animation fixture; mappings never unmap.
    pub const ANIMATION_PROPERTY_PAIR_INIT: usize = 0xe100_0000;
    // 0x6f10_0000 / 0x6f20_0000: dedicated to
    // app/datetime_adjust's target-width controller, selector, and provider
    // fixtures; mappings never unmap, so no other port may share either hint.
    // 0x6f30_0000: dedicated to app/registry_display_client_construct's
    // 300-byte target-width client fixture; mappings never unmap.
    pub const REGISTRY_DISPLAY_CLIENT_CONSTRUCT: usize = 0x6f30_0000;
    pub const DATETIME_ADJUST_AND_STORE: usize = 0x6f10_0000;
    pub const DATETIME_ADJUST_AND_STORE_INVALID_MODE: usize = 0x6f20_0000;
    // 0x6f40_0000: dedicated to app/iap_packet's target-width service
    // validity and descriptor-table fixture; mappings never unmap.
    pub const IAP_SERVICE_DESCRIPTOR_FOR_OWNER_MODE: usize = 0x6f40_0000;
    // 0x6b00_0000: dedicated to sqlite/schema_get's target-width Btree,
    // shared-cache, and Schema fixture; mappings never unmap.
    pub const SQLITE_SCHEMA_GET: usize = 0x6b00_0000;
    // 0x6d70_0000: dedicated to app/anchor_identifier_find's target-width
    // owner, collection, StringObject, and candidate fixtures; mappings never
    // unmap, so no other user may share this hint.
    pub const ANCHOR_IDENTIFIER_FIND: usize = 0x6d70_0000;
    // 0x6d80_0000: dedicated to app/strided_record_find_by_key's target-width
    // container and 12-byte record fixtures; mappings never unmap.
    pub const STRIDED_RECORD_FIND_BY_KEY: usize = 0x6d80_0000;
    // 0x6b10_0000 / 0x6b20_0000: dedicated to sqlite/append_owned_pointer's
    // target-width owner and pointer-array fixtures; mappings never unmap.
    pub const SQLITE_APPEND_OWNED_POINTER_GROW: usize = 0x6b10_0000;
    pub const SQLITE_APPEND_OWNED_POINTER_FAILURE: usize = 0x6b20_0000;
    // 0x6901_0000: dedicated to sqlite/vdbe_cursor_reference_list_release's
    // target-width list and cursor-reference fixtures; mappings never unmap.
    pub const SQLITE_VDBE_CURSOR_REFERENCE_LIST_RELEASE: usize = 0x6901_0000;
    // 0x6a10_0000: dedicated to sqlite/btree_set_cache_size's target-width
    // Btree and BtShared fixture; mappings never unmap.
    pub const SQLITE_BTREE_SET_CACHE_SIZE: usize = 0x6a10_0000;
    // 0x6a20_0000: dedicated to sqlite/btree_factory's target-width
    // Btree and BtShared fixture; mappings never unmap.
    pub const SQLITE_BTREE_FACTORY: usize = 0x6a20_0000;
    // 0x6a30_0000: dedicated to sqlite/btree_schema's target-width Btree
    // and BtShared fixture; mappings never unmap, so no other module may
    // share this hint.
    pub const BTREE_SCHEMA: usize = 0x6a30_0000;
    // 0x6c00_0000: dedicated to sqlite/emit_compound_select_rows's
    // target-width Parse, Select chain, Vdbe, and opcode fixture; mappings
    // never unmap, so no other module may share it.
    pub const EMIT_COMPOUND_SELECT_ROWS: usize = 0x6c00_0000;
    // 0x7ea0_0000 / 0x7eb0_0000: dedicated to
    // cxx/opaque_observable_array_destroy's target-width derived object
    // fixtures; mappings never unmap, so no other user may share either hint.
    pub const OPAQUE_OBSERVABLE_ARRAY_DESTROY: usize = 0x7ea0_0000;
    pub const OPAQUE_OBSERVABLE_ARRAY_DESTROY_NULL: usize = 0x7eb0_0000;
    // 0x7ec0_0000 / 0x7ed0_0000: dedicated to
    // cxx/opaque_observable_array_payload_destroy's target-width derived
    // object fixtures; mappings never unmap, so no other user may share either hint.
    pub const OPAQUE_OBSERVABLE_ARRAY_PAYLOAD_DESTROY: usize = 0x7ec0_0000;
    pub const OPAQUE_OBSERVABLE_ARRAY_PAYLOAD_DESTROY_NULL: usize = 0x7ed0_0000;
    // 0x7ee0_0000: dedicated to cxx/vtable_08990af8_destruct's target-width
    // owner and embedded observable-array fixtures; mappings never unmap.
    pub const VTABLE_08990AF8_DESTRUCT: usize = 0x7ee0_0000;
    // 0x7f40_0000: dedicated to runtime/trim_ctype_whitespace's raw-u32
    // LC_CTYPE table fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const STRING_TRIM_CTYPE: usize = 0x7f40_0000;
    // 0x6d40_0000: dedicated to cxx/segmented_iter_post_increment's raw-u32
    // segment-map fixture; mappings never unmap, so no other user may share it.
    pub const SEGMENTED_ITER_POST_INCREMENT: usize = 0x6d40_0000;
    // 0x083d_0000: dedicated to app/element_table's raw-u32 one-based array
    // accessor fixture; mappings never unmap, so no other user may share it.
    // 0x7c00_0000 and 0x7c10_0000: dedicated to
    // util/indexed_record_pointer_and_value's target-width record fixtures.
    pub const INDEXED_RECORD_POINTER_AND_VALUE_FIRST: usize = 0x7c00_0000;
    pub const INDEXED_RECORD_POINTER_AND_VALUE_SECOND: usize = 0x7c10_0000;
    pub const ELEMENT_ARRAY_ONE_BASED_AT: usize = 0x083d_0000;
    // 0x2350_0000: dedicated to app/resource_slot_acquire's target-width
    // pool and slot fixtures; mappings never unmap, so no other user may share it.
    pub const RESOURCE_SLOT_ACQUIRE: usize = 0x2350_0000;
    // 0x7e90_0000: dedicated to cxx/list_release_chain_destroy's raw-u32
    // object and sentinel fixtures; mappings never unmap.
    pub const LIST_RELEASE_CHAIN_DESTROY: usize = 0x7e90_0000;
    // 0x6f00_0000: dedicated to cxx/linked_list_has_items's raw-u32 list
    // and intrusive-node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const LINKED_LIST_HAS_ITEMS: usize = 0x6f00_0000;
    // 0x7e50_0000 / 0x7e40_0000: dedicated to
    // cxx/list_node_prepend_release's target-width list and node fixtures;
    // mappings never unmap, so no other user may share either hint.
    pub const LIST_NODE_PREPEND_RELEASE: usize = 0x7e50_0000;
    pub const LIST_NODE_PREPEND_RELEASE_RELEASE: usize = 0x7e40_0000;
    // 0x7e60_0000: dedicated to util/hash_table_chain_destroy's target-width
    // table, bucket, and intrusive-node fixture; mappings never unmap.
    pub const HASH_TABLE_CHAIN_DESTROY: usize = 0x7e60_0000;
    // 0x7e70_0000: dedicated to cxx/list_range_clear's target-width list
    // fixture; mappings never unmap, so no other user may share it.
    pub const LIST_RANGE_CLEAR: usize = 0x7e70_0000;
    // 0x7e80_0000: dedicated to cxx/list_insert_header_value's raw-u32 list
    // and node-slot fixture; mappings never unmap, so no other user may share it.
    pub const LIST_INSERT_HEADER_VALUE: usize = 0x7e80_0000;
    // 0x7fd0_0000: dedicated to crypto/bio_push's raw-u32 BIO-chain fixture;
    // mappings never unmap, so no other user may share this hint.
    pub const BIO_PUSH: usize = 0x7fd0_0000;
    // 0xd100_0000: dedicated to cxx/vector8_erase's raw-u32 vector fixture;
    // mappings never unmap, so no other user may share this hint.
    pub const VECTOR8_ERASE: usize = 0xd100_0000;
    // 0x6c10_0000: dedicated to cxx/vector4_resize_fill's target-width
    // vector and allocation fixtures; mappings never unmap.
    pub const VECTOR4_RESIZE_FILL: usize = 0x6c10_0000;
    // 0x6d10_0000: dedicated to cxx/vector_word_copy_construct's target-width
    // vector source, destination, and allocation fixtures; mappings never unmap.
    pub const VECTOR_WORD_COPY_CONSTRUCT: usize = 0x6d10_0000;
    // 0x6e10_0000: dedicated to ui/tracked_object_register's raw-u32 object
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const TRACKED_OBJECT_REGISTER: usize = 0x6e10_0000;
    // 0x7f00_0000: dedicated to app/file_record_registry_destruct's
    // target-width registry fixture; mappings never unmap.
    pub const FILE_RECORD_REGISTRY_DESTRUCT: usize = 0x7f00_0000;
    // 0x6f90_0000: dedicated to app/thumbnail_location_cache_entry's
    // request, cache, and entry-base raw-u32 fixture; mappings never unmap.
    pub const THUMBNAIL_LOCATION_CACHE_ENTRY: usize = 0x6f90_0000;
    // 0x7f80_0000: dedicated to codegen/interference's raw-u32 graph and
    // arena fixture; mappings never unmap, so no other user may share it.
    pub const CG_INTERFERENCE_EDGE_LINK: usize = 0x7f80_0000;
    // 0xde00_0000: dedicated to app/path_entry_load_to_heap's raw-u32
    // buffered-loader source fixture; mappings never unmap, so no other user
    // may share this hint.
    pub const PATH_ENTRY_LOAD_TO_HEAP: usize = 0xde00_0000;
    // 0x3e00_0000: dedicated to app/string_resolve's raw-u32 provider
    // registry fixture; mappings never unmap, so no other user may share it.
    pub const APP_STRING_PROVIDER_LOOKUP: usize = 0x3e00_0000;
    // 0x1234_0000: dedicated to cxx/basic_ios_initialize's raw-u32 stream,
    // locale, and facet-table fixture; mappings never unmap, so no other user
    // may share this hint.
    pub const STREAM_BASIC_IOS_INITIALIZE: usize = 0x1234_0000;
    // 0x2345_0000: dedicated to app/timing_wheel_node_replace_value's
    // target-width node and value fixtures; mappings never unmap.
    pub const TIMING_WHEEL_NODE_REPLACE_VALUE: usize = 0x2345_0000;
    // 0x0100_0000: dedicated to cxx/stream_read's target-width descriptor,
    // complete-owner state, and reader fixture; mappings never unmap.
    pub const CXX_STREAM_READ: usize = 0x0100_0000;
    // 0x6310_0000: dedicated to jpeg/stream_read_u16's raw-u32 stream and
    // file-handle fixture; mappings never unmap, so no other user may share it.
    pub const JPEG_STREAM_READ_U16: usize = 0x6310_0000;
    // 0x0800_0000: dedicated to util/predicate_list_find's raw-u32 list and
    // node fixture; mappings never unmap, so no other user may share it.
    pub const PREDICATE_LIST_FIND: usize = 0x0800_0000;
    // 0x0400_0000: dedicated to cxx/shared_handle_owner_destroy's raw-u32
    // owner fixture; mappings never unmap, so no other user may share it.
    pub const SHARED_HANDLE_OWNER_DESTROY: usize = 0x0400_0000;
    pub const HEAP_INTEGRATION: usize = 0x0900_0000;
    // 0x5500_0000: dedicated to ft/sfnt's raw-u32 TT_Face table-directory
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const TT_FACE_LOOKUP: usize = 0x5500_0000;
    pub const ATA_CMD: usize = 0x0a00_0000;
    // 0xf200_0000: dedicated to sqlite/pager_page_unlink's target-width page
    // and owner fixture; mappings never unmap, so no other port may share it.
    pub const SQLITE_PAGER_PAGE_UNLINK: usize = 0xf200_0000;
    // 0x0010_0000: dedicated to sqlite/pcache_pin_page's target-width page
    // and cache fixture; mappings never unmap, so no other port may share it.
    pub const SQLITE_PCACHE_PIN_PAGE: usize = 0x0010_0000;
    // 0x6300_0000: dedicated to util/video_engine's target-width frame-slot
    // table fixture; mappings never unmap, so no other user may share it.
    pub const VIDEO_ENGINE_CURRENT_FRAME_SLOT: usize = 0x6300_0000;
    // 0xcf00_0000: dedicated to util/video_engine's primary-frame table,
    // record, and payload fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const VIDEO_ENGINE_FRAME_PAYLOAD: usize = 0xcf00_0000;
    // 0x6a00_0000: dedicated to util/video_engine's target-width pending
    // release-state and allocation fixtures; mappings never unmap, so no
    // other port may share this hint.
    pub const VIDEO_ENGINE_RELEASE_PENDING_HANDLES: usize = 0x6a00_0000;
    // 0x6400_0000: dedicated to ATA command execution/submission's raw-u32
    // status-source fixtures; mappings never unmap, so neither port shares it.
    pub const ATA_COMMAND_EXECUTE: usize = 0x6400_0000;
    pub const ATA_COMMAND_SUBMIT_WAIT: usize = 0x6500_0000;
    // 0x6900_0000: dedicated to drivers/ata_command_prepare's target-width
    // ATA status-source fixture; mappings never unmap.
    pub const ATA_COMMAND_PREPARE: usize = 0x6900_0000;
    // 0x6700_0000: dedicated to drivers/ata_command_wait_idle's paired
    // target-width command-global and controller-state fixtures.
    pub const ATA_COMMAND_WAIT_IDLE: usize = 0x6700_0000;
    // 0x7f70_0000: dedicated to drivers/ata_taskfile_program's raw-u32
    // task-file fixture; mappings never unmap, so no other user may share it.
    pub const ATA_TASKFILE_PROGRAM: usize = 0x7f70_0000;
    // 0x6600_0000: dedicated to ui/object_stack_push's raw-u32 owner items
    // array and growth-allocation slab; mappings never unmap, so no other
    // user may share this hint.
    pub const OBJECT_STACK_PUSH: usize = 0x6600_0000;
    // 0x6b00_0000: dedicated to cxx/owner_callback_dispatch's target-width
    // owner, object, and queued-word-copy fixture; mappings never unmap.
    pub const OWNER_CALLBACK_DISPATCH: usize = 0x6b00_0000;
    // 0x6b10_0000: dedicated to sqlite/free_function_context's raw-u32
    // context fixture; mappings never unmap, so no other port may share it.
    pub const SQLITE_FREE_FUNCTION_CONTEXT: usize = 0x6b10_0000;
    // 0x6e20_0000 / 0x6e30_0000: dedicated to
    // app/global_transition_callback_dispatch's target-width global-state
    // fixtures; mappings never unmap.
    pub const GLOBAL_TRANSITION_CALLBACK_DISPATCH: usize = 0x6e20_0000;
    pub const GLOBAL_TRANSITION_CALLBACK_DISPATCH_NO_MUTEX: usize = 0x6e30_0000;
    pub const CLIENT_POPULATE: usize = 0x0b00_0000;
    pub const BLOCK_MGR: usize = 0x0c00_0000;
    pub const LIST_SPLICE: usize = 0x0d00_0000;
    // 0x7fb0_0000: dedicated to heap/block_mgr's target-width client
    // capacity-cache manager, sentinel, node, handle, and client fixtures.
    pub const BLOCK_MGR_CLIENT_CAPACITY: usize = 0x7fb0_0000;
    pub const EVENT_LIST: usize = 0x0e00_0000;
    // 0x7e00_0000: dedicated to app/observer_list_register's raw-u32
    // context, intrusive-list anchor, successor, and record fixture.
    pub const OBSERVER_LIST_REGISTER: usize = 0x7e00_0000;
    pub const CONTEXT_SCOPE: usize = 0x0f00_0000;
    // 0x1600_0000: dedicated to ui/range_release's raw-u32 owner,
    // operation, cursor, and item fixtures; mappings never unmap.
    pub const RANGE_RELEASE: usize = 0x1600_0000;
    // 0x6900_0000: dedicated to cxx/opaque_context_drain's target-width
    // context and deque fixture; mappings never unmap.
    pub const OPAQUE_CONTEXT_DRAIN: usize = 0x6900_0000;
    // 0x7f90_0000: dedicated to cxx/opaque_context_activate's target-width
    // context, child, and selected-record fixture; mappings never unmap.
    pub const OPAQUE_CONTEXT_ACTIVATE: usize = 0x7f90_0000;
    // 0x7fa0_0000 / 0x7fb0_0000: dedicated to cxx/shared_cell_field_copy's
    // raw-u32 object, slot, and shared-cell fixtures; mappings never unmap.
    pub const SHARED_CELL_FIELD_COPY: usize = 0x7fa0_0000;
    pub const SHARED_CELL_FIELD_COPY_NULL: usize = 0x7fb0_0000;
    pub const BTREE_PARSE_CELL: usize = 0x1000_0000;
    // 0xb100_0000: dedicated to util/bounded_word_bit_set_contains's raw-u32
    // word-bitmap fixture; mappings never unmap, so no other user may share it.
    pub const BOUNDED_WORD_BIT_SET_CONTAINS: usize = 0xb100_0000;
    pub const BTREE_DATA_SIZE: usize = 0x1100_0000;
    // 0x7200_0000: dedicated to sqlite/key's raw-u32 BtCursor/MemPage
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const BTREE_KEY: usize = 0x7200_0000;
    // 0x7000_0000: dedicated to sqlite/restore_cursor_position's raw-u32
    // BtCursor fixture; mappings never unmap, so no other user may share it.
    pub const BTREE_RESTORE_CURSOR: usize = 0x7000_0000;
    // 0x7300_0000: dedicated to sqlite/save_cursor_position's raw-u32
    // Btree/BtCursor fixture; mappings never unmap, so no other user may share it.
    pub const BTREE_SAVE_ALL_CURSORS: usize = 0x7300_0000;
    // 0x0837_0000: dedicated to sqlite/fix_init's raw-u32 Parse/sqlite3/
    // Db-array/DbFixer fixture page; all xx00_0000 slots are taken, so it
    // uses the function's own address prefix. Mappings never unmap.
    pub const SQLITE_FIX_INIT: usize = 0x0837_0000;
    // 0x0837_1000: dedicated to sqlite/fix_expr_list's raw-u32 ExprList
    // and 12-byte ExprList_item fixture; mappings never unmap.
    pub const SQLITE_FIX_EXPR_LIST: usize = 0x0837_1000;
    // 0x0838_0000: dedicated to sqlite/fix_src_list's raw-u32 DbFixer,
    // Parse, SrcList, and SrcList_item fixture; mappings never unmap.
    pub const SQLITE_FIX_SRC_LIST: usize = 0x0838_0000;
    // 0x7100_0000: dedicated to sqlite/cursor_moveto's raw-u32 VdbeCursor
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const VDBE_CURSOR_MOVETO: usize = 0x7100_0000;
    pub const ELEMENT_REFERENCE: usize = 0x1200_0000;
    pub const VTABLE_SET_ITERATOR: usize = 0x1300_0000;
    // 0x7e50_0000: dedicated to cxx/word_table_index_pair's target-width
    // descriptor and word-table fixture; mappings never unmap.
    pub const WORD_TABLE_INDEX_PAIR: usize = 0x7e50_0000;
    // 0x7e40_0000: dedicated to cxx/word_table_index_pair_at's target-width
    // descriptor and word-table fixture; mappings never unmap.
    pub const WORD_TABLE_INDEX_PAIR_AT: usize = 0x7e40_0000;
    pub const OBSERVABLE_ARRAY: usize = 0x1400_0000;
    pub const OBSERVABLE_ARRAY_DRAIN: usize = 0x1500_0000;
    pub const EVENT_SOURCE_DESTRUCT: usize = 0x1600_0000;
    // 0x1f00_0000 / 0x1f10_0000: dedicated to
    // app/event_source_find_payload's raw-u32 vector, entries, and payload
    // fixtures; mappings never unmap, so no other user may share either hint.
    pub const EVENT_SOURCE_FIND_PAYLOAD: usize = 0x1f00_0000;
    pub const EVENT_SOURCE_FIND_PAYLOAD_NO_MATCH: usize = 0x1f10_0000;
    pub const SILVER_CONTROLLER: usize = 0x1700_0000;
    // 0x7f20_0000: dedicated to app/locked_owned_context_destroy's controller
    // and owned-context raw-u32-pointer fixture.
    pub const LOCKED_OWNED_CONTEXT_DESTROY: usize = 0x7f20_0000;
    pub const QUEUED_MESSAGE_POST: usize = 0x1800_0000;
    pub const VTABLE_SET_ITERATOR_RELEASE: usize = 0x1900_0000;
    pub const VDBE_SERIAL_PUT: usize = 0x1a00_0000;
    // 0x1a10_0000: dedicated to sqlite/vdbe_free_ops's target-layout
    // Vdbe and VdbeOp array fixture; mappings never unmap, so no other user
    // may share this hint.
    pub const VDBE_FREE_OPS: usize = 0x1a10_0000;
    // 0x1a20_0000: dedicated to sqlite/vdbe_free_cursor's target-width
    // Vdbe/cursor fixture; mappings never unmap, so no other user may share it.
    pub const VDBE_FREE_CURSOR: usize = 0x1a20_0000;
    // 0x1a30_0000: dedicated to sqlite/vdbe_frame_list_clear's target-width
    // descriptor and pending-frame fixtures; mappings never unmap, so no other
    // port may share this hint.
    pub const VDBE_FRAME_LIST_CLEAR: usize = 0x1a30_0000;
    pub const PENDING_EVENT_TAKE: usize = 0x1b00_0000;
    pub const PENDING_EVENT_DISCARD_ALL_FOR_KEY: usize = 0x1b10_0000;
    // 0x1b20_0000: dedicated to app/pending_event_timer_rearm's raw-u32
    // session, node, and IAP-thread fixture; mappings never unmap.
    pub const PENDING_EVENT_TIMER_REARM: usize = 0x1b20_0000;
    // Dedicated raw-u32 owner fixtures for iterator seek tests; mappings
    // never unmap, so each target layout has its own hint.
    pub const ITERATOR_STATE_SEEK: usize = 0x1c10_0000;
    pub const ITERATOR_STATE_SEEK_CONSTRUCT: usize = 0x1c20_0000;
    pub const ITERATOR_STATE_SEEK_BEGIN: usize = 0x1c30_0000;
    pub const ITERATOR_STATE_CURRENT_INDEX: usize = 0x1c40_0000;
    // 0x1c70_0000: dedicated to app/vtable_set's collection reverse-search
    // fixture; mappings never unmap, so no other port may share this hint.
    pub const COLLECTION_FIND_PREVIOUS_HANDLER: usize = 0x1c70_0000;
    // 0x1c50_0000: dedicated to app/collection_entry_teardown's target-width
    // owner fixture; mappings never unmap, so no other user may share it.
    pub const COLLECTION_ENTRY_TEARDOWN: usize = 0x1c50_0000;
    // 0x1c80_0000: dedicated to app/collection_entry_action_clear's
    // target-width owner fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const COLLECTION_ENTRY_ACTION_CLEAR: usize = 0x1c80_0000;
    // 0x1c90_0000 / 0x1ca0_0000: dedicated to
    // app/collection_count_eligible_entries' target-width owner fixtures;
    // mappings never unmap, so no other port may share either hint.
    pub const COLLECTION_COUNT_ELIGIBLE_ENTRIES: usize = 0x1c90_0000;
    pub const COLLECTION_COUNT_ELIGIBLE_ENTRIES_EMPTY: usize = 0x1ca0_0000;
    // 0x1cb0_0000: dedicated to app/registered_listener_dispatch's
    // target-width entry fixture; mappings never unmap, so no other port may
    // share this hint.
    pub const REGISTERED_LISTENER_DISPATCH: usize = 0x1cb0_0000;
    // 0x1cd0_0000: dedicated to drivers/display_layer_reset's target-width
    // pending-object fixture; mappings never unmap.
    pub const LAYER_PENDING_OBJECT_STOP: usize = 0x1cd0_0000;
    // Dedicated target-width bucket fixture for vtable_file_record_inner_iterator_begin.
    pub const VTABLE_FILE_RECORD_INNER_ITERATOR_BEGIN: usize = 0x1c60_0000;
    // 0xbf00_0000: dedicated to app/pending_event_take_due's raw-u32
    // session and pending-event fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const PENDING_EVENT_TAKE_DUE: usize = 0xbf00_0000;
    pub const ANIMATION_INIT: usize = 0x1c00_0000;
    pub const STRING_RECORD: usize = 0x1d00_0000;
    // 0x1d20_0000: dedicated to app/class_6280_refresh_ui's raw-u32
    // UI-element fixture; mappings never unmap.
    pub const CLASS_6280_REFRESH_UI: usize = 0x1d20_0000;
    // 0x1d10_0000: dedicated to cxx/named_object_cache's target-width owner,
    // container, key, and allocated-object fixture; mappings never unmap.
    pub const NAMED_OBJECT_CACHE: usize = 0x1d10_0000;
    // 0x1d20_0000: dedicated to cxx/equal_key_tree_clear's raw-u32 header
    // node and tree record fixture; mappings never unmap.
    pub const EQUAL_KEY_TREE_CLEAR: usize = 0x1d20_0000;
    // 0x1d30_0000: dedicated to cxx/u32_map_value_slot's raw-u32 node and
    // map fixture; mappings never unmap.
    pub const U32_MAP_VALUE_SLOT: usize = 0x1d30_0000;
    // 0x1d40_0000: dedicated to cxx/element_registry_slot_for_key's raw-u32
    // node and map fixture; mappings never unmap, so no other user may share it.
    pub const ELEMENT_REGISTRY_SLOT_FOR_KEY: usize = 0x1d40_0000;
    // 0x1d50_0000: dedicated to ui/indexed_rect's raw-u32 rectangle-table
    // fixture; mappings never unmap, so no other user may share it.
    pub const INDEXED_RECT_COPY_OFFSET: usize = 0x1d50_0000;
    // 0x1d60_0000: dedicated to cxx/keyed_record_find_string_match's raw-u32
    // owner, entry, candidate and C-string fixture; mappings never unmap.
    pub const KEYED_RECORD_FIND_STRING_MATCH: usize = 0x1d60_0000;
    pub const IAP_PACKET_OWNER_MODE: usize = 0x1e00_0000;
    pub const TOKENIZER: usize = 0x1f00_0000;
    // 0x1f10_0000: dedicated to cxx/tokenizer_next_string's raw-u32 UTF-16
    // range fixture; mappings never unmap, so no other port may share it.
    pub const TOKENIZER_NEXT_STRING: usize = 0x1f10_0000;
    // Dedicated target-layout sqlite3 connection fixtures for
    // sqlite/close; mappings never unmap.
    pub const SQLITE_CLOSE: usize = 0x2000_0000;
    pub const SQLITE_CLOSE_SCHEMA: usize = 0x2100_0000;
    // 0xc000_0000 and 0xc100_0000: dedicated to
    // cxx/opaque_vtable_record_copy_construct's target-width source fixtures.
    pub const OPAQUE_VTABLE_RECORD_COPY_CONSTRUCT: usize = 0xc000_0000;
    pub const OPAQUE_VTABLE_RECORD_COPY_CONSTRUCT_DEFAULT: usize = 0xc100_0000;
    // 0xc400_0000 and 0xc500_0000: dedicated to
    // cxx/opaque_vtable_record_construct's target-width source fixtures.
    pub const OPAQUE_VTABLE_RECORD_CONSTRUCT: usize = 0xc400_0000;
    pub const OPAQUE_VTABLE_RECORD_CONSTRUCT_DEFAULT: usize = 0xc500_0000;
    // 0xc600_0000: dedicated to cxx/vtable_089a8414_construct's target-width fixture.
    pub const VTABLE_089A8414_CONSTRUCT: usize = 0xc600_0000;
    // 0xc200_0000: dedicated to cxx/opaque_shared_record_construct's
    // target-width source, vtable, shared-object, and destination fixture.
    pub const OPAQUE_SHARED_RECORD_CONSTRUCT: usize = 0xc200_0000;
    // 0xc300_0000: dedicated to cxx/shared_record_construct's target-width
    // storage and shared-handle fixture; mappings never unmap.
    pub const SHARED_RECORD_CONSTRUCT: usize = 0xc300_0000;
    // 0xc310_0000: dedicated to cxx/shared_record_create's target-width
    // storage and shared-handle fixture; mappings never unmap.
    pub const SHARED_RECORD_CREATE: usize = 0xc310_0000;
    // 0x6700_0000: dedicated to app/registry's raw-u32 owner field
    // fixture for field_dc_as_class_4a80; mappings never unmap, so no other
    // user may share this hint.
    pub const FIELD_DC_AS_CLASS_4A80: usize = 0x6700_0000;
    // 0x6d00_0000: dedicated to app/registry's raw-u32 owner field
    // fixture for field_dc_as_class_4b00; mappings never unmap, so no other
    // user may share this hint.
    pub const FIELD_DC_AS_CLASS_4B00: usize = 0x6d00_0000;
    // 0x6d10_0000: dedicated to app/context_select_item_and_dispatch's
    // target-width owner and pair-table fixture; mappings never unmap, so no
    // other port may share this hint.
    pub const CONTEXT_SELECT_ITEM_AND_DISPATCH: usize = 0x6d10_0000;
    // 0x7e00_0000 and 0x7e10_0000: dedicated to crypto/bio_handle_write's
    // target-width BIO fixture; mappings never unmap.
    pub const BIO_HANDLE_WRITE: usize = 0x7e00_0000;
    pub const BIO_HANDLE_WRITE_FAILURE: usize = 0x7e10_0000;
    // 0x7ff8_0000 and 0x7ff9_0000: dedicated to
    // ui/object_resource_max_ordinal_for_presence's target-width fixtures;
    // mappings never unmap.
    pub const OBJECT_RESOURCE_MAX_ORDINAL_FOR_PRESENCE: usize = 0x7ff8_0000;
    pub const OBJECT_RESOURCE_MAX_ORDINAL_FOR_PRESENCE_RAW_SELECTOR: usize = 0x7ff9_0000;
    pub const VIEW_TIMER: usize = 0x2000_0000;
    // 0x2100_0000: dedicated to util/raster_profile's raw-u32 active and
    // successor profile fixture; mappings never unmap, so no other user may
    // share it.
    pub const RASTER_PROFILE_END: usize = 0x2100_0000;
    // 0xe000_0000: dedicated to ui/plst_task_complete's raw-u32 task and
    // element fixture; mappings never unmap, so no other user may share it.
    pub const PLST_TASK_COMPLETE: usize = 0xe000_0000;
    // 0xe010_0000: dedicated to ui/plst_task_resource_callback's raw-u32
    // task and element fixture; mappings never unmap, so no other user may
    // share it.
    pub const PLST_TASK_RESOURCE_CALLBACK: usize = 0xe010_0000;
    pub const STRING_TABLE: usize = 0x2100_0000;
    pub const VIEW_EVENT_TIMER_STOP: usize = 0x5b00_0000;
    // 0x6000_0000 is reserved for app::view_event's localized-flag
    // fixture; mappings never unmap, so no other test may reuse it.
    pub const VIEW_EVENT_LOCALIZED_FLAGS: usize = 0x6000_0000;
    // 0x2500_0000, not the sequential 0x2200_0000: sibling ports in
    // flight take the sequential slots, and a collision skips tests
    // silently on every host.
    pub const IAP_THREAD_SLOT_POLL: usize = 0x2500_0000;
    pub const SCHEMA_TO_INDEX: usize = 0x2600_0000;
    // 0x2700_0000, skipping the sequential 0x2200_0000..0x2400_0000:
    // sibling ports in flight take the sequential slots, and a
    // collision skips tests silently on every host.
    pub const STRING_VIEW: usize = 0x2700_0000;
    pub const CONDVAR_WAIT_FOREVER_SIGNALED: usize = 0x2800_0000;
    pub const CONDVAR_WAIT_FOREVER_EMPTY: usize = 0x2900_0000;
    // 0x2a00_0000: dedicated to app/stream_ensure_available's raw-u32 stream
    // and callback-record fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const STREAM_ENSURE_AVAILABLE: usize = 0x2a00_0000;
    // 0x2d00_0000, skipping 0x2a00_0000..0x2c00_0000: sibling ports in
    // flight take the sequential slots, and a collision skips tests
    // silently on every host.
    pub const VIEW_BASE: usize = 0x2d00_0000;
    pub const SERVICE_MANAGER_SECONDARY_HANDLER: usize = 0x3600_0000;
    // 0x6a00_0000: dedicated to ui/geometry_changed's target-width view,
    // parent, and owner fixture; mappings never unmap.
    pub const VIEW_BASE_GEOMETRY_CHANGED: usize = 0x6a00_0000;
    // 0x7b00_0000: dedicated to app/service_manager's raw-u32 slot-handler
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const SERVICE_MANAGER_SLOT_HANDLER: usize = 0x7b00_0000;
    // 0x8600_0000: dedicated to app/service_handler_masked_event_dispatch's
    // raw-u32 service-manager and handler fixture; mappings never unmap, so
    // no other user may share this hint.
    pub const SERVICE_HANDLER_MASKED_EVENT_DISPATCH: usize = 0x8600_0000;
    // 0x8700_0000: dedicated to app/scoped_context's raw-u32 owner context
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const SCOPED_CONTEXT_OWNER_STRING: usize = 0x8700_0000;
    pub const CHARACTER_CLASS: usize = 0x3700_0000;
    pub const TIMER_RESET_4000: usize = 0x3800_0000;
    // 0x8800_0000: dedicated to app/context_timer_restart's embedded
    // target-width timer fixture; mappings never unmap.
    pub const CONTEXT_TIMER_RESTART: usize = 0x8800_0000;
    // 0x3900_0000, skipping 0x2e00_0000..0x3500_0000: sibling ports in
    // flight take the sequential slots, and a collision skips tests
    // silently on every host.
    // 0x5d10_0000: dedicated to cxx/string_record_clone's target-width
    // source and C-string fixture; mappings never unmap.
    pub const STRING_RECORD_CLONE: usize = 0x5d10_0000;
    pub const SET_STRING: usize = 0x3900_0000;
    // 0x4c00_0000, skipping 0x3a00_0000..0x4b00_0000: sibling ports in
    // flight take the sequential slots, and a collision skips tests
    // silently on every host.
    pub const TDAT_NODE_FIND: usize = 0x4c00_0000;
    // 0x4500_0000: dedicated to ui/tdat_node_find's alternate-key
    // (node+0x118/+0x11c) lookup fixtures; 0x4500..0x45ff is free of
    // other hint constants.
    pub const TDAT_NODE_FIND_ALT_ID: usize = 0x4500_0000;
    // 0x5000_0000: dedicated to app/typed_handler_registry_lookup's raw-u32
    // registry and table fixture; mappings never unmap, so no other test may
    // reuse this hint.
    pub const TYPED_HANDLER_REGISTRY_LOOKUP: usize = 0x5000_0000;
    // 0x5200_0000: dedicated to util/hash_table_slot_find's target-width
    // table, bucket, node, and key fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const HASH_TABLE_SLOT_FIND: usize = 0x5200_0000;
    // 0x5100_0000: dedicated to app/type_handler_lookup's raw-u32 registry
    // fixture; mappings never unmap, so no other test may reuse this hint.
    pub const TYPE_HANDLER_LOOKUP_WRAPPER: usize = 0x5100_0000;
    // 0x5300_0000: dedicated to app/type_handler_lookup_alt_id's raw-u32
    // registry fixture; mappings never unmap, so no other test may reuse this hint.
    pub const TYPE_HANDLER_LOOKUP_ALT_ID: usize = 0x5300_0000;
    // 0x5c90_0000: dedicated to app/type_handler_lookup_primary_id's raw-u32
    // registry fixture; mappings never unmap, so no other test may reuse it.
    pub const TYPE_HANDLER_LOOKUP_PRIMARY_ID: usize = 0x5c90_0000;
    // 0x3a00_0000: sibling ports in flight take the sequential slots,
    // and a collision skips tests silently on every host.
    pub const KINDED_CONTROLLER: usize = 0x3a00_0000;
    // 0x3b00_0000: sibling ports in flight take the sequential slots,
    // and a collision skips tests silently on every host.
    pub const ELEMENT_REFERENCE_COOKIE: usize = 0x3b00_0000;
    // 0x3c00_0000: sibling ports in flight take the sequential slots,
    // and a collision skips tests silently on every host.
    pub const BIT_SET_TEST: usize = 0x3c00_0000;
    // 0x3d00_0000: dedicated to cxx/opaque_storage_destroy's raw-u32 object
    // fixture; mappings never unmap, so no other test may reuse this hint.
    pub const OPAQUE_STORAGE_DESTROY: usize = 0x3d00_0000;
    // 0x4100_0000, skipping 0x3d00_0000..0x4000_0000: sibling ports in
    // flight take the sequential slots, and a collision skips tests
    // silently on every host.
    pub const PLST_SLOT_ITEM: usize = 0x4100_0000;
    // 0x4180_0000: dedicated to ui/plst_slot_source_clone's raw-u32 element
    // and slot-source fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const PLST_SLOT_SOURCE_CLONE: usize = 0x4180_0000;
    // 0x5e00_0000: dedicated to ui/plst_slot_materialize's raw-u32 element,
    // header, slot-record, and source-buffer fixture; mappings never unmap.
    pub const PLST_SLOT_MATERIALIZE: usize = 0x5e00_0000;
    // 0x5f10_0000: dedicated to cxx/deque_front_advance_release's
    // target-width segment-map fixture; mappings never unmap.
    pub const DEQUE_FRONT_ADVANCE_RELEASE: usize = 0x5f10_0000;
    // 0x5f20_0000: dedicated to cxx/deque_front_advance_release's empty
    // deque target-width segment-map fixture; mappings never unmap.
    pub const DEQUE_FRONT_ADVANCE_RELEASE_EMPTY: usize = 0x5f20_0000;
    // 0x4600_0000, skipping 0x4200_0000..0x4500_0000: sibling ports in
    // flight take the sequential slots, and a collision skips tests
    // silently on every host.
    pub const PENDING_EVENT_INSERT: usize = 0x4600_0000;
    // 0x5f00_0000: dedicated to cxx/stream_read_cxx_string's raw-u32
    // descriptor, owner-state, and reader fixture; mappings never unmap.
    pub const CXX_STREAM_READ_CXX_STRING: usize = 0x5f00_0000;
    // 0x5f10_0000: dedicated to cxx/record_priority_heap_adjust's raw-u32
    // priority-record and heap-array fixture; mappings never unmap.
    pub const RECORD_PRIORITY_HEAP_ADJUST: usize = 0x5f10_0000;
    // 0x4a00_0000, skipping the sequential 0x4700_0000..0x4900_0000:
    // sibling ports in flight take the sequential slots, and a
    // collision skips tests silently on every host.
    pub const TAGGED_WORD_BUFFER: usize = 0x4a00_0000;
    // 0x5a00_0000, skipping 0x4b00_0000..0x5900_0000: sibling ports in
    // flight take the sequential slots, and a collision skips tests
    // silently on every host.
    pub const ELEMENT_REFERENCE_PERSISTENT_ID: usize = 0x5a00_0000;
    pub const TIMED_TRANSITION: usize = 0x5c00_0000;
    // 0x5c30_0000: dedicated to app/locked_callback_list_any's target-width
    // list, semaphore slot, and node fixtures; mappings never unmap.
    pub const LOCKED_CALLBACK_LIST_ANY: usize = 0x5c30_0000;
    // 0x5c40_0000: dedicated to kernel/semaphore_wait's target-width
    // semaphore-record table fixture; mappings never unmap.
    pub const KERNEL_SEMAPHORE_WAIT: usize = 0x5c40_0000;
    // 0x5c10_0000: dedicated to cxx/string_object's raw-u32 path-chain
    // context, nodes, and C-string fixture; mappings never unmap.
    pub const PATH_CHAIN_TO_STRING: usize = 0x5c10_0000;
    // 0x5c20_0000: dedicated to cxx/string_object's raw-u32 linked-chain
    // constructor fixture; mappings never unmap.
    pub const STRING_OBJECT_CONSTRUCT_FROM_LINKED_CHAIN: usize = 0x5c20_0000;
    // 0x5b00_0000: dedicated to app/transition_page_clone's raw-u32 source,
    // destination, and transition fixtures; mappings never unmap, so no other
    // test may share this hint.
    pub const TRANSITION_PAGE_CLONE: usize = 0x5b00_0000;
    // 0x5d00_0000: dedicated to util/tagged_resource_payload's raw-u32
    // indirect-value fixture; mappings never unmap, so no other test may
    // share this hint.
    pub const TAGGED_RESOURCE_VALUE: usize = 0x5d00_0000;
    // 0x6a00_0000, far clear of the sequential run: sibling ports in
    // flight take the next free slots, and a collision skips tests
    // silently on every host.
    pub const HFS_BTREE_GET_NODE: usize = 0x6a00_0000;
    // 0x6900_0000: dedicated to fs/cache_block_prepare's raw-u32 request
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const CACHE_BLOCK_PREPARE: usize = 0x6900_0000;
    // 0x6b00_0000: dedicated to fp_misc query-object destructor tests;
    // fixture mappings never unmap, so no other user may share this hint.
    pub const QUERY_OBJECT_DESTROY: usize = 0x6b00_0000;
    // 0x6c00_0000: dedicated to ui/query_object_display_name's raw-u32
    // query and backend fixture; mappings never unmap.
    pub const QUERY_OBJECT_DISPLAY_NAME: usize = 0x6c00_0000;
    // 0x7a00_0000: dedicated to cxx/list_item_count's raw-u32 embedded
    // collection-pointer fixtures; mappings never unmap.
    pub const LIST_ITEM_COUNT: usize = 0x7a00_0000;
    // 0x7f10_0000: dedicated to cxx/list_cursor_count's raw-u32 list and
    // cursor-record fixture; mappings never unmap, so no other user may share it.
    pub const LIST_CURSOR_COUNT: usize = 0x7f10_0000;
    // 0x7f00_0000: dedicated to cxx/bit_set's write-transition fixture;
    // fixture mappings never unmap, so no other user may share this hint.
    pub const BIT_SET_WRITE: usize = 0x7f00_0000;
    // 0x7f20_0000: dedicated to app/event_source's raw-u32 owning-registry
    // fixture; fixture mappings never unmap, so no other user may share it.
    pub const EVENT_SOURCE_REGISTRY: usize = 0x7f20_0000;
    // 0xb600_0000: dedicated to cxx/bit_set's clear-transition fixture;
    // fixture mappings never unmap, so no other user may share this hint.
    pub const BIT_SET_CLEAR: usize = 0xb600_0000;
    // 0xcc00_0000: dedicated to cxx/bit_set's constructor allocation
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const BIT_SET_CONSTRUCT: usize = 0xcc00_0000;
    // 0xce00_0000: dedicated to cxx/bit_set's clear-all fixture; fixture
    // mappings never unmap, so no other user may share this hint.
    pub const BIT_SET_CLEAR_ALL: usize = 0xce00_0000;
    // 0x7fa0_0000: dedicated to cxx/bit_set's next-set-bit search fixture;
    // fixture mappings never unmap, so no other user may share this hint.
    pub const BIT_SET_FIND_NEXT_SET: usize = 0x7fa0_0000;
    // 0x7f30_0000: dedicated to util/singly_linked_list_unlink's raw-u32
    // link-field fixture; mappings never unmap, so no other test may share it.
    pub const SINGLY_LINKED_LIST_UNLINK: usize = 0x7f30_0000;
    // 0x7f40_0000: dedicated to cxx/string_map_assign_tree_records' raw-u32
    // tree, header, and node fixtures; mappings never unmap.
    pub const STRING_MAP_ASSIGN_TREE_RECORDS: usize = 0x7f40_0000;
    // 0xc000_0000: dedicated to cxx/bit_set's copy-constructor source
    // fixture; fixture mappings never unmap, so no other user may share it.
    pub const BIT_SET_COPY_SOURCE: usize = 0xc000_0000;
    // 0xd900_0000: dedicated to cxx/timer_stop_then_clear_bit_set's raw-u32
    // embedded bit-set and timer fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const TIMER_STOP_THEN_CLEAR_BIT_SET: usize = 0xd900_0000;
    // 0xd980_0000: dedicated to app/showcase_clear_timer_slots's raw-u32
    // showcase and timer fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const SHOWCASE_CLEAR_TIMER_SLOTS: usize = 0xd980_0000;
    // 0xd940_0000: dedicated to app/input_sequence_find_item's raw-u32
    // owner, collection, and item fixtures; mappings never unmap.
    pub const INPUT_SEQUENCE_FIND_ITEM: usize = 0xd940_0000;
    // 0xda00_0000: dedicated to app/showcase_pending_queues_complete's
    // raw-u32 Showcase, slot queues, and queue-completion state fixture;
    // mappings never unmap, so no other test may reuse this hint.
    pub const SHOWCASE_PENDING_QUEUES_COMPLETE: usize = 0xda00_0000;
    // 0xdc00_0000: dedicated to h264/strided_plane_copy's target-width source
    // index and destination plane fixture; mappings never unmap.
    pub const STRIDED_PLANE_COPY: usize = 0xdc00_0000;
    // 0xda80_0000: dedicated to app/showcase_initialization_complete's raw-u32
    // Showcase state fixture; mappings never unmap, so no other test may
    // share this hint.
    pub const SHOWCASE_INITIALIZATION_COMPLETE: usize = 0xda80_0000;
    // 0xdb00_0000: dedicated to ui/selection_schedule_timer's target-width
    // controller, timer, and bit-set fixture; mappings never unmap.
    pub const SELECTION_SCHEDULE_TIMER: usize = 0xdb00_0000;
    // 0x6c00_0000, far clear of the sequential run: sibling ports in
    // flight take the next free slots, and a collision skips tests
    // silently on every host.
    pub const IAP_THREAD_SLOT_WAIT: usize = 0x6c00_0000;
    // 0x6c40_0000: dedicated to app/iap_incoming_process_thread's
    // slot-deadline wrapper fixture; mappings never unmap, so no other user
    // may share it.
    pub const IAP_THREAD_SLOT_DEADLINE: usize = 0x6c40_0000;
    // 0x6cc0_0000: dedicated to app/iap_incoming_process_thread's
    // slot-release fixture; mappings never unmap, so no other user may share it.
    pub const IAP_THREAD_SLOT_RELEASE: usize = 0x6cc0_0000;
    // 0x6d80_0000: dedicated to util/unique_word_array_insert's raw-u32
    // header and backing-array fixture; mappings never unmap, so no other user
    // may share this hint.
    pub const UNIQUE_WORD_ARRAY_INSERT: usize = 0x6d80_0000;
    // 0x6fb0_0000: dedicated to app/object_activate_until_query_matches's
    // raw-u32 opaque-object traversal fixture; mappings never unmap, so no
    // other test may reuse this hint.
    pub const OBJECT_ACTIVATE_UNTIL_QUERY_MATCHES: usize = 0x6fb0_0000;
    // 0x6c80_0000: dedicated to cxx/hash_table_bucket_slot's raw-u32 table
    // and bucket-array fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const HASH_TABLE_BUCKET_SLOT: usize = 0x6c80_0000;
    // 0x6c90_0000: dedicated to crypto/bio_find_type's target-width BIO
    // chain and method-type-word fixture; mappings never unmap, so no other
    // user may share it.
    pub const BIO_FIND_TYPE: usize = 0x6c90_0000;
    // 0x6d00_0000: dedicated to util/global_state's raw-u32 table, bucket,
    // record, and string fixtures; mappings never unmap, so no other test
    // may share this hint.
    pub const GLOBAL_STATE_SLOT_FIND: usize = 0x6d00_0000;
    // 0x6e80_0000: dedicated to app/two_value_wheel_node's target-width
    // node and FixedValue fixtures; mappings never unmap, so no other test
    // may share this hint.
    pub const TWO_VALUE_WHEEL_NODE: usize = 0x6e80_0000;
    // 0x6e00_0000: dedicated to heap/word_buffer's raw-u32 singleton-reset
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const WORD_BUFFER_RESET_OPTIONAL_SINGLETON: usize = 0x6e00_0000;
    // 0x6e40_0000: dedicated to app/slot_buffers_release's raw-u32 owner
    // fixture; mappings never unmap, so no other test may reuse it.
    pub const SLOT_BUFFERS_RELEASE: usize = 0x6e40_0000;
    // 0x6e60_0000: dedicated to cxx/stream_write_owner_destroy's raw-u32
    // owner, stream object, and native-width vtable fixture; mappings never
    // unmap, so no other test may reuse it.
    pub const STREAM_WRITE_OWNER_DESTROY: usize = 0x6e60_0000;
    // 0x6e70_0000: dedicated to app/transition_page_reset_animation_targets
    // raw-u32 page, shared-context, and default-record fixture; mappings never
    // unmap, so no other test may reuse it.
    pub const TRANSITION_PAGE_RESET_ANIMATION_TARGETS: usize = 0x6e70_0000;
    // 0x6eb0_0000 / 0x6ec0_0000: dedicated to
    // app/callback_queue_context_post's target-width context and lifecycle
    // fixtures; mappings never unmap, so no other port may share either hint.
    pub const CALLBACK_QUEUE_CONTEXT_POST: usize = 0x6eb0_0000;
    pub const CALLBACK_QUEUE_CONTEXT_POST_NON_IDLE: usize = 0x6ec0_0000;
    // 0x6f00_0000: dedicated to app/service_handler_pending_event_reset's
    // session fixture; mappings never unmap, so no other test may reuse it.
    pub const SERVICE_HANDLER_PENDING_EVENT_RESET: usize = 0x6f00_0000;
    // 0x7a10_0000: dedicated to util/singly_linked_list_append's raw-u32
    // head and node fixture; mappings never unmap, so no other user may share it.
    pub const SINGLY_LINKED_LIST_APPEND: usize = 0x7a10_0000;
    // 0x6f10_0000: dedicated to util/bit_buffer_copy's raw-u32 cursor and
    // output-buffer fixture; mappings never unmap, so no other user may share it.
    pub const BIT_BUFFER_COPY: usize = 0x6f10_0000;
    // 0x6c20_0000: dedicated to util/queue_match_and_promote's raw-u32
    // intrusive queue and entry fixture; mappings never unmap.
    pub const QUEUE_MATCH_AND_PROMOTE: usize = 0x6c20_0000;
    // 0x6d60_0000: dedicated to util/queue_refresh_and_match_kind_two's
    // target-width context fixture; mappings never unmap.
    pub const QUEUE_REFRESH_AND_MATCH_KIND_TWO: usize = 0x6d60_0000;
    // 0x6f20_0000: dedicated to util/bit_buffer_set_bit's raw-u32 byte
    // storage fixture; mappings never unmap, so no other user may share it.
    pub const BIT_BUFFER_SET_BIT: usize = 0x6f20_0000;
    // 0x6f30_0000: dedicated to util/bit_buffer_ensure_capacity's target-width
    // allocation fixture; mappings never unmap.
    pub const BIT_BUFFER_ENSURE_CAPACITY: usize = 0x6f30_0000;
    // 0x9200_0000: dedicated to app/service_handler_status's raw-u32 query
    // object fixture; mappings never unmap, so no other user may share it.
    pub const SERVICE_HANDLER_STATUS_QUERY: usize = 0x9200_0000;
    // 0x7c00_0000: dedicated to heap/word_buffer's raw-u32 assignment
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const MARKED_WORD_BUFFER_ASSIGN: usize = 0x7c00_0000;
    // 0x7c10_0000: dedicated to heap/word_buffer's raw-u32 comparator
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const MARKED_WORD_BUFFER_COMPARE: usize = 0x7c10_0000;
    // 0x6d90_0000: dedicated to app/notes_view_reset_resources's raw-u32
    // owned-object fixture; mappings never unmap, so no other user may share it.
    pub const NOTES_VIEW_RESET_RESOURCES: usize = 0x6d90_0000;
    // 0x6dc0_0000: dedicated to heap/owned_pair_destroy_and_deallocate's
    // target-width owner and pair fixture; mappings never unmap, so no other
    // user may share it.
    pub const OWNED_PAIR_DESTROY_AND_DEALLOCATE: usize = 0x6dc0_0000;

    // 0x7e00_0000: dedicated to class-0x7f80 artwork-slot fixtures;
    // fixture mappings never unmap, so no other user may share this hint.
    pub const ARTWORK_SLOT_AVAILABILITY: usize = 0x7e00_0000;
    // 0x7e10_0000: dedicated to app/artwork_cache_prepare's raw-u32 cache
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const ARTWORK_CACHE_PREPARE: usize = 0x7e10_0000;
    // 0x6e90_0000: dedicated to app/selection_available's raw-u32 object
    // and primary/fallback table fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const SELECTION_AVAILABLE: usize = 0x6e90_0000;
    // 0x7d00_0000: dedicated to runtime/ctype isdigit's raw-u32 LC_CTYPE
    // table fixture; mappings never unmap, so no other user may share this
    // hint.
    pub const CTYPE_ISDIGIT: usize = 0x7d00_0000;
    // 0x7d10_0000: dedicated to app/context_index_matches_context_field_f40's
    // target-width context and index-table fixture; mappings never unmap.
    pub const CONTEXT_INDEX_MATCHES_CONTEXT_FIELD_F40: usize = 0x7d10_0000;
    // 0x1230_0000: dedicated to util/indexed_state_set_and_poll's raw-u32
    // state-table and selected-record fixture; mappings never unmap, so no
    // other user may share this hint.
    pub const INDEXED_STATE_SET_AND_POLL: usize = 0x1230_0000;
    // 0x1240_0000: dedicated to util/indexed_state_status's raw-u32
    // state-table and selected-record fixture; mappings never unmap, so no
    // other user may share this hint.
    pub const INDEXED_STATE_STATUS: usize = 0x1240_0000;
    // 0x1250_0000: dedicated to util/indexed_record_bounded_value's raw-u32
    // header and record fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const INDEXED_RECORD_BOUNDED_VALUE: usize = 0x1250_0000;
    // 0x0400_0000: dedicated to runtime/ctype isspace's raw-u32 LC_CTYPE
    // table fixture; mappings never unmap, so no other user may share this
    // hint.
    pub const CTYPE_ISSPACE: usize = 0x0400_0000;
    // 0x6000_0000: dedicated to runtime/ctype isxdigit's raw-u32 LC_CTYPE
    // table fixture; mappings never unmap, so no other user may share this
    // hint.
    pub const CTYPE_ISXDIGIT: usize = 0x6000_0000;
    // 0x7100_0000: dedicated to ui/coordinate_origin's raw-u32 display
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const COORDINATE_OWNER_DISPLAY_LAYER: usize = 0x7100_0000;
    // 0x7300_0000: dedicated to crypto/bio_ctrl's raw-u32 BIO/method
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const BIO_CTRL: usize = 0x7300_0000;
    // 0x0401_0000: dedicated to crypto/bio_puts's raw-u32 BIO/method
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const BIO_PUTS: usize = 0x0401_0000;
    // 0x6600_0000: dedicated to crypto/bio_free's raw-u32 BIO/method
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const BIO_FREE: usize = 0x6600_0000;
    // 0x6da0_0000: dedicated to cxx/byte_vector_owner_push_back's raw-u32
    // owner and backing-storage fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const BYTE_VECTOR_OWNER_PUSH_BACK: usize = 0x6da0_0000;
    // 0x7200_0000: dedicated to crypto/bio_copy_next_retry's raw-u32 BIO
    // chain fixture; mappings never unmap, so no other user may share this
    // hint.
    pub const BIO_COPY_NEXT_RETRY: usize = 0x7200_0000;
    // 0x7400_0000: dedicated to sqlite/nested_parse's raw-u32 Parse/db
    // fixture; mappings never unmap.
    pub const SQLITE_NESTED_PARSE: usize = 0x7400_0000;
    // 0x6800_0000: dedicated to sqlite/src_list_lookup's raw-u32 database,
    // schema, and Table reference-count fixture; mappings never unmap.
    pub const SQLITE_SRC_LIST_LOOKUP: usize = 0x6800_0000;
    // 0x7500_0000: dedicated to sqlite/find_table's raw-u32 sqlite3/Db
    // fixture; fixture mappings never unmap, so no other user may share
    // this hint.
    pub const SQLITE_FIND_TABLE: usize = 0x7500_0000;
    // 0x8500_0000: dedicated to sqlite/find_index's raw-u32 sqlite3/Db
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const SQLITE_FIND_INDEX: usize = 0x8500_0000;
    // 0x7700_0000: dedicated to sqlite/find_collation_encoding's raw-u32
    // sqlite3/default-collation fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const SQLITE_FIND_COLLATION_ENCODING: usize = 0x7700_0000;
    // 0x7f50_0000: dedicated to sqlite/locate_coll_seq's raw-u32
    // sqlite3/aDb/Schema and CollSeq fixtures; mappings never unmap, so no
    // other user may share this hint.
    pub const SQLITE_LOCATE_COLL_SEQ: usize = 0x7f50_0000;
    // 0x7f60_0000: dedicated to sqlite/column_default's raw-u32
    // sqlite3/aDb/Schema and Column-array fixtures; mappings never
    // unmap, so no other user may share this hint.
    pub const SQLITE_COLUMN_DEFAULT: usize = 0x7f60_0000;
    // 0x7f70_0000: dedicated to sqlite/column_index's raw-u32 Table and
    // Column-array fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const SQLITE_COLUMN_INDEX: usize = 0x7f70_0000;
    // 0x7f30_0000: dedicated to app/character_class_scan's target-width
    // parser and character-class-table fixture; mappings never unmap, so no
    // other user may share this hint.
    pub const PARSER_SCAN_TO_CLASS_BOUNDARY: usize = 0x7f30_0000;
    // 0x7f31_0000: dedicated to app/parser_scan_to_token_boundary's
    // target-width parser and character-class-table fixture; mappings never
    // unmap, so no other user may share this hint.
    pub const PARSER_SCAN_TO_TOKEN_BOUNDARY: usize = 0x7f31_0000;
    // 0x7f32_0000: dedicated to cxx/owned_offset_object_delete's raw-u32
    // object fixture; mappings never unmap, so no other test may share it.
    pub const OWNED_OFFSET_OBJECT_DELETE: usize = 0x7f32_0000;
    // 0x7f35_0000: dedicated to util/utf16_next_whitespace_delimited_range's
    // raw-u32 UTF-16 cursor and range fixture; mappings never unmap, so no
    // other user may share this hint.
    pub const UTF16_NEXT_WHITESPACE_DELIMITED_RANGE: usize = 0x7f35_0000;
    // 0x8300_0000: dedicated to sqlite/index_key_info's raw-u32 Index,
    // KeyInfo, collation-array, and tracked-allocation fixtures; mappings
    // never unmap, so no other user may share this hint.
    pub const SQLITE_INDEX_KEY_INFO: usize = 0x8300_0000;
    // 0x8200_0000: dedicated to sqlite/index_affinity's raw-u32 Index,
    // Table, column-index, and Column-array fixture; mappings never unmap.
    pub const SQLITE_INDEX_AFFINITY: usize = 0x8200_0000;
    // 0x8600_0000: dedicated to sqlite/open_table_and_indices' target-width
    // Parse and Table fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const SQLITE_OPEN_TABLE_AND_INDICES: usize = 0x8600_0000;
    // 0x8400_0000: dedicated to sqlite/expr_list_key_info's raw-u32 Parse,
    // ExprList, KeyInfo, and allocation fixtures; mappings never unmap.
    pub const SQLITE_EXPR_LIST_KEY_INFO: usize = 0x8400_0000;
    // 0x8500_0000: dedicated to sqlite/vtab_lock's target-width Parse,
    // sqlite3, and VTable pointer-list fixtures; mappings never unmap.
    pub const SQLITE_VTAB_LOCK: usize = 0x8500_0000;
    // 0x7600_0000: dedicated to app/resource_chain's
    // resource_chain_find_on_current_task chain fixture (the context
    // block carries the chain head as a raw u32 word); mappings never
    // unmap, so no other user may share this hint.
    pub const RESOURCE_CHAIN_ON_CURRENT_TASK: usize = 0x7600_0000;
    // 0x7800_0000: dedicated to heap/releasable_buffer's raw-u32 data
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const RELEASABLE_BUFFER: usize = 0x7800_0000;
    // 0xb400_0000: dedicated to heap/three_buffer_owner's raw-u32 data
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const THREE_BUFFER_OWNER_RELEASE: usize = 0xb400_0000;
    // 0xb500_0000: dedicated to heap/sixteen_resource_slots's raw-u32
    // resource fixture; mappings never unmap, so no other user may share
    // this hint.
    pub const SIXTEEN_RESOURCE_SLOTS_DESTROY: usize = 0xb500_0000;
    // 0xcd00_0000: dedicated to heap/two_buffer_owner's raw-u32 buffer and
    // data fixture; mappings never unmap, so no other user may share this
    // hint.
    pub const TWO_BUFFER_OWNER_RELEASE: usize = 0xcd00_0000;
    // 0xce00_0000: dedicated to heap/bucket_chain_table's target-width
    // bucket and linked-node fixture; mappings never unmap, so no other user
    // may share this hint.
    pub const BUCKET_CHAIN_TABLE_DESTROY: usize = 0xce00_0000;
    // 0xc500_0000: dedicated to heap/three_buffer_owner_create's raw-u32
    // allocation fixture; mappings never unmap, so no other user may share
    // this hint.
    pub const THREE_BUFFER_OWNER_CREATE: usize = 0xc500_0000;
    // 0x6d00_0000: dedicated to ui/string_view_array's derived-view
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const STRING_VIEW_ARRAY: usize = 0x6d00_0000;
    // 0x7900_0000: dedicated to ui/element_reference_item_count's raw-u32
    // reference/target/collection fixtures; mappings never unmap, so no other
    // user may share this hint.
    pub const ELEMENT_REFERENCE_ITEM_COUNT: usize = 0x7900_0000;
    // 0x7910_0000: dedicated to app/genius_request_selection_is_complete's
    // request, element-reference, target, and collection fixture; mappings
    // never unmap, so no other user may share this hint.
    pub const GENIUS_REQUEST_SELECTION_IS_COMPLETE: usize = 0x7910_0000;
    // 0xa800_0000: dedicated to ui/element_reference_target_field_210's
    // raw-u32 reference/target fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const ELEMENT_REFERENCE_TARGET_FIELD_210: usize = 0xa800_0000;
    // 0xa900_0000: dedicated to app/resource/cache_available's raw-u32
    // object/vtable fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RESOURCE_CACHE_GET_IF_AVAILABLE: usize = 0xa900_0000;
    // 0x6a00_0000: dedicated to ui/element_reference_target_flag_bit_0's
    // raw-u32 reference/target fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const ELEMENT_REFERENCE_TARGET_FLAG_BIT_0: usize = 0x6a00_0000;
    // 0x6800_0000: dedicated to cxx/tagged_record's raw-u32 payload field
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const TAGGED_RECORD_PAYLOAD_LITI_CLASS_CHECK: usize = 0x6800_0000;
    // `heap/pool.rs` maps its own arena at 0x0800_0000 through a separate
    // path: it needs only bit 31 clear, not full u32 addressability.
    // 0x8100_0000: dedicated to cxx/draw_state_surface's surface-descriptor
    // fixture (the record's +0x1c stores the surface identity as a raw u32);
    // mappings never unmap, so no other user may share this hint.
    pub const SURFACE_ATTACH: usize = 0x8100_0000;
    // 0xae00_0000: dedicated to cxx/draw_state_font's raw-u32 font-object
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const DRAW_STATE_FONT: usize = 0xae00_0000;
    // 0x8200_0000: dedicated to cxx/list_cursor_index's raw-u32
    // list/cursor fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const LIST_CURSOR_INDEX: usize = 0x8200_0000;
    // 0x8300_0000: dedicated to cxx/list_cursor_item_at's raw-u32
    // list/cursor fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const LIST_CURSOR_ITEM_AT: usize = 0x8300_0000;
    // 0x81f0_0000: dedicated to cxx/list_cursor_base_index's raw-u32
    // list/cursor fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const LIST_CURSOR_BASE_INDEX: usize = 0x81f0_0000;
    // 0x9e00_0000: dedicated to util/attr_record's raw-u32
    // named-attribute table fixture; mappings never unmap, so no other user
    // may share this hint.
    pub const NAMED_ATTRIBUTE_LOOKUP: usize = 0x9e00_0000;
    // 0x9f00_0000: dedicated to ui/tdat_payload's raw-u32 element, pool,
    // and payload fixture; mappings never unmap, so no other user may share it.
    pub const TDAT_PAYLOAD: usize = 0x9f00_0000;
    // 0xa900_0000: dedicated to fs/resource_reader_read_exact's raw-u32
    // file-handle fixture; mappings never unmap, so no other user may share it.
    pub const RESOURCE_READER_READ_EXACT: usize = 0xa900_0000;
    // 0xaa00_0000: dedicated to fs/resource_reader_seek_absolute's raw-u32
    // file-handle fixture; mappings never unmap, so no other user may share it.
    pub const RESOURCE_READER_SEEK_ABSOLUTE: usize = 0xaa00_0000;
    // 0xab00_0000: dedicated to jpeg/stream_read_byte's raw-u32 stream and
    // file-handle fixture; mappings never unmap, so no other user may share it.
    pub const JPEG_STREAM_READ_BYTE: usize = 0xab00_0000;
    // 0xb700_0000: dedicated to app/animation timing-wheel unlink fixtures;
    // mappings never unmap, so no other user may share this hint.
    pub const TIMING_WHEEL_REMOVE: usize = 0xb700_0000;
    // 0xb500_0000: dedicated to sqlite/change_cookie's target-width
    // Parse/database/schema fixture; mappings never unmap, so no other user
    // may share this hint.
    pub const SQLITE_CHANGE_COOKIE: usize = 0xb500_0000;
    // 0xba00_0000: dedicated to app/progress_layout_transition's raw-u32
    // controller, timer, and activity fixture; mappings never unmap, so no
    // other user may share this hint.
    pub const PROGRESS_LAYOUT_TRANSITION: usize = 0xba00_0000;
    // 0xbc00_0000: dedicated to app/fixed_value's refcounted-base
    // destructor fixture; mappings never unmap, so no other user may share
    // this hint.
    pub const REFCOUNTED_BASE_DESTROY: usize = 0xbc00_0000;
    // 0xc600_0000: dedicated to fs/shared_data's raw-u32 linked-list
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const SHARED_DATA_RELEASE: usize = 0xc600_0000;
    // 0xc610_0000: dedicated to fs/shared_data_initialize's raw-u32
    // linked-list fixture; mappings never unmap, so no other user may share it.
    pub const SHARED_DATA_INITIALIZE: usize = 0xc610_0000;
    // 0xc618_0000: dedicated to fs/shared_data_find_and_retain's raw-u32
    // linked-list fixture; mappings never unmap, so no other user may share it.
    pub const SHARED_DATA_FIND_AND_RETAIN: usize = 0xc618_0000;
    // 0xc620_0000: dedicated to mov/atom_node's raw-u32 recursive
    // post-order destructor fixture; mappings never unmap, so no other user
    // may share this hint.
    pub const MOV_ATOM_NODE_DESTROY: usize = 0xc620_0000;
    // 0xca00_0000: dedicated to app/iap_incoming_client_base's raw-u32
    // client-object and thread-context fixtures; mappings never unmap, so
    // no other user may share this hint.
    pub const IAP_INCOMING_CLIENT_BASE: usize = 0xca00_0000;
    // 0x4300_0000: dedicated to ui/current_window's raw-u32 session and
    // window fixture; mappings never unmap, so no other user may share
    // this hint.
    pub const CURRENT_WINDOW: usize = 0x4300_0000;
    // 0xc700_0000: dedicated to sqlite/integrity_check_append_msg's
    // target-width vararg string-list fixture; mappings never unmap, so no
    // other user may share this hint.
    pub const SQLITE_INTEGRITY_CHECK_APPEND_MSG: usize = 0xc700_0000;
    // 0xc800_0000: dedicated to app/context_scope's subject/current-context
    // predicate fixture; it carries raw-u32 scope and context links, and
    // fixture mappings never unmap, so no other user may share this hint.
    // 0xc000_0000: dedicated to ui/set_x_extent's raw-u32 view fixture;
    // fixture mappings never unmap, so no other user may share this hint.
    pub const VIEW_BASE_SET_X_EXTENT: usize = 0xc000_0000;
    // 0x9700_0000: dedicated to ui/set_y_extent's raw-u32 view fixture;
    // fixture mappings never unmap, so no other user may share this hint.
    pub const VIEW_BASE_SET_Y_EXTENT: usize = 0x9700_0000;
    pub const CONTEXT_SCOPE_SUBJECT_MATCHES_CONTEXT_FIELD_F40: usize = 0xc800_0000;
    // 0xc900_0000: dedicated to ui/element_reference_construct_string's
    // raw-u32 reference/vtable/target fixture; mappings never unmap, so no
    // other user may share this hint.
    pub const ELEMENT_REFERENCE_CONSTRUCT_STRING: usize = 0xc900_0000;
    // 0xcb00_0000: dedicated to app/handle_slot_18_predicate_and_state_is_two's
    // raw-u32 handle/state fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const HANDLE_SLOT_18_PREDICATE_AND_STATE: usize = 0xcb00_0000;
    // 0xe600_0000: dedicated to app/strided_buffer_entry's raw-u32 table
    // and layout fixture; fixture mappings never unmap, so no other user may
    // share this hint.
    pub const STRIDED_BUFFER_ENTRY: usize = 0xe600_0000;
    // 0xe700_0000: dedicated to app/path_probe's raw-u32 counted-mutex
    // guard-destructor fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const PATH_PROBE_GUARD_DESTROY: usize = 0xe700_0000;
    // 0xe800_0000: dedicated to app/path_probe's raw-u32 interface and
    // counted-mutex constructor fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const PATH_PROBE_GUARD_CONSTRUCT: usize = 0xe800_0000;
    // 0xe880_0000: dedicated to cxx/string_pair_word_uninitialized_copy's
    // raw-u32 source and destination record fixture; mappings never unmap.
    pub const CXX_STRING_PAIR_WORD_UNINITIALIZED_COPY: usize = 0xe880_0000;
    // 0xe8d0_0000: dedicated to cxx/cxx_string_uninitialized_copy's raw-u32
    // source and destination string-word fixture; mappings never unmap.
    pub const CXX_STRING_UNINITIALIZED_COPY: usize = 0xe8d0_0000;
    // 0xe890_0000: dedicated to cxx/cxx_string_range_assign's raw-u32 source
    // and destination string-word fixture; mappings never unmap.
    pub const CXX_STRING_RANGE_ASSIGN: usize = 0xe890_0000;
    // 0xe8a0_0000: dedicated to cxx/cxx_string_pair_range_assign's raw-u32
    // source and destination pair fixture; mappings never unmap.
    pub const CXX_STRING_PAIR_RANGE_ASSIGN: usize = 0xe8a0_0000;
    // 0xe8b0_0000: dedicated to cxx/cxx_string_pair_entry_range_assign's raw-u32
    // source and destination entry fixture; mappings never unmap.
    pub const CXX_STRING_PAIR_ENTRY_RANGE_ASSIGN: usize = 0xe8b0_0000;
    // 0xe8e0_0000: dedicated to cxx/cxx_string_pair_entry_range_copy_construct's
    // raw-u32 source and destination entry fixture; mappings never unmap.
    pub const CXX_STRING_PAIR_ENTRY_RANGE_COPY_CONSTRUCT: usize = 0xe8e0_0000;
    // 0xe8c0_0000: dedicated to cxx/cxx_string_vector_range_assign's raw-u32
    // source and destination 16-byte record fixture; mappings never unmap.
    pub const CXX_STRING_VECTOR_RANGE_ASSIGN: usize = 0xe8c0_0000;
    // 0xea00_0000: dedicated to app/path_probe's raw-u32 base-destructor
    // owner fixture; mappings never unmap, so no other user may share this hint.
    pub const PATH_PROBE_BASE_DESTROY: usize = 0xea00_0000;
    // 0xe900_0000: dedicated to app/timer_step_value's raw-u32 node and
    // value fixture; mappings never unmap, so no other user may share
    // this hint.
    pub const TIMER_STEP_VALUE: usize = 0xe900_0000;
    // 0xa000_0000: dedicated to util/resource_list's raw-u32 vector and
    // element fixture; mappings never unmap, so no other user may share it.
    pub const RESOURCE_LIST_DESTROY: usize = 0xa000_0000;
    // 0xa100_0000: dedicated to fs/cache_entry_flush's raw-u32 context link;
    // fixture mappings never unmap, so no other user may share this hint.
    pub const CACHE_ENTRY_FLUSH: usize = 0xa100_0000;
    // 0xed10_0000: dedicated to util/request_queue_clear_matching_entries'
    // raw-u32 queue and entry fixture; mappings never unmap, so no other user
    // may share this hint.
    pub const REQUEST_QUEUE_CLEAR_MATCHING_ENTRIES: usize = 0xed10_0000;
    // 0xee30_0000: dedicated to util/singly_linked_list_remove's raw-u32
    // head and node fixture; mappings never unmap, so no other user may share
    // this hint.
    pub const SINGLY_LINKED_LIST_REMOVE: usize = 0xee30_0000;
    // 0xee40_0000: dedicated to util/dynamic_array_remove's raw-u32 backing
    // storage fixture; mappings never unmap, so no other user may share it.
    pub const DYNAMIC_ARRAY_REMOVE: usize = 0xee40_0000;
    // 0xee60_0000: dedicated to util/word_array_remove_prefix's raw-u32
    // header and backing-word fixture; mappings never unmap, so no other user
    // may share this hint.
    pub const WORD_ARRAY_REMOVE_PREFIX: usize = 0xee60_0000;
    // 0xee50_0000: dedicated to ft/linked_module_find_by_class's raw-u32
    // owner, linked-record, and module fixture; mappings never unmap, so no
    // other user may share this hint.
    pub const FT_LINKED_MODULE_FIND_BY_CLASS: usize = 0xee50_0000;
    // 0xdb00_0000: dedicated to app/root_context_f9c_bound's raw-u32
    // root/context fixture; mappings never unmap, so no other user may share it.
    pub const ROOT_CONTEXT_F9C_BOUND: usize = 0xdb00_0000;
    // 0xd000_0000: dedicated to app/animation's destructor fixture;
    // mappings never unmap, so no other user may share this hint.
    pub const ANIMATION_DESTROY: usize = 0xd000_0000;
    // 0xd100_0000: dedicated to ui/operation_destroy's raw-u32 operation
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const UI_OPERATION_DESTROY: usize = 0xd100_0000;
    // 0xd200_0000: dedicated to app/event_list's raw-u32 event-tree
    // destructor fixture; fixture mappings never unmap, so no other user
    // may share this hint.
    pub const EVENT_LIST_TREE_DESTRUCT: usize = 0xd200_0000;
    // 0x2f00_0000: dedicated to ui/plst_next's raw-u32 element and
    // chain-node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const PLST_NEXT: usize = 0x2f00_0000;
    // 0xea00_0000: dedicated to fs/block_window's raw-u32 owner/interface
    // chain fixture; mappings never unmap, so no other user may share it.
    pub const MAPPED_BLOCK_WINDOW_FINISH: usize = 0xea00_0000;
    // 0xeb00_0000: dedicated to fs/block_window's allocation-bitmap mapper
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const ALLOCATION_BITMAP_BLOCK_MAP: usize = 0xeb00_0000;
    // 0xf000_0000: dedicated to cxx/observable_array's copy-constructor
    // source/destination storage fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const OBSERVABLE_ARRAY_COPY_CONSTRUCT: usize = 0xf000_0000;
    // 0xf100_0000: dedicated to app/iap_packet_event_schedule's raw-u32
    // active-context, packet, owner and pending-node fixture; mappings never
    // unmap, so no other user may share this hint.
    pub const IAP_PACKET_EVENT_SCHEDULE: usize = 0xf100_0000;
    // 0xf180_0000: dedicated to app/iap_packet_completion_event's raw-u32
    // active-context, packet, owner and pending-node fixture; mappings never
    // unmap, so no other user may share this hint.
    pub const IAP_PACKET_COMPLETION_EVENT: usize = 0xf180_0000;
    // 0xf1c0_0000: dedicated to app/iap_incoming_process_thread's raw-u32
    // thread, service-handler-table, and message fixtures; mappings never
    // unmap, so no other port may share this hint.
    pub const IAP_THREAD_MESSAGE_SUBMIT: usize = 0xf1c0_0000;
    // 0xf200_0000: dedicated to app/context_scope_selector's raw-u32
    // subject/context fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const CONTEXT_SCOPE_SELECTOR: usize = 0xf200_0000;
    // 0xf800_0000: dedicated to app/current_record_handle's containing-owner
    // cursor fixture; mappings never unmap, so no other user may share this
    // hint.
    pub const OWNER_CURRENT_RECORD_HANDLE: usize = 0xf800_0000;
    // 0xf600_0000: dedicated to app/opaque_impl_callback_validate's raw-u32
    // owner and implementation fixture; mappings never unmap.
    pub const OPAQUE_IMPL_CALLBACK_VALIDATE: usize = 0xf600_0000;
    // 0xd300_0000, far clear of the sequential run: sibling ports in
    // flight take the next free slots, and a collision skips tests
    // silently on every host.
    pub const PLST_SLOT_POSITION: usize = 0xd300_0000;
    // 0xd500_0000: dedicated to app/record_manager's target-width current
    // record registration fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RECORD_MANAGER_CURRENT_RECORD_STATUS: usize = 0xd500_0000;
    // 0xd400_0000: dedicated to app/operator_cycle_advance_if_successor's
    // target-width parser-state fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const OPERATOR_CYCLE_ADVANCE: usize = 0xd400_0000;
    // 0xee20_0000: dedicated to app/visible_range_recompute's target-width
    // state and collection fixture; mappings never unmap, so no other user
    // may share this hint.
    pub const VISIBLE_RANGE_RECOMPUTE: usize = 0xee20_0000;
    // 0xd600_0000: dedicated to cxx/sorted_pointer_array_insert's raw-u32
    // array, entry, and record fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const SORTED_POINTER_ARRAY_INSERT: usize = 0xd600_0000;
    // 0xf300_0000: dedicated to app/enumerated_handle_collection's paired
    // target-width vector fixtures; mappings never unmap, so no other user
    // may share this hint.
    pub const ENUMERATED_HANDLE_COLLECTION: usize = 0xf300_0000;
    // 0xc100_0000: dedicated to cxx/payload_list_owner_destroy's raw-u32
    // owner/list fixture; mappings never unmap, so no other user may share it.
    pub const PAYLOAD_LIST_OWNER_DESTROY: usize = 0xc100_0000;
    // 0xc200_0000: dedicated to cxx/shared_cell's direct-release payload
    // fixture; mappings never unmap, so no other user may share it.
    pub const SHARED_CELL_DIRECT_RELEASE: usize = 0xc200_0000;
    // 0xc300_0000: dedicated to cxx/shared_cell's secondary direct-release
    // payload fixture; mappings never unmap, so no other user may share it.
    pub const SHARED_CELL_DIRECT_RELEASE_SECONDARY: usize = 0xc300_0000;
    // 0xc400_0000: dedicated to cxx/shared_payload_select_kind's raw-u32
    // state fixture; mappings never unmap, so no other user may share it.
    pub const SHARED_PAYLOAD_SELECT_KIND: usize = 0xc400_0000;
    // 0xf300_0000: dedicated to fs/volume_table's raw-u32 descriptor-table
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const VOLUME_TABLE_LOOKUP: usize = 0xf300_0000;
    // 0xf700_0000: dedicated to fs/volume_seek's raw-u32 descriptor,
    // owner, and ATA-device fixture; mappings never unmap, so no other user
    // may share this hint.
    pub const VOLUME_SEEK: usize = 0xf700_0000;
    // 0xf400_0000: dedicated to fs/drive_slot's raw-u32 drive-slot table
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const DRIVE_SLOT_LOOKUP: usize = 0xf400_0000;
    // 0xd400_0000: dedicated to codegen/expression_dependency_mask's raw-u32
    // expression-node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const CG_EXPRESSION_DEPENDENCY_MASK: usize = 0xd400_0000;
    // 0xd500_0000: dedicated to codegen/expression_collection_dependency_mask's
    // raw-u32 collection, entry, expression-node, and context fixture;
    // mappings never unmap, so no other user may share this hint.
    pub const CG_EXPRESSION_COLLECTION_DEPENDENCY_MASK: usize = 0xd500_0000;
    // 0xda10_0000: dedicated to codegen/dependency_tail_has_uncovered_mask's
    // raw-u32 rule, entry, and expression-node fixture; mappings never unmap,
    // so no other user may share this hint.
    pub const CG_DEPENDENCY_TAIL_HAS_UNCOVERED_MASK: usize = 0xda10_0000;
    // 0x8400_0000: dedicated to util/fixed_matrix_cursor's raw-u32 base
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const FIXED_MATRIX_CURSOR: usize = 0x8400_0000;
    // 0x9600_0000: dedicated to app/command_dispatch_name_callback's
    // raw-u32 dispatcher and command-record fixture; mappings never unmap,
    // so no other user may share this hint.
    pub const COMMAND_DISPATCH_BY_NAME_SINGLE_ARG: usize = 0x9600_0000;
    // 0xf500_0000: dedicated to app/application_string_registry's raw-u32
    // provider/registry fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const APPLICATION_STRING_REGISTRY: usize = 0xf500_0000;
    // 0xf800_0000: dedicated to app/indexed_payload_lookup's raw-u32 record
    // and index fixture; mappings never unmap, so no other user may share it.
    pub const RECORD_METADATA_LOOKUP: usize = 0xf800_0000;
    // 0xc800_0000: dedicated to app/indexed_payload_lookup's raw-u32 record
    // and index fixture for the index+0x118 word-15 wrapper; mappings never
    // unmap, so no other user may share this hint.
    pub const RECORD_INDEXED_PAYLOAD_LOOKUP_118_WORD15: usize = 0xc800_0000;
    // 0xe800_0000: dedicated to app/indexed_payload_lookup's raw-u32 record
    // and index fixture for the index+0x1c8 wrapper; mappings never unmap,
    // so no other user may share this hint.
    pub const RECORD_INDEXED_PAYLOAD_LOOKUP_1C8: usize = 0xe800_0000;
    // 0xd800_0000: dedicated to app/indexed_payload_lookup's raw-u32 record
    // and index fixture for the index+0x278 wrapper; mappings never unmap,
    // so no other user may share this hint.
    pub const RECORD_INDEXED_PAYLOAD_LOOKUP_278: usize = 0xd800_0000;
    // 0xf600_0000: dedicated to app/string_table's raw-u32 COW value
    // fixture for the signed-decimal getter; mappings never unmap, so no
    // other user may share this hint.
    pub const STRING_TABLE_PARSE_I32: usize = 0xf600_0000;
    // 0xcafe_0000: dedicated to app/string_table's raw-u32 COW value
    // fixture for the unsigned-hexadecimal getter; mappings never unmap, so
    // no other user may share this hint.
    pub const STRING_TABLE_PARSE_U32_HEX: usize = 0xcafe_0000;
    // 0xe600_0000: dedicated to app/string_table's current-to-peer copy
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const STRING_TABLE_COPY_CURRENT_TO_PEER: usize = 0xe600_0000;
    // 0xb300_0000: dedicated to cxx/nested_object_value's raw-u32
    // owner/nested-object fixtures; mappings never unmap, so no other user
    // may share this hint.
    pub const NESTED_OBJECT_VALUE: usize = 0xb300_0000;
    // 0xee10_0000: dedicated to app/rb_tree_pool_destruct's raw-u32 tree,
    // header, and chunk-record fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const RB_TREE_POOL_DESTRUCT: usize = 0xee10_0000;
    // 0x8280_0000: dedicated to app/item_collection_dispatch's raw-u32
    // context, owner, and collection fixture; mappings never unmap, so no
    // other user may share this hint.
    pub const ITEM_COLLECTION_DISPATCH: usize = 0x8280_0000;
    // 0xd600_0000: dedicated to sqlite/corrupt_schema's raw-u32 InitData,
    // connection, string, and allocator-result fixture; mappings never
    // unmap, so no other user may share this hint.
    pub const CORRUPT_SCHEMA: usize = 0xd600_0000;
    // 0xb320_0000: dedicated to cxx/nested_object_value_at_4's raw-u32
    // owner/nested-object fixtures; mappings never unmap, so no other user
    // may share this hint.
    pub const NESTED_OBJECT_VALUE_AT_4: usize = 0xb320_0000;
    // 0xb310_0000: dedicated to cxx/nested_object_value_at_14's raw-u32
    // owner/nested-object fixtures; mappings never unmap, so no other user
    // may share this hint.
    pub const NESTED_OBJECT_VALUE_AT_14: usize = 0xb310_0000;
    // 0xfa00_0000: dedicated to ui/plst_linked_item_count's raw-u32 owner,
    // element, and collection-header fixture; mappings never unmap, so no
    // other user may share this hint.
    pub const PLST_LINKED_ITEM_COUNT: usize = 0xfa00_0000;
    // 0xfa10_0000: dedicated to app/selection_context_nested_u16's raw-u32
    // context, tail-target, nested record, and header fixture; mappings never
    // unmap, so no other port may share it.
    pub const SELECTION_CONTEXT_NESTED_U16: usize = 0xfa10_0000;
    // 0xfb00_0000: dedicated to ui/tdat_message_dispatch's raw-u32 virtual
    // handler and context fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const TDAT_MESSAGE_DISPATCH: usize = 0xfb00_0000;
    // 0xe010_0000: dedicated to ui/plst_resource_dispatch_pldm's raw-u32
    // task, Tdat element, and resource-root fixture; mappings never unmap,
    // so no other user may share this hint.
    pub const PLST_RESOURCE_DISPATCH_PLDM: usize = 0xe010_0000;
    // 0xe020_0000: dedicated to ui/plst_task_message's raw-u32 task,
    // Tdat-element, and argument fixtures; mappings never unmap, so no other
    // user may share this hint.
    pub const PLST_TASK_MESSAGE: usize = 0xe020_0000;
    // 0xf900_0000: dedicated to util/tagged_payload_read_signed_field_0x54's
    // raw-u32 object/payload fixture; mappings never unmap, so no other user
    // may share this hint.
    pub const TAGGED_PAYLOAD_READ_SIGNED_FIELD_0X54: usize = 0xf900_0000;
    // 0x9d00_0000: dedicated to util/tagged_payload_read_signed_field_0x52's
    // raw-u32 object/payload fixture; mappings never unmap, so no other user
    // may share this hint.
    pub const TAGGED_PAYLOAD_READ_SIGNED_FIELD_0X52: usize = 0x9d00_0000;
    // 0x9d10_0000: dedicated to util/tagged_payload_word_read_signed_field_0x52's
    // raw-u32 tagged-payload-word fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const TAGGED_PAYLOAD_WORD_READ_SIGNED_FIELD_0X52: usize = 0x9d10_0000;
    // 0x0834_0000: dedicated to util/scaled_word_list_from_i32's raw-u32
    // output fixture; mappings never unmap, so no other user may share it.
    pub const SCALED_WORD_LIST_FROM_I32: usize = 0x0834_0000;
    // 0xfc00_0000: dedicated to util/object_masked_word_refresh's raw-u32
    // owner fixture; mappings never unmap, so no other user may share it.
    pub const OBJECT_MASKED_WORD_REFRESH: usize = 0xfc00_0000;
    // 0xfd00_0000: dedicated to app/opaque_keyed_collection_item_at's raw-u32
    // vector-head and entry fixture; mappings never unmap, so no other user
    // may share this hint.
    pub const OPAQUE_KEYED_COLLECTION_ITEM_AT: usize = 0xfd00_0000;
    // 0xef00_0000: dedicated to app/opaque_keyed_collection_item_count's
    // raw-u32 vector-head fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const OPAQUE_KEYED_COLLECTION_ITEM_COUNT: usize = 0xef00_0000;
    // 0xd500_0000: dedicated to app/opaque_keyed_collection_find_item_by_id's
    // raw-u32 vector, entry table, and item fixtures; mappings never unmap.
    pub const OPAQUE_KEYED_COLLECTION_FIND_ITEM_BY_ID: usize = 0xd500_0000;
    // 0xd600_0000: dedicated to util/matrix_state_apply_transform's raw-u32
    // active-matrix fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const MATRIX_STATE_APPLY_TRANSFORM: usize = 0xd600_0000;
    // 0xd700_0000: dedicated to util/matrix_state_apply_six_coordinate_transform's
    // raw-u32 active-matrix fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const MATRIX_STATE_APPLY_SIX_COORDINATE_TRANSFORM: usize = 0xd700_0000;
    // 0xed00_0000: dedicated to ui/typeface_resource_apply's raw-u32 owner,
    // provider, metrics, and payload fixture; mappings never unmap, so no
    // other user may share this hint.
    pub const TYPEFACE_RESOURCE_APPLY: usize = 0xed00_0000;
    
    // 0xfe00_0000: dedicated to util/tagged_payload_signed_field_sum's raw-u32
    // object/payload fixture; mappings never unmap, so no other user may share it.
    pub const TAGGED_PAYLOAD_SIGNED_FIELD_SUM: usize = 0xfe00_0000;
    // 0xff00_0000: dedicated to ui/view_base's raw-u32 resource-provider
    // setter fixture; mappings never unmap, so no other user may share it.
    pub const VIEW_BASE_RESOURCE_PROVIDER: usize = 0xff00_0000;
    // 0xac00_0000: dedicated to app/global_callback_unregister's raw-u32
    // circular-list fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const GLOBAL_CALLBACK_UNREGISTER: usize = 0xac00_0000;
    // 0xaf00_0000: dedicated to app/global_callback_register's raw-u32
    // circular-list fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const GLOBAL_CALLBACK_REGISTER: usize = 0xaf00_0000;
    // 0xae10_0000: dedicated to app/global_word_list_prepend's raw-u32
    // circular-list fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const GLOBAL_WORD_LIST_PREPEND: usize = 0xae10_0000;
    // 0xb600_0000: dedicated to app/vtable_set file-record teardown's
    // raw-u32 node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const FILE_RECORD_TEARDOWN: usize = 0xb600_0000;
    // 0xbb00_0000: dedicated to app/vtable_set's file-store destructor
    // fixture; it carries raw-u32 vtable and aligned-buffer words, and
    // fixture mappings never unmap.
    pub const VTABLE_FILE_STORE_DESTRUCT: usize = 0xbb00_0000;
    // 0xad00_0000: dedicated to ui/first_collection_item_bounds' raw-u32
    // collection-owner fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const UI_FIRST_COLLECTION_ITEM_BOUNDS: usize = 0xad00_0000;
    // 0xb800_0000: dedicated to app/tuning_timer's raw-u32 controller and
    // timer fixtures; mappings never unmap, so no other user may share it.
    // 0x8b00_0000: dedicated to app/controller_timer_pair's raw-u32
    // controller and timer fixtures; mappings never unmap, so no other user
    // may share this hint.
    pub const DUAL_CONTROLLER_TIMER_STOP: usize = 0x8b00_0000;
    // 0x8c00_0000: dedicated to app/controller_timer_pair_destruct's raw-u32
    // controller, timer, and optional-object fixture; mappings never unmap.
    pub const CONTROLLER_TIMER_PAIR_DESTRUCTOR: usize = 0x8c00_0000;
    // 0x8d00_0000: dedicated to app/controller_timer_pair_construct's raw-u32
    // controller and timer fixture; mappings never unmap.
    pub const CONTROLLER_TIMER_PAIR_CONSTRUCT: usize = 0x8d00_0000;
    pub const TUNING_TIMER_SEQUENCE: usize = 0xb800_0000;
    // 0x9a00_0000: dedicated to cxx/string_object's case-folded
    // resource-construction fixture; it carries the provider-chain head as
    // a raw u32 word, and fixture mappings never unmap.
    pub const STRING_OBJECT_RESOURCE_CASEFOLD_MATCH: usize = 0x9a00_0000;
    // 0x9b00_0000: dedicated to util/stream_seek_tagged_entry's raw-u32
    // stream-handle fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const STREAM_SEEK_TAGGED_ENTRY: usize = 0x9b00_0000;
    // 0xb900_0000: dedicated to ft/buffer_skip's raw-u32 buffered-stream
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const BUFFERED_STREAM_SKIP: usize = 0xb900_0000;
    // 0xbe00_0000: dedicated to app/scoped_context's raw-u32 'plst'
    // selection-source fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const SERVICE_CONTEXT_SELECTION_CONSTRUCT: usize = 0xbe00_0000;
    // 0xa600_0000: dedicated to cxx/streambuf_slot_peek_equal's raw-u32
    // context, slot, and stream-buffer fixtures; mappings never unmap, so no
    // other user may share this hint.
    pub const STREAMBUF_SLOT_PEEK_EQUAL: usize = 0xa600_0000;
    // 0xed00_0000: dedicated to cxx/streambuf_slot_peek_byte's raw-u32
    // stream-buffer-slot fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const STREAMBUF_SLOT_PEEK_BYTE: usize = 0xed00_0000;
    // 0xe500_0000: dedicated to cxx/streambuf_slot_consume's raw-u32
    // stream-buffer-slot fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const STREAMBUF_SLOT_CONSUME: usize = 0xe500_0000;
    // 0xee00_0000: dedicated to kernel/debug_task_selector's raw-u32
    // scheduler-label fixture; fixture mappings never unmap, so no other user
    // may share this hint.
    pub const DEBUG_TASK_SELECTOR_LABELS: usize = 0xee00_0000;
    // 0xa700_0000: dedicated to ui/render_context_suspend's raw-u32
    // render-context fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RENDER_CONTEXT_SUSPEND: usize = 0xa700_0000;
    // 0xa800_0000: dedicated to ui/render_context_release_resource's raw-u32
    // resource fixture; mappings never unmap, so no other user may share this
    // hint.
    pub const RENDER_CONTEXT_RELEASE_RESOURCE: usize = 0xa800_0000;
    // 0xa900_0000: dedicated to ui/render_context_release_presentation's
    // raw-u32 context, slot, and presentation fixtures; mappings never unmap,
    // so no other user may share this hint.
    pub const RENDER_CONTEXT_RELEASE_PRESENTATION: usize = 0xa900_0000;
    // 0x1337_0000: dedicated to app/transfer_slot_resource_release's raw-u32
    // transfer-slot and resource fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const TRANSFER_SLOT_RESOURCE_RELEASE: usize = 0x1337_0000;
    // 0x8a00_0000: dedicated to app/layout_state activation's target-width
    // profile-pointer fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const LAYOUT_STATE_ACTIVATE: usize = 0x8a00_0000;
    // 0x8800_0000: dedicated to kernel/clock_snapshot_trace's raw-u32
    // clock-snapshot chain fixture; mappings never unmap, so no other user
    // may share this hint.
    pub const CLOCK_SNAPSHOT_TRACE: usize = 0x8800_0000;
    // 0x8900_0000: dedicated to fs/fat_cursor's target-width cursor-state,
    // FAT-volume, and directory-entry fixture; mappings never unmap, so no
    // other user may share this hint.
    pub const FAT_CURSOR_SYNCHRONIZE: usize = 0x8900_0000;
    // 0x9000_0000: dedicated to util/framed_word_buffer_decode's raw-u32
    // target-word output fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const FRAMED_WORD_BUFFER_DECODE: usize = 0x9000_0000;
    // 0xbd00_0000: dedicated to ui/object_state's raw-u32 selected-item
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const OBJECT_SELECTED_ITEM: usize = 0xbd00_0000;
    // 0xfc00_0000: dedicated to cxx/signed_key_tree_find's raw-u32 node
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const SIGNED_KEY_TREE_FIND_VALUE: usize = 0xfc00_0000;
    // 0x0200_0000: dedicated to cxx/signed_key_tree_find's raw-u32
    // node fixture for FUN_0839bbd0; mappings never unmap, so no other user
    // may share this hint.
    pub const SIGNED_KEY_TREE_FIND_VALUE_COPY: usize = 0x0200_0000;
    // 0x8200_0000: dedicated to cxx/signed_key_tree_find's raw-u32 header,
    // node, and tree fixture for FUN_083dbf00; mappings never unmap, so no
    // other user may share this hint.
    pub const SIGNED_KEY_TREE_FIND_NODE: usize = 0x8200_0000;
    // 0x9d40_0000: dedicated to cxx/byte_key_word_map's raw-u32 node
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const BYTE_KEY_WORD_MAP_LOOKUP_OR_INSERT: usize = 0x9d40_0000;
    // Dedicated to sqlite/parse_release_deferred_vdbe's target-width
    // Parse/db/Vdbe fixture; mappings never unmap, so each test has a
    // distinct hint.
    pub const DEFERRED_OWNER_CHILD_RELEASE: usize = 0x0300_0000;
    pub const DEFERRED_OWNER_CHILD_RELEASE_BLOCKED: usize = 0x0500_0000;
    pub const DEFERRED_OWNER_CHILD_ABSENT: usize = 0x0600_0000;
    pub const DEFERRED_OWNER_CHILD_SIGNED: usize = 0x0700_0000;
    // 0xec00_0000: dedicated to app/current_record_handle's raw-u32 record
    // array fixture; mappings never unmap, so no other user may share it.
    pub const CURRENT_RECORD_HANDLE: usize = 0xec00_0000;
    // 0x9100_0000: dedicated to app/member_release's raw-u32 list-state
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const MEMBER_RELEASE_LIST_STATE: usize = 0x9100_0000;

    // 0x8d00_0000: dedicated to app/selection_position_at_or_past_item_count's
    // raw-u32 element-reference, target, and collection fixture; mappings
    // never unmap, so no other user may share this hint.
    pub const SELECTION_POSITION_AT_OR_PAST_ITEM_COUNT: usize = 0x8d00_0000;

    // 0x9400_0000: dedicated to app/slot_signal_reset's target-width
    // manager and mailbox fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const SLOT_SIGNAL_RESET: usize = 0x9400_0000;
    // 0xa500_0000: dedicated to heap/client_reserve's raw-u32 client and
    // manager fixture; mappings never unmap, so no other user may share it.
    pub const CLIENT_RESERVE: usize = 0xa500_0000;
    // 0xa600_0000: dedicated to heap/client_request_update's raw-u32 client
    // and manager fixture; mappings never unmap, so no other user may share it.
    pub const CLIENT_REQUEST_UPDATE: usize = 0xa600_0000;
    // 0xb100_0000: dedicated to heap/client_available_blocks's raw-u32
    // client and manager fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const CLIENT_AVAILABLE_BLOCKS: usize = 0xb100_0000;
    // 0xa200_0000: dedicated to app/context_callback_dispatch's raw-u32
    // owner/state/list fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const CONTEXT_CALLBACK_DISPATCH: usize = 0xa200_0000;
    // 0xa300_0000: dedicated to heap/fixa's raw-u32 owner and FixL-link
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const FIXA_OWNER_DESTROY: usize = 0xa300_0000;
    // 0xb000_0000: dedicated to heap/fixa_owner_create's raw-u32 output
    // slot and owner fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const FIXA_OWNER_CREATE: usize = 0xb000_0000;


    // 0x9300_0000: dedicated to util/inner_state's selected-resource table
    // and object fixture; mappings never unmap, so no other user may share it.
    pub const OBJECT_SELECT_RESOURCE_INDEX: usize = 0x9300_0000;
    // 0x9500_0000: dedicated to app/media_player_reset_default_resource's
    // raw-u32 player and inner-state fixture; mappings never unmap, so no
    // other user may share this hint.
    pub const MEDIA_PLAYER_RESET_DEFAULT_RESOURCE: usize = 0x9500_0000;
    // 0xa700_0000: dedicated to util/inner_state's raw-u32 query-object cache
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const QUERY_OBJECT_ENSURE: usize = 0xa700_0000;
    // 0x8c00_0000: dedicated to app/descriptor_attachment's raw-u32 owner,
    // descriptor, and link fixtures; mappings never unmap.
    pub const DESCRIPTOR_ATTACHMENT: usize = 0x8c00_0000;
    // 0x8d00_0000: dedicated to cxx/descriptor_lookup_exact_or_tail's
    // descriptor-result fixture; mappings never unmap.
    pub const DESCRIPTOR_LOOKUP_EXACT_OR_TAIL: usize = 0x8d00_0000;
    // 0x8f00_0000: dedicated to mov/chain_value_span's raw-u32 chain-value
    // record fixture; mappings never unmap, so no other user may share it.
    pub const MOV_CHAIN_TABLE_LOAD_SPAN: usize = 0x8f00_0000;
    // 0x8f10_0000: dedicated to mov/chain_segment_bounds's raw-u32
    // chain-value record fixtures; mappings never unmap.
    pub const MOV_CHAIN_TABLE_LOAD_SEGMENT_BOUNDS: usize = 0x8f10_0000;
    // 0x8f20_0000: dedicated to mov/chain_table's raw-u32 playback-context,
    // manager, and matched-record fixture; mappings never unmap.
    pub const MOV_CHAIN_TABLE_LOOKUP_PAYLOAD_WORD: usize = 0x8f20_0000;
    // 0x9c00_0000: dedicated to mov/atom_table's raw-u32 node-tree and
    // factory-result fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const MOV_ATOM_TABLE_LOOKUP: usize = 0x9c00_0000;
    // 0x9e00_0000: dedicated to mov/atom_tree_has_offsets's raw-u32 node
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const MOV_ATOM_TREE_HAS_OFFSETS: usize = 0x9e00_0000;
    // 0x9f00_0000: dedicated to mov/chunk_offset_table_load_window's raw-u32
    // table fixture; mappings never unmap, so no other user may share this hint.
    pub const MOV_CHUNK_OFFSET_TABLE_LOAD_WINDOW: usize = 0x9f00_0000;
    // 0x9f10_0000: dedicated to mov/sample_size_table_load_window's raw-u32
    // table fixture; mappings never unmap, so no other user may share this hint.
    pub const MOV_SAMPLE_SIZE_TABLE_LOAD_WINDOW: usize = 0x9f10_0000;
    // 0x9f20_0000: dedicated to mov/sync_sample_table_load_window's raw-u32
    // table fixture; mappings never unmap, so no other user may share this hint.
    pub const MOV_SYNC_SAMPLE_TABLE_LOAD_WINDOW: usize = 0x9f20_0000;
    // 0x9d00_0000: dedicated to util/linked_list_append's raw-u32 anchor
    // and intrusive-node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const LINKED_LIST_APPEND: usize = 0x9d00_0000;
    // 0x8e00_0000: dedicated to ui/element_reference_item's raw-u32
    // reference, vtable, element, header, and slot fixtures; mappings never
    // unmap, so no other user may share this hint.
    pub const ELEMENT_REFERENCE_ITEM: usize = 0x8e00_0000;
    // 0x8d10_0000: dedicated to app/indexed_timestamp_bounds's raw-u32
    // state, table, and entry fixtures; mappings never unmap, so no other
    // user may share this hint.
    pub const INDEXED_TIMESTAMP_BOUNDS: usize = 0x8d10_0000;
    // 0x8d30_0000: dedicated to app/timestamp_index_seek's raw-u32 table
    // and timestamp fixtures; mappings never unmap, so no other user may
    // share this hint.
    pub const TIMESTAMP_INDEX_SEEK: usize = 0x8d30_0000;
    // 0x8d20_0000: dedicated to app/indexed_timestamp_window_bounds's raw-u32
    // context, state, table, and entry fixtures; mappings never unmap, so no
    // other user may share this hint.
    pub const INDEXED_TIMESTAMP_WINDOW_BOUNDS: usize = 0x8d20_0000;
    // 0x9800_0000: dedicated to sqlite/btree_drop_cell's target-width
    // MemPage aData fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const BTREE_DROP_CELL: usize = 0x9800_0000;
    // 0x6200_0000: dedicated to sqlite/btree_balance's target-width MemPage
    // and BtShared fixture; mappings never unmap, so no other user may share it.
    pub const BTREE_BALANCE_PAGE: usize = 0x6200_0000;
    // 0xa400_0000: dedicated to sqlite/move_to_root's target-width cursor,
    // Btree, and MemPage fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const BTREE_MOVE_TO_ROOT: usize = 0xa400_0000;
    // 0xa500_0000: dedicated to ui/refresh_notification_state's target-width
    // owner and notification-target fixture; mappings never unmap.
    pub const UI_REFRESH_NOTIFICATION_STATE: usize = 0xa500_0000;
    // 0x5d00_0000: dedicated to sqlite/move_to_child's target-width cursor,
    // Btree, and MemPage fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const BTREE_MOVE_TO_CHILD: usize = 0x5d00_0000;
    // 0x5300_0000 and 0x5400_0000: dedicated to the cxx shared-handle
    // initializer and its vtable-owner constructor fixtures; mappings never
    // unmap, so each mapping site has its own hint.
    pub const SHARED_HANDLE_INITIALIZE: usize = 0x5300_0000;
    pub const VTABLE_SHARED_HANDLE_CONSTRUCT: usize = 0x5400_0000;
    // 0x5500_0000: dedicated to cxx/basic_ostream_construct's target-width
    // stream, locale, facet table, and shared-object fixture; mappings never
    // unmap, so no other user may share this hint.
    pub const BASIC_OSTREAM_CONSTRUCT: usize = 0x5500_0000;
    // 0x5350_0000: dedicated to ui/collection_first_item_word_at_1c's raw-u32
    // owner, collection, and item fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const UI_COLLECTION_FIRST_ITEM_WORD_AT_1C: usize = 0x5350_0000;
    // 0x9900_0000: dedicated to cxx/templates' raw-u32 cursor-state
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const CONTAINER_BEGIN_CURSOR: usize = 0x9900_0000;
    // 0x5600_0000: dedicated to app/opaque_record_source_item_count's raw-u32
    // provider fixture; mappings never unmap, so no other user may share it.
    pub const OPAQUE_RECORD_SOURCE_ITEM_COUNT: usize = 0x5600_0000;
    // 0x5900_0000: dedicated to app/opaque_record_source_entry_count's raw-u32
    // source, provider, and state fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const OPAQUE_RECORD_SOURCE_ENTRY_COUNT: usize = 0x5900_0000;
    // 0xe100_0000: dedicated to app/opaque_record_source_copy_item's raw-u32
    // record-table fixture; mappings never unmap, so no other user may share it.
    pub const OPAQUE_RECORD_SOURCE_COPY_ITEM: usize = 0xe100_0000;
    // 0xe300_0000: dedicated to app/opaque_record_source_entry_lookup's raw-u32
    // source, provider, count-state, and entry-table fixture; mappings never
    // unmap, so no other user may share this hint.
    pub const OPAQUE_RECORD_SOURCE_ENTRY_LOOKUP: usize = 0xe300_0000;
    // 0xe200_0000: dedicated to app/opaque_record_source_find_at_or_after's
    // raw-u32 record-table fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const OPAQUE_RECORD_SOURCE_FIND_AT_OR_AFTER: usize = 0xe200_0000;
    // 0x5800_0000: dedicated to heap/memh_handle's target-width handle
    // fixture; mappings never unmap, so no other user may share it.
    pub const MEMH_HANDLE_DESTROY: usize = 0x5800_0000;
    // 0x3400_0000: dedicated to heap/memh_set_len's target-width header,
    // payload, and mock-allocation fixture; mappings never unmap, so no
    // other user may share this hint.
    pub const MEMH_SET_LEN: usize = 0x3400_0000;
    // 0x5900_0000: dedicated to heap/memh_resize's target-width header and
    // payload fixture; mappings never unmap, so no other user may share it.
    pub const MEMH_RESIZE: usize = 0x5900_0000;
    // 0x5700_0000: dedicated to util/mapped_subobject_for_slot's raw-u32
    // context and selected-subobject fixture; mappings never unmap.
    pub const MAPPED_SUBOBJECT_FOR_SLOT: usize = 0x5700_0000;
    // 0x3000_0000: dedicated to ui/view_base's render-state release fixture;
    // mappings never unmap, so no other user may share this hint.
    pub const VIEW_BASE_RENDER_STATE_RELEASE: usize = 0x3000_0000;
    // 0x4e00_0000: dedicated to ui/element_slot_reset's raw-u32 element and
    // transient-object fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const UI_ELEMENT_SLOT_RESET: usize = 0x4e00_0000;
    // 0x4d00_0000: dedicated to ui/clear_pending_notify's target-width
    // object fixture; mappings never unmap, so no other user may share it.
    pub const UI_CLEAR_PENDING_NOTIFY: usize = 0x4d00_0000;
    // 0x5c80_0000: dedicated to ui/tdat_flagged_plst's target-width context
    // and linked-element fixture; mappings never unmap, so no other test may
    // share it.
    pub const TDAT_FLAGGED_PLST: usize = 0x5c80_0000;
    // 0x5100_0000: dedicated to ui/layout_apply_pending_offsets' raw-u32
    // entry-offset fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const TEXT_LAYOUT_APPLY_PENDING_OFFSETS: usize = 0x5100_0000;
    // 0x6100_0000: dedicated to app/segmented_entry_lookup's raw-u32 table
    // and entry-data fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const SEGMENTED_ENTRY_LOOKUP: usize = 0x6100_0000;
    // 0x4f00_0000: dedicated to app/controller_context_scope_dispatch's
    // target-width context-scope subject fixture; mappings never unmap, so no
    // other user may share this hint.
    pub const CONTROLLER_CONTEXT_SCOPE_DISPATCH: usize = 0x4f00_0000;
    // 0x5200_0000: dedicated to kernel/task_lock's raw-u32 current-task
    // record fixture; mappings never unmap, so no other user may share it.
    pub const CURRENT_TASK_ID: usize = 0x5200_0000;
    // 0xdc00_0000: dedicated to kernel/task_priority's raw-u32 task-record
    // table and current-task record fixture; mappings never unmap, so no
    // other user may share this hint.
    pub const TASK_PRIORITY_GET: usize = 0xdc00_0000;
    // 0x8000_0000: dedicated to cxx/red_black_tree_increment's raw-u32
    // red-black-tree node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_INCREMENT: usize = 0x8000_0000;
    // 0x1010_0000: dedicated to cxx/red_black_tree_increment's raw-u32
    // cursor-advance fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ADVANCE_CURSOR: usize = 0x1010_0000;
    // 0x8140_0000: dedicated to cxx/red_black_tree_increment's raw-u32
    // cursor-decrement fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_DECREMENT_CURSOR: usize = 0x8140_0000;
    // 0x8c10_0000: dedicated to cxx/red_black_tree_rotate_right's raw-u32
    // tree and node fixture; mappings never unmap, so no other user may share
    // this hint.
    pub const RED_BLACK_TREE_ROTATE_RIGHT: usize = 0x8c10_0000;
    // 0x8cb0_0000: dedicated to cxx/red_black_tree_rotate_right_second's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_RIGHT_SECOND: usize = 0x8cb0_0000;
    // 0x8cd0_0000: dedicated to cxx/red_black_tree_rotate_right_third's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_RIGHT_THIRD: usize = 0x8cd0_0000;
    // 0x8cf0_0000: dedicated to cxx/red_black_tree_rotate_right_fourth's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_RIGHT_FOURTH: usize = 0x8cf0_0000;
    // 0x8c30_0000: dedicated to cxx/red_black_tree_rotate_right_alt's raw-u32
    // tree and node fixture; mappings never unmap, so no other user may share
    // this hint.
    pub const RED_BLACK_TREE_ROTATE_RIGHT_ALT: usize = 0x8c30_0000;
    // 0x8c60_0000: dedicated to cxx/red_black_tree_rotate_left_fourth's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_LEFT_FOURTH: usize = 0x8c60_0000;
    // 0x8c20_0000: dedicated to cxx/red_black_tree_rotate_left's raw-u32
    // tree and node fixture; mappings never unmap, so no other user may share
    // this hint.
    pub const RED_BLACK_TREE_ROTATE_LEFT: usize = 0x8c20_0000;
    // 0x8cc0_0000: dedicated to cxx/red_black_tree_rotate_left_second's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_LEFT_SECOND: usize = 0x8cc0_0000;
    // 0x8c40_0000: dedicated to cxx/red_black_tree_rotate_left_alt's raw-u32
    // tree and node fixture; mappings never unmap, so no other user may share
    // this hint.
    pub const RED_BLACK_TREE_ROTATE_LEFT_ALT: usize = 0x8c40_0000;
    // 0x8c50_0000: dedicated to cxx/red_black_tree_rotate_left_third's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user
    // may share this hint.
    pub const RED_BLACK_TREE_ROTATE_LEFT_THIRD: usize = 0x8c50_0000;
    // 0x8c70_0000: dedicated to cxx/red_black_tree_rotate_right_fifth's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_RIGHT_FIFTH: usize = 0x8c70_0000;
    // 0x8c80_0000: dedicated to cxx/red_black_tree_rotate_left_fifth's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_LEFT_FIFTH: usize = 0x8c80_0000;
    // 0x8ca0_0000: dedicated to cxx/red_black_tree_rotate_left_sixth's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_LEFT_SIXTH: usize = 0x8ca0_0000;
    // 0x8c90_0000: dedicated to cxx/red_black_tree_rotate_right_sixth's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_RIGHT_SIXTH: usize = 0x8c90_0000;
    // 0x8cf0_0000: dedicated to cxx/red_black_tree_rotate_right_seventh's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_RIGHT_SEVENTH: usize = 0x8cf0_0000;
    // 0x8ce0_0000: dedicated to cxx/red_black_tree_rotate_left_seventh's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_LEFT_SEVENTH: usize = 0x8ce0_0000;
    // 0x8d30_0000: dedicated to cxx/red_black_tree_rotate_left_eighth's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_LEFT_EIGHTH: usize = 0x8d30_0000;
    // 0x8d40_0000: dedicated to cxx/red_black_tree_rotate_right_eighth's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_RIGHT_EIGHTH: usize = 0x8d40_0000;
    // 0x8d60_0000: dedicated to cxx/red_black_tree_rotate_right_ninth's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_RIGHT_NINTH: usize = 0x8d60_0000;
    // 0x8d70_0000: dedicated to cxx/red_black_tree_rotate_right_tenth's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_RIGHT_TENTH: usize = 0x8d70_0000;
    // 0x8d80_0000: dedicated to cxx/red_black_tree_rotate_right_eleventh's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_RIGHT_ELEVENTH: usize = 0x8d80_0000;
    // 0x8d90_0000: dedicated to cxx/red_black_tree_rotate_right_thirteenth's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_RIGHT_THIRTEENTH: usize = 0x8d90_0000;
    // 0x8d50_0000: dedicated to cxx/red_black_tree_rotate_left_ninth's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_LEFT_NINTH: usize = 0x8d50_0000;
    // 0x8d60_0000: dedicated to cxx/red_black_tree_rotate_left_tenth's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_LEFT_TENTH: usize = 0x8d60_0000;
    // 0x8d70_0000: dedicated to cxx/red_black_tree_rotate_left_eleventh's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_LEFT_ELEVENTH: usize = 0x8d70_0000;
    // 0x8d80_0000: dedicated to cxx/red_black_tree_rotate_left_twelfth's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_LEFT_TWELFTH: usize = 0x8d80_0000;
    // 0x8da0_0000: dedicated to cxx/red_black_tree_rotate_left_thirteenth's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_LEFT_THIRTEENTH: usize = 0x8da0_0000;
    // 0x8db0_0000: dedicated to cxx/red_black_tree_rotate_left_fourteenth's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_LEFT_FOURTEENTH: usize = 0x8db0_0000;
    // 0x8dd0_0000: dedicated to cxx/red_black_tree_rotate_left_fifteenth's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_LEFT_FIFTEENTH: usize = 0x8dd0_0000;
    // 0x8dc0_0000: dedicated to cxx/red_black_tree_rotate_right_fourteenth's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_RIGHT_FOURTEENTH: usize = 0x8dc0_0000;
    // 0x8e10_0000: dedicated to cxx/red_black_tree_rotate_right_fifteenth's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_RIGHT_FIFTEENTH: usize = 0x8e10_0000;
    // 0x8de0_0000: dedicated to cxx/red_black_tree_rotate_right_twelfth's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_RIGHT_TWELFTH: usize = 0x8de0_0000;
    // 0x8df0_0000: dedicated to cxx/red_black_tree_rotate_left_sixteenth's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_LEFT_SIXTEENTH: usize = 0x8df0_0000;
    // 0x8e30_0000: dedicated to cxx/red_black_tree_rotate_left_seventeenth's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_LEFT_SEVENTEENTH: usize = 0x8e30_0000;
    // 0x8e50_0000: dedicated to cxx/red_black_tree_rotate_left_eighteenth's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_LEFT_EIGHTEENTH: usize = 0x8e50_0000;
    // 0x8e60_0000: dedicated to cxx/red_black_tree_rotate_left_nineteenth's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_LEFT_NINETEENTH: usize = 0x8e60_0000;
    // 0x8e70_0000: dedicated to cxx/red_black_tree_rotate_left_twentieth's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_LEFT_TWENTIETH: usize = 0x8e70_0000;
    // 0x8e90_0000: dedicated to cxx/red_black_tree_rotate_left_twenty_first's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_LEFT_TWENTY_FIRST: usize = 0x8e90_0000;
    // 0x8eb0_0000: dedicated to cxx/red_black_tree_rotate_right_twentieth's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_RIGHT_TWENTIETH: usize = 0x8eb0_0000;
    // 0x8ea0_0000: dedicated to cxx/red_black_tree_rotate_right_nineteenth's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_RIGHT_NINETEENTH: usize = 0x8ea0_0000;
    // 0x8e20_0000: dedicated to cxx/red_black_tree_rotate_right_sixteenth's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_RIGHT_SIXTEENTH: usize = 0x8e20_0000;
    // 0x8e40_0000: dedicated to cxx/red_black_tree_rotate_right_seventeenth's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_RIGHT_SEVENTEENTH: usize = 0x8e40_0000;
    // 0x8e80_0000: dedicated to cxx/red_black_tree_rotate_right_eighteenth's
    // raw-u32 tree and node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_ROTATE_RIGHT_EIGHTEENTH: usize = 0x8e80_0000;
    // 0x0400_0000: dedicated to sqlite/expr_worklist's target-width owner,
    // worklist, entry, and tracked-allocation fixtures; mappings never unmap.
    pub const SQLITE_EXPR_WORKLIST: usize = 0x0400_0000;
    // 0x0480_0000: dedicated to sqlite/expr_worklist's matching-subtree
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const SQLITE_EXPR_WORKLIST_MATCHING_SUBTREE: usize = 0x0480_0000;
    // 0x0600_0000: dedicated to sqlite/expr_code_expr_list's raw-u32
    // ExprList and item fixtures; mappings never unmap, so no other user may
    // share this hint.
    pub const SQLITE_EXPR_CODE_EXPR_LIST: usize = 0x0600_0000;
    // 0x0700_0000: dedicated to sqlite/expr_code_pair's raw-u32 Expr
    // fixtures; mappings never unmap, so no other user may share this hint.
    pub const SQLITE_EXPR_CODE_PAIR: usize = 0x0700_0000;
    // 0xd800_0000: dedicated to sqlite/step's target-width Vdbe and
    // connection fixtures; mappings never unmap, so no other user may share it.
    pub const SQLITE_STEP: usize = 0xd800_0000;
    // 0xd700_0000: dedicated to sqlite/exec_first_column_sql's target-width
    // prepared statement and connection fixture; mappings never unmap, so no
    // other user may share this hint.
    pub const SQLITE_EXEC_FIRST_COLUMN_SQL: usize = 0xd700_0000;
    // 0x4800_0000: dedicated to sqlite/pager_lookup's raw-u32 Pager,
    // bucket table, and page-hash chain fixture; mappings never unmap.
    pub const SQLITE_PAGER_LOOKUP: usize = 0x4800_0000;
    // 0x4900_0000: dedicated to sqlite/pager_read_pending's raw-u32 PgHdr
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const SQLITE_PAGER_READ_PENDING: usize = 0x4900_0000;
    // 0x3300_0000: dedicated to sqlite/pager_set_page_size's raw-u32 Pager
    // and replacement-temporary-space fixture; mappings never unmap.
    pub const SQLITE_PAGER_SET_PAGE_SIZE: usize = 0x3300_0000;
    // 0x9500_0000: dedicated to sqlite/pcache_remove_from_lru_list's raw-u32
    // cache and three-page LRU fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const SQLITE_PCACHE_REMOVE_FROM_LRU_LIST: usize = 0x9500_0000;
    // 0x9700_0000: dedicated to sqlite/pcache_add_to_lru_list's raw-u32
    // cache and LRU-page fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const SQLITE_PCACHE_ADD_TO_LRU_LIST: usize = 0x9700_0000;
    // 0x9600_0000: dedicated to sqlite/pcache_truncate's raw-u32 cache,
    // page-chain, and payload fixture; mappings never unmap, so no other user
    // may share this hint.
    pub const SQLITE_PCACHE_TRUNCATE: usize = 0x9600_0000;
    // 0xa500_0000: dedicated to sqlite/stmt_lru_remove's raw-u32
    // three-statement LRU fixture; mappings never unmap, so no other user
    // may share this hint.
    pub const SQLITE_STMT_LRU_REMOVE: usize = 0xa500_0000;
    // 0x9d20_0000: dedicated to app/bool_message_dispatch's raw-u32
    // message and vtable fixture; mappings never unmap, so no other user
    // may share this hint.
    pub const BOOL_MESSAGE_DISPATCH: usize = 0x9d20_0000;
    // 0x9d30_0000: dedicated to cxx/list_node_pool_erase_owned's raw-u32
    // ring, header, and refcounted-body fixture; mappings never unmap, so no
    // other user may share this hint.
    pub const LIST_NODE_POOL_ERASE_OWNED: usize = 0x9d30_0000;
    // 0x9d40_0000: dedicated to cxx/list_node_pool_recycle_all's target-width
    // intrusive-ring and free-list fixture; mappings never unmap.
    pub const LIST_NODE_POOL_RECYCLE_ALL: usize = 0x9d40_0000;
    // 0x9d50_0000: dedicated to cxx/word_list_node_pool_list_recycle_all's
    // target-width intrusive-ring and free-list fixture; mappings never unmap.
    pub const WORD_LIST_NODE_POOL_LIST_RECYCLE_ALL: usize = 0x9d50_0000;
    // 0x9d60_0000: dedicated to cxx/two_word_list_node_pool_list_recycle_all's
    // target-width intrusive-ring and free-list fixture; mappings never unmap.
    pub const TWO_WORD_LIST_NODE_POOL_LIST_RECYCLE_ALL: usize = 0x9d60_0000;
    // 0x4400_0000: dedicated to sqlite/expr_worklist's parent-release
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const SQLITE_EXPR_WORKLIST_RELEASE_PARENTS: usize = 0x4400_0000;
    // 0xe300_0000: dedicated to util/scoped_global_guard_destroy's target-width
    // guard and allocation fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const SCOPED_GLOBAL_GUARD_DESTROY: usize = 0xe300_0000;
    // 0x2300_0000: dedicated to util/nested_container_item_count's raw-u32
    // owner and nested-container fixture; mappings never unmap.
    pub const NESTED_CONTAINER_ITEM_COUNT: usize = 0x2300_0000;
    // 0x2e00_0000: dedicated to app/object_owner_set's raw-u32 object
    // fixture; mappings never unmap, so no other user may share it.
    pub const OBJECT_OWNER_SET: usize = 0x2e00_0000;
    // 0xda00_0000: dedicated to drivers/surface_plane_owner's raw-u32
    // surface-plane fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const SURFACE_PLANE_OWNER_RELEASE: usize = 0xda00_0000;
    // 0x4b00_0000: dedicated to app/output_buffer_reset's target-width data
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const OUTPUT_BUFFER_RESET: usize = 0x4b00_0000;
    // 0x4b10_0000: dedicated to app/output_buffer_write_dictionary_close's
    // target-width state and variadic-string fixture; mappings never unmap,
    // so no other user may share this hint.
    pub const OUTPUT_BUFFER_WRITE_DICTIONARY_CLOSE: usize = 0x4b10_0000;
    // 0xe200_0000: dedicated to printf/retail_sscanf's target-width
    // varargs/output fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RETAIL_SSCANF: usize = 0xe200_0000;
    // 0xe400_0000: dedicated to ui/element_change_notify's target-width
    // element fixture; mappings never unmap, so no other user may share it.
    pub const UI_ELEMENT_CHANGE_NOTIFY: usize = 0xe400_0000;
    // 0xa1a0_0000: dedicated to app/entry_match_next's raw-u32 container,
    // entry chain, and nested-class fixture; mappings never unmap, so no
    // other user may share this hint.
    pub const ENTRY_MATCH_NEXT: usize = 0xa1a0_0000;
    // 0xa1b0_0000: dedicated to app/nested_liti_class_check's raw-u32
    // container and nested-class fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const NESTED_LITI_FIELD_CHECK: usize = 0xa1b0_0000;
    // 0xa1c0_0000: dedicated to app/entry_match_first's raw-u32 container
    // and nested-class fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const ENTRY_MATCH_FIRST: usize = 0xa1c0_0000;
    // 0xa1d0_0000: dedicated to app/entry_match_source_payload's raw-u32
    // source and nested collection fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const ENTRY_MATCH_SOURCE_PAYLOAD: usize = 0xa1d0_0000;
    // 0xa1e0_0000: dedicated to cxx/magic_tagged_object_release's raw-u32
    // object, child-table, and nested-child fixture; mappings never unmap, so
    // no other user may share this hint.
    pub const MAGIC_TAGGED_OBJECT_RELEASE: usize = 0xa1e0_0000;
    // 0xa160_0000: dedicated to cxx/magic_tagged_object_destroy's raw-u32
    // owner, child-table, and nested-child fixture; mappings never unmap, so
    // no other user may share this hint.
    pub const MAGIC_TAGGED_OBJECT_DESTROY: usize = 0xa160_0000;
    // 0xa1f0_0000: dedicated to cxx/magic_tagged_object_retain's raw-u32
    // object, child-table, and nested-child fixture; mappings never unmap, so
    // no other user may share this hint.
    pub const MAGIC_TAGGED_OBJECT_RETAIN: usize = 0xa1f0_0000;
    // 0xa1c0_0000: dedicated to app/liti_field_class_check's raw-u32 object
    // and class-target fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const LITI_FIELD_CLASS_CHECK: usize = 0xa1c0_0000;
    // 0xa1d0_0000: dedicated to app/liti_indexed_entry_lookup's raw-u32
    // object, class-target, and table fixture; mappings never unmap, so no
    // other user may share this hint.
    pub const LITI_INDEXED_ENTRY_LOOKUP: usize = 0xa1d0_0000;
    // 0xa200_0000: dedicated to app/liti_entry_next's raw-u32 entry and
    // class-target fixture; mappings never unmap, so no other user may share
    // this hint.
    pub const LITI_ENTRY_NEXT: usize = 0xa200_0000;
    // 0xa210_0000: dedicated to app/image_library_first_entry's raw-u32
    // database fixture; mappings never unmap, so no other user may share it.
    pub const IMAGE_LIBRARY_FIRST_ENTRY: usize = 0xa210_0000;
    // 0x2b00_0000: dedicated to crypto/buffered_writer_write's raw-u32
    // handle and page-state fixture; mappings never unmap, so no other user
    // may share this hint.
    pub const BUFFERED_WRITER_WRITE: usize = 0x2b00_0000;
    // 0x1f00_0000: dedicated to crypto/tagged_reference_retain's raw-u32
    // entry and object fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const CRYPTO_TAGGED_REFERENCE_RETAIN: usize = 0x1f00_0000;
    // 0xb200_0000: dedicated to cxx/list_iter_advance's raw-u32 list-node
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const LIST_ITER_ADVANCE: usize = 0xb200_0000;
    // 0x3100_0000: dedicated to cxx/red_black_tree_node_pool_acquire's
    // target-width pool/chunk/node fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const RED_BLACK_TREE_NODE_POOL_ACQUIRE: usize = 0x3100_0000;
    // 0x3500_0000: dedicated to cxx/red_black_tree_node_pool_release_refcounted's
    // target-width pool/node/body fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const RED_BLACK_TREE_NODE_POOL_RELEASE_REFCOUNTED: usize = 0x3500_0000;
    // 0x3600_0000: dedicated to cxx/red_black_tree_node_pool_release_vector's
    // target-width pool/node/vector fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const RED_BLACK_TREE_NODE_POOL_RELEASE_VECTOR: usize = 0x3600_0000;
    // 0xdd00_0000: dedicated to cxx/list_node_pool_acquire's target-width
    // ListNodePool fixture slab, skipping 0xdc00_0000 (reserved).
    pub const LIST_NODE_POOL_ACQUIRE: usize = 0xdd00_0000;
    // 0xde00_0000: dedicated to cxx/word_list_node_pool_acquire's target-width
    // pool/chunk/node fixture; mappings never unmap, so no other user may share it.
    pub const WORD_LIST_NODE_POOL_ACQUIRE: usize = 0xde00_0000;
    // 0xde80_0000: dedicated to cxx/list_node_pool_acquire_083dd4cc's
    // pool/chunk/node fixture; mappings never unmap, so no other user may share it.
    pub const LIST_NODE_POOL_ACQUIRE_083DD4CC: usize = 0xde80_0000;
    // 0xdec0_0000: dedicated to cxx/list_node_pool_acquire_083dd2e4's
    // pool/chunk/node fixture; mappings never unmap, so no other user may share it.
    pub const LIST_NODE_POOL_ACQUIRE_083DD2E4: usize = 0xdec0_0000;
    // 0xdf80_0000: dedicated to cxx/list_node_pool_acquire_083dd1a8's
    // pool/chunk/node fixture; mappings never unmap, so no other user may share it.
    pub const LIST_NODE_POOL_ACQUIRE_083DD1A8: usize = 0xdf80_0000;
    // 0xdf00_0000: dedicated to cxx/list_node_pool_list_init's target-width
    // list-owner and sentinel fixture; mappings never unmap, so no other user
    // may share this hint.
    pub const LIST_NODE_POOL_LIST_INIT: usize = 0xdf00_0000;
    // 0xe000_0000: dedicated to cxx/list_node_pool_list_append_value's
    // target-width owner and three-node intrusive-ring fixture; mappings never
    // unmap, so no other user may share this hint.
    pub const LIST_NODE_POOL_LIST_APPEND_VALUE: usize = 0xe000_0000;
    // 0xe080_0000: dedicated to cxx/word_pair_list_copy_construct's source,
    // destination, and target-width node-ring fixture; mappings never unmap.
    pub const WORD_PAIR_LIST_COPY_CONSTRUCT: usize = 0xe080_0000;
    // 0xe180_0000: dedicated to cxx/word_pair_list_insert_before's target-width
    // list-owner and three-node intrusive-ring fixture; mappings never unmap.
    pub const WORD_PAIR_LIST_INSERT_BEFORE: usize = 0xe180_0000;
    // 0xe100_0000: dedicated to cxx/word_pair_list_sentinel_initialize's
    // target-width list-owner and node-pool fixture; mappings never unmap.
    pub const WORD_PAIR_LIST_SENTINEL_INITIALIZE: usize = 0xe100_0000;
    // 0xe200_0000: dedicated to cxx/word_pair_list_node_pool_acquire's target-width
    // pool/chunk/node fixture; mappings never unmap, so no other user may share it.
    pub const WORD_PAIR_LIST_NODE_POOL_ACQUIRE: usize = 0xe200_0000;
    // 0xe280_0000: dedicated to cxx/app_block_manager_node_pool_acquire's
    // target-width pool/chunk/node fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const APP_BLOCK_MANAGER_NODE_POOL_ACQUIRE: usize = 0xe280_0000;
    // 0xe380_0000: dedicated to cxx/two_word_list_node_pool_acquire's
    // target-width pool/chunk/node fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const TWO_WORD_LIST_NODE_POOL_ACQUIRE: usize = 0xe380_0000;
    // 0xe400_0000: dedicated to cxx/record_40_list_node_pool_acquire's
    // target-width pool/chunk/node fixture; mappings never unmap, so no other user may share it.
    pub const RECORD_40_LIST_NODE_POOL_ACQUIRE: usize = 0xe400_0000;
    // 0x3a00_0000: dedicated to cxx/list_node_pool_list_erase's target-width
    // owner and four-node intrusive-ring fixture; mappings never unmap, so no
    // other user may share this hint.
    pub const LIST_NODE_POOL_LIST_ERASE: usize = 0x3a00_0000;
    // 0x3b00_0000: dedicated to cxx/list_node_pool_list_clear's target-width
    // owner and three-node intrusive-ring fixture; mappings never unmap, so no
    // other user may share this hint.
    pub const LIST_NODE_POOL_LIST_CLEAR: usize = 0x3b00_0000;
    // 0x3200_0000: dedicated to cxx/red_black_tree_payload_24_node_pool_acquire's
    // target-width pool/chunk/node fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const RED_BLACK_TREE_PAYLOAD_24_NODE_POOL_ACQUIRE: usize = 0x3200_0000;
    // 0x2400_0000: dedicated to cxx/red_black_tree_payload_16_node_pool_acquire's
    // target-width pool/chunk/node fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const RED_BLACK_TREE_PAYLOAD_16_NODE_POOL_ACQUIRE: usize = 0x2400_0000;
    // 0x3400_0000: dedicated to cxx/red_black_tree_payload_word_node_pool_acquire's
    // target-width pool/chunk/node fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const RED_BLACK_TREE_PAYLOAD_WORD_NODE_POOL_ACQUIRE: usize = 0x3400_0000;
    // 0x3600_0000: dedicated to cxx/red_black_tree_word_node_pool_acquire's
    // target-width pool/chunk/node fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const RED_BLACK_TREE_WORD_NODE_POOL_ACQUIRE: usize = 0x3600_0000;
    // 0x3300_0000: dedicated to cxx/red_black_tree_payload_24_construct's
    // recycled sentinel-node fixture; mappings never unmap, so no other user
    // may share this hint.
    pub const RED_BLACK_TREE_PAYLOAD_24_CONSTRUCT: usize = 0x3300_0000;
    // 0x4242_0000: dedicated to sqlite/btree_lock's raw-u32 sqlite3, Db,
    // and Btree fixture for sqlite3BtreeLeaveAll; mappings never unmap, so
    // no other user may share this hint.
    pub const BTREE_LEAVE_ALL: usize = 0x4242_0000;
    // 0x4243_0000: dedicated to sqlite/btree_lock's raw-u32 sqlite3, Db,
    // and Btree sibling-list fixture for sqlite3BtreeEnterAll; mappings
    // never unmap, so no other user may share this hint.
    pub const BTREE_ENTER_ALL: usize = 0x4243_0000;
    // 0x4244_0000: dedicated to sqlite/btree_query_table_lock's raw-u32
    // Btree, BtShared, pager, and table-lock fixture; mappings never unmap.
    pub const SQLITE_BTREE_QUERY_TABLE_LOCK: usize = 0x4244_0000;
    // 0x3e00_0000: dedicated to sqlite/ptrmap_put_overflow_cell's raw-u32
    // segmented-entry table and entry-data fixture; mappings never unmap, so
    // no other user may share this hint.
    pub const SQLITE_PTRMAP_PUT_OVERFLOW_CELL: usize = 0x3e00_0000;
    // 0x45ff_0000: dedicated to sqlite/clear_page_overflow_cells's raw-u32
    // MemPage and cell-data fixture; mappings never unmap, so no other user
    // may share this hint.
    pub const SQLITE_CLEAR_PAGE_OVERFLOW_CELLS: usize = 0x45ff_0000;
    // 0x4600_0000: dedicated to sqlite/clear_overflow_cell's target-width
    // MemPage, BtShared, and overflow-cell fixture; mappings never unmap.
    pub const SQLITE_CLEAR_OVERFLOW_CELL: usize = 0x4600_0000;
    // 0x8200_0000: dedicated to sqlite/clear_saved_overflow's target-width
    // BtCursor and tracked-allocation fixture; mappings never unmap.
    pub const SQLITE_CLEAR_SAVED_OVERFLOW: usize = 0x8200_0000;
    // 0x8230_0000: dedicated to sqlite/release_tracked_pair's target-width
    // pair and tracked-allocation fixture; mappings never unmap.
    pub const SQLITE_RELEASE_TRACKED_PAIR: usize = 0x8230_0000;
    // 0x2b80_0000 and 0x2b90_0000: dedicated to
    // sqlite/release_refcounted_list's target-width owner and object-list
    // fixtures; mappings never unmap, so no other user may share them.
    pub const SQLITE_RELEASE_REFCOUNTED_LIST: usize = 0x2b80_0000;
    pub const SQLITE_RELEASE_REFCOUNTED_LIST_EMPTY: usize = 0x2b90_0000;
    // 0x8210_0000 and 0x8220_0000: dedicated to
    // sqlite/clear_cursor_saved_overflows' target-width cursor-list fixtures;
    // mappings never unmap, so each test needs its own hint.
    pub const SQLITE_CLEAR_CURSOR_SAVED_OVERFLOWS: usize = 0x8210_0000;
    pub const SQLITE_CLEAR_CURSOR_SAVED_OVERFLOWS_EMPTY: usize = 0x8220_0000;
    // 0x2c00_0000: dedicated to sqlite/pager_reset's raw-u32 Pager, Page,
    // page-payload, and temporary-space fixture; mappings never unmap, so no
    // other user may share this hint.
    pub const SQLITE_PAGER_RESET: usize = 0x2c00_0000;
    // 0x2d00_0000: dedicated to sqlite/get_and_init_page's raw-u32 page
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const BTREE_GET_AND_INIT_PAGE: usize = 0x2d00_0000;
    // 0xf100_0000: dedicated to sqlite/check_read_locks's raw-u32 Btree,
    // BtShared, cursor, and sqlite3 fixture; mappings never unmap, so no
    // other user may share this hint.
    pub const BTREE_CHECK_READ_LOCKS: usize = 0xf100_0000;
    // 0x5550_0000: dedicated to crypto/asn1_adb's raw-u32 ADB, template,
    // table, and containing-value fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const ASN1_DO_ADB: usize = 0x5550_0000;
    // 0x55a0_0000: dedicated target-width ASN1_INTEGER fixtures for crypto/asn1_integer_get;
    // mappings never unmap, so no other user may share this hint.
    pub const ASN1_INTEGER_GET: usize = 0x55a0_0000;
    // 0x5d00_0000: dedicated to ui/element_refresh's raw-u32 element fixture;
    // mappings never unmap, so no other user may share this hint.
    pub const UI_ELEMENT_REFRESH: usize = 0x5d00_0000;
    // 0xfe00_0000: dedicated to cxx/parse_i32_list's UTF-16 raw-u32 range
    // fixture; mappings never unmap, so no other user may share it.
    pub const PARSE_I32_LIST: usize = 0xfe00_0000;
    // 0x5e00_0000: dedicated to app/pending_object_pair_release's raw-u32
    // pending-object fixture; mappings never unmap, so no other user may share it.
    pub const PENDING_OBJECT_PAIR_RELEASE: usize = 0x5e00_0000;
    // 0x5f00_0000: dedicated to app/pending_object_release's raw-u32 pending-
    // object fixture; mappings never unmap, so no other user may share it.
    pub const PENDING_OBJECT_RELEASE: usize = 0x5f00_0000;
    // 0xdf00_0000: dedicated to app/controller_candidate_notify's raw-u32
    // controller, candidate, and notification-target fixture; mappings never
    // unmap, so no other user may share this hint.
    pub const CONTROLLER_CANDIDATE_NOTIFY: usize = 0xdf00_0000;
    // 0x3c00_0000: dedicated to util/growable_buffer_append's target-width
    // buffer and data fixture; mappings never unmap, so no other user may share it.
    pub const GROWABLE_BUFFER_APPEND: usize = 0x3c00_0000;
    // Dedicated raw-u32 input-sequence state fixtures; mappings never unmap.
    pub const INPUT_SEQUENCE_ITEM_FOUND: usize = 0x3d00_0000;
    pub const INPUT_SEQUENCE_ITEM_BUILD: usize = 0x3f00_0000;
    // 0x0826_0000: dedicated to app/pixel_write_red_alpha's target-width
    // output cursor fixture; mappings never unmap, so no other user may share it.
    pub const PIXEL_WRITE_RED_ALPHA: usize = 0x0826_0000;
    // 0x4000_0000: dedicated to ui/notification_dispatch's owner, target,
    // and vtable raw-u32 fixture; mappings never unmap.
    pub const UI_NOTIFICATION_DISPATCH: usize = 0x4000_0000;
    // 0x4100_0000: dedicated to ui/text_line_offset_slot's target-width
    // layout record fixture; mappings never unmap, so no other user may share it.
    pub const UI_TEXT_LINE_OFFSET_SLOT: usize = 0x4100_0000;
    // 0x4200_0000: dedicated to ui/text_line_offset_read_be's target-width
    // layout record fixture; mappings never unmap, so no other user may share it.
    pub const UI_TEXT_LINE_OFFSET_READ_BE: usize = 0x4200_0000;
    // 0x4300_0000: dedicated to ft/cff_parse_fixed's target-width cursor
    // record and operand fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const CFF_PARSE_FIXED: usize = 0x4300_0000;
    // 0x4400_0000: dedicated to ui/pool_entry_create's owner fixture; mappings
    // never unmap, so no other user may share this hint.
    pub const UI_POOL_ENTRY_CREATE: usize = 0x4400_0000;
    // 0x4450_0000: dedicated to crypto/bio_free_all's target-width BIO
    // chain fixture; mappings never unmap, so no other port may share it.
    pub const BIO_FREE_ALL: usize = 0x4450_0000;
    // 0x4500_0000: dedicated to ft/cff_pshinter_callback's target-width face,
    // state, and callback-table fixture; mappings never unmap, so no other user
    // may share this hint.
    pub const CFF_PSHINTER_CALLBACK: usize = 0x4500_0000;
    // 0x9d20_0000: dedicated to cxx/reverse_byte_cursor_pop's raw-u32 cursor
    // and byte-range fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const REVERSE_BYTE_CURSOR_POP: usize = 0x9d20_0000;
    // 0x9d50_0000: dedicated to util/byte_bit_set_mask's raw-u32 byte-bitset
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const BYTE_BIT_SET_MASK: usize = 0x9d50_0000;
    // 0xc400_0000: dedicated to ui/plst_find_by_persistent_id's raw-u32
    // 'tdat' element and linked 'plst' chain fixture; mappings never
    // unmap, so no other test may reuse this hint.
    pub const UI_PLST_FIND_BY_PERSISTENT_ID: usize = 0xc400_0000;
    // 0x0101_0000: dedicated to cxx/strstreambuf_copy_active_buffer's
    // target-width stream-buffer and source fixture; mappings never unmap,
    // so no other user may share this hint.
    pub const STRSTREAMBUF_COPY_ACTIVE_BUFFER: usize = 0x0101_0000;
    // 0x6100_0000: dedicated to sqlite/lock_and_prepare's raw-u32 connection
    // and Db-record fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const SQLITE_LOCK_AND_PREPARE: usize = 0x6100_0000;
    // 0xdead_0000: dedicated to util/encoded_pair_matches_magic's raw-u32
    // target-layout pair fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const ENCODED_PAIR_MATCHES_MAGIC: usize = 0xdead_0000;
    // 0xface_0000: dedicated to heap/memh_handle_release's target-width slot
    // and refcounted MemH-handle fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const MEMH_HANDLE_RELEASE: usize = 0xface_0000;
    // 0xabcd_0000: dedicated to app/buffered_stream_flush_pending's raw-u32
    // backing-object fixture; mappings never unmap, so no other user may share it.
    pub const BUFFERED_STREAM_FLUSH_PENDING: usize = 0xabcd_0000;
    // 0xbeef_0000: dedicated to heap/region_list_erase_recycle's raw-u32
    // list and node fixture; mappings never unmap, so no other user may share
    // this hint.
    pub const REGION_LIST_ERASE_RECYCLE: usize = 0xbeef_0000;
    // 0x082c_0000/0x082d_0000: dedicated to util/buffer_result_take's
    // target-width owner and buffer fixtures; mappings never unmap.
    pub const BUFFER_RESULT_TAKE: usize = 0x082c_0000;
    pub const BUFFER_RESULT_TAKE_REJECT: usize = 0x082d_0000;
    // 0x7600_0000: dedicated to ui/candidate_is_accepted's target-width
    // context, candidate, and payload fixture; mappings never unmap.
    pub const CANDIDATE_IS_ACCEPTED: usize = 0x7600_0000;
    // 0x7700_0000: dedicated to app/object_has_resolved_flag_0x800's
    // target-width object, successor, and payload fixtures; mappings never
    // unmap, so no other user may share this hint.
    pub const OBJECT_HAS_RESOLVED_FLAG_0X800: usize = 0x7700_0000;
    // 0x7701_0000: dedicated to app/object_has_resolved_flag_0x40's
    // target-width object, successor, and payload fixtures; mappings never
    // unmap, so no other user may share this hint.
    pub const OBJECT_HAS_RESOLVED_FLAG_0X40: usize = 0x7701_0000;
    // 0x7702_0000: dedicated to app/resolve_successor_value's target-width
    // successor, child, and value fixtures; mappings never unmap, so no other
    // user may share this hint.
    pub const RESOLVE_SUCCESSOR_VALUE: usize = 0x7702_0000;
    // 0x7800_0000: dedicated to util/object_selected_payload_index's
    // target-width object, descriptor, and payload fixture; mappings never
    // unmap, so no other user may share this hint.
    pub const OBJECT_SELECTED_PAYLOAD_INDEX: usize = 0x7800_0000;
    // 0x7801_0000: dedicated to app/object_child_count_is_positive's raw-u32
    // object and child-record fixture; mappings never unmap, so no other user
    // may share this hint.
    pub const OBJECT_CHILD_COUNT_IS_POSITIVE: usize = 0x7801_0000;
    // 0x4244_0000: dedicated to util/tagged_buffer_payload_address's raw-u32
    // descriptor and payload fixture; mappings never unmap.
    pub const TAGGED_BUFFER_PAYLOAD_ADDRESS: usize = 0x4244_0000;
    // 0x7900_0000: dedicated to cxx/slot_array_owner_get's raw-u32 slot
    // array and storage fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const SLOT_ARRAY_OWNER_GET: usize = 0x7900_0000;
    // 0x7fa0_0000: dedicated to ui/selection_clear_and_stop_timer's raw-u32
    // controller, embedded BitSet, and timer fixture; mappings never unmap.
    pub const SELECTION_CLEAR_AND_STOP_TIMER: usize = 0x7fa0_0000;
    // 0x7fb0_0000: dedicated to app/media_player_transition_dispatch's
    // raw-u32 object, target-slot, and target fixture; mappings never unmap.
    pub const MEDIA_PLAYER_TRANSITION_DISPATCH: usize = 0x7fb0_0000;
    // 0x7fc0_0000: dedicated to app/playback_action_flags's raw-u32 player
    // and nested-state fixture; mappings never unmap.
    pub const PLAYBACK_ACTION_FLAGS: usize = 0x7fc0_0000;
    // 0x7fd0_0000: dedicated to app/media_player_set_volume's raw-u32 player
    // fixture; mappings never unmap, so no other port may share this hint.
    pub const MEDIA_PLAYER_SET_VOLUME: usize = 0x7fd0_0000;
    // 0x1357_0000: dedicated to util/active_selection_previous_index's raw-u32
    // selection-state fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const ACTIVE_SELECTION_PREVIOUS_INDEX: usize = 0x1357_0000;
    // 0x1358_0000: dedicated to util/choice_state_prune_duplicate_tail's
    // raw target-width choice-state fixture; mappings never unmap, so no
    // other user may share this hint.
    pub const CHOICE_STATE_PRUNE_DUPLICATE_TAIL: usize = 0x1358_0000;
    // 0x1359_0000: dedicated to app/opaque_collection_copy_entry's raw-u32
    // collection and entry-table fixture; mappings never unmap.
    pub const OPAQUE_COLLECTION_COPY_ENTRY: usize = 0x1359_0000;
    // 0x7fd0_0000: dedicated to kernel/task_message's raw-u32 receive-cell
    // and emit-marker fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const TASK_MESSAGE_RECEIVE: usize = 0x7fd0_0000;
    // 0x7fe0_0000: dedicated to kernel/task_message transport enqueue's
    // target-width transport, ring, semaphore, and data fixtures; mappings
    // never unmap, so no other user may share this hint.
    pub const TASK_MESSAGE_TRANSPORT_ENQUEUE: usize = 0x7fe0_0000;
    // 0x7ff0_0000: dedicated to util/indexed_slot_pointer's raw-u32 object
    // and table fixture; mappings never unmap, so no other user may share it.
    pub const INDEXED_SLOT_POINTER: usize = 0x7ff0_0000;
    // 0x8010_0000: dedicated to app/task_context_observable_dispatch's
    // target-width current-task-context fixture; mappings never unmap, so no
    // other user may share this hint.
    pub const TASK_CONTEXT_OBSERVABLE_DISPATCH: usize = 0x8010_0000;
    // 0x8020_0000: dedicated to app/task_context_observable_dispatch's
    // cached-observable context fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const TASK_CONTEXT_OBSERVABLE_DISPATCH_CACHED: usize = 0x8020_0000;
    // 0x8030_0000: dedicated to util/free_index_table_grow's target-width
    // table header and old-slot fixture; mappings never unmap.
    pub const FREE_INDEX_TABLE_GROW: usize = 0x8030_0000;
    // 0x083e_9000: dedicated to util/fixed_record_u16_lookup's runtime
    // record-table fixture; mappings never unmap, so no other user may share it.
    pub const FIXED_RECORD_U16_LOOKUP: usize = 0x083e_9000;
    // 0x8030_0000: dedicated to util/linked_list_refresh_sort_ascending's
    // target-width anchor, nodes, and cursor fixture; mappings never unmap.
    pub const LINKED_LIST_REFRESH_SORT_ASCENDING: usize = 0x8030_0000;
    // 0x8040_0000 and 0x8050_0000: dedicated to
    // util/tagged_record_storage_address's raw-u32 base, descriptor, and
    // layout fixtures; mappings never unmap, so no other user may share them.
    pub const TAGGED_RECORD_STORAGE_ADDRESS: usize = 0x8040_0000;
    pub const TAGGED_RECORD_STORAGE_ADDRESS_RESULT: usize = 0x8050_0000;
    // 0x8060_0000: dedicated to ui/plst_element_load_item's target-width
    // element, source, result, and item fixture; mappings never unmap.
    pub const PLST_ELEMENT_LOAD_ITEM: usize = 0x8060_0000;
    // 0x8061_0000: dedicated to ui/plst_find_by_selector's raw-u32 element,
    // cache, and item fixtures; mappings never unmap, so no other user may share it.
    pub const PLST_FIND_BY_SELECTOR: usize = 0x8061_0000;
    // 0x8070_0000: dedicated to ui/plst_apply_counted_string's raw-u32
    // item and owner fixture; mappings never unmap, so no other user may share it.
    pub const PLST_APPLY_COUNTED_STRING: usize = 0x8070_0000;
    // Dedicated target-width ASN1_OBJECT fixtures for crypto/obj_cmp.
    pub const OBJ_CMP: usize = 0x8080_0000;
    pub const OBJ_CMP_ZERO: usize = 0x8090_0000;
    // 0x80a0_0000: dedicated to util/zeroing_bump_alloc's raw-u32 arena
    // state and payload fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const ZEROING_BUMP_ALLOC: usize = 0x80a0_0000;
    // 0x80b0_0000: dedicated to app/entry_match_successor's raw-u32 entry,
    // nested-container, and target fixture; mappings never unmap.
    pub const ENTRY_MATCH_SUCCESSOR: usize = 0x80b0_0000;
    // 0x80b1_0000: dedicated to app/entry_match_find_eligible's raw-u32
    // container, nested-object, and entry-list fixture; mappings never unmap.
    pub const ENTRY_MATCH_FIND_ELIGIBLE: usize = 0x80b1_0000;
    // 0x80b2_0000: dedicated to app/entry_nested_liti_class_check's raw-u32
    // entry, nested-container, and target fixture; mappings never unmap.
    pub const ENTRY_NESTED_LITI_CLASS_CHECK: usize = 0x80b2_0000;
    // 0x80c0_0000 and 0x80d0_0000: dedicated to
    // ui/object_resource_counted_string's raw-u32 object and entry-table
    // fixtures; mappings never unmap, so no other user may share them.
    pub const OBJECT_RESOURCE_COUNTED_STRING: usize = 0x80c0_0000;
    pub const OBJECT_RESOURCE_COUNTED_STRING_VALID: usize = 0x80d0_0000;
    // 0xb020_0000 and 0xb030_0000: dedicated to ui/backend_active_item's
    // raw-u32 backend, 'tdat', and 'plst' chain fixtures; mappings never
    // unmap, so no other user may share them.
    pub const BACKEND_ACTIVE_ITEM: usize = 0xb020_0000;
    pub const BACKEND_ACTIVE_ITEM_CHAIN: usize = 0xb030_0000;
    pub const OBJECT_RESOURCE_STRING: usize = 0x80e0_0000;
    pub const OBJECT_RESOURCE_TABLE_COUNTED_STRING: usize = 0x80f0_0000;
    pub const OBJECT_RESOURCE_VECTOR20_COUNTED_STRING: usize = 0x8100_0000;
    pub const OBJECT_RESOURCE_VECTOR24_COUNTED_STRING: usize = 0x8110_0000;
    // 0x82a0_0000 and 0x82b0_0000: dedicated to
    // ui/object_resource_vector16_counted_string's raw-u32 object and
    // entry-table fixtures; mappings never unmap, so no other user may share them.
    pub const OBJECT_RESOURCE_VECTOR16_COUNTED_STRING: usize = 0x82a0_0000;
    pub const OBJECT_RESOURCE_VECTOR16_COUNTED_STRING_VALID: usize = 0x82b0_0000;
    // 0x8120_0000 and 0x8130_0000: dedicated to
    // cxx/red_black_tree_root_replace's target-layout root and node fixtures;
    // mappings never unmap, so no other user may share these hints.
    pub const RED_BLACK_TREE_ROOT_REPLACE: usize = 0x8120_0000;
    pub const RED_BLACK_TREE_ROOT_REPLACE_STRINGS: usize = 0x8130_0000;
    // 0x8140_0000: dedicated to cxx/condition_queue_dequeue's target-width
    // queue, node, and item fixture; mappings never unmap.
    pub const CONDITION_QUEUE_DEQUEUE: usize = 0x8140_0000;
    // 0x4b70_0000: dedicated to cxx/tagged_context_dequeue's target-width
    // owner, deque, and front-item fixture; mappings never unmap.
    pub const TAGGED_CONTEXT_DEQUEUE: usize = 0x4b70_0000;
    // 0x8150_0000 / 0x8160_0000: dedicated to sqlite/triggers_exist's
    // target-width table and trigger-chain fixtures; mappings never unmap.
    pub const SQLITE_TRIGGERS_EXIST: usize = 0x8150_0000;
    pub const SQLITE_TRIGGERS_EXIST_VIRTUAL: usize = 0x8160_0000;
    // 0x8170_0000..0x8190_0000: dedicated to sqlite/src_list_assign_cursors'
    // target-layout parse, source-list, and SELECT fixtures; mappings never
    // unmap, so each test needs its own hint.
    pub const SQLITE_SRC_LIST_ASSIGN_CURSORS: usize = 0x8170_0000;
    pub const SQLITE_SRC_LIST_ASSIGN_CURSORS_DEPTH_FIRST: usize = 0x8180_0000;
    pub const SQLITE_SRC_LIST_ASSIGN_CURSORS_STOP: usize = 0x8190_0000;
    pub const BIGINT_TRIM_HIGH_ZERO_LIMBS: usize = 0x81a0_0000;
    // 0x81b0_0000..0x81d0_0000: dedicated to app/record_commit's target-width
    // record and descriptor fixtures; mappings never unmap.
    pub const RECORD_COMMIT_REJECT: usize = 0x81b0_0000;
    pub const RECORD_COMMIT_FAILURE: usize = 0x81c0_0000;
    pub const RECORD_COMMIT_SUCCESS: usize = 0x81d0_0000;
    // 0x81e0_0000: dedicated to h264/decoder_range_lookup's target-width
    // stream and packed range-table fixture; mappings never unmap, so no
    // other test may share this hint.
    pub const DECODER_RANGE_LOOKUP: usize = 0x81e0_0000;
    // 0x81f0_0000: dedicated to app/linked_list_merge_by_word_4's
    // target-width intrusive-node fixture; mappings never unmap.
    pub const LINKED_LIST_MERGE_BY_WORD_4: usize = 0x81f0_0000;
    // 0x8240_0000: dedicated to app/media_item_matches_context's target-width
    // object, item table, and selected-record fixture; mappings never unmap.
    pub const MEDIA_ITEM_MATCHES_CONTEXT: usize = 0x8240_0000;
    // 0x8200_0000 / 0x8210_0000: dedicated to h264/fragment_list_append's
    // target-width list, storage, source and directory fixtures; mappings
    // never unmap, so no other test may share either hint.
    pub const H264_FRAGMENT_LIST_APPEND: usize = 0x8200_0000;
    pub const H264_FRAGMENT_LIST_APPEND_ZERO: usize = 0x8210_0000;
    // 0x8220_0000: dedicated to fs/cache_request_flush's target-width
    // request and descriptor fixture; mappings never unmap.
    pub const CACHE_REQUEST_FLUSH: usize = 0x8220_0000;
    // 0x8290_0000: dedicated to ui/plst_file_element_create's target-width
    // owner, factory output, registry, and navigation-source fixture; mappings
    // never unmap, so no other user may share this hint.
    pub const PLST_FILE_ELEMENT_CREATE: usize = 0x8290_0000;
    // 0x6f00_0000: dedicated to cxx/lazy_string_tables_initialize's two
    // raw-u32 opaque-table fixtures; mappings never unmap, so no other user
    // may share these hints.
    pub const LAZY_STRING_TABLES_INITIALIZE_FIRST: usize = 0x6f00_0000;
    pub const LAZY_STRING_TABLES_INITIALIZE_SECOND: usize = 0x6f10_0000;
    // 0x6f20_0000: dedicated to ui/range_byte_lookup's target-width table
    // fixture; mappings never unmap, so no other test may share this hint.
    pub const RANGE_BYTE_LOOKUP: usize = 0x6f20_0000;
    // 0x8230_0000: dedicated to util/object_record_at's target-width object
    // and eight-byte record-table fixture; mappings never unmap.
    pub const OBJECT_RECORD_AT: usize = 0x8230_0000;
    // 0x8240_0000: dedicated to util/selected_or_all_entry_range's
    // target-width owner and entry-list fixture; mappings never unmap.
    pub const SELECTED_OR_ALL_ENTRY_RANGE: usize = 0x8240_0000;
    // 0x8250_0000: dedicated to util/segment_cursor_snapshot's target-width
    // cursor, source, and segment fixture; mappings never unmap.
    pub const SEGMENT_CURSOR_SNAPSHOT: usize = 0x8250_0000;
    // 0x8270_0000: dedicated to util/segment_index_bounds's target-width
    // context and provider fixture; mappings never unmap.
    pub const SEGMENT_INDEX_BOUNDS: usize = 0x8270_0000;
    // 0x8260_0000: dedicated to ui/view_resource_provider_assign's
    // target-width view and provider fixtures; mappings never unmap.
    pub const VIEW_RESOURCE_PROVIDER_ASSIGN: usize = 0x8260_0000;
    // 0x6da0_0000 / 0x6db0_0000: dedicated to
    // app/opaque_record_vector_last_entry's target-width owner and vector
    // fixtures; mappings never unmap, so no other user may share them.
    pub const OPAQUE_RECORD_VECTOR_LAST_ENTRY: usize = 0x6da0_0000;
    pub const OPAQUE_RECORD_VECTOR_LAST_ENTRY_WRAP: usize = 0x6db0_0000;
    // 0x6f30_0000: dedicated to app/activity_media_player_cleanup's
    // target-width six-word activity-cleanup fixture; mappings never unmap.
    pub const ACTIVITY_MEDIA_PLAYER_CLEANUP: usize = 0x6f30_0000;
    // 0x6f50_0000: dedicated to app/linked_node_status_set's target-width
    // intrusive node ring and owner fixture; mappings never unmap, so no other
    // port may share this hint.
    pub const LINKED_NODE_STATUS_SET: usize = 0x6f50_0000;
    // 0x6f40_0000: dedicated to app/volume_controller_reschedule_timer's
    // target-width controller and embedded timer fixture; mappings never unmap.
    pub const VOLUME_CONTROLLER_RESCHEDULE_TIMER: usize = 0x6f40_0000;
    // 0x8270_0000: dedicated to app/transfer_slot_process's target-width
    // transfer context and MOV manager fixture; mappings never unmap.
    pub const TRANSFER_SLOT_PROCESS: usize = 0x8270_0000;
    // 0x8280_0000: dedicated to app/transfer_slot_reconcile's target-width
    // transfer context and MOV chain-table fixture; mappings never unmap.
    pub const TRANSFER_SLOT_RECONCILE: usize = 0x8280_0000;
    // 0x8290_0000: dedicated to fs/storage_transfer_chunked's target-width
    // temporary aligned-buffer fixture; mappings never unmap.
    pub const STORAGE_TRANSFER_CHUNKED: usize = 0x8290_0000;
    // 0x6e30_0000: dedicated to cxx/tagged_bit_set_insert_utf8's target-width
    // BitSet word-storage fixture; mappings never unmap.
    pub const TAGGED_BIT_SET_INSERT_UTF8: usize = 0x6e30_0000;
    // 0x6e40_0000: dedicated to util/vtable_slot_0x5c_result_is_three's
    // target-width object and vtable fixture; mappings never unmap.
    pub const VTABLE_SLOT_0X5C_RESULT_IS_THREE: usize = 0x6e40_0000;
    // 0x6e50_0000: dedicated to fs/fat_entry_write's target-width volume
    // context and FAT data fixture; mappings never unmap.
    pub const FAT_ENTRY_WRITE: usize = 0x6e50_0000;
    // 0x7df0_0000: dedicated to app/associated_object_word_at_0c_or_negative_one's
    // target-width object and associated-object fixture; mappings never unmap.
    pub const ASSOCIATED_OBJECT_WORD_AT_0C: usize = 0x7df0_0000;
    // 0x7de0_0000: dedicated to app/resource/prepare's target-width state
    // and identifier-range fixture; mappings never unmap.
    pub const RESOURCE_ARENA_PREPARE: usize = 0x7de0_0000;
    // 0x7dc0_0000 / 0x7dd0_0000: dedicated to
    // app/context_secondary_target_set's target-width context and target
    // fixtures; mappings never unmap, so no other user may share either hint.
    pub const CONTEXT_SECONDARY_TARGET_SET: usize = 0x7dc0_0000;
    pub const CONTEXT_SECONDARY_TARGET_SET_NON_NULL: usize = 0x7dd0_0000;
    // 0x6f60_0000 / 0x6f70_0000 / 0x6f80_0000: dedicated to
    // app/work_record_assign_value's target-width record and object fixtures;
    // mappings never unmap, so each test uses a distinct address.
    pub const WORK_RECORD_ASSIGN_VALUE: usize = 0x6f60_0000;
    pub const WORK_RECORD_ASSIGN_VALUE_UNCHANGED: usize = 0x6f70_0000;
    pub const WORK_RECORD_ASSIGN_VALUE_SAME_OBJECT: usize = 0x6f80_0000;
    // 0x6f90_0000 / 0x6fa0_0000: dedicated to
    // app/media_player_set_inner_state_selector's target-width player and
    // inner-state fixtures; mappings never unmap, so each test uses a
    // distinct address.
    pub const MEDIA_PLAYER_SET_INNER_STATE_SELECTOR: usize = 0x6f90_0000;
    pub const MEDIA_PLAYER_SET_INNER_STATE_SELECTOR_INVALID: usize = 0x6fa0_0000;
    // 0xde80_0000: dedicated to app/input_sequence_item_clear_action's
    // target-width item and pending-node fixture; mappings never unmap.
    pub const INPUT_SEQUENCE_ITEM_CLEAR_ACTION: usize = 0xde80_0000;
    // 0x6e60_0000: dedicated to app/registered_listener_remove_by_pair's
    // target-width listener owner and circular-list fixture; mappings never unmap.
    pub const REGISTERED_LISTENER_REMOVE_BY_PAIR: usize = 0x6e60_0000;
    // 0x6e70_0000: dedicated to app/selection_state_apply_index_and_dispatch's
    // target-width state and target fixture; mappings never unmap.
    pub const SELECTION_STATE_APPLY_INDEX_DISPATCH: usize = 0x6e70_0000;
    // 0x6ea0_0000: dedicated to util/ring_write's target-width ring and data
    // fixture; mappings never unmap, so no other port may share this hint.
    pub const RING_WRITE: usize = 0x6ea0_0000;
    // 0x6eb0_0000: dedicated to app/message_selector_read's target-width
    // message and selector-word fixture; mappings never unmap, so no other
    // port may share this hint.
    pub const MESSAGE_SELECTOR_READ: usize = 0x6eb0_0000;
    // 0x6ec0_0000: dedicated to ui/plst_optional_fields_read's target-width
    // parser state, source record, and destination buffer fixture; mappings
    // never unmap, so no other port may share this hint.
    pub const PLST_OPTIONAL_FIELDS_READ: usize = 0x6ec0_0000;
    // 0x7920_0000: dedicated to ui/plst_secondary_slot_item's target-width
    // element, header, and lazily materialized secondary-slot fixture; mappings
    // never unmap, so no other port may share this hint.
    pub const PLST_SECONDARY_SLOT_ITEM: usize = 0x7920_0000;
    // 0x6fc0_0000: dedicated to util/entry_table_finalize_and_append's
    // target-width state fixture; mappings never unmap, so no other user may
    // share it.
    pub const ENTRY_TABLE_FINALIZE_AND_APPEND: usize = 0x6fc0_0000;
    // 0x6fd0_0000: dedicated to util/queue_remove_source_tail_index's
    // target-width source-record and queue fixture; mappings never unmap.
    pub const QUEUE_REMOVE_SOURCE_TAIL_INDEX: usize = 0x6fd0_0000;
    // 0x6fe0_0000: dedicated to ui/flush_pending_cell's target-width cell
    // record fixture; mappings never unmap, so no other port may share it.
    pub const UI_FLUSH_PENDING_CELL: usize = 0x6fe0_0000;
    // 0x6ff0_0000: dedicated to ui/tdat_element_teardown's target-width
    // element and linked 'plst' node fixture; mappings never unmap.
    pub const TDAT_ELEMENT_TEARDOWN: usize = 0x6ff0_0000;
    // 0x6ff8_0000: dedicated to util/big_endian_bit_cell_store's target-width
    // table and cell fixtures; mappings never unmap, so no other port may use it.
    pub const BIG_ENDIAN_BIT_CELL_STORE: usize = 0x6ff8_0000;
    // 0x6ec0_0000: dedicated to util/big_endian_bit_cell_store_and_mark_pending's
    // target-width table and cell fixtures; mappings never unmap.
    pub const BIG_ENDIAN_BIT_CELL_STORE_AND_MARK_PENDING: usize = 0x6ec0_0000;
    // 0x6ef0_0000: dedicated to ui/plst_task_is_active's target-width task
    // element fixture; mappings never unmap, so no other port may share it.
    pub const PLST_TASK_IS_ACTIVE: usize = 0x6ef0_0000;
    // 0x6fb0_0000: dedicated to ui/navigation_mode_from_state's target-width
    // owner and nested-state fixture; mappings never unmap, so no other port
    // may share it.
    pub const UI_NAVIGATION_MODE_FROM_STATE: usize = 0x6fb0_0000;
    // 0x7000_0000: dedicated to fs/hfs_btree_lookup_key's target-width
    // handle and control-block fixture; mappings never unmap.
    pub const HFS_BTREE_LOOKUP_KEY: usize = 0x7000_0000;
    // 0x6aa0_0000: dedicated to kernel/thunks's target-width UI-manager,
    // state, and current-context fixture; mappings never unmap.
    pub const UI_MANAGER_CURRENT_CONTEXT: usize = 0x6aa0_0000;
    // 0x6a90_0000: dedicated to util/record_min_heap_sift_up's record and
    // heap fixtures; mappings never unmap, so no other port may share it.
    pub const RECORD_MIN_HEAP_SIFT_UP: usize = 0x6a90_0000;
    // 0x6ac0_0000: dedicated to cxx/trivial_vector24_destroy's target-width
    // vector backing-storage fixture; mappings never unmap.
    pub const TRIVIAL_VECTOR24_DESTROY: usize = 0x6ac0_0000;
    // 0x6ad0_0000 / 0x6ae0_0000: dedicated to
    // heap/trivial_range_destroy_and_deallocate's target-width range fixtures;
    // mappings never unmap, so no other port may share them.
    pub const TRIVIAL_RANGE_DESTROY_AND_DEALLOCATE: usize = 0x6ad0_0000;
    pub const TRIVIAL_RANGE_DESTROY_AND_DEALLOCATE_NULL: usize = 0x6ae0_0000;
    // 0x6af0_0000 / 0x6b00_0000: dedicated to
    // cxx/path_object_vector_push_back's target-width vector and record fixtures;
    // mappings never unmap.
    pub const PATH_OBJECT_VECTOR_PUSH_BACK: usize = 0x6af0_0000;
    pub const PATH_OBJECT_VECTOR_PUSH_BACK_EMPTY: usize = 0x6b00_0000;
}

/// Maps `len` bytes at `hint` and returns it only if the whole span
/// round-trips through `u32` unchanged. `None` means this host cannot place
/// the fixture below 4 GiB; callers skip rather than guess an address.
///
/// Pass a constant from [`hints`] — never a bare literal.
pub fn try_map_u32_slab(hint: usize, len: usize) -> Option<*mut u8> {
    extern "C" {
        fn mmap(addr: usize, len: usize, prot: i32, flags: i32, fd: i32, offset: i64) -> usize;
    }
    #[cfg(target_os = "macos")]
    const MAP_PRIVATE_ANON: i32 = 0x1002;
    #[cfg(target_os = "linux")]
    const MAP_PRIVATE_ANON: i32 = 0x22;
    const PROT_READ_WRITE: i32 = 3;

    let p = unsafe { mmap(hint, len, PROT_READ_WRITE, MAP_PRIVATE_ANON, -1, 0) };
    if p == usize::MAX || p == 0 || p.checked_add(len)? > 0x1_0000_0000 {
        return None;
    }
    Some(p as *mut u8)
}

/// Prints a one-line notice so a skipped fixture is never mistaken for a
/// passing test. Always returns `true`, to read as `if unavailable() {
/// return; }` at the top of a test.
pub fn note_missing_u32_fixture(module: &str) -> bool {
    extern crate std;
    std::eprintln!(
        "{module}: skipped — this host cannot map the fixture below 4 GiB \
         (u32 object pointers cannot round-trip); run these on Linux"
    );
    true
}
/// Serializes host tests that enter `ui::tdat_flag_20_bit_2` through its
/// shared mutable dispatch table, including callers that set its flag.
pub static TDAT_FLAG_20_OPS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
/// Serializes every host test that replaces the event-loop callback target.
pub static EVENT_LOOP_CALLBACK_DISPATCH_OPS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
/// Serializes all host tests that replace `runtime::message_0x17::MESSAGE_DISPATCH_OPS`.
/// The message-0x10, message-0x17, and message-0x23 wrappers share this seam.
pub static MESSAGE_DISPATCH_OPS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
/// Serializes every host test that replaces libspace's LC_CTYPE table slot.
/// Ctype readers and ctype-string ports must share this lock so their fixture
/// installation and restoration cannot race.
pub static CTYPE_TABLE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes every host test that installs a recording model into
/// `sqlite::walk_expr::SQLITE_EXPR_LIST_WALK` against the `expr_list_walk`
/// port's own tests, which rely on that slot's real-port default.
pub static SQLITE_EXPR_WALK_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes every host test that installs mocks into the crate-global
/// `drivers::ata_cmd::TRACED_ALLOC_HOOKS`. That table is one shared
/// mutable global, and `cargo test` runs test functions on parallel
/// threads, so the allocator tests in `drivers::ata_cmd` and every
/// ported caller that allocates (`sqlite::blob_to_hex`, ...) must take
/// this lock for the duration of a test rather than each keeping a
/// private one.
pub static TRACED_ALLOC_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes every host test that replaces
/// `util::global_state::GLOBAL_STATE_SLOT_FIND`. The global-state wrapper and
/// attribute-record lookup both install test slot finders into this one seam.
pub static GLOBAL_STATE_SLOT_FIND_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes every host test that installs a container vtable into
/// `app::registry::CLASS_REGISTRY`. That registry is one shared mutable
/// global whose default vtable is NULL, so any test that resolves a
/// class id through it — `app::registry`'s own container tests and every
/// ported caller of `demo_mode_instance`, such as `app::class_6800` —
/// must hold this lock rather than each keeping a private one.
pub static CLASS_REGISTRY_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes every host test that installs a fixture root into
/// `app::context_scope::APP_ROOT_OBJECT`. That static is the crate's single
/// model of the firmware word @ 0x089ca674 and is read by both
/// `app::context_scope` and `app::scoped_context`, so a per-module lock would
/// let one module's teardown NULL the root while the other is walking it.
pub static APP_ROOT_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes every host test that installs mocks into
/// `sqlite::cell_size::BTREE_CELL_OPS`. That dispatch static is shared by
/// `sqlite::cell_size`'s own wrapper tests and `sqlite::parse_cell`'s
/// varint-seam tests (both swap slots on it), so a per-module lock would
/// let one module's teardown restore defaults under the other's mock.
pub static BTREE_CELL_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes every host test that installs a mock reset into
/// `cxx::pair_header::PAIR_HEADER_ELEMENT_ARRAY_OPS`. That seam is one
/// shared mutable global read by the ported `FUN_082ab398` wrapper, and
/// both `cxx::pair_header`'s own tests and `runtime::cpp_array_construct`'s
/// adapter tests swap it, so a per-module lock would let one module's
/// teardown restore defaults under the other's mock.
pub static CPP_ARRAY_OPS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes every host test that replaces
/// `cxx::pair_header::PAIR_HEADER_BASE_BIND_PAYLOAD_OPS`. The base binder's
/// own tests and callers that bind a resource through it must share this
/// lock, or one test can restore the panic defaults while another is running.
pub static PAIR_HEADER_BASE_BIND_PAYLOAD_TEST_LOCK: std::sync::Mutex<()> =
    std::sync::Mutex::new(());

/// Serializes host tests that replace
/// `cxx::pair_header::PAIR_HEADER_BASE_POOLED_OWNED_PAYLOAD_OPS`.
pub static PAIR_HEADER_BASE_POOLED_OWNED_PAYLOAD_TEST_LOCK: std::sync::Mutex<()> =
    std::sync::Mutex::new(());

/// Serializes every host test that installs a fixture block into
/// `kernel::diag_ring_record::DIAG_RING_BLOCK_GETTER`. That seam is one
/// shared mutable global pointing at the per-task diagnostic ring, and
/// the sibling ring functions still unported (reset 0x08049694, dump
/// 0x080496f0) will share it, so they must hold this lock rather than
/// each keeping a private one.
pub static DIAG_RING_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
/// Serializes every host test that swaps
/// `kernel::diag_ring_strings::DIAG_RING_STRING_OPS`. The varargs string
/// joiner owns this seam today; future callers must reuse this lock so their
/// restoration cannot race its tests.
pub static DIAG_RING_STRING_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

/// Serializes every host test that swaps `app::view_event::VIEW_EVENT_OPS`.
/// The view-event epilogue and `app::view_timer` both invoke the unported
/// view-timer-stop wrapper through this one dispatch table.
pub static VIEW_EVENT_OPS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes every host test that swaps `app::string_table::STRING_TABLE_OPS`.
/// Derived view-event handlers use the real membership port through this
/// seam, so they share this lock with string-table's own tests.
pub static STRING_TABLE_OPS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes host tests that swap `app::string_table::STRING_TABLE_MAP_OPS`.
pub static STRING_TABLE_MAP_OPS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes every host test that swaps `drivers::timer::TIMER_OPS`.
/// The timer module and view-timer callers both drive the ported timer
/// helpers through this one dispatch table.
pub static TIMER_OPS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes every host test that swaps `ui::string_view::STRING_VIEW_OPS`.
/// Both the base view constructor tests and derived-view constructor tests
/// replace this shared mutable table.
pub static STRING_VIEW_OPS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes host tests that replace
/// `app::screen_layout::SCREEN_LAYOUT_ASSIGN_OPS`. The notification callback
/// is a shared dispatch seam, so a module-private lock would race teardown.
pub static SCREEN_LAYOUT_ASSIGN_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes every host test that swaps
/// `cxx::string_object::STRING_OBJECT_ASSIGN_CSTR_OPS`. That seam models the
/// StringObject vtable slots +0x8/+0xc process-wide: `cxx::string_object`'s
/// own assignment tests install recorders on it, and ported callers whose
/// flow passes through `string_object_assign_payload` (e.g.
/// `app::screen_layout`'s resource-setter tests) install heap-backed slots,
/// so a module-private lock would race teardown across modules.
pub static STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK: std::sync::Mutex<()> =
    std::sync::Mutex::new(());

/// Serializes tests that swap the `cxx::string_export_counted_utf16`
/// worker seam.
pub static STRING_EXPORT_COUNTED_UTF16_TEST_LOCK: std::sync::Mutex<()> =
    std::sync::Mutex::new(());

/// Serializes tests that swap the
/// `app::path_facade_probe_dispatch_counted` probe and slot +0x60 seams.
pub static PATH_FACADE_PROBE_DISPATCH_COUNTED_TEST_LOCK: std::sync::Mutex<()> =
    std::sync::Mutex::new(());

/// Serializes tests that replace the unresolved worker used by
/// `app::path_facade_resolve_relative`.
pub static PATH_FACADE_RESOLVE_RELATIVE_TEST_LOCK: parking_lot::Mutex<()> =
    parking_lot::Mutex::new(());


/// Serializes every host test that swaps
/// `util::context_field::CURRENT_TASK_CTX_BLOCK`. That slot is one shared
/// mutable global: the accessor's own tests and the `app::resource_chain`
/// task-local front-end tests both install recording mocks into it, and
/// `cargo test` runs test functions on parallel threads, so a
/// module-private lock would race teardown across modules.
pub static TASK_CTX_BLOCK_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes every host test that replaces `kernel::task::TASK_HOOKS`.
/// The task module's own tests and callers that exercise a port through
/// `current_task_ctx_block` both need to install a synthetic running node.
pub static TASK_HOOKS_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

/// Serializes every host test that replaces
/// `util::scheduler_label_lookup::SCHEDULER_LABEL_FIND`. The label lookup's
/// own tests and debug-task selection both swap this one mutable seam.
pub static SCHEDULER_LABEL_FIND_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes every host test that swaps
/// `util::interp_stack_pop_release::INTERP_OPCODE_RELEASE`. The interpreter
/// value-stack pop owns this seam today; future ports of sibling stack
/// helpers must reuse this lock so seam restoration cannot race.
pub static INTERP_OPCODE_RELEASE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes every host test that swaps
/// `app::event_code_queue::EVENT_CODE_QUEUE_HOOKS`. The queue module's own
/// tests and the `app::class_8c00` timer-rearm tests both install
/// recording enqueues into that one mutable global, so a module-private
/// lock would race teardown across modules.
pub static EVENT_CODE_QUEUE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes tests that replace the active service-handler context slot at
/// 0x089ccb5c. The readiness gate and iAP packet event scheduler share it.
pub static ACTIVE_SERVICE_HANDLER_CONTEXT_TEST_LOCK: std::sync::Mutex<()> =
    std::sync::Mutex::new(());

/// Serializes tests that replace `app::pending_event_insert`'s shared ops
/// table. The queue port and packet-event caller both install host models.
pub static PENDING_EVENT_INSERT_OPS_TEST_LOCK: std::sync::Mutex<()> =
    std::sync::Mutex::new(());

/// Serializes tests that replace the shared pending-event take ops table.
/// `pending_event_take` and `pending_event_take_due` both replace its
/// release/rearm slots with host models.
pub static PENDING_EVENT_TAKE_OPS_TEST_LOCK: std::sync::Mutex<()> =
    std::sync::Mutex::new(());

/// Serializes every host test that replaces the shared unported
/// `FUN_081d7f14` completion-dispatch table. The packet-event scheduler and
/// packet-completion port install models into this one mutable global.
pub static IAP_PACKET_EVENT_SCHEDULE_OPS_TEST_LOCK: std::sync::Mutex<()> =
    std::sync::Mutex::new(());

/// Serializes host tests that mutate the shared timing-wheel bucket array
/// behind `app::animation::scheduler_table`. The animation and refcounted
/// base-destruction ports both unlink nodes through this one host model.
pub static SCHEDULER_TABLE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
/// Serializes tests that replace controller_timer_pair_destruct's host seams.
pub static CONTROLLER_TIMER_PAIR_DESTRUCTOR_TEST_LOCK: std::sync::Mutex<()> =
    std::sync::Mutex::new(());
/// Serializes every host test that swaps
/// `app::opaque_keyed_collection_item_at::OPAQUE_KEYED_COLLECTION_VECTOR`.
/// Both keyed-collection accessors install host selectors into this shared
/// seam, so a module-private lock would race selector restoration.
pub static OPAQUE_KEYED_COLLECTION_VECTOR_TEST_LOCK: parking_lot::Mutex<()> =
    parking_lot::Mutex::new(());

/// Serializes every host test that replaces
/// `kernel::posix_mutex::POSIX_MUTEX_OPS`. The mutex port and callers that
/// query the mask-ROM running-thread entry share this one dispatch table.
pub static POSIX_MUTEX_OPS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes host tests that replace the input-sequence item lookup/build
/// seam. Both operations share one dispatch pair and must restore together.
pub static INPUT_SEQUENCE_ITEM_OPS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
/// Serializes tests that mutate the shared UI sequence identifier at
/// `0x089c_fcc4`, including callers that consume an identifier.
pub static SEQUENCE_ID_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
/// Serializes tests that replace object-selected-payload lookup's virtual and
/// stock tail-call seams.
pub static OBJECT_SELECTED_PAYLOAD_INDEX_TEST_LOCK: parking_lot::Mutex<()> =
    parking_lot::Mutex::new(());
/// Serializes host tests that replace `ui::pool_entry_create::FIXED_POOL_OPS`.
pub static UI_POOL_ENTRY_CREATE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
/// Serializes host tests that replace the unidentified UI base constructor
/// used only by `app::ui_object_construct`.
pub static UI_OBJECT_BASE_CONSTRUCT_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
/// Serializes tests that replace the media-player transition dispatch seams.
pub static MEDIA_PLAYER_TRANSITION_DISPATCH_TEST_LOCK: parking_lot::Mutex<()> =
    parking_lot::Mutex::new(());
/// Serializes host tests that mutate the fixed record table at `0x083e9d94`.
pub static FIXED_RECORD_U16_LOOKUP_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
/// Serializes every host test that replaces the unported `FUN_081d6380` base
/// constructor seam shared by derived-object constructor ports.
pub static BASE_CONSTRUCT_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
/// Serializes host tests that replace
/// `app::selection_state_copy_item_at::ARRAY_COPY_DISPATCH`.
pub static SELECTION_STATE_COPY_ITEM_AT_TEST_LOCK: parking_lot::Mutex<()> =
    parking_lot::Mutex::new(());
/// Serializes host tests that replace transfer_slot_reconcile's unported
/// `FUN_081e39e8` advance seam.
pub static TRANSFER_SLOT_RECONCILE_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
/// Serializes host tests that replace the singleton mode-dispatch target.
pub static SINGLETON_MODE_DISPATCH_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
/// Serializes host tests that replace the slot-`+0xd8` wrapper's terminal
/// command-dispatcher getter seam.
pub static OBJECT_SLOT_D8_NOTIFY_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
/// Serializes host tests that replace `app::tuning_status::SHOW_TUNING_REGION_OPS`.
pub static SHOW_TUNING_REGION_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
/// Serializes host tests that replace `cxx::draw_state_fill::DRAW_STATE_FILL_OPS`.
pub static DRAW_STATE_FILL_OPS_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

/// Serializes host tests that replace big-endian bit-cell store seams.
pub static BIG_ENDIAN_BIT_CELL_STORE_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());