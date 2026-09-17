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
    // 0x7f40_0000: dedicated to runtime/trim_ctype_whitespace's raw-u32
    // LC_CTYPE table fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const STRING_TRIM_CTYPE: usize = 0x7f40_0000;
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
    // 0x0100_0000: dedicated to cxx/stream_read's target-width descriptor,
    // complete-owner state, and reader fixture; mappings never unmap.
    pub const CXX_STREAM_READ: usize = 0x0100_0000;
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
    // 0x6300_0000: dedicated to util/video_engine's target-width frame-slot
    // table fixture; mappings never unmap, so no other user may share it.
    pub const VIDEO_ENGINE_CURRENT_FRAME_SLOT: usize = 0x6300_0000;
    // 0xcf00_0000: dedicated to util/video_engine's primary-frame table,
    // record, and payload fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const VIDEO_ENGINE_FRAME_PAYLOAD: usize = 0xcf00_0000;
    // 0x6400_0000: dedicated to ATA command execution/submission's raw-u32
    // status-source fixtures; mappings never unmap, so neither port shares it.
    pub const ATA_COMMAND_EXECUTE: usize = 0x6400_0000;
    pub const ATA_COMMAND_SUBMIT_WAIT: usize = 0x6500_0000;
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
    pub const CLIENT_POPULATE: usize = 0x0b00_0000;
    pub const BLOCK_MGR: usize = 0x0c00_0000;
    pub const LIST_SPLICE: usize = 0x0d00_0000;
    pub const EVENT_LIST: usize = 0x0e00_0000;
    pub const CONTEXT_SCOPE: usize = 0x0f00_0000;
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
    // 0x7100_0000: dedicated to sqlite/cursor_moveto's raw-u32 VdbeCursor
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const VDBE_CURSOR_MOVETO: usize = 0x7100_0000;
    pub const ELEMENT_REFERENCE: usize = 0x1200_0000;
    pub const VTABLE_SET_ITERATOR: usize = 0x1300_0000;
    pub const OBSERVABLE_ARRAY: usize = 0x1400_0000;
    pub const OBSERVABLE_ARRAY_DRAIN: usize = 0x1500_0000;
    pub const EVENT_SOURCE_DESTRUCT: usize = 0x1600_0000;
    pub const SILVER_CONTROLLER: usize = 0x1700_0000;
    pub const QUEUED_MESSAGE_POST: usize = 0x1800_0000;
    pub const VTABLE_SET_ITERATOR_RELEASE: usize = 0x1900_0000;
    pub const VDBE_SERIAL_PUT: usize = 0x1a00_0000;
    // 0x1a10_0000: dedicated to sqlite/vdbe_free_ops's target-layout
    // Vdbe and VdbeOp array fixture; mappings never unmap, so no other user
    // may share this hint.
    pub const VDBE_FREE_OPS: usize = 0x1a10_0000;
    pub const PENDING_EVENT_TAKE: usize = 0x1b00_0000;
    // Dedicated raw-u32 owner fixtures for iterator seek tests; mappings
    // never unmap, so each target layout has its own hint.
    pub const ITERATOR_STATE_SEEK: usize = 0x1c10_0000;
    pub const ITERATOR_STATE_SEEK_CONSTRUCT: usize = 0x1c20_0000;
    pub const ITERATOR_STATE_SEEK_BEGIN: usize = 0x1c30_0000;
    // 0xbf00_0000: dedicated to app/pending_event_take_due's raw-u32
    // session and pending-event fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const PENDING_EVENT_TAKE_DUE: usize = 0xbf00_0000;
    pub const ANIMATION_INIT: usize = 0x1c00_0000;
    pub const STRING_RECORD: usize = 0x1d00_0000;
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
    pub const IAP_PACKET_OWNER_MODE: usize = 0x1e00_0000;
    pub const TOKENIZER: usize = 0x1f00_0000;
    // Dedicated target-layout sqlite3 connection fixtures for
    // sqlite/close; mappings never unmap.
    pub const SQLITE_CLOSE: usize = 0x2000_0000;
    pub const SQLITE_CLOSE_SCHEMA: usize = 0x2100_0000;
    // 0xc000_0000 and 0xc100_0000: dedicated to
    // cxx/opaque_vtable_record_copy_construct's target-width source fixtures.
    pub const OPAQUE_VTABLE_RECORD_COPY_CONSTRUCT: usize = 0xc000_0000;
    pub const OPAQUE_VTABLE_RECORD_COPY_CONSTRUCT_DEFAULT: usize = 0xc100_0000;
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
    pub const VIEW_TIMER: usize = 0x2000_0000;
    // 0x2100_0000: dedicated to util/raster_profile's raw-u32 active and
    // successor profile fixture; mappings never unmap, so no other user may
    // share it.
    pub const RASTER_PROFILE_END: usize = 0x2100_0000;
    // 0xe000_0000: dedicated to ui/plst_task_complete's raw-u32 task and
    // element fixture; mappings never unmap, so no other user may share it.
    pub const PLST_TASK_COMPLETE: usize = 0xe000_0000;
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
    // 0x3900_0000, skipping 0x2e00_0000..0x3500_0000: sibling ports in
    // flight take the sequential slots, and a collision skips tests
    // silently on every host.
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
    // 0x5100_0000: dedicated to app/type_handler_lookup's raw-u32 registry
    // fixture; mappings never unmap, so no other test may reuse this hint.
    pub const TYPE_HANDLER_LOOKUP_WRAPPER: usize = 0x5100_0000;
    // 0x3a00_0000: sibling ports in flight take the sequential slots,
    // and a collision skips tests silently on every host.
    pub const KINDED_CONTROLLER: usize = 0x3a00_0000;
    // 0x3b00_0000: sibling ports in flight take the sequential slots,
    // and a collision skips tests silently on every host.
    pub const ELEMENT_REFERENCE_COOKIE: usize = 0x3b00_0000;
    // 0x3c00_0000: sibling ports in flight take the sequential slots,
    // and a collision skips tests silently on every host.
    pub const BIT_SET_TEST: usize = 0x3c00_0000;
    // 0x4100_0000, skipping 0x3d00_0000..0x4000_0000: sibling ports in
    // flight take the sequential slots, and a collision skips tests
    // silently on every host.
    pub const PLST_SLOT_ITEM: usize = 0x4100_0000;
    // 0x5e00_0000: dedicated to ui/plst_slot_materialize's raw-u32 element,
    // header, slot-record, and source-buffer fixture; mappings never unmap.
    pub const PLST_SLOT_MATERIALIZE: usize = 0x5e00_0000;
    // 0x4600_0000, skipping 0x4200_0000..0x4500_0000: sibling ports in
    // flight take the sequential slots, and a collision skips tests
    // silently on every host.
    pub const PENDING_EVENT_INSERT: usize = 0x4600_0000;
    // 0x5f00_0000: dedicated to cxx/stream_read_cxx_string's raw-u32
    // descriptor, owner-state, and reader fixture; mappings never unmap.
    pub const CXX_STREAM_READ_CXX_STRING: usize = 0x5f00_0000;
    // 0x4a00_0000, skipping the sequential 0x4700_0000..0x4900_0000:
    // sibling ports in flight take the sequential slots, and a
    // collision skips tests silently on every host.
    pub const TAGGED_WORD_BUFFER: usize = 0x4a00_0000;
    // 0x5a00_0000, skipping 0x4b00_0000..0x5900_0000: sibling ports in
    // flight take the sequential slots, and a collision skips tests
    // silently on every host.
    pub const ELEMENT_REFERENCE_PERSISTENT_ID: usize = 0x5a00_0000;
    pub const TIMED_TRANSITION: usize = 0x5c00_0000;
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
    // 0xd900_0000: dedicated to cxx/timer_stop_then_clear_bit_set's raw-u32
    // embedded bit-set and timer fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const TIMER_STOP_THEN_CLEAR_BIT_SET: usize = 0xd900_0000;
    // 0x6c00_0000, far clear of the sequential run: sibling ports in
    // flight take the next free slots, and a collision skips tests
    // silently on every host.
    pub const IAP_THREAD_SLOT_WAIT: usize = 0x6c00_0000;
    // 0x6e00_0000: dedicated to heap/word_buffer's raw-u32 singleton-reset
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const WORD_BUFFER_RESET_OPTIONAL_SINGLETON: usize = 0x6e00_0000;
    // 0x6f00_0000: dedicated to app/service_handler_pending_event_reset's
    // session fixture; mappings never unmap, so no other test may reuse it.
    pub const SERVICE_HANDLER_PENDING_EVENT_RESET: usize = 0x6f00_0000;
    // 0x9200_0000: dedicated to app/service_handler_status's raw-u32 query
    // object fixture; mappings never unmap, so no other user may share it.
    pub const SERVICE_HANDLER_STATUS_QUERY: usize = 0x9200_0000;
    // 0x7c00_0000: dedicated to heap/word_buffer's raw-u32 assignment
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const MARKED_WORD_BUFFER_ASSIGN: usize = 0x7c00_0000;

    // 0x7e00_0000: dedicated to class-0x7f80 artwork-slot fixtures;
    // fixture mappings never unmap, so no other user may share this hint.
    pub const ARTWORK_SLOT_AVAILABILITY: usize = 0x7e00_0000;
    // 0x7d00_0000: dedicated to runtime/ctype isdigit's raw-u32 LC_CTYPE
    // table fixture; mappings never unmap, so no other user may share this
    // hint.
    pub const CTYPE_ISDIGIT: usize = 0x7d00_0000;
    // 0x0400_0000: dedicated to runtime/ctype isspace's raw-u32 LC_CTYPE
    // table fixture; mappings never unmap, so no other user may share this
    // hint.
    pub const CTYPE_ISSPACE: usize = 0x0400_0000;
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
    // 0x7f30_0000: dedicated to app/character_class_scan's target-width
    // parser and character-class-table fixture; mappings never unmap, so no
    // other user may share this hint.
    pub const PARSER_SCAN_TO_CLASS_BOUNDARY: usize = 0x7f30_0000;
    // 0x8300_0000: dedicated to sqlite/index_key_info's raw-u32 Index,
    // KeyInfo, collation-array, and tracked-allocation fixtures; mappings
    // never unmap, so no other user may share this hint.
    pub const SQLITE_INDEX_KEY_INFO: usize = 0x8300_0000;
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
    // 0xcd00_0000: dedicated to heap/two_buffer_owner's raw-u32 buffer and
    // data fixture; mappings never unmap, so no other user may share this
    // hint.
    pub const TWO_BUFFER_OWNER_RELEASE: usize = 0xcd00_0000;
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
    // 0xa800_0000: dedicated to ui/element_reference_target_field_210's
    // raw-u32 reference/target fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const ELEMENT_REFERENCE_TARGET_FIELD_210: usize = 0xa800_0000;
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
    // 0xf200_0000: dedicated to app/context_scope_selector's raw-u32
    // subject/context fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const CONTEXT_SCOPE_SELECTOR: usize = 0xf200_0000;
    // 0xf800_0000: dedicated to app/current_record_handle's containing-owner
    // cursor fixture; mappings never unmap, so no other user may share this
    // hint.
    pub const OWNER_CURRENT_RECORD_HANDLE: usize = 0xf800_0000;
    // 0xd300_0000, far clear of the sequential run: sibling ports in
    // flight take the next free slots, and a collision skips tests
    // silently on every host.
    pub const PLST_SLOT_POSITION: usize = 0xd300_0000;
    // 0xc100_0000: dedicated to cxx/payload_list_owner_destroy's raw-u32
    // owner/list fixture; mappings never unmap, so no other user may share it.
    pub const PAYLOAD_LIST_OWNER_DESTROY: usize = 0xc100_0000;
    // 0xc200_0000: dedicated to cxx/shared_cell's direct-release payload
    // fixture; mappings never unmap, so no other user may share it.
    pub const SHARED_CELL_DIRECT_RELEASE: usize = 0xc200_0000;
    // 0xc300_0000: dedicated to cxx/shared_cell's secondary direct-release
    // payload fixture; mappings never unmap, so no other user may share it.
    pub const SHARED_CELL_DIRECT_RELEASE_SECONDARY: usize = 0xc300_0000;
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
    // 0xfb00_0000: dedicated to ui/tdat_message_dispatch's raw-u32 virtual
    // handler and context fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const TDAT_MESSAGE_DISPATCH: usize = 0xfb00_0000;
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
    // 0x8c00_0000: dedicated to app/descriptor_attachment's raw-u32 owner,
    // descriptor, and link fixtures; mappings never unmap.
    pub const DESCRIPTOR_ATTACHMENT: usize = 0x8c00_0000;
    // 0x8f00_0000: dedicated to mov/chain_value_span's raw-u32 chain-value
    // record fixture; mappings never unmap, so no other user may share it.
    pub const MOV_CHAIN_TABLE_LOAD_SPAN: usize = 0x8f00_0000;
    // 0x9c00_0000: dedicated to mov/atom_table's raw-u32 node-tree and
    // factory-result fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const MOV_ATOM_TABLE_LOOKUP: usize = 0x9c00_0000;
    // 0x8e00_0000: dedicated to ui/element_reference_item's raw-u32
    // reference, vtable, element, header, and slot fixtures; mappings never
    // unmap, so no other user may share this hint.
    pub const ELEMENT_REFERENCE_ITEM: usize = 0x8e00_0000;
    // 0x8d10_0000: dedicated to app/indexed_timestamp_bounds's raw-u32
    // state, table, and entry fixtures; mappings never unmap, so no other
    // user may share this hint.
    pub const INDEXED_TIMESTAMP_BOUNDS: usize = 0x8d10_0000;
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
    // 0x5d00_0000: dedicated to sqlite/move_to_child's target-width cursor,
    // Btree, and MemPage fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const BTREE_MOVE_TO_CHILD: usize = 0x5d00_0000;
    // 0x5300_0000 and 0x5400_0000: dedicated to the cxx shared-handle
    // initializer and its vtable-owner constructor fixtures; mappings never
    // unmap, so each mapping site has its own hint.
    pub const SHARED_HANDLE_INITIALIZE: usize = 0x5300_0000;
    pub const VTABLE_SHARED_HANDLE_CONSTRUCT: usize = 0x5400_0000;
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
    // 0x5800_0000: dedicated to heap/memh_handle's target-width handle
    // fixture; mappings never unmap, so no other user may share it.
    pub const MEMH_HANDLE_DESTROY: usize = 0x5800_0000;
    // 0x3400_0000: dedicated to heap/memh_set_len's target-width header,
    // payload, and mock-allocation fixture; mappings never unmap, so no
    // other user may share this hint.
    pub const MEMH_SET_LEN: usize = 0x3400_0000;
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
    // 0x0600_0000: dedicated to sqlite/expr_code_expr_list's raw-u32
    // ExprList and item fixtures; mappings never unmap, so no other user may
    // share this hint.
    pub const SQLITE_EXPR_CODE_EXPR_LIST: usize = 0x0600_0000;
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
    // 0x3300_0000: dedicated to sqlite/pager_set_page_size's raw-u32 Pager
    // and replacement-temporary-space fixture; mappings never unmap.
    pub const SQLITE_PAGER_SET_PAGE_SIZE: usize = 0x3300_0000;
    // 0x9500_0000: dedicated to sqlite/pcache_remove_from_lru_list's raw-u32
    // cache and three-page LRU fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const SQLITE_PCACHE_REMOVE_FROM_LRU_LIST: usize = 0x9500_0000;
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
    // 0xe200_0000: dedicated to printf/retail_sscanf's target-width
    // varargs/output fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RETAIL_SSCANF: usize = 0xe200_0000;
    // 0xe400_0000: dedicated to ui/element_change_notify's target-width
    // element fixture; mappings never unmap, so no other user may share it.
    pub const UI_ELEMENT_CHANGE_NOTIFY: usize = 0xe400_0000;
    // 0xa1b0_0000: dedicated to app/nested_liti_class_check's raw-u32
    // container and nested-class fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const NESTED_LITI_FIELD_CHECK: usize = 0xa1b0_0000;
    // 0xa1c0_0000: dedicated to app/entry_match_first's raw-u32 container
    // and nested-class fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const ENTRY_MATCH_FIRST: usize = 0xa1c0_0000;
    // 0xa1e0_0000: dedicated to cxx/magic_tagged_object_release's raw-u32
    // object, child-table, and nested-child fixture; mappings never unmap, so
    // no other user may share this hint.
    pub const MAGIC_TAGGED_OBJECT_RELEASE: usize = 0xa1e0_0000;
    // 0xa1f0_0000: dedicated to cxx/magic_tagged_object_retain's raw-u32
    // object, child-table, and nested-child fixture; mappings never unmap, so
    // no other user may share this hint.
    pub const MAGIC_TAGGED_OBJECT_RETAIN: usize = 0xa1f0_0000;
    // 0xa1c0_0000: dedicated to app/liti_field_class_check's raw-u32 object
    // and class-target fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const LITI_FIELD_CLASS_CHECK: usize = 0xa1c0_0000;
    // 0x2b00_0000: dedicated to crypto/buffered_writer_write's raw-u32
    // handle and page-state fixture; mappings never unmap, so no other user
    // may share this hint.
    pub const BUFFERED_WRITER_WRITE: usize = 0x2b00_0000;
    // 0xb200_0000: dedicated to cxx/list_iter_advance's raw-u32 list-node
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const LIST_ITER_ADVANCE: usize = 0xb200_0000;
    // 0x3100_0000: dedicated to cxx/red_black_tree_node_pool_acquire's
    // target-width pool/chunk/node fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const RED_BLACK_TREE_NODE_POOL_ACQUIRE: usize = 0x3100_0000;
    // 0xdd00_0000: dedicated to cxx/list_node_pool_acquire's target-width
    // ListNodePool fixture slab, skipping 0xdc00_0000 (reserved).
    pub const LIST_NODE_POOL_ACQUIRE: usize = 0xdd00_0000;
    // 0x3200_0000: dedicated to cxx/red_black_tree_payload_24_node_pool_acquire's
    // target-width pool/chunk/node fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const RED_BLACK_TREE_PAYLOAD_24_NODE_POOL_ACQUIRE: usize = 0x3200_0000;
    // 0x2400_0000: dedicated to cxx/red_black_tree_payload_16_node_pool_acquire's
    // target-width pool/chunk/node fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const RED_BLACK_TREE_PAYLOAD_16_NODE_POOL_ACQUIRE: usize = 0x2400_0000;
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
    // 0x3e00_0000: dedicated to sqlite/ptrmap_put_overflow_cell's raw-u32
    // segmented-entry table and entry-data fixture; mappings never unmap, so
    // no other user may share this hint.
    pub const SQLITE_PTRMAP_PUT_OVERFLOW_CELL: usize = 0x3e00_0000;
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
/// Serializes host tests that replace `ui::pool_entry_create::FIXED_POOL_OPS`.
pub static UI_POOL_ENTRY_CREATE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
