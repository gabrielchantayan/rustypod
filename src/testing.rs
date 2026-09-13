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
    // 0x0100_0000: dedicated to cxx/stream_read's target-width descriptor,
    // complete-owner state, and reader fixture; mappings never unmap.
    pub const CXX_STREAM_READ: usize = 0x0100_0000;
    pub const HEAP_INTEGRATION: usize = 0x0900_0000;
    // 0x5500_0000: dedicated to ft/sfnt's raw-u32 TT_Face table-directory
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const TT_FACE_LOOKUP: usize = 0x5500_0000;
    pub const ATA_CMD: usize = 0x0a00_0000;
    // 0x6300_0000: dedicated to util/video_engine's target-width frame-slot
    // table fixture; mappings never unmap, so no other user may share it.
    pub const VIDEO_ENGINE_CURRENT_FRAME_SLOT: usize = 0x6300_0000;
    // 0x6400_0000: dedicated to ATA command execution/submission's raw-u32
    // status-source fixtures; mappings never unmap, so neither port shares it.
    pub const ATA_COMMAND_EXECUTE: usize = 0x6400_0000;
    pub const ATA_COMMAND_SUBMIT_WAIT: usize = 0x6500_0000;
    pub const CLIENT_POPULATE: usize = 0x0b00_0000;
    pub const BLOCK_MGR: usize = 0x0c00_0000;
    pub const LIST_SPLICE: usize = 0x0d00_0000;
    pub const EVENT_LIST: usize = 0x0e00_0000;
    pub const CONTEXT_SCOPE: usize = 0x0f00_0000;
    pub const BTREE_PARSE_CELL: usize = 0x1000_0000;
    pub const BTREE_DATA_SIZE: usize = 0x1100_0000;
    // 0x7000_0000: dedicated to sqlite/restore_cursor_position's raw-u32
    // BtCursor fixture; mappings never unmap, so no other user may share it.
    pub const BTREE_RESTORE_CURSOR: usize = 0x7000_0000;
    pub const ELEMENT_REFERENCE: usize = 0x1200_0000;
    pub const VTABLE_SET_ITERATOR: usize = 0x1300_0000;
    pub const OBSERVABLE_ARRAY: usize = 0x1400_0000;
    pub const OBSERVABLE_ARRAY_DRAIN: usize = 0x1500_0000;
    pub const EVENT_SOURCE_DESTRUCT: usize = 0x1600_0000;
    pub const SILVER_CONTROLLER: usize = 0x1700_0000;
    pub const QUEUED_MESSAGE_POST: usize = 0x1800_0000;
    pub const VTABLE_SET_ITERATOR_RELEASE: usize = 0x1900_0000;
    pub const VDBE_SERIAL_PUT: usize = 0x1a00_0000;
    pub const PENDING_EVENT_TAKE: usize = 0x1b00_0000;
    // 0xbf00_0000: dedicated to app/pending_event_take_due's raw-u32
    // session and pending-event fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const PENDING_EVENT_TAKE_DUE: usize = 0xbf00_0000;
    pub const ANIMATION_INIT: usize = 0x1c00_0000;
    pub const STRING_RECORD: usize = 0x1d00_0000;
    pub const IAP_PACKET_OWNER_MODE: usize = 0x1e00_0000;
    pub const TOKENIZER: usize = 0x1f00_0000;
    // 0x5f00_0000: dedicated to util/string_pool's target-width context
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const STRING_POOL_READ_COUNTED_CONTEXT: usize = 0x5f00_0000;
    // 0x6700_0000: dedicated to app/registry's raw-u32 owner field
    // fixture for field_dc_as_class_4a80; mappings never unmap, so no other
    // user may share this hint.
    pub const FIELD_DC_AS_CLASS_4A80: usize = 0x6700_0000;
    // 0x6d00_0000: dedicated to app/registry's raw-u32 owner field
    // fixture for field_dc_as_class_4b00; mappings never unmap, so no other
    // user may share this hint.
    pub const FIELD_DC_AS_CLASS_4B00: usize = 0x6d00_0000;
    pub const VIEW_TIMER: usize = 0x2000_0000;
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
    // 0x2d00_0000, skipping 0x2a00_0000..0x2c00_0000: sibling ports in
    // flight take the sequential slots, and a collision skips tests
    // silently on every host.
    pub const VIEW_BASE: usize = 0x2d00_0000;
    pub const SERVICE_MANAGER_SECONDARY_HANDLER: usize = 0x3600_0000;
    // 0x7b00_0000: dedicated to app/service_manager's raw-u32 slot-handler
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const SERVICE_MANAGER_SLOT_HANDLER: usize = 0x7b00_0000;
    // 0x8600_0000: dedicated to app/service_handler_masked_event_dispatch's
    // raw-u32 service-manager and handler fixture; mappings never unmap, so
    // no other user may share this hint.
    pub const SERVICE_HANDLER_MASKED_EVENT_DISPATCH: usize = 0x8600_0000;
    pub const CHARACTER_CLASS: usize = 0x3700_0000;
    pub const TIMER_RESET_4000: usize = 0x3800_0000;
    // 0x3900_0000, skipping 0x2e00_0000..0x3500_0000: sibling ports in
    // flight take the sequential slots, and a collision skips tests
    // silently on every host.
    pub const SET_STRING: usize = 0x3900_0000;
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
    // 0x4a00_0000, skipping the sequential 0x4700_0000..0x4900_0000:
    // sibling ports in flight take the sequential slots, and a
    // collision skips tests silently on every host.
    pub const TAGGED_WORD_BUFFER: usize = 0x4a00_0000;
    // 0x5a00_0000, skipping 0x4b00_0000..0x5900_0000: sibling ports in
    // flight take the sequential slots, and a collision skips tests
    // silently on every host.
    pub const ELEMENT_REFERENCE_PERSISTENT_ID: usize = 0x5a00_0000;
    pub const TIMED_TRANSITION: usize = 0x5c00_0000;
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
    // 0x7f00_0000: dedicated to cxx/bit_set's write-transition fixture;
    // fixture mappings never unmap, so no other user may share this hint.
    pub const BIT_SET_WRITE: usize = 0x7f00_0000;
    // 0xb600_0000: dedicated to cxx/bit_set's clear-transition fixture;
    // fixture mappings never unmap, so no other user may share this hint.
    pub const BIT_SET_CLEAR: usize = 0xb600_0000;
    // 0xcc00_0000: dedicated to cxx/bit_set's constructor allocation
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const BIT_SET_CONSTRUCT: usize = 0xcc00_0000;
    // 0xce00_0000: dedicated to cxx/bit_set's clear-all fixture; fixture
    // mappings never unmap, so no other user may share this hint.
    pub const BIT_SET_CLEAR_ALL: usize = 0xce00_0000;
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
    // 0xa200_0000: dedicated to app/context_callback_dispatch's raw-u32
    // owner/state/list fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const CONTEXT_CALLBACK_DISPATCH: usize = 0xa200_0000;
    // 0xa300_0000: dedicated to heap/fixa's raw-u32 owner and FixL-link
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const FIXA_OWNER_DESTROY: usize = 0xa300_0000;


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
    // 0x5300_0000 and 0x5400_0000: dedicated to the cxx shared-handle
    // initializer and its vtable-owner constructor fixtures; mappings never
    // unmap, so each mapping site has its own hint.
    pub const SHARED_HANDLE_INITIALIZE: usize = 0x5300_0000;
    pub const VTABLE_SHARED_HANDLE_CONSTRUCT: usize = 0x5400_0000;
    // 0x9900_0000: dedicated to cxx/templates' raw-u32 cursor-state
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const CONTAINER_BEGIN_CURSOR: usize = 0x9900_0000;
    // 0x5600_0000: dedicated to app/opaque_record_source_item_count's raw-u32
    // provider fixture; mappings never unmap, so no other user may share it.
    pub const OPAQUE_RECORD_SOURCE_ITEM_COUNT: usize = 0x5600_0000;
    // 0x5800_0000: dedicated to heap/memh_handle's target-width handle
    // fixture; mappings never unmap, so no other user may share it.
    pub const MEMH_HANDLE_DESTROY: usize = 0x5800_0000;
    // 0x5700_0000: dedicated to util/mapped_subobject_for_slot's raw-u32
    // context and selected-subobject fixture; mappings never unmap.
    pub const MAPPED_SUBOBJECT_FOR_SLOT: usize = 0x5700_0000;
    // 0x3000_0000: dedicated to ui/view_base's render-state release fixture;
    // mappings never unmap, so no other user may share this hint.
    pub const VIEW_BASE_RENDER_STATE_RELEASE: usize = 0x3000_0000;
    // 0x5100_0000: dedicated to ui/layout_apply_pending_offsets' raw-u32
    // entry-offset fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const TEXT_LAYOUT_APPLY_PENDING_OFFSETS: usize = 0x5100_0000;
    // 0x5200_0000: dedicated to kernel/task_lock's raw-u32 current-task
    // record fixture; mappings never unmap, so no other user may share it.
    pub const CURRENT_TASK_ID: usize = 0x5200_0000;
    // 0x8000_0000: dedicated to cxx/red_black_tree_increment's raw-u32
    // red-black-tree node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const RED_BLACK_TREE_INCREMENT: usize = 0x8000_0000;
    // 0x0400_0000: dedicated to sqlite/expr_worklist's target-width owner,
    // worklist, entry, and tracked-allocation fixtures; mappings never unmap.
    pub const SQLITE_EXPR_WORKLIST: usize = 0x0400_0000;
    // 0xd800_0000: dedicated to sqlite/step's target-width Vdbe and
    // connection fixtures; mappings never unmap, so no other user may share it.
    pub const SQLITE_STEP: usize = 0xd800_0000;
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
