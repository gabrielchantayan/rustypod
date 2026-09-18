//! MPEG-4 / QuickTime (MOV) container parser ports.
pub mod atom_info;
pub mod atom_table;
pub mod chunk_offset_table_load_window;
pub mod u32_window_reader;
pub mod atom_tree_has_offsets;
pub mod atom_node;
pub mod chain_table;
pub mod chain_table_find_predecessor;
pub mod esds_descriptor_size;
pub mod fatal_mov_cleanup_no_op;
pub mod fatal_mov_object_cleanup_no_op;
pub mod fatal_mov_cleanup_08153bc0_no_op;
pub mod optional_flagged_byte;
pub mod checked_flagged_width;
pub mod chain_value_span;
pub mod mov_parser_slot_14_is_set;
