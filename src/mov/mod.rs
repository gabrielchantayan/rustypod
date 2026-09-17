//! MPEG-4 / QuickTime (MOV) container parser ports.
pub mod atom_info;
pub mod atom_table;
pub mod atom_node;
pub mod chain_table;
pub mod chain_table_find_predecessor;
pub mod esds_descriptor_size;
pub mod optional_flagged_byte;
pub mod checked_flagged_width;
pub mod chain_value_span;
