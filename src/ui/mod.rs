//! retailOS UI / graphics layer — the geometry primitives the drawing
//! and view code is built on.
pub mod block_map;
pub mod byte_store;
pub mod checked_byte_block_forwarder;
pub mod color;
pub mod flag_2c;
pub mod flag_bit_2_at_4;
pub mod startup_sequence;
pub mod table_slot_allocate;
pub mod render_context;
pub mod rect;
pub mod noop_f7f4;
pub mod operation_unavailable;
pub mod pending_cleanup;
pub mod width_inset;
pub mod static_descriptor;
pub mod styled_text_view;
pub mod string_view;
pub mod vtable_slot_20;
pub mod vtable_slot_24;
pub mod resource_release;
pub mod object_state;
pub mod plst_class_check;
pub mod tdat_class_check;
pub mod element_reference;
pub mod font_handle;
pub mod invalidate;
pub mod draw_state_setup;
pub mod shown_state;

pub mod mode_state;
pub mod view_base;