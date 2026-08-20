//! C++ standard-library runtime: the container and string implementations
//! retailOS's application layer is built on. They live in the
//! 0x083c0000-0x083dffff block of osos (~1000 functions), separate from
//! the ARM ADS C runtime.
pub mod bit_set;
pub mod byte_key_map;
pub mod clock_source_destroy;
pub mod color_copy;
pub mod decoder_begin_batch;
pub mod decoder_end_batch;
pub mod decoder_cleanup;
pub mod draw_state;
pub mod draw_state_color;
pub mod handle;
pub mod list_splice;
pub mod mutex;
pub mod mutex_attr_init;
pub mod mutex_settype_init;
pub mod observable_array;
pub mod pending_event;
pub mod null_pointer_status;
pub mod mode;
pub mod object_flags;
mod object_state;
pub mod pair_header;
pub mod release;
pub mod return_forwarder;
pub mod settings;
pub mod scaled_cursor;
pub mod slot_reset;
pub mod string;
pub mod string_map;
pub mod stream_write_cstr;
pub mod string_object;
pub mod templates;
pub mod trivial_destructor;
pub mod wheel_event;
pub mod transition_addon;
pub mod value_compare;
pub mod vtable;
