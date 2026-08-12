//! C++ standard-library runtime: the container and string implementations
//! retailOS's application layer is built on. They live in the
//! 0x083c0000-0x083dffff block of osos (~1000 functions), separate from
//! the ARM ADS C runtime.
pub mod byte_key_map;
pub mod decoder_begin_batch;
pub mod decoder_end_batch;
pub mod decoder_cleanup;
pub mod draw_state;
pub mod handle;
pub mod list_splice;
pub mod observable_array;
pub mod object_flags;
pub mod pair_header;
pub mod release;
pub mod settings;
pub mod string;
pub mod string_map;
pub mod string_object;
pub mod templates;
pub mod trivial_destructor;
pub mod wheel_event;
