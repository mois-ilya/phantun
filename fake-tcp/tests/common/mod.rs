// Integration test helpers: re-exported from fake_tcp::testing.
// Gated behind the integration-tests feature — this entire module is a no-op
// when compiled without it.
#![cfg(feature = "integration-tests")]

// Glob re-export is intentional: only `pub` items from testing.rs are visible
// to the test crate (`pub(crate)` helpers like unique_suffix are excluded).
pub use fake_tcp::testing::*;
