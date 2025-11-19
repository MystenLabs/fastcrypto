mod compact_display;
#[cfg(test)]
mod compact_display_test;

pub type Ratio = num_rational::Ratio<u64>;

pub use compact_display::CompactDisplay;
