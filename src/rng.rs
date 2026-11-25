//! A seeded SplitMix64 generator, for payloads and key names that a run can
//! repeat from its seed. It is not for secrets.

/// SplitMix64 (Steele, Lea and Flood, 2014), as used to seed xoshiro.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// A generator that will produce the same sequence for the same seed.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// The next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A number in `0..bound`, or 0 when `bound` is 0. The modulo bias is
    /// below 2^-40 for the bounds proofmark uses, which is fine for test data.
    pub fn below(&mut self, bound: usize) -> usize {
        let bound64 = u64::try_from(bound).unwrap_or(u64::MAX);
        if bound64 == 0 {
            return 0;
        }
        usize::try_from(self.next_u64() % bound64).unwrap_or(0)
    }

    /// `len` random bytes.
    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len + 8);
        while out.len() < len {
            out.extend_from_slice(&self.next_u64().to_le_bytes());
        }
        out.truncate(len);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // First outputs for seed 1234567, from the reference C implementation
    // (prng.di.unimi.it/splitmix64.c).
    #[test]
    fn matches_the_reference_sequence() {
        let mut rng = SplitMix64::new(1_234_567);
        assert_eq!(rng.next_u64(), 6_457_827_717_110_365_317);
        assert_eq!(rng.next_u64(), 3_203_168_211_198_807_973);
        assert_eq!(rng.next_u64(), 9_817_491_932_198_370_423);
    }

    #[test]
    fn below_stays_in_range() {
        let mut rng = SplitMix64::new(7);
        assert_eq!(rng.below(0), 0);
        assert!((0..1000).all(|_| rng.below(10) < 10));
    }
}
