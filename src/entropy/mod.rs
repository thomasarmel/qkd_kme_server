pub(crate) trait EntropyAccumulator {
    fn add_bytes(&mut self, bytes: &[u8]);
    fn get_entropy(&self) -> f64;
}

pub(crate) struct ShannonEntropyAccumulator {
    /// Counter for each byte value
    bytes_counter: [u64; 256],
    /// Total received bytes
    total_bytes: u64,
}

impl ShannonEntropyAccumulator {
    pub(crate) fn new() -> Self {
        Self {
            bytes_counter: [0; 256],
            total_bytes: 0,
        }
    }
}

impl EntropyAccumulator for ShannonEntropyAccumulator {
    fn add_bytes(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.bytes_counter[*byte as usize] += 1;
        }
        self.total_bytes += bytes.len() as u64;
    }

    fn get_entropy(&self) -> f64 {
        let mut entropy = 0.0;
        for count in self.bytes_counter.iter() {
            if *count == 0 {
                continue;
            }
            let symbol_probability = *count as f64 / self.total_bytes as f64;
            entropy -= symbol_probability * symbol_probability.log2();
        }
        entropy
    }
}

#[cfg(test)]
mod tests {
    use crate::entropy::EntropyAccumulator;

    #[test]
    fn test_shannon_entropy_accumulator() {
        let mut entropy_accumulator_1 = super::ShannonEntropyAccumulator::new();
        entropy_accumulator_1.add_bytes(&[0, 0, 0, 0, 0, 0]);
        assert_eq!(entropy_accumulator_1.get_entropy(), 0.0);

        let mut entropy_accumulator_2 = super::ShannonEntropyAccumulator::new();
        entropy_accumulator_2.add_bytes(&[0x00, 0x00, 0x01, 0x01, 0x02]);
        assert_eq!(entropy_accumulator_2.get_entropy(), 1.5219280948873621);

        let mut entropy_accumulator_3 = super::ShannonEntropyAccumulator::new();
        entropy_accumulator_3.add_bytes("Souvent sur la montagne, à l’ombre du vieux chêne,\n".as_bytes());
        assert_eq!(entropy_accumulator_3.get_entropy(), 4.465641023041018);
        entropy_accumulator_3.add_bytes("Au coucher du soleil, tristement je m’assieds ;\n".as_bytes());
        assert_eq!(entropy_accumulator_3.get_entropy(), 4.507894683096287);
    }
}