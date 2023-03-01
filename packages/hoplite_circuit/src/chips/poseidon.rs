pub struct PoseidonChip {
    pub ecc_chip: EccChip,
    pub fp_chip: FpChip,
    pub window_bits: usize,
}