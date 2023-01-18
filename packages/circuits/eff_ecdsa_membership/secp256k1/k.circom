// Assum that the scalar is in the range [0, q)
template K() {
    slo <-- scalar & (2 ** (bits / 2) - 1);
    shi <-- scalar >> (bits / 2);

    component inBits = Num2Bits((bits / 2) + 1);
    inBits.in <== slo + tQlo;
    carry <== inBits.out[bits / 2];

    // (s + tQ) > q -> s > (q - tQ)
    component isSloEqLarger = GreaterEqThan(128);
    packages/circuits/eff_ecdsa_membership/secp256k1/big_mod_q.circom    isSloEqLarger.in[0] <== 92138019644721193389046258963199934143; // 2^256 % q
    isSloEqLarger.in[1] <== slo;

    component isSHiLarger = GreaterThan(128);
    isSHiLarger.in[0] <== 1; // 2^256 % q
    isSHiLarger.in[1] <== shi;

    component isSHiEqual = IsEqual();
    isSHiEqual.in[0] <== 1;
    isSHiEqual.in[1] <== shi;

    // isSHiLarger.out ==> true
    // isSHiLarger.out = 0 ==> false
    // isSHiEqual.out && isSloEqLarger = 1 ==> true
    // isSHiEqual.out && isSloEqLarger = 0 ==> false
    component isHiEqualAndLoEqLarger = AND();
    isHiEqualAndLoEqLarger.a <== isSHiEqual.out;
    isHiEqualAndLoEqLarger.b <== isSloEqLarger.out;

    // isQuotientOne: if (s + tQ) > q then quotient = 1 else quotient = 0
    component isQuotientOne = OR();
    isQuotientOne.a <== isHiEqualAndLoEqLarger.out;
    isQuotientOne.b <== isSHiLarger.out;

    // if the quotient is 1, then q * 1 + k = s + tQ
    // if the quotient is 0, then k = s + tQ
    // s + tQ / div = quotient, k
    // s + tQ = quotient * div + k
    // k = (s + tQ) / q  * quotient

    // Check that if the mod was done correctly
    // (slo + shi * 2^128) * quotient + r = divisor
    // divisor * quotient + r = slo * quotient + shi * 2^128 
    var borrow = 1;
    var borrowlo = 1 << 128;

    klo <== (slo + tQlo) - isQuotientOne.out * qlo;
    khi <== (shi + tQhi)  - isQuotientOne.out * qhi;

    signal kBits[256];
    component kloBits = Num2Bits(256);
    kloBits.in <== klo;

    component khiBits = Num2Bits(256);
    khiBits.in <== khi;

    for (var i = 0; i < 128; i++) {
        kBits[i] <== kloBits.out[i];
        kBits[i + 128] <== khiBits.out[i];
    }

    var knum = 0;
    for (var i = 0; i < bits; i++) {
        knum += kBits[i] * (2 ** i);
    }
    log("klo", klo);
    log("khi", khi);
}