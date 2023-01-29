# Check security inequalities as specified in the Neptune specification

M=128
t=3
p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
Rf=8
Rp=56
R=Rf + Rp
a=5

# this is defined in Section 5.5.1 https://eprint.iacr.org/2019/458.pdf
# (a = 5 then C = 2)
C = 2

# https://spec.filecoin.io/#section-algorithms.crypto.poseidon.security-inequalities
print("(1) 2^M <= p^t", 2^M <= p^t)
print("(2) M <= (⌊log2(p) - C)⌋・(t + 1)", M <= (floor(log(p, 2)).n() - C) * (t + 1))  # Section 5.5.1 https://eprint.iacr.org/2019/458.pdf
print("(3) R > M(log_a(2) + log_a(t)))", R > (M * log(2, a).n()) + log(t, a).n())
print("(4a) R >  M * log(2, a).n() / 3", R > (M * log(2, a).n()) / 3)
print("(4b) R > t - 1 + (M * log(2, a).n() / (t + 1))", R > t - 1 + (M * log(2, a).n() / (t + 1)))