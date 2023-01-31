import sage.schemes.elliptic_curves.isogeny_small_degree as isd
load("sqrt_ratio_params.sage")

# https://neuromancer.sk/std/secg/secp256k1

# Secp256k1
p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
Fp = GF(p)
pA = Fp(0x0000000000000000000000000000000000000000000000000000000000000000)
pB = Fp(0x0000000000000000000000000000000000000000000000000000000000000007)
Ep = EllipticCurve(Fp, (pA, pB))
G = Ep(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
Ep.set_order(0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 * 0x1)

# Secq256k1
q = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
Fq = GF(q)
qA = Fq(0x0000000000000000000000000000000000000000000000000000000000000000)
qB = Fq(0x0000000000000000000000000000000000000000000000000000000000000007)
Eq = EllipticCurve(Fq, (qA, qB)) # secq256k1

# https://eprint.iacr.org/2019/403.pdf p.26 A The isogeny maps
def find_iso(E):
    for p_test in primes(60):
        isos = [ i for i in isd.isogenies_prime_degree(E, p_test)
            if i.codomain().j_invariant() not in (0, 1728) ]
        if len(isos) > 0:
            return isos[0].dual()
    return None
    


# https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html#sswu-z-code
# Arguments:
# - F, a field object
# - A and B, the coefficients of the curve equation y^2 = x^3 + A * x + B
def find_z_sswu(F, A, B):
    R.<xx> = F[]                       # Polynomial ring over F
    g = xx^3 + F(A) * xx + F(B)        # y^2 = g(x) = x^3 + A * x + B
    ctr = F.gen()
    while True:
        for Z_cand in (F(ctr), F(-ctr)):
            # Criterion 1: Z is non-square in F.
            if is_square(Z_cand):
                continue
            # Criterion 2: Z != -1 in F.
            if Z_cand == F(-1):
                continue
            # Criterion 3: g(x) - Z is irreducible over F.
            if not (g - Z_cand).is_irreducible():
                continue
            # Criterion 4: g(B / (Z * A)) is square in F.
            if is_square(g(B / (Z_cand * A))):
                return Z_cand
        ctr += 1

# Secp256k1
isogeny_ep = find_iso(Ep)

IsoEpA = isogeny_ep.domain().a4()
IsoEpB = isogeny_ep.domain().a6()

IsoEpZNatural = find_z_sswu(Fp, IsoEpA, IsoEpB)
IsoEpZ = Integer(IsoEpZNatural) - p

(c1, c2, c3, c4, c5, c6, c7) = sqrt_ratio_params(p, IsoEpZ)

print("Secp256k1")
print("Isogeny A:", isogeny_ep.domain().a4())
print("Isogeny B:", isogeny_ep.domain().a6())
print("Constants:", [k for k in isogeny_ep.rational_maps()])
print("Z", IsoEpZNatural, "=", IsoEpZ)
print("\nsqrt_ratio constants")
print("c1:", c1)
print("c2:", c2)
print("c3:", c3)
print("c4:", c4)
print("c5:", c5)
print("c6:", c6)
print("c7:", c7)

# Secq256k1

isogeny_eq = find_iso(Eq)

IsoEqA = isogeny_eq.domain().a4()
IsoEqB = isogeny_eq.domain().a6()

IsoEqZNatural = find_z_sswu(Fq, IsoEqA, IsoEqB)
IsoEqZ = Integer(IsoEqZNatural) - q
(c1, c2, c3, c4, c5, c6, c7) = sqrt_ratio_params(q, IsoEqZ)

print("\nSecq256k1")
print("\nIsogeny A:", isogeny_eq.domain().a4())
print("Isogeny B:", isogeny_eq.domain().a6())
print("Constants:", [k for k in isogeny_eq.rational_maps()])

print("Z:", IsoEqZNatural, "=", IsoEqZ)

print("\nsqrt_ratio constants")
print("c1:", c1)
print("c2:", c2)
print("c3:", c3)
print("c4:", c4)
print("c5:", c5)
print("c6:", c6)
print("c7:", c7)