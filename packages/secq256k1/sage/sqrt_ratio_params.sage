# https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html#name-sqrt_ratio-for-any-field
def sqrt_ratio_params(p, z) -> tuple([int, int, int, int, int, int, int]):
    for i in range(256):
        if ((p - 1) % (2^i) == 0):
            c1 = i
    c2 = (p - 1) / 2^c1
    c3 = (c2 - 1) / 2
    c4 = 2^c1 - 1               
    c5 = 2^(c1 - 1)              
    c6 = z.powermod(c2, p)
    c7 = z.powermod((c2 + 1) / 2, p)
    return (
        c1, c2, c3, c4, c5, c6, c7
    )







