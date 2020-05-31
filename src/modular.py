def legendre_symbol(a, p):
    """ Compute the Legendre symbol a|p using
        Euler's criterion. p is a prime, a is
        relatively prime to p (if p divides
        a, then a|p = 0)

        Returns 1 if a has a square root modulo
        p, -1 otherwise.

        Source: Eli Bendersky https://eli.thegreenplace.net/2009/03/07/computing-modular-square-roots-in-python
    """
    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls


def hasModSqrt(a, p):
    return legendre_symbol(a, p) == 1


def modular_sqrt(a, p):
    """ Find a quadratic residue (mod p) of 'a'. p
        must be an odd prime.

        Solve the congruence of the form:
            x^2 = a (mod p)
        And returns x. Note that p - x is also a root.

        0 is returned is no square root exists for
        these a and p.

        The Tonelli-Shanks algorithm is used (except
        for some simple cases in which the solution
        is known from an identity). This algorithm
        runs in polynomial time (unless the
        generalized Riemann hypothesis is false).

        Source:  Eli Bendersky https://eli.thegreenplace.net/2009/03/07/computing-modular-square-roots-in-python
    """
    # Simple cases
    #
    if legendre_symbol(a, p) != 1:
        return False
    elif a == 0:
        return 0
    elif p == 2:
        return 0
    elif p % 4 == 3:
        return pow(a, (p + 1) // 4, p)

    # Partition p-1 to s * 2^e for an odd s (i.e.
    # reduce all the powers of 2 from p-1)
    #
    s = p - 1
    e = 0
    while s % 2 == 0:
        s /= 2
        e += 1

    # Find some 'n' with a legendre symbol n|p = -1.
    # Shouldn't take long.
    #
    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1

    # Here be dragons!
    # Read the paper "Square roots from 1; 24, 51,
    # 10 to Dan Shanks" by Ezra Brown for more
    # information
    #

    # x is a guess of the square root that gets better
    # with each iteration.
    # b is the "fudge factor" - by how much we're off
    # with the guess. The invariant x^2 = ab (mod p)
    # is maintained throughout the loop.
    # g is used for successive powers of n to update
    # both a and b
    # r is the exponent - decreases with each update
    #
    x = pow(a, (s + 1) // 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e

    while True:
        t = b
        m = 0
        for m in xrange(r):
            if t == 1:
                break
            t = pow(t, 2, p)

        if m == 0:
            return x

        gs = pow(g, 2 ** (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m

def egcd(a, b):
    """
    Extended Euclidean Algorithm
    Source: https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
    """
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def modinv(a, m):
    """
    Find modular inverse of a (mod m).
    Source: https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
    """
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


def alpha_00(p):
    """
    Pairs of residues and nonresidues (Source: https://en.wikipedia.org/wiki/Quadratic_residue)

    Give the number of residues that are followed by a residue
    """
    if p % 4 == 1:
        return (p - 5) / 4
    elif p % 4 == 3:
        return (p - 3) / 4
    else:
        print("Error: not an odd prime")
        return None


def alpha_01(p):
    """
    Pairs of residues and nonresidues (Source: https://en.wikipedia.org/wiki/Quadratic_residue)

    Give the number of residues that are followed by a nonresidue
    """
    if p % 4 == 1:
        return (p - 1) / 4
    elif p % 4 == 3:
        return (p + 1) / 4
    else:
        print("Error: not an odd prime")
        return None


def alpha_10(p):
    """
    Pairs of residues and nonresidues (Source: https://en.wikipedia.org/wiki/Quadratic_residue)

    Give the number of nonresidues that are followed by a nonresidue
    """
    if p % 4 == 1:
        return (p - 1) / 4
    elif p % 4 == 3:
        return (p - 3) / 4
    else:
        print("Error: not an odd prime")
        return None


def alpha_11(p):
    """
    Pairs of residues and nonresidues (Source: https://en.wikipedia.org/wiki/Quadratic_residue)
    """
    if p % 4 == 1:
        return (p - 1) / 4
    elif p % 4 == 3:
        return (p - 3) / 4
    else:
        print("Error: not an odd prime")
        return None
