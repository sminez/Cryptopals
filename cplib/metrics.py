'''
.:Metrics and statistical summaries:.
-------------------------------------
A collection of useful things to calculate when trying to compare
plaintext and ciphertext.

NOTE: In some cases the output of these functions differs from the
      normal mathematical definition so that a lower value is taken
      to be better. This is to ensure that further processing and
      ranking based on these metrics is consistent.
'''
from math import sqrt
from operator import mul
from functools import reduce, lru_cache
from cplib.utils import bits


def hamming(string1, string2):
    '''
    Compute the hamming distance between two strings. This is just
    the number of differing bits between their bytestring binary
    representations.
    - https://en.wikipedia.org/wiki/Hamming_distance

    hamming('this is a test', 'wokka wokka!!!') == 37
    '''
    return sum(a ^ b for (a, b) in zip(bits(string1), bits(string2)))


def similarity(v1, v2):
    '''
    Compute the cosine similarity of two equal length vectors.
    >>> https://en.wikipedia.org/wiki/Cosine_similarity

    similarity = cos(θ) = (v1 . v2) / (|v1||v2|)

    Returns a float in the range 0 -> 1
         0   :: perfect match
         0.5 :: orthogonal (no correlation at all)
         1   :: exactly opposite
    '''
    def square_sum(vec):
        return sum(v ** 2 for v in vec)

    try:
        dot_product = sum(p * q for p, q in zip(v1, v2))
        magnitude_product = sqrt(reduce(mul, map(square_sum, (v1, v2))))
        return dot_product / magnitude_product
    except ZeroDivisionError:
        # At least one of the magnitudes is 0. If both are 0 then
        # they are a perfect match, otherwise they are orthogonal.
        return int(v1 == v2)


def chi_squared(expected, candidate):
    '''
    Compute Pearson's Chi-squared test for the candidate vs an expected
    result.
    >>> https://en.wikipedia.org/wiki/Pearson%27s_chi-squared_test

    See here for critical values: DoF is len(plaintext alphabet) - 1
    http://www.itl.nist.gov/div898/handbook/eda/section3/eda3674.htm
    '''
    return sum(((c-e)**2)/e for e, c in zip(expected, candidate))


@lru_cache(maxsize=None)
def levenshtein(s1, s2):
    '''
    Compute the Levenshtein edit distance between two strings. This is
    the minimum number of edits required to turn one string into the other.
    >>> https://en.wikipedia.org/wiki/Levenshtein_distance

    Code taken from Rosetta Code.
    '''
    if not s1:
        return len(s2)
    elif not s2:
        return len(s1)
    elif s1[0] == s2[0]:
        return levenshtein(s1[1:], s2[1:])
    else:
        l1 = levenshtein(s1, s2[1:])
        l2 = levenshtein(s1[1:], s2)
        l3 = levenshtein(s1[1:], s2[1:])
        return 1 + min(l1, l2, l3)
