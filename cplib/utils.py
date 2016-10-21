'''
Utility functions and data to help with the Cryptopals challenges.
==================================================================
[https://cryptopals.com/]

Challenge solutions are organised by the sets given on the website.
This file contains common helper functions that are used in multiple
places along with useful data structures and notes.
'''
from math import sqrt
from operator import mul
from collections import Counter
from operator import itemgetter
from codecs import encode, decode
from string import ascii_lowercase
from functools import reduce, lru_cache
from itertools import repeat, zip_longest, combinations


###############################################################################
# .:Constants, data-structures and useful values to remember:.  #
#   Using bytestrings as most - if not all - intermediate data  #
#   will be bytes and this avoids repeated conversions.         #
#################################################################

# Relative frequencies for characters in the English Language.
# >>> https://en.wikipedia.org/wiki/Frequency_analysis
rel_char_freqs = {
    b'e': 12.70, b't': 9.06, b'a': 8.17, b'o': 7.51, b'i': 6.97, b'n': 6.75,
    b's': 6.33, b'h': 6.09, b'r': 5.99, b'd': 4.25, b'l': 4.03, b'c': 2.78,
    b'u': 2.76, b'm': 2.41, b'w': 2.36, b'f': 2.23, b'g': 2.02, b'y': 1.97,
    b'p': 1.93, b'b': 1.29, b'v': 0.98, b'k': 0.77, b'j': 0.15, b'x': 0.15,
    b'q': 0.10, b'z': 0.07
    }

int_char_freqs = {
    b'e': 27, b't': 26, b'a': 25, b'o': 24, b'i': 23, b'n': 22,
    b's': 21, b'r': 20, b'h': 19, b'l': 18, b'd': 17, b'c': 16,
    b'u': 15, b'm': 14, b'f': 13, b'p': 12, b'g': 11, b'w': 10,
    b'y': 9, b'b': 8, b'v': 7, b'k': 6, b'x': 5, b' ': 4,
    b'j': 3, b'q': 2, b'z': 1
    }

# Letters ordered by frequency in english
etaoin = b'etaoinshrdlcumwfgypbvkjxqz'

# The top 16 trigrams in the English language. These are three letter
# groups that are allowed to span word boundaries. It looks like these
# 16 are a good starting point.
# >>> https://en.wikipedia.org/wiki/Trigram
eng_trigrams = {
    b'men': 1, b'sth': 2, b'oft': 3, b'tis': 4,
    b'edt': 5, b'nce': 6, b'has': 7, b'nde': 8,
    b'for': 9, b'tio': 10, b'ion': 11, b'ing': 12,
    b'ent': 13, b'tha': 14, b'and': 15, b'the': 16
}


###############################################################################
# .:General utility functions:. #
#################################
def sort_by_value(d, reverse=False):
    '''
    Sort a dict by it's values
    '''
    return sorted(d, key=d.get, reverse=reverse)


def chunks(it, size, fillvalue=None):
    '''
    Split an iterable into even length chunks
    '''
    zipped = zip_longest(*[iter(it)]*size, fillvalue=fillvalue)
    return [list(chunk) for chunk in zipped]


def transpose(matrix):
    '''
    Transpose a matrix. Input is assumed to be an nested
    iterable of equal length iterables.
    '''
    return [list(z) for z in zip(*matrix)]


def sliding_slice(size, col, as_lists=False):
    '''
    Yield a sliding series of iterables of length _size_ from a collection.
    If as_lists=True, yield full lists instead.

    NOTE:
    - yields [] if the supplied collection has less than _size_ elements
    - keeps _size_ elements in memory at all times
    '''
    remaining = iter(col)
    current_slice = list(next(remaining) for n in range(size))

    if len(current_slice) < size:
        raise StopIteration
    else:
        while True:
            if not as_lists:
                yield (elem for elem in current_slice)
            else:
                yield [elem for elem in current_slice]
            next_element = next(remaining)
            if next_element:
                current_slice = current_slice[1:] + [next_element]
            else:
                break


###############################################################################
# .:Conversions between formats / representations:. #
#####################################################
def hex_to_b64(hex_encoded_string):
    '''
    Convert a hex encoded string to base64.
    Preserves string type by default but can be overwritten.
    '''
    return encode(decode(hex_encoded_string, 'hex'), 'base64')


def b64_to_hex(b64_encoded_string):
    '''
    Convert a hex encoded string to base64.
    Preserves string type by default but can be overwritten.
    '''
    return encode(decode(b64_encoded_string, 'base64'), 'hex')


def bits(s):
    '''
    Convert a bytestring to a list of bits.
    '''
    # convert utf-8 strings to bytes
    bstr = s.encode() if type(s) == str else s
    return [int(b) for b in bin(int(bstr.hex(), 16))[2:]]


def trigrams(s):
    '''
    Get all trigrams from a string. (triplets of alpha-numeric characters)
    See link with eng_trigrams for more information.
    '''
    # convert utf-8 strings to bytes
    s = s.encode() if type(s) == str else s
    s = b''.join(s.split())
    punctuation = b'!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
    s = b''.join(bytes([c]) for c in s if c not in punctuation)
    t = list({s[n:n+3] for n in range(len(s) - 2)})
    t = [cand for cand in t if all(c in etaoin for c in cand)]
    return t


###############################################################################
# .:Metrics and statistical summaries:. #
#   Lower should always be better!      #
#########################################
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


###############################################################################
# .:Crypto :: Encryption:. #
############################
def xor(buf1, buf2):
    '''
    Computes the bytewise XOR of two equal length buffers.
    '''
    # Assume that utf-8 strings are hex encoded and convert them
    try:
        buf1 = bytes.fromhex(buf1) if type(buf1) == str else buf1
        buf2 = bytes.fromhex(buf2) if type(buf2) == str else buf2
    except:
        raise ValueError('non Hexadecimal digit in input')
    if len(buf1) != len(buf2):
        raise ValueError('Inputs must be equal length.')

    return b''.join(bytes([a ^ b]) for (a, b) in zip(buf1, buf2))


def repeating_key_xor(buf, key):
    '''
    XOR encrypt a buffer using a repeating key and return
    as a hexencoded bytestring.
    '''
    mask = b''.join(repeat(key, ((len(buf) // len(key)) + 1)))
    # trim down to match the length of buf
    mask = mask[:len(buf)]
    return xor(mask, buf)


###############################################################################
# .:Crypto :: Decryption:. #
############################
def check_decryption_attempt(candidate):
    '''
    Compute some useful metric for comparing decryption attempts on a
    Cypher Text. (This will probably grow as I find more metrics).
    There will probably be additional meta-data related to the decryption
    process being used that you will want to add in to the returned
    dictionary as well.
    '''
    # Find letter frequecies and compare similarity with English
    count = Counter(candidate.lower())
    freqs = {bytes([k]): v * 100 / len(candidate) for k, v in count.items()}
    alpha = {l.encode(): 0 for l in ascii_lowercase}
    alpha.update(freqs)

    cand_freqs = [alpha[c] for c in sorted(alpha) if c in rel_char_freqs]
    eng_freqs = [rel_char_freqs[c] for c in sorted(rel_char_freqs)]

    return {
        'plaintext': candidate,
        'chi-squared': chi_squared(eng_freqs, cand_freqs),
        'score': sum(int_char_freqs.get(bytes([c]), 0) for c in candidate)
    }


def break_char_xor(buf):
    '''
    Decode a string that has been XOR'd against a single ASCII char
    '''
    results = []
    byte_buf = bytes.fromhex(buf) if type(buf) == str else buf

    for key in range(256):
        key = bytes([key])
        cand = repeating_key_xor(byte_buf, key)
        summary = check_decryption_attempt(cand)
        summary['key'] = key
        results.append(summary)

    ordered = sorted(results, key=itemgetter('score'), reverse=True)
    return ordered[0]


def break_repeating_xor(buf, max_key_size=10, verbose=False):
    '''
    Given a base64 encoded string that has been encrypted with
    a repeating key XOR of unknown length, find the plaintext.
    '''
    buf = bytes.fromhex(buf) if type(buf) == str else buf
    lev = {}

    # .::Find probable key lengths::.
    # Shortest Levenshtein distance is the most likely
    for k in range(1, max_key_size + 1):
        sample = buf[:k*4]
        lev_score = 0
        chunks = [sample[i:i+k] for i in range(0, len(sample), k)]
        for a, b in combinations(chunks, 2):
            lev_score += levenshtein(a, b)
        lev[k] = lev_score / k

    ranked = sort_by_value(lev, reverse=False)

    if verbose:
        msg = 'Levenshtein distances\n=====================\n'
        msg += ''.join('{}: {}\n'.format(l, lev[l]) for l in ranked[:10])
        print(msg)

    candidate = {'chi-squared': 9999999999}

    for k in ranked:
        if k != 1:
            chunks = [buf[i:i+k] for i in range(0, len(buf), k)]
            chunksT = [c for c in zip_longest(*chunks, fillvalue=0)]
            key = [break_char_xor(chunk)['key'] for chunk in chunksT]
            key = b''.join(key)
        else:
            # transposing single char chunks is idempotent
            # so just try to break with single char XOR.
            key = break_char_xor(buf)['key']

        cand = repeating_key_xor(buf, key)
        summary = check_decryption_attempt(cand)
        summary['key'] = key

        if verbose:
            msg = '\nAttempting keysize {}'.format(k)
            print(msg, '\n' + '=' * len(msg))
            for k, v in summary.items():
                if k not in ['plaintext', 'letter_dist']:
                    print(k, ': ', v)

        if summary['chi-squared'] < 52:
            # Critical value for chi-squared with 26 degrees of freedom
            # is 52.620 for 0.999 probability.
            return summary
        elif summary['chi-squared'] < candidate['chi-squared']:
            candidate = summary

    # Nothing passed the threshold so return the best we've got
    return candidate


###############################################################################
# .:Crypto :: AES:.                                          #
# AES is a subset of the Rijndeal block cipher:              #
# https://en.wikipedia.org/wiki/Advanced_Encryption_Standard #
# https://en.wikipedia.org/wiki/Rijndael_key_schedule        #
# https://en.wikipedia.org/wiki/Finite_field_arithmetic      #
# https://en.wikipedia.org/wiki/Rijndael_S-box               #
#                                                            #
# In GF(2^8), addition and subtraction are both bitwise XOR  #
##############################################################
#
# Rcon
# ====
# The Rijndael docs describe the Rcon operation as raising 2 to
# (1 - round number) in the Rijndael finite field; GF(2^8):
# --> rcon[i] == 2 ** (i - 1) calculated in GF(2^8)
#
# As this is a finite field (256 elements), multiplication
# can be replaced with an array lookup for efficiency.
# For AES-128 there are 11 rounds so we only need the first 11
# elements of the array but all are included here for completeness.
#
# Elements can be calculated as follows:
# ======================================
# def rcon(i):
#     if i == 0:
#         return 0x8d  # By definition as 0x8d * 0x02 == 0x01 in GF(2^8)
#     elif i == 1:
#         return 0x01  # Anything to the power of 0 is 1
#     else:
#         n = 1
#         for _ in range(i - 1):
#             product, a, b = 0, 2, n
#             while b:
#                 if b & 1:
#                     product ^= a
#                 a <<= 1
#                 b >>= 1
#                 if a & 0x100:
#                     # Correct overflow into the next bit
#                     a ^= 0x11b
#             n = product
#         return n
AES_rcon = [
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
    0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a,
    0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6,
    0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72,
    0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e,
    0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
    0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02,
    0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
    0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
    0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb,
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
    0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a,
    0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d
]

AES_sbox = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B,
    0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26,
    0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
    0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
    0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F,
    0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC,
    0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14,
    0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
    0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F,
    0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11,
    0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
    0xB0, 0x54, 0xBB, 0x16
]


def AES_KS_core(_4bytes, iteration):
    _4bytes = [b for b in _4bytes]
    _4bytes = _4bytes[1:] + [_4bytes[0]]
    _4bytes = [AES_sbox[b] for b in _4bytes]
    _4bytes[0] ^= AES_rcon[iteration]
    return bytes(_4bytes)


def AES_key_schedule(key):
    '''
    Run the Rijndael key schedule algorithm to expand the user
    key to the required length.

    This was useful for getting test data to verify with:
    >> http://www.samiam.org/key-schedule.html
    '''
    # Key length in bits
    key_len = len(key) * 8

    if key_len == 128:
        step, final_key_len = 16, 176
    elif key_len == 192:
        step, final_key_len = 24, 208
    elif key_len == 256:
        step, final_key_len = 32, 240
    else:
        raise ValueError('Invalid length key')

    expanded_key = key
    round = 1

    while len(expanded_key) < final_key_len:
        temp = expanded_key[-4:]
        temp = AES_KS_core(temp, round)
        round += 1
        expanded_key += xor(expanded_key[-step:4-step], temp)

        for i in range(3):
            temp = expanded_key[-4:]
            expanded_key += xor(expanded_key[-step:4-step], temp)

        if key_len == 256:
            temp = expanded_key[-4:]
            temp = bytes([AES_sbox[b] for b in temp])
            expanded_key += xor(expanded_key[-step:4-step], temp)

        if key_len != 128:
            n = 2 if key_len == 192 else 3
            for _ in range(n):
                temp = expanded_key[-4:]
                expanded_key += xor(expanded_key[-step:4-step], temp)
    # Trim to size and then return
    return expanded_key[:final_key_len]


def AES_encrypt(key, plaintext):
    '''
    Encrypt the given plaintext with AES encryption.
    key must be a hex encoded bytestring of 128, 192 or 256 bits
    '''
    def _to_blocks(plaintext):
        '''NOTE: this returns a nested list of lists of ints'''
        blocks = chunks(plaintext, 16)
        return [transpose(chunks(block, 4)) for block in blocks]

    def _sub_bytes():
        pass

    ###########################################################################

    try:
        key_len = len(key) * 8
        n_rounds = {128: 10, 192: 12, 256: 14}[key_len]
    except KeyError:
        raise ValueError('Invalid key length')

    for round in range(n_rounds):
        pass
        # 1 .:Round-key expansion:.
        # 2 .:Initial Round:.
        #   AddRoundKey
        # 3 .:Rounds:.
        #   SubBytes
        #   ShiftRows
        #   MixColumns
        #   AddRoundkey
        # 4 .:Final Round:.
        #   SubBytes
        #   ShiftRows
        #   AddRoundKey
