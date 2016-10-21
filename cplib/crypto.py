'''
Cryptographic Encryption & Decrpytion
=====================================
This module contains a variety of pure Python implementations for common
cryptographic encryption and decryption operations that should NEVER be
used for anything other that gaining an overview of the algorithms
involved.

Seriously, use something written in C that is tested and relaible...
'''
from operator import itemgetter
from collections import Counter
from string import ascii_lowercase
from itertools import repeat, combinations, zip_longest

from cplib.metrics import chi_squared, levenshtein
from cplib.data import int_char_freqs, rel_char_freqs, AES_rcon, AES_sbox
from cplib.utils import sort_by_value, transpose, chunks


##############################################################################
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

##############################################################################
# .:Crypto :: AES:.
# -----------------
# AES is a subset of the Rijndeal block cipher:
# https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
# https://en.wikipedia.org/wiki/Rijndael_key_schedule
# https://en.wikipedia.org/wiki/Finite_field_arithmetic
# https://en.wikipedia.org/wiki/Rijndael_S-box
#
# In GF(2^8), addition and subtraction are both bitwise XOR


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
        round_keys = chunks(AES_key_schedule(key), 16)
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
