'''
Utility functions for https://cryptopals.com
============================================
More specific functions and library functions are found in the other files
in this module.
'''
from codecs import encode, decode
from string import ascii_lowercase


###############################################################################
# .:General utility functions:. #
#################################
def sort_by_value(d, reverse=False):
    '''
    Sort a dict by it's values
    '''
    return sorted(d, key=d.get, reverse=reverse)


def chunks(it, size):
    '''
    Split an iterable into even length chunks
    '''
    if len(it) % size:
        return [list(chunk) for chunk in zip(*[iter(it)]*size)]
    else:
        raise ValueError('Iterable is not divisible by {}'.format(size))


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
    t = [cand for cand in t if all(c in ascii_lowercase for c in cand)]
    return t
