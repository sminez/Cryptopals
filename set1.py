'''
My solutions to the Cryptopals challenges set1
==============================================

Most of the actual code can be found in cplib. These files contain
use cases and solutions for the specific challenges themselves.
'''
from base64 import b64decode
from itertools import islice
from os.path import dirname, join
from string import ascii_lowercase, ascii_uppercase

from cplib.crypto import xor, repeating_key_xor, \
    break_char_xor, break_repeating_xor


# https://cryptopals.com/sets/1/challenges/1
def challenge1(hex_encoded, utf8=False):
    '''
    Convert hex encoded (byte)string to a base64 encoded bytestring.
    Set utf8=True to return a utf-8 encoded string rather than bytes.

    NOTE: This is horribly slow and hacky. Using the hex_to_b64 function
          defined in utils instead whenever this needs to be used!
    '''
    # Strip off the leading '0b' flag for a binary format string
    bits = bin(int(hex_encoded, base=16))[2:]
    # make a multiple of 6 (2^6 == 64)
    leftpad = '0' * (6 - len(bits) % 6)
    bits = iter(leftpad + bits)

    ints = b'0123456789'
    b64_chars = (ascii_uppercase + ascii_lowercase).encode() + ints + b'+/'

    b64_encoded = []

    while True:
        chunk = ''.join(islice(bits, 6))
        if not chunk:
            # we're done
            break

        index = int(chunk, base=2)
        b64_encoded.append(b64_chars[index])

    converted = bytes(b64_encoded)
    if utf8:
        return converted.decode('utf8')
    else:
        return converted


# https://cryptopals.com/sets/1/challenges/2
def challenge2(buf1, buf2):
    '''
    Return the XOR of two equal length hex encoded byte buffers.
    '''
    return xor(buf1, buf2)


# https://cryptopals.com/sets/1/challenges/3
def challenge3():
    return break_char_xor('1b37373331363f78151b7f2b783431333d'
                          '78397828372d363c78373e783a393b3736')


# https://cryptopals.com/sets/1/challenges/4
def challenge4():
    '''
    The 4.txt file in the challenge_data directory has 60 strings,
    one of which has been encrypted. This should find the best candidate
    decryption for each string and then find an overall best match.
    '''
    path = join(dirname(__file__), 'challenge_data/4.txt')
    answer = {'trigrams': 0}

    with open(path, 'r') as f:
        for lno, line in enumerate(f):
            cand = break_char_xor(line.strip())
            if cand['trigrams'] > answer['trigrams']:
                answer = cand
                answer['line'] = lno
        return answer


# https://cryptopals.com/sets/1/challenges/5
def challenge5():
    plaintext = (b"Burning 'em, if you ain't quick and nimble\n"
                 b"I go crazy when I hear a cymbal")
    key = b'ICE'
    ans = (b'0b3637272a2b2e63622c2e69692a23693a2a3c632420'
           b'2d623d63343c2a26226324272765272a282b2f20430'
           b'a652e2c652a3124333a653e2b2027630c692b2028316'
           b'5286326302e27282f')

    encrypted = repeating_key_xor(plaintext, key).hex().encode()
    return encrypted == ans


# https://cryptopals.com/sets/1/challenges/6
def challenge6():

    path = join(dirname(__file__), 'challenge_data/6.txt')

    with open(path, 'r') as f:
        ciphertext = b64decode(f.read())
        return break_repeating_xor(ciphertext, max_key_size=40, verbose=True)


if __name__ == '__main__':
    # print(challenge3())
    # print(challenge4())
    res = challenge6()
    print('\n\n.:RESULT:.\n- Key:\n{}\n\n- Plaintext:\n{}'.format(
        res['key'].decode('utf-8'),
        res['plaintext'].decode('utf-8')))
