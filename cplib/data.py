'''
.:Constants, data-structures and useful values to remember:.
------------------------------------------------------------
  Using bytestrings as most - if not all - intermediate data
  will be bytes and this avoids repeated conversions.
'''
# Relative frequencies for characters in the English Language.
# Useful for comparing distributions of characters
# >>> https://en.wikipedia.org/wiki/Frequency_analysis
rel_char_freqs = {
    b'e': 12.70, b't': 9.06, b'a': 8.17, b'o': 7.51, b'i': 6.97, b'n': 6.75,
    b's': 6.33, b'h': 6.09, b'r': 5.99, b'd': 4.25, b'l': 4.03, b'c': 2.78,
    b'u': 2.76, b'm': 2.41, b'w': 2.36, b'f': 2.23, b'g': 2.02, b'y': 1.97,
    b'p': 1.93, b'b': 1.29, b'v': 0.98, b'k': 0.77, b'j': 0.15, b'x': 0.15,
    b'q': 0.10, b'z': 0.07
    }

# As above but normalised so that the least frequent (z) has a value of 1
# This is useful for scoring a decryption attempt based on the characters
# that are present (adding ints is faster than adding floats!)
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
