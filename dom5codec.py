import codecs

lowercase = [0x2E,0x2D,0x2C,0x2B,0x2A,0x29,0x28,0x27,0x26,0x25,0x24,0x23,0x22,0x21,0x20,0x3F,0x3E,0x3D,0x3C,0x3B,0x3A,0x39,0x38,0x37,0x36,0x35]
uppercase = [0x0E,0x0D,0x0C,0x0B,0x0A,0x09,0x08,0x07,0x06,0x05,0x04,0x03,0x02,0x01,0x00,0x1F,0x1E,0x1D,0x1C,0x1B,0x1A,0x19,0x18,0x17,0x16,0x15]
digit = [0x7F,0x7E,0x7D,0x7C,0x7B,0x7A,0x79,0x78,0x77,0x76]

letter_dict = {}
for i in range(0, 26):
    val = lowercase[i]
    letter = ord('a') + i

    letter_dict[val] = chr(letter)

for i in range(0, 26):
    val = uppercase[i]
    letter = ord('A') + i

    letter_dict[val] = chr(letter)

for i in range(0, 10):
    val = digit[i]
    letter = ord('0') + i

    letter_dict[val] = chr(letter)

letter_dict[0x6F] = ' '
letter_dict[0x64] = '+'
letter_dict[0x62] = '-'
letter_dict[0x61] = '.'

# 0x2E ^ 0x61 = 0x4F # '.'
# 0x20 ^ 0x6F = 0x4F # ' '
# 0x35 ^ 0x7A = 0x4F # '5'

# It looks like for the special symbols, x ^ 0x4F gives you the encoding (and decoding) of x
# Same holds true for the digits

# 0x61 ^ 0x2E = 0x4F # 'a'
# 0x5A ^ x015 = 0x4F # 'Z'

# And letters !


def decode(input, errors='strict'):
    #result = ''.join([letter_dict.get(x, '[{:02X}]'.format(x)) for x in input])
    result = ''.join(chr(x^0x4F) for x in input)
    return (result, len(result)) 

def encode(input, errors='strict'):
    return (b'', 0)

codecs.register(lambda x: codecs.CodecInfo(encode, decode, 'dom5'))
