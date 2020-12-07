import sys
import binascii
import json
import collections
import util
import dom5codec

lowercase = [0x2E,0x2D,0x2C,0x2B,0x2A,0x29,0x28,0x27,0x26,0x25,0x24,0x23,0x22,0x21,0x20,0x3F,0x3E,0x3D,0x3C,0x3B,0x3A,0x39,0x38,0x37,0x36,0x35]
uppercase = [0x0E,0x0D,0x0C,0x0B,0x0A,0x09,0x08,0x07,0x06,0x05,0x04,0x03,0x02,0x01,0x00,0x1F,0x1E,0x1D,0x1C,0x1B,0x1A,0x19,0x18,0x17,0x16,0x15]
digit = [0x7E,0x7D,0x7C,0x7B,0x7A,0x79,0x78,0x77,0x76,0x7F]

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
letter_dict[0x61] = '.'

blesses_dict = {
        26: 'Defense',
        21: 'Minor Cold Resist',
        24: 'Water Walking',
        24: 'Major Cold Resist',
        58: 'Undead Regeneration'
        }

def decode(decode_me):
    try:
        #return ''.join([letter_dict.get(x, 0x8F - x) for x in decode_me])
        return ''.join([letter_dict.get(x, '[{:02X}]'.format(x)) for x in decode_me])
    except:
        return 'ERROR'


def dumphex(data):
    result = ''
    for i,d in enumerate(data):
        result += '{:02X}'.format(d)
        if i % 4 == 3:
            result += '  '
        else:
            result += ' '
    return result.strip()

def prettyhex(data):
    #result = '\n'.join('  '.join(' '.join('{:02X}'.format(d))
    return '\n'.join('  '.join(' '.join('{:02X}'.format(d) for d in data4) for data4 in util.grouper(data20, 4)) for data20 in util.grouper(data, 16))

def pretender(filename):
    result = collections.OrderedDict()

    with open(filename, "rb") as f:
        data = f.read()

    # The first 26 bytes are always the same
    result['head'] = data[:0x1A] 
    result['nation_id'] = data[0x1A]

    result['dunno'] = data[0x1B:0x5D]
    result['dunno1'] = data[0x1B:0x2F]
    pos = 0x2F

    # If no password, [0x78, 0x78]
    # If password, [*, 0x78]
    # It looks like the password is just a pad cipher.  Could figure it out but why bother?
    has_password = (data[pos] != 0x78)
    if has_password:
        next_field_index = data[pos:].index(0x78)
        password = data[pos:pos + next_field_index]
        pos = pos + next_field_index
    else:
        assert data[pos + 1] == 0x78
        password = data[pos:pos+1]
        pos = pos + 1

    result['has_password'] = has_password
    result['password'] = password
    result['dunno2'] = data[pos:pos+0x2D]
    pos = pos + 0x2D

    pretender_id = data[pos:pos+2]
    result['pretender_id'] = int.from_bytes(pretender_id, byteorder='little')
    pos = pos + 2

    result['mystery'] = data[pos:pos+16]
    pos = pos + 16

    alt_form = data[pos:pos+2]
    result['alt_form'] = int.from_bytes(alt_form, byteorder='little')
    pos = pos + 2


    name_start = 0x84
    name_length = data[name_start:].index(0x4F)
    name = data[name_start:name_start + name_length]
    #name_ascii = [chr(0x8F - x) for x in name]
    name_ascii = decode(name)
    name_ascii = name.decode('dom5')
    #result['name'] = ','.join('0x{:02X}'.format(x) for x in name)
    result['name'] = dumphex(name)
    result['name_ascii'] = name_ascii
    pos = name_start + name_length

    rest = data[pos:]

    a,b,c = rest.partition(bytes.fromhex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'))
    result['resta'] = a
    result['ffa'] = b
    rest = c

    a,b,c = rest.partition(bytes.fromhex('FFFFFFFFFFFFFFFFFFFF'))
    result['restb'] = a
    result['ffb'] = b
    rest = c

    result['zeroesiguess'] = rest[:7]
    rest = rest[7:]

    result['dom'] = int(rest[0])
    rest = rest[1:]

    result['FAWE'] = rest[:4]
    rest = rest[4:]

    result['SDNB'] = rest[:4]
    rest = rest[4:]

    result['divine'] = int(rest[0])
    rest = rest[1:]

    result['zeroes_near_end'] = rest[:40]
    rest = rest[40:]

    result['02_31'] = rest[:2]
    rest = rest[2:]

    result['maybe_string?'] = rest[:7]
    #result['maybe_as_string'] = decode(result['maybe_string?'])
    rest = rest[7:]

    result['awaken'] = rest[:4]
    rest = rest[4:]

    result['zeroes_at_end'] = rest[:8]
    rest = rest[8:]

    result['num_blesses'] = rest[:8]
    result['num_blesses'] = int.from_bytes(result['num_blesses'], byteorder='little')
    rest = rest[8:]

    result['blesses'] = [rest[x*4:x*4+4] for x in range(result['num_blesses'])]
    result['blesses'] = [int.from_bytes(x, byteorder='little') for x in result['blesses']]
    rest = rest[4*result['num_blesses']:]

    a,b,c = rest.partition(bytes.fromhex('4F4F4FAC'))
    result['Name Again'] = decode(a)
    result['4F4F4FAC'] = b
    rest = c

    result['D3000'] = decode(rest[:5])
    result['checksum'] = rest[5:]

    return result

if __name__ == '__main__':
    if len(sys.argv) == 2:
        filename = sys.argv[1]
        #print(pretender(filename))
        print(json.dumps(pretender(filename), indent=4, default=dumphex))

    elif len(sys.argv) > 2:
        # Diff two pretenders
        p = [pretender(fname) for fname in sys.argv[1:]]
        for key in p[1]:
            if isinstance(p[1][key], bytes):
                values = [prettyhex(k[key]) for k in p]
                if not all(k == values[0] for k in values):
                    print(key)
                    #print ('\n---\n'.join(prettyhex(k[key]) for k in p))
                    print ('\n---\n'.join(values))
                    print()
            else:
                values = [str(k[key]) for k in p]
                if not all(k == values[0] for k in values):
                    print(key)
                    print ('\n---\n'.join(values))
                    print()
