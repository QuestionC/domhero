import hex_analysis
import dom5codec
import sys

blesses_dict = {
        26: 'Defense',
        21: 'Minor Cold Resist',
        24: 'Water Walking',
        24: 'Major Cold Resist',
        58: 'Undead Regeneration'
        }

def pretender_from_data(data: bytes): 
    h = hex_analysis.HexAnalysis(data)
    h.bytefield('head', 26)
    #h.charfield('head', 26, encoding='dom5')

    h.int8('nation_id')

    #h.bytefield('dunno1', 20)
    h.charfield('gamename?', 20, encoding='dom5')

    # If no password, 0x78
    # If password, 0x78-terminated line
    if h.curr_byte() == 0x78:
        # No password
        h.bytefield('no password', 2)
    else:
        # 0x78 terminated string
        h.bytestring('password', 0x78)

    h.bytefield('dunno2', 44)
    h.int16('pretender_id')
    h.int16('hp')
    h.bytefield('mystery', 14)
    h.int16('alt_form')
    h.bytefield('some zeroes', 6)
    h.int16('??')
    h.int16('??')
    h.bytefield('FFx4', 4)
    h.bytefield('00x5', 5)
    #h.bytestring('namebytes', 0x4F)
    h.string('name', 0x4F, encoding='dom5')
    #h.bytestring('namebytes', bytes(0x4F)) 
    h.bytefield('??', 4)
    h.bytefield('FF and 00', 20 + 6*16)
    h.bytefield('dom and scales', 10)
    h.bytefield('??', 43)
    h.int8('Chaos')
    h.int8('Sloth')
    h.int8('Cold')
    h.int8('Death')
    h.int8('Misf')
    h.int8('Drain')
    h.bytefield('4F', 1)
    h.int32('awaken')
    h.bytefield('zeroes', 8)
    
    n = h.int32('number of blesses')
    h.int32('0')
    for i in range(n):
        h.int32('bless')
    h.string('name', 0x4F, encoding='dom5')
    h.bytefield('4F4FAC', 3)

    h.charfield('D4000', 5, encoding='dom5')
    h.bytefield('checksum', 2)

    return h

def print_pretender(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    h = pretender_from_data(data)
    print(h)

def diff_pretenders(filenames):
    pretenders = []
    for filename in filenames:
        with open(filename, 'rb') as f:
            data = f.read()
        pretenders.append(pretender_from_data(data))

    hex_analysis.diff(pretenders)

def main():
    if len(sys.argv) == 1:
        print('python3 ' + sys.argv[0] + ' <pretender.2h>')
        sys.exit()

    elif len(sys.argv) == 2:
        filename = sys.argv[1]
        print_pretender(filename)

    elif len(sys.argv) > 2:
        filenames = sys.argv[1:]
        diff_pretenders(filenames)


if __name__ == '__main__':
    main()
