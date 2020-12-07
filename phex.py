import hex_analysis
import dom5codec
import sys


def main():
    if len(sys.argv) == 1:
        print('python phex.py <filename>')
        sys.exit()

    filename = sys.argv[1]

    with open(filename, 'rb') as f:
        data = f.read()

    h = hex_analysis.HexAnalysis(data)
    h.bytefield('head', 26)

    h.int8('nation_id')

    h.bytefield('dunno1', 20)

    # If no password, 0x78
    # If password, 0x78-terminated line
    print(h.curr_byte())
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
    
    print(h)


if __name__ == '__main__':
    main()
