import util
import dom5codec

def _printhex(b: bytes) -> str:
    return '\n'.join('  '.join(' '.join('{:02X}'.format(d) for d in data4) for data4 in util.grouper(data20, 4)) for data20 in util.grouper(b, 16))


class HexAnalysis:
    def __init__(self, b: bytes):
        self.data = b
        self.addr = 0
        self.fields = []

    def __str__(self):
        print_fields = []

        curr_addr = 0;
        for field in self.fields:
            name,addr_from,addr_to,f_type,*f_data = field

            # If for some reason undefined bytes, dump them
            if curr_addr < addr_from:
                # Unclassified bytes
                print_fields.append(('undefined', _printhex(self.data[curr_addr:addr_to])))
                curr_addr = addr_from

            print('Handle {},{},{},{}'.format(name, addr_from, addr_to, f_type))
            title = '{}: {} {}:{}'.format(name, f_type, addr_from, addr_to)
            if f_type in ['bytes', 'bytestring']:
                print_fields.append((title, _printhex(self.data[addr_from:addr_to])))
                curr_addr = addr_to
            elif f_type == 'int8':
                val = int(self.data[addr_from])
                print_fields.append((title, val))
                curr_addr = addr_to
            elif f_type == 'int16':
                val = int.from_bytes(self.data[addr_from:addr_to], byteorder='little', signed=True)
                print_fields.append((title, val))
                curr_addr = addr_to
            elif f_type == 'int32':
                val = int.from_bytes(self.data[addr_from:addr_to], byteorder='little', signed=True)
                print_fields.append((title, val))
                curr_addr = addr_to
            elif f_type == 'string':
                val = self.data[addr_from:addr_to].decode(f_data[0])
                print_fields.append((title, val))
                curr_addr = addr_to
                
        def stringfields():
            
        
        # All bytes after the defined fields
        if curr_addr < len(self.data):
            print_fields.append(('undefined: {}:{}'.format(curr_addr, len(self.data)), _printhex(self.data[curr_addr:len(self.data)])))

        result = ''
        for fieldname,fielddata in print_fields:
            result += fieldname
            result += '\n'
            result += str(fielddata)
            result += '\n'
            result += '\n'
        return result

    def curr_byte(self):
        return self.data[self.addr]

    def bytefield(self, name, l):
        # Assume we're adding to the end of fields
        self.fields.append((name, self.addr, self.addr + l, 'bytes'))
        self.addr += l

    def int8(self, name):
        self.fields.append((name, self.addr, self.addr + 1, 'int8'))
        self.addr += 1

    def int16(self, name):
        self.fields.append((name, self.addr, self.addr + 2, 'int16'))
        self.addr += 2 
    
    def int32(self, name):
        self.fields.append((name, self.addr, self.addr + 4, 'int32'))
        self.addr += 4

    def bytestring(self, name, terminator):
        r = self.data.find(terminator, self.addr) + 1
        if r == 0:
            raise BufferError('Terminator {} not found searching for {}'.format(terminator, name))
        self.fields.append((name, self.addr, r, 'bytestring'))
        self.addr = r

    def string(self, name, terminator, encoding='utf-8'):
        r = self.data.find(terminator, self.addr) + 1
        if r == 0:
            raise BufferError('Terminator {} not found searching for {}'.format(terminator, name))
        self.fields.append((name, self.addr, r, 'string', encoding))
        self.addr = r


