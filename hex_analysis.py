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
        print_fields = self.str_prep()

        result = ''
        for fieldname,fielddata,fieldtype,addr_from,addr_to in print_fields:
            result += '{}: {} {}:{}'.format(fieldname, fieldtype, addr_from, addr_to)
            result += '\n'
            result += str(fielddata)
            result += '\n'
            result += '\n'
        return result

    def str_prep(self):
        print_fields = []

        curr_addr = 0;
        for field in self.fields:
            name,addr_from,addr_to,f_type,*f_data = field
            
            # If for some reason undefined bytes, dump them
            if curr_addr < addr_from:
                # Unclassified bytes
                printval = _printhex(self.data[curr_addr:addr_to])
                print_fields.append(('undefined', printval, 'bytes', curr_addr, addr_from))
                curr_addr = addr_from

            # Field types decoded here
            data = self.data[addr_from:addr_to]
            if f_type in ['bytes', 'bytestring']:
                printval = _printhex(data)
            elif f_type in ('int8', 'int16', 'int32'):
                printval = int.from_bytes(data, byteorder='little', signed=True)
            elif f_type in ['string', 'chars']:
                printval = data.decode(f_data[0])
                
            print_fields.append((name, printval, f_type, addr_from, addr_to))
            curr_addr = addr_to

        # Dump all bytes after the defined fields
        if curr_addr < len(self.data):
            print_fields.append(('undefined', _printhex(self.data[curr_addr:len(self.data)]), 'bytes', curr_addr, len(self.data)))
        
        return print_fields

    def curr_byte(self):
        return self.data[self.addr]

    def bytefield(self, name, l):
        self.fields.append((name, self.addr, self.addr + l, 'bytes'))
        self.addr += l

    def charfield(self, name, l, encoding='utf-8'):
        self.fields.append((name, self.addr, self.addr + l, 'chars', encoding))
        self.addr += l

    def int8(self, name):
        self.fields.append((name, self.addr, self.addr + 1, 'int8'))
        self.addr += 1

    def int16(self, name):
        self.fields.append((name, self.addr, self.addr + 2, 'int16'))
        self.addr += 2 
    
    def int32(self, name):
        data = self.data[self.addr:self.addr+4]
        val = int.from_bytes(data, byteorder='little', signed=True)
        self.fields.append((name, self.addr, self.addr + 4, 'int32'))
        self.addr += 4
        return val

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

def diff(analyses):
    diff_us = [x.str_prep() for x in analyses]

    # This should match each element by field offset
    for field in zip(*diff_us):
        # Each field is a 2ple.  Zip the first elements and second elements together
        field_names,field_data,field_types,field_begins,field_ends = zip(*field)

        nameset = set(field_names)
        if len(nameset) > 1:
            print ('WARNING: field name mismatch')
            print (nameset)

        if any(d != field_data[0] for d in field_data):
            # There's a diff so print it
            print (field_names[0])
            print ('\n---\n'.join(str(d) for d in field_data))
            print()
