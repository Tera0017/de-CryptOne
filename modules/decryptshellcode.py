"""
Author: @Tera0017/@SentinelOne
"""
import re
import pefile
import struct
from .generic import match_rule, message, readfile, split_per, ERRORS


class DecryptShellcode:
    def __init__(self, filepath, osa, rules):
        self.filepath = filepath
        self.filedata = readfile(filepath)
        self.pe = pefile.PE(name=self.filepath, fast_load=True)
        self.osa = osa
        self.rules = rules

    def extract_interface(self):
        data = self.filedata.replace(b'\x00', b'')
        reg = re.compile(rb'.{9}[\\]*\{[a-f0-9\-]{30,45}\}')
        return reg.findall(data)[0].decode('utf-8')

    def extract_encr(self, address, chunk_size, junk_size, total_size):
        counter = 0
        data = b''
        while len(data) + chunk_size < total_size:
            data += self.pe.get_data(address + counter, length=chunk_size)
            counter += chunk_size + junk_size
        data += self.pe.get_data(address + counter, length=total_size - len(data))
        data += self.pe.get_data(address + counter, length=total_size - len(data))
        if len(data) == total_size:
            return data
        else:
            raise Exception(ERRORS['04'])

    def decrypt_encr(self, encr_data):
        xor_init = self.get_xors()
        message('Init XOR-KEY: ' + hex(xor_init).upper())
        counter = 0
        decrypted = b''
        for d in split_per(encr_data, 4):
            temp = (struct.unpack('I', d)[0] + counter) ^ (xor_init + counter)
            decrypted += struct.pack('I', temp & 0xFFFFFFFF)
            counter += 4
        rl = '$code6'
        for match in match_rule(rl, self.rules[rl], decrypted):
            ep = match[0]
            break
        return decrypted, ep

    def decrypt(self):
        message('Registry Interface: ' + self.extract_interface())
        address, size = self.encr_address()
        chunk_size, junk_size = self.encr_chunk_size()
        encr_data = self.extract_encr(address, chunk_size, junk_size, size)
        shellcode_data, shellcode_ep = self.decrypt_encr(encr_data)
        message('Shellcode EntryPoint: ' + hex(shellcode_ep).upper())
        return shellcode_data


class DecryptShellcode86(DecryptShellcode):
    def __init__(self, filepath):
        rules = {
            '$code1': '{C7 [4] 00 [4] EB}',
            '$code12': '{05 [4] A3 [4] 8B [5] 81 [5] 89}',
            '$code121': '{B8 [5] 05 [4] A3 [4] 81 [9] 5D}',
            '$code13': '{7? ?? C7 05 [8] (8B| A1) [4-5] (81| 2D) [4-5] (89| A3)}',
            '$code14': '{55 8B EC B8 [4] 03 05 [4] A3 [4] 81 2D [8] 5D}',
            '$code15': '{05 [4] A3 [4] EB ?? EB}',
            '$code2': '{((51| 50) 8B ??| 52 A1) [4] 03}',
            '$code4': '{C7 45 ?? [4] C7 45 ?? 00 00 00 00 (C7 45| 33 C0| 29 C0)}',
            '$code5': '{83 C4 08 [6] 8D [3-6] 89}',
            '$code6': '{55 8B EC 81 EC (A0 03| 80 00) 00 00 C7}'
        }
        DecryptShellcode.__init__(self, filepath, 0x32, rules)

    def seach_assign(self, opc):
        addr = b'\xC7\x05' + opc
        val = 0
        for idx in [i for i in range(len(self.filedata)) if self.filedata.startswith(addr, i)]:
            idx += 6
            val = struct.unpack('I', self.filedata[idx: idx + 4])[0]
            if val == 0:
                continue
            else:
                break
        return val

    def encr_address(self):
        for rl in ['$code1', '$code14', '$code13', '$code15', '$code12', '$code121']:
            for match in match_rule(rl, self.rules[rl], self.filedata):
                opcodes = match[2]
                if rl == '$code1':
                    address = struct.unpack('I', opcodes[6: 6 + 4])[0]
                elif rl in ['$code12', '$code121', '$code13', '$code15']:
                    idx = 1 if rl in ['$code12', '$code121', '$code15', '$code121'] else 8
                    addr1 = struct.unpack('I', opcodes[idx: idx + 4])[0]
                    address = addr1 if rl == '$code15' else addr1 - struct.unpack('I', opcodes[-5: -5 + 4])[0]
                    if rl == '$code121':
                        val = self.seach_assign(opcodes[7: 7 + 4])
                        address += val
                elif rl == '$code14':
                    addr1 = struct.unpack('I', opcodes[4: 4 + 4])[0]
                    val = self.seach_assign(opcodes[10: 10 + 4])
                    address = (addr1 + val) - struct.unpack('I', opcodes[25: 25 + 4])[0]
                address -= self.pe.OPTIONAL_HEADER.ImageBase
                try:
                    size = struct.unpack('I', self.pe.get_data(rva=address-4, length=4))[0]
                except (struct.error, pefile.PEFormatError):
                    continue
                message("Encoded Layer Size: " + hex(size).upper())
                return address, size

    def encr_chunk_size(self):
        for rl in ['$code2']:
            for match in match_rule(rl, self.rules[rl], self.filedata):
                opcodes = match[2]
                idx = 3 if len(opcodes) == 8 else 2
                addr_chunk = struct.unpack('I', opcodes[idx: idx + 4])[0]
                address = addr_chunk - self.pe.OPTIONAL_HEADER.ImageBase
                try:
                    chunk_size = struct.unpack('I', self.pe.get_data(rva=address, length=4))[0]
                except pefile.PEFormatError:
                    continue
                message("Chunks Size: " + hex(chunk_size).upper())
                addr_junk = addr_chunk + 4
                addr_junk_str = struct.pack('I', addr_junk)
                addr_junk_str = b'\xC7\x05' + addr_junk_str
                if addr_junk_str not in self.filedata:
                    addr_junk -= self.pe.OPTIONAL_HEADER.ImageBase
                    junk_size = struct.unpack('I', self.pe.get_data(rva=addr_junk, length=4))[0]
                else:
                    idx = self.filedata.index(addr_junk_str) + 6
                    junk_size = struct.unpack('I', self.filedata[idx: idx + 4])[0]
                message("Junk Size: " + hex(junk_size).upper())
                break
        return chunk_size, junk_size

    def get_xors(self):
        for rl in ['$code4', '$code5']:
            for match in match_rule(rl, self.rules[rl], self.filedata):
                opcodes = match[2]
                if rl == '$code4':
                    xor_incr = struct.unpack('I', opcodes[3: 3 + 4])[0]
                    if xor_incr > 0x400000 or xor_incr == 0:
                        continue
                    break
                else:
                    fmt, idx = ('I', 4) if len(opcodes) == 17 else ('b', 1)
                    xor_base = struct.unpack(fmt, opcodes[12: 12 + idx])[0]
                    break
        return xor_incr + xor_base


class DecryptShellcode64(DecryptShellcode):
    def __init__(self, filepath):
        rules = {
            '$code1': '{48 8D [5] 48 89 [5] 48 8B [5] 48 83 C0 04 48 89}',
            '$code2': '{8B 0D [4] 03 C8 E8}',
            '$code3': '{C7 05 [4] 00 00 00 00 [12] C7 05 [8] C7}',
            '$code4': '{C7 44 24 [5] C7 44 24 ?? 00 00 00 00}',
            '$code5': '{41 8D (84| 44) 03 ?? (?? 0? 00| 89 44)}',
            '$code6': '{89 4C 24 08 48 83 EC 38 C7}'
        }
        DecryptShellcode.__init__(self, filepath, 0x64, rules)

    def encr_address(self):
        rl = '$code1'
        for match in match_rule(rl, self.rules[rl], self.filedata):
            address = match[0]
            opcodes = match[2]
            address = self.pe.get_rva_from_offset(address)
            address += struct.unpack('<l', opcodes[3: 3 + 4])[0] + 7
            size = struct.unpack('I', self.pe.get_data(rva=address, length=4))[0]
            message("Encoded Layer Size: " + hex(size).upper())
            return address + 4, size

    def encr_chunk_size(self):
        for rl in ['$code2', '$code3']:
            for match in match_rule(rl, self.rules[rl], self.filedata):
                address = match[0]
                opcodes = match[2]
                if rl == '$code2':
                    address = self.pe.get_rva_from_offset(address)
                    address += struct.unpack('I', opcodes[2: 2 + 4])[0] + 6
                    chunk_size = struct.unpack('I', self.pe.get_data(rva=address, length=4))[0]
                    message("Chunks Size: " + hex(chunk_size).upper())
                    continue
                else:
                    junk_size = struct.unpack('I', opcodes[28: 28 + 4])[0]
                    message("Junk Size: " + hex(junk_size).upper())
                    break
        return chunk_size, junk_size

    def get_xors(self):
        for rl in ['$code4', '$code5']:
            for match in match_rule(rl, self.rules[rl], self.filedata):
                opcodes = match[2]
                if rl == '$code4':
                    xor_incr = struct.unpack('I', opcodes[4: 4 + 4])[0]
                    continue
                else:
                    xor_base = struct.unpack('I', opcodes[4: 4 + 4])[0] if opcodes[2] == 0x84 else opcodes[4]
                    break
        return xor_incr + xor_base

