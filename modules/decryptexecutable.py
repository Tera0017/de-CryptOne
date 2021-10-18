"""
Author: @Tera0017/@SentinelOne
"""
import struct
from .generic import match_rule, split_per, message, fix_dword, hexy


class DecryptExecutable:
    def __init__(self, shellcode, osa, rules):
        self.shellcode = shellcode
        self.rules = rules
        self.osa = osa

    def decr_xorkey(self):
        rl = '$scode2'
        for match in match_rule(rl, self.rules[rl], self.shellcode):
            opcodes = match[2]
            idx = 5 if self.osa == 0x32 else 2
            val = struct.unpack('<l', opcodes[idx: idx + 4])[0]
            if val < 0:
                continue
            else:
                return val

    def get_size(self, address):
        try:
            size = struct.unpack('I', self.shellcode[address - 4: address])[0]
            if size < 0xFF:
                address += 4
                size = struct.unpack('I', self.shellcode[address - 4: address])[0]
        except struct.error:
            fnd = b'\x20\x00\x00\x00\x40\x00\x00\x00'
            if fnd in self.shellcode:
                address = self.shellcode.index(fnd) + 12
                size = struct.unpack('I', self.shellcode[address - 4: address])[0]
        return address, size

    def decrypt(self):
        mz_addr = self.exec_address()
        mz_addr, size = self.get_size(mz_addr)
        xorkey = self.decr_xorkey()
        message('Init XOR-KEY: ' + hex(xorkey).upper())
        mz_data = fix_dword(self.shellcode[mz_addr: mz_addr + size])
        counter = 0
        mz_decr = b''
        for dw in split_per(mz_data, 4):
            dw = (struct.unpack('I', dw)[0] + counter) & 0xFFFFFFFF
            xortemp = (xorkey + counter) & 0xFFFFFFFF
            counter += 4
            mz_decr += struct.pack('I', dw ^ xortemp)
        return mz_decr


class DecryptExecutable86(DecryptExecutable):
    def __init__(self, shellcode):
        rules = {
            '$scode1': '{E8 00 00 00 00 58 2D [4] C3}',
            '$scode12': '{05 [4] 89 [5] 8B [4-6] E8}',
            '$scode2': '{8B [2] 81 (C1| C2| C3| C4| C5| C6| C7) [4] 8B}'
        }
        DecryptExecutable.__init__(self, shellcode, 0x32, rules)

    def exec_address(self):
        for rl in ['$scode1', '$scode12']:
            for match in match_rule(rl, self.rules[rl], self.shellcode):
                if rl == '$scode1':
                    addr1 = match[0] + 5
                    addr1 -= struct.unpack('I', match[2][7: 7 + 4])[0]
                    break
                else:
                    addr2 = struct.unpack('I', match[2][1: 1 + 4])[0]
                    break
        return addr1 + addr2


class DecryptExecutable64(DecryptExecutable):
    def __init__(self, shellcode):
        rules = {
            '$scode1': '{48 8D 05 ?? ?? ?? ?? 48 83 C0 04}',
            '$scode2': '{81 C1 [3] 00 48}'
        }
        DecryptExecutable.__init__(self, shellcode, 0x64, rules)

    def exec_address(self):
        rl = '$scode1'
        for match in match_rule(rl, self.rules[rl], self.shellcode):
            address = match[0]
            opcodes = match[2]
            return address + 7 + struct.unpack('<l', opcodes[3: 3 + 4])[0] + 4
