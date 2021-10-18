# -*- coding: utf-8 -*-
"""
Author: @Tera0017/@SentinelOne
"""
import os.path

import yara
import pefile
import struct

ERRORS = {
    '01': 'File not found',
    '02': 'Yara rules didn\'t match. Make sure it is packed with CryptOne packer else DM hash @Tera0017',
    '03': 'File seems to be corrupted please validate, else DM hash @Tera0017',
    '04': 'Error while unpacking, please DM hash @Tera0017'
}


def readfile(filepath):
    return open(filepath, 'rb').read()


def writefile(filepath, data):
    open(filepath, 'wb').write(data)


def process_args():
    import sys

    def error_msg():
        message('CryptOne Unpacker')
        message('Add file as argument.')
        message('Example: "$ python3 decrypt1.py sample.bin"')
        exit(-1)

    printlogo()
    if len(sys.argv) != 2:
        error_msg()

    filename = sys.argv[1].strip()
    if not os.path.isfile(filename):
        error_msg()

    return filename


def hexy(st):
    line = " ".join("{:02x}".format(c) for c in st).upper()
    n = 48
    return '\n'.join([line[i:i + n] for i in range(0, len(line), n)])


def get_size(file_data):
    pe = pefile.PE(data=file_data)
    total_size = pe.OPTIONAL_HEADER.SizeOfHeaders
    for section in pe.sections:
        total_size += section.SizeOfRawData
    return total_size


def get_osa(file_data=None, file_path=None):
    if file_data is not None:
        pe = pefile.PE(data=file_data, fast_load=True)
    else:
        pe = pefile.PE(name=file_path, fast_load=True)
    # 0x014C == x86, 0x8664 == x86-x64
    return 0x32 if pe.FILE_HEADER.Machine == 0x14c else 0x64


def match_rule(rule_name, rule_val, data):
    tmp_rule = '''
    rule match_rule
    {
        strings:
            %s = %s
        condition:
            any of them
    }'''.strip()
    myrules = tmp_rule % (rule_name, rule_val)
    yararules = yara.compile(source=myrules)
    matches = yararules.match(data=data)
    try:
        matches = matches[0].strings
    except:
        matches = []
    return matches


def split_per(line, n):
    return [line[i:i + n] for i in range(0, len(line), n)]


def gen_name(file_path, new_name):
    import os
    filename = os.path.basename(file_path)
    folder = '/'.join(file_path.split('/')[:-1]) + '/'
    folder = '' if folder == '/' else folder
    return folder + new_name + filename


def fix_dword(enc_data):
    ln = len(enc_data) % 4
    if ln != 0:
        enc_data += b''.join([b'\x00' for _ in range(0, 4 - ln)])
    return enc_data


def to_hex_dword(val):
    return struct.unpack('<I', val)[0]


def message(msg):
    print('|--> {}'.format(msg))


def printlogo():
    logo = u'''
██████  ███████      ██████ ██████  ██    ██ ██████  ████████  ██ 
██   ██ ██          ██      ██   ██  ██  ██  ██   ██    ██    ███ 
██   ██ █████ █████ ██      ██████    ████   ██████     ██     ██ 
██   ██ ██          ██      ██   ██    ██    ██         ██     ██ 
██████  ███████      ██████ ██   ██    ██    ██         ██     ██ 
                                                                  
 Author: @Tera0017/@SentinelOne
'''
    print(logo)
