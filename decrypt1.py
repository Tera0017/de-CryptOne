"""
Author: @Tera0017/@SentinelOne
"""
from modules.decryptshellcode import DecryptShellcode64, DecryptShellcode86
from modules.decryptexecutable import DecryptExecutable64, DecryptExecutable86
from modules.generic import message, writefile, get_osa, gen_name, process_args, get_size, ERRORS


class DeCrypt1:
    def __init__(self, filepath):
        self.filepath = filepath

    def unpack(self):
        line = '------------------------'
        osa = get_osa(file_path=self.filepath)

        message(line)
        message('CryptOne Unpacker {}'.format(hex(osa)))
        message(line)

        DecryptShell, DecryptExec = {
            0x32: (DecryptShellcode86, DecryptExecutable86),
            0x64: (DecryptShellcode64, DecryptExecutable64),
        }[osa]
        
        shellcode = DecryptShell(self.filepath)
        shellcode_data = shellcode.decrypt()
        filename_shellcode = gen_name(self.filepath, 'CryptOne_Shellcode_')
        writefile(filename_shellcode, shellcode_data)
        message('CryptOne Shellcode successfully dumped: {}'.format(filename_shellcode))
        message(line)

        executable = DecryptExec(shellcode_data)
        executable_data = executable.decrypt()
        filename_executable = gen_name(self.filepath, 'CryptOne_Exec_')
        writefile(filename_executable, executable_data)
        message('CryptOne Executable Size: {}'.format(hex(get_size(executable_data)).upper()))
        message('CryptOne Executable successfully dumped: {}'.format(filename_executable))
        message(line)


if __name__ == '__main__':
    decrypt1 = DeCrypt1(process_args())
    decrypt1.unpack()
