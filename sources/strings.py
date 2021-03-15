# <script src="https://gist.github.com/williballenthin/8e3913358a7996eab9b96bd57fc59df2.js"></script>
import re
from collections import namedtuple

# added the regex to be bytes based
ASCII_BYTE = rb" !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"

String = namedtuple('String', ['s', 'offset'])


def ascii_strings(buf, n=4):
    reg = rb"([%s]{%d,})" % (ASCII_BYTE, n)  # added the regex to be bytes based
    ascii_re = re.compile(reg)
    for match in ascii_re.finditer(buf):
        yield String(match.group().decode('ascii'), match.start())


def unicode_strings(buf, n=4):
    reg = rb"((?:[%s]\x00){%d,})" % (ASCII_BYTE, n)  # added the regex to be bytes based
    uni_re = re.compile(reg)
    for match in uni_re.finditer(buf):
        try:
            yield String(match.group().decode('utf-16'), match.start())
        except UnicodeDecodeError:
            pass


def file_strings(file):
    ascii_list, uni_list = [], []
    with open(file, 'rb') as f:
        b = f.read()

    for s in ascii_strings(b, n=4):
        str1 = ('0x{:x}: {:s}'.format(s.offset, s.s))
        ascii_list.append(str1)

    for s in unicode_strings(b):
        str2 = ('0x{:x}: {:s}'.format(s.offset, s.s))
        uni_list.append(str2)

    return ascii_list, uni_list
