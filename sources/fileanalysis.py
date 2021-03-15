from pprint import pprint

from filehash import FileHash
import magic
import pefile


def file_type_hashes(file):
    md5Hash = FileHash('md5')
    sha1Hash = FileHash('sha1')
    sha256Hash = FileHash('sha256')
    sha512Hash = FileHash('sha512')
    crcHash = FileHash('crc32')
    adler32Hash = FileHash('adler32')

    file_info = {
        'filetype': magic.from_file(file),
        'md5': md5Hash.hash_file(file),
        'sha1': sha1Hash.hash_file(file),
        'sha256': sha256Hash.hash_file(file),
        'sha512': sha512Hash.hash_file(file),
        'crc32': crcHash.hash_file(file),
        'adler32': adler32Hash.hash_file(file)
    }

    return file_info


def pe_check(file):
    try:
        pe = pefile.PE(file)
        if pe:
            return {'errorState': False}
    except Exception as e:
        return {'errorState': True}


class PE:
    def __init__(self, file):
        self.pe = pefile.PE(file)

    def get_imported_symbols(self):

        imports = []
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            try:
                for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name, imp_list = entry.dll.decode('utf-8'), []
                    for func in entry.imports:
                        try:
                            imp_list.append({
                                'name': func.name.decode('utf-8'),
                                'address': '0x%08x' % func.address})
                        except AttributeError:
                            pass
                    imp_dict = {dll_name: imp_list}
                    imports.append(imp_dict)
            except AttributeError:
                pass

        return imports

    def get_exported_symbols(self):
        """Gets exported symbols.
        @return: exported symbols dict or None.
        """
        exports = []

        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            try:
                for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    add = int(self.pe.OPTIONAL_HEADER.ImageBase + exp.address)
                    exports.append({
                        'name': exp.name.decode('utf-8'),
                        'address': '0x%08x' % (int(add))})
            except AttributeError:
                pass

        return exports

    def pe_info(self):
        try:
            sections_list, directory_names = [], []
            binary = '32-bit Binary' if hex(self.pe.FILE_HEADER.Machine) == '0x14c' else '64-bit Binary'
            basic_info = {
                'Magic Value': hex(self.pe.DOS_HEADER.e_magic),
                'Signature Value': hex(self.pe.NT_HEADERS.Signature),
                'Number of Data Directories': self.pe.OPTIONAL_HEADER.NumberOfRvaAndSizes,
                'Machine': hex(self.pe.FILE_HEADER.Machine),
                'Binary': binary,
                'TimeDateStamp': self.pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split('[')[1][:-1],
            }

            for section in self.pe.sections:
                section_dict = {
                    'name': str(section.Name.decode('utf-8')).strip('\x00'),
                    'vAddress': 'Virtual Address: ' + hex(section.VirtualAddress),
                    'vSize': 'Virtual Size: ' + hex(section.Misc_VirtualSize),
                    'raw': 'Raw Size: ' + hex(section.SizeOfRawData)
                }
                sections_list.append(section_dict)

            header_dump = self.pe.DOS_HEADER.dump()
            hd_list = []
            for x in header_dump:
                hd1 = x.split(' ')
                hd2 = [y for y in hd1 if y != '']
                hd_list.append(hd2)

            directory_names = [x.name for x in self.pe.OPTIONAL_HEADER.DATA_DIRECTORY]

            data_directory = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY

            imports = self.get_imported_symbols()
            exports = self.get_exported_symbols()

            all_section = self.pe.sections
            sec_list, all_section_len = [], []

            for x in all_section:
                as1 = ((repr(x).replace('<Structure: ', '')).replace('>', '')).split(' ')
                all_section_len.append(len(as1))
                sec_list.append(as1)

            final_info = {
                'basic': basic_info,
                'sectionSize': sections_list,
                'headerDump': hd_list,
                'headerDumpLength': len(hd_list),
                'directoryNames': directory_names,
                'dataDirectory': data_directory,
                'imports': imports,
                'exports': exports,
                'allSection': sec_list,
                'SectionLength': len(sec_list),
                'allSectionLength': all_section_len,
                'errorState': False
            }

            return final_info

        except OSError as e:
            final_info = {
                'errorState': True,
                'error': e
            }
            return final_info

        except pefile.PEFormatError as e:
            final_info = {
                'errorState': True,
                'error': 'PEFormatError: %s' % e.value
            }
            return final_info
