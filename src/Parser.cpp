#include "Parser.h"

PE_Parser::PE_Parser(const char* file_path) : m_file_path(file_path)
{
	if (!std::filesystem::exists(file_path) || !std::filesystem::is_regular_file(file_path))
	{
		m_error = ERROR_FILE_NOT_FOUND;
		return;
	}

	m_file.open(file_path, std::ios::binary | std::ios::in | std::ios::out);
	if (m_file.fail())
	{
		m_error = ERROR_COULDNT_OPEN_FILE;
		return;
	}
}

unsigned short PE_Parser::Error()
{
	return m_error;
}

const _Parsed_Data& PE_Parser::GetParsedData() const
{
	return m_parsed_data;
}

const _Offset_Data& PE_Parser::GetOffsetData() const
{
	return m_offset_data;
}

const IMAGE_NT_HEADERS64& PE_Parser::GetNtHeaders() const
{
	return m_nt_headers;
}

bool PE_Parser::Parse(bool skip_volatile)
{
	if (m_file.fail())
	{
		m_error = ERROR_FILE_FALIURE;
		return true;
	}
	m_file.seekg(0, std::ios::beg);

	m_parsed_data.ImportTable.clear();
	m_parsed_data.RelocTable.clear();
	m_parsed_data.SectionHeaders.clear();

	IMAGE_DOS_HEADER dos_h = ParseDosH();

	if (ParseNtHeader(&dos_h))
		return true;

	ParseSectionH();

	if (!skip_volatile)
	{
		if (ParseImportTable())
			return true;

		if (ParseRealocTable())
			return true;
	}

	m_parsed = true;
	return false;
}


DWORD PE_Parser::ResloveRvaAddress(DWORD rva)
{
	size_t index = 0;
	for (; index < m_parsed_data.SectionHeaders.size(); index++)
	{
		DWORD upper_bound = m_parsed_data.SectionHeaders[index].Misc.VirtualSize + m_parsed_data.SectionHeaders[index].VirtualAddress;
		if (rva >= m_parsed_data.SectionHeaders[index].VirtualAddress && rva <= upper_bound)
			break;
	}

	if (index + 1 == m_parsed_data.SectionHeaders.size())
	{
		DWORD upper_bound = m_parsed_data.SectionHeaders[index].Misc.VirtualSize + m_parsed_data.SectionHeaders[index].VirtualAddress;
		if (rva >= m_parsed_data.SectionHeaders[index].VirtualAddress && rva <= upper_bound)
		{
		}
		else
			return 0;
	}

	rva -= m_parsed_data.SectionHeaders[index].VirtualAddress;
	rva += m_parsed_data.SectionHeaders[index].PointerToRawData;
	return rva;
}

IMAGE_DOS_HEADER PE_Parser::ParseDosH()
{
	IMAGE_DOS_HEADER dos_h;
	memset(&dos_h, 0x0, sizeof(dos_h));

	m_file.read((char*)&dos_h, sizeof(dos_h));

	if (dos_h.e_magic != IMAGE_DOS_SIGNATURE)
	{
		m_error = ERROR_INVALID_FILE;
		memset(&dos_h, 0x0, sizeof(dos_h));
		return dos_h;
	}

	return dos_h;
}

bool PE_Parser::ParseNtHeader(PIMAGE_DOS_HEADER dos_h)
{
	m_file.seekg(dos_h->e_lfanew, std::ios::beg);
	m_offset_data.NtHeaderStart = dos_h->e_lfanew;

	memset(&m_nt_headers, 0x0, sizeof(m_nt_headers));

	m_file.read((char*)&m_nt_headers.Signature, 4);

	if (m_nt_headers.Signature != IMAGE_NT_SIGNATURE)
	{
		m_error = ERROR_INVALID_FILE;
		return true;
	}

	m_file.read((char*)&m_nt_headers.FileHeader, sizeof(m_nt_headers.FileHeader));

	m_offset_data.OptionalHeaderStart = m_file.tellg();

	m_file.read((char*)&m_nt_headers.OptionalHeader, m_nt_headers.FileHeader.SizeOfOptionalHeader);

	m_offset_data.OptionalHeaderEnd = m_file.tellg();

	if (m_nt_headers.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		m_error = ERROR_INVALID_FILE;
		return true;
	}
	return false;
}

void PE_Parser::ParseSectionH()
{
	for (WORD i = 0; i < m_nt_headers.FileHeader.NumberOfSections; i++)
	{
		IMAGE_SECTION_HEADER sech;
		m_file.read((char*)&sech, sizeof(sech));
		m_parsed_data.SectionHeaders.push_back(sech);
	}
	m_offset_data.SecHeadersEnd = m_file.tellg();
}

bool PE_Parser::ParseImportTable()
{
	DWORD import_dir_start_offset = ResloveRvaAddress(m_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	if (import_dir_start_offset == 0)
	{
		m_error = ERROR_INVALID_ADDRESS;
		return true;
	}

	m_file.seekg(import_dir_start_offset, std::ios::beg);

	while (true)
	{
		std::pair<IMAGE_IMPORT_DESCRIPTOR, std::vector<ILT_ENTRY_64>> pair;
		m_file.read((char*)&pair.first, sizeof(pair.first));
		if (pair.first.DUMMYUNIONNAME.OriginalFirstThunk == 0)
			break;

		long long end_pos = m_file.tellg();

		DWORD entry_addr = ResloveRvaAddress(pair.first.DUMMYUNIONNAME.OriginalFirstThunk);

		if (entry_addr == 0)
		{
			m_error = ERROR_INVALID_ADDRESS;
			return true;
		}

		m_file.seekg(entry_addr, std::ios::beg);

		while (true)
		{
			QWORD num = 0;
			m_file.read((char*)&num, sizeof(num));
			if (num == 0)
				break;
			pair.second.push_back(*(ILT_ENTRY_64*)&num);
		}

		m_offset_data.IltEntriesEnd[pair.first.DUMMYUNIONNAME.OriginalFirstThunk] = (LLONG)m_file.tellg() - sizeof(QWORD);

		m_file.seekg(end_pos, std::ios::beg);
		m_parsed_data.ImportTable.push_back(pair);
	}
	m_offset_data.ImportDllEnd = m_file.tellg();
	m_offset_data.ImportDllEnd -= sizeof(IMAGE_IMPORT_DESCRIPTOR);

	m_file.clear(m_file.rdstate() & ~std::ios::eofbit);
	return false;
}

std::fstream& PE_Parser::GetFileHandle()
{
	return m_file;
}

bool PE_Parser::ParseRealocTable()
{
	DWORD realoc_table_start_offset = ResloveRvaAddress(m_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	if (realoc_table_start_offset == 0)
	{
		m_error = ERROR_INVALID_ADDRESS;
		return true;
	}

	m_file.seekg(realoc_table_start_offset, std::ios::beg);

	while (true)
	{
		std::pair<IMAGE_BASE_RELOCATION, std::vector<WORD>> pair;
		m_file.read((char*)&pair.first, sizeof(pair.first));
		if (pair.first.SizeOfBlock == 0 && pair.first.VirtualAddress == 0)
			break;

		DWORD entry_count = (pair.first.SizeOfBlock - 8) / 2;

		for (DWORD i = 0; i < entry_count; i++)
		{
			WORD tmp = 0;
			m_file.read((char*)&tmp, sizeof(tmp));
			pair.second.push_back(tmp);
		}
		m_parsed_data.RelocTable.push_back(pair);
	}

	m_file.clear(m_file.rdstate() & ~std::ios::eofbit);
	return false;
}

const char* PE_Parser::GetFilePath()
{
	return m_file_path;
}

bool PE_Parser::Parsed()
{
	return m_parsed;
}

const char* FormatError(unsigned short error)
{
	switch (error)
	{
	case ERROR_FILE_NOT_FOUND:
		return "File not found";
	case ERROR_COULDNT_OPEN_FILE:
		return "Couldn't open file";
	case ERROR_FILE_FALIURE:
		return "File operation faliure";
	case ERROR_INVALID_FILE:
		return "Invalid File";
	case ERROR_INVALID_ADDRESS:
		return "Address contained in NT Header pointing to an invalid location";
	default:
		return "";
	}
}
