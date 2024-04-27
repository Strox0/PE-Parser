#pragma once
#include <vector>
#include <string>
#include <memory>
#include <fstream>
#include <filesystem>
#include <unordered_map>

#include "Winnth_def.h"

#define ERROR_SUCCESS 0
#define ERROR_FILE_NOT_FOUND 1
#define ERROR_COULDNT_OPEN_FILE 2
#define ERROR_INVALID_FILE 3
#define ERROR_INVALID_ADDRESS 4
#define ERROR_INJ_IMPORT_ALLOC_MODIFY_MISSMATCH 5
#define ERROR_FILE_FALIURE 6

typedef unsigned char HEXCODE;
typedef long long LLONG;

struct _Offset_Data
{
	LLONG NtHeaderStart;
	LLONG OptionalHeaderStart;
	LLONG OptionalHeaderEnd;
	LLONG ImportDllEnd;
	LLONG SecHeadersEnd;
	std::unordered_map<DWORD, LLONG> IltEntriesEnd;
};

struct _Parsed_Data
{
	std::vector<IMAGE_SECTION_HEADER> SectionHeaders;
	std::vector<std::pair<IMAGE_IMPORT_DESCRIPTOR, std::vector<ILT_ENTRY_64>>> ImportTable;
	std::vector<std::pair<IMAGE_BASE_RELOCATION, std::vector<WORD>>> RelocTable;
};

struct _Section_Info
{
	unsigned char Name[IMAGE_SIZEOF_SHORT_NAME];
	DWORD SectionRawSize;
	DWORD Charachteristics;
};

class PE_Parser
{
public:

	PE_Parser(const char* file_path);

	unsigned short Error();

	bool Parse(bool skip_volatile = false);
	bool Parsed();

	const _Parsed_Data& GetParsedData() const;
	const _Offset_Data& GetOffsetData() const;
	const IMAGE_NT_HEADERS64& GetNtHeaders() const;

	std::fstream& GetFileHandle();

	const char* GetFilePath();
private:
	DWORD ResloveRvaAddress(DWORD rva);

	IMAGE_DOS_HEADER ParseDosH();
	bool ParseNtHeader(PIMAGE_DOS_HEADER dos_h);
	void ParseSectionH();
	bool ParseImportTable();
	bool ParseRealocTable();
private:
	std::fstream m_file;

	unsigned short m_error = ERROR_SUCCESS;
	bool m_parsed = false;

	IMAGE_NT_HEADERS64 m_nt_headers;

	_Offset_Data m_offset_data;
	_Parsed_Data m_parsed_data;

	const char* m_file_path;
};

const char* FormatError(unsigned short error);