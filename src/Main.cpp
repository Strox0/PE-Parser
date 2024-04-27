#include "Parser.h"
#include <iostream>


void print_nt_headers(const IMAGE_NT_HEADERS64& nt_headers)
{
	std::cout << "Signature: " << std::hex << nt_headers.Signature << std::endl;
	std::cout << "Machine: " << std::hex << nt_headers.FileHeader.Machine << std::endl;
	std::cout << "NumberOfSections: " << std::hex << nt_headers.FileHeader.NumberOfSections << std::endl;
	std::cout << "TimeDateStamp: " << std::hex << nt_headers.FileHeader.TimeDateStamp << std::endl;
	std::cout << "PointerToSymbolTable: " << std::hex << nt_headers.FileHeader.PointerToSymbolTable << std::endl;
	std::cout << "NumberOfSymbols: " << std::hex << nt_headers.FileHeader.NumberOfSymbols << std::endl;
	std::cout << "SizeOfOptionalHeader: " << std::hex << nt_headers.FileHeader.SizeOfOptionalHeader << std::endl;
	std::cout << "Characteristics: " << std::hex << nt_headers.FileHeader.Characteristics << std::endl;
}

void print_section_headers(const std::vector<IMAGE_SECTION_HEADER>& section_headers)
{
	for (const IMAGE_SECTION_HEADER& section : section_headers)
	{
		std::cout << "Name: " << section.Name << std::endl;
		std::cout << "VirtualSize: " << std::hex << section.Misc.VirtualSize << std::endl;
		std::cout << "VirtualAddress: " << std::hex << section.VirtualAddress << std::endl;
		std::cout << "SizeOfRawData: " << std::hex << section.SizeOfRawData << std::endl;
		std::cout << "PointerToRawData: " << std::hex << section.PointerToRawData << std::endl;
		std::cout << "PointerToRelocations: " << std::hex << section.PointerToRelocations << std::endl;
		std::cout << "PointerToLinenumbers: " << std::hex << section.PointerToLinenumbers << std::endl;
		std::cout << "NumberOfRelocations: " << std::hex << section.NumberOfRelocations << std::endl;
		std::cout << "NumberOfLinenumbers: " << std::hex << section.NumberOfLinenumbers << std::endl;
		std::cout << "Characteristics: " << std::hex << section.Characteristics << std::endl;
	}
}

void print_import_table(const std::vector<std::pair<IMAGE_IMPORT_DESCRIPTOR, std::vector<ILT_ENTRY_64>>>& import_table)
{
	for (const auto& import : import_table)
	{
		std::cout << "OriginalFirstThunk: " << std::hex << import.first.DUMMYUNIONNAME.OriginalFirstThunk << std::endl;
		std::cout << "TimeDateStamp: " << std::hex << import.first.TimeDateStamp << std::endl;
		std::cout << "ForwarderChain: " << std::hex << import.first.ForwarderChain << std::endl;
		std::cout << "Name: " << import.first.Name << std::endl;
		std::cout << "FirstThunk: " << std::hex << import.first.FirstThunk << std::endl;

		for (const ILT_ENTRY_64 & entry : import.second)
		{
			std::cout << "HintTable Address: " << std::hex << entry.HintTable << std::endl;
		}
	}
}

void print_relocation_table(const std::vector<std::pair<IMAGE_BASE_RELOCATION, std::vector<WORD>>>& reloc_table)
{
	for (const auto& reloc : reloc_table)
	{
		std::cout << "VirtualAddress: " << std::hex << reloc.first.VirtualAddress << std::endl;
		std::cout << "SizeOfBlock: " << std::hex << reloc.first.SizeOfBlock << std::endl;

		for (const WORD& entry : reloc.second)
		{
			std::cout << "Type: " << std::hex << (entry >> 12) << std::endl;
			std::cout << "Offset: " << std::hex << (entry & 0xFFF) << std::endl;
		}
	}
}

int main(int argc, char** argv) 
{
	if (argc < 2 || argc > 2) {
		std::cout << "Usage: " << argv[0] << " <PE file path>" << std::endl;
		return 1;
	}

	PE_Parser parser(argv[1]);

	parser.Parse();

	if (parser.Error())
	{
		std::cout << "Error: " << FormatError(parser.Error()) << std::endl;
		return 1;
	}

	const IMAGE_NT_HEADERS64 nt_headers = parser.GetNtHeaders();
	const _Parsed_Data& parsed_data = parser.GetParsedData();
	
	print_nt_headers(nt_headers);
	print_section_headers(parsed_data.SectionHeaders);
	print_import_table(parsed_data.ImportTable);
	//print_relocation_table(parsed_data.RelocTable);	

	return 0;
}