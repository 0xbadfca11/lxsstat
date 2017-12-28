#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <vector>
#include "../fileopen.hpp"

bool operator==(const FILE_ID_128& l, const FILE_ID_128& r)
{
	return memcmp(&l.Identifier, &r.Identifier, sizeof(FILE_ID_128::Identifier)) == 0;
}
FILE_ID_128 GetFileID(HANDLE f)
{
	FILE_ID_INFO file_id;
	GetFileInformationByHandleEx(f, FileIdInfo, &file_id, sizeof file_id);
	return file_id.FileId;
}
int wmain(int argc, PWSTR argv[])
{
	std::vector<FILE_ID_128> ids;
	for (int i = 1; i < argc; i++)
	{
		FILE_ID_128 id = GetFileID(OpenFileCaseSensitive(argv[i]));
		for (int j = _countof(FILE_ID_128::Identifier) - 1; j >= 0; --j)
			printf("%02x", id.Identifier[j]);
		printf("\t%ls\n", argv[i]);
		if (std::find(std::cbegin(ids), std::cend(ids), id) != std::cend(ids))
			puts("Identical file id found.");
		ids.push_back(id);
	}
}