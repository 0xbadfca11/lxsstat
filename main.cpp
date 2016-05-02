#define WIN32_LEAN_AND_MEAN
#define STRICT
#define _ATL_NO_AUTOMATIC_NAMESPACE
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <pathcch.h>
#include <atlalloc.h>
#include <atlbase.h>
#include <cstdio>
#include <cstdlib>
#include <crtdbg.h>
#include "lxsstat.hpp"

int __cdecl wmain(int argc, wchar_t* argv[])
{
	_CrtSetDbgFlag(_CrtSetDbgFlag(_CRTDBG_REPORT_FLAG) | _CRTDBG_LEAK_CHECK_DF);
	_CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDERR);
	_CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_DEBUG | _CRTDBG_MODE_FILE);
	setlocale(LC_ALL, "");
	if (argc <= 1)
	{
		fputs("lxsstat {POSIX_PATH|Windows_PATH} [...]\n", stderr);
		return EXIT_FAILURE;
	}

	for (int i = 1; i < argc; ++i)
	{
		auto windows_path = Lxss::realpath(argv[i]);
		struct Lxss::stat buf;
		if (Lxss::stat(windows_path.c_str(), &buf) != 0)
		{
			ULONG error = GetLastError();
			if (error == STATUS_NO_EAS_ON_FILE)
			{
				fprintf(stderr, "%ls\nExtended Attributes not found\n", windows_path.c_str());
			}
			else
			{
				fprintf(stderr, "%ls\nGetLastError()==0x%08lx\n", windows_path.c_str(), error);
			}
		}
		else
		{
			printf("  File: '%ls'", argv[i]);
			if (Lxss::S_ISLNK(buf.st_mode))
			{
				if (buf.st_size <= PATHCCH_MAX_CCH)
				{
					ATL::CTempBuffer<BYTE> buffer(buf.st_size);
					ULONG read_size;
					ATL::CHandle h(CreateFileW(windows_path.c_str(), FILE_READ_DATA, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_POSIX_SEMANTICS, nullptr));
					if (h != INVALID_HANDLE_VALUE && ReadFile(h, buffer, (ULONG)buf.st_size, &read_size, nullptr))
					{
						printf("  ->  '%.*s'\n", read_size, (PBYTE)buffer);
					}
					else
					{
						ULONG error = GetLastError();
						if (error == ERROR_SHARING_VIOLATION)
						{
							puts("  ->  ?\?\?\?(ERROR_SHARING_VIOLATION)");
						}
						else
						{
							printf("  ->  ?\?\?\?(%lx)", error);
						}
						if (h == INVALID_HANDLE_VALUE)
						{
							h.Detach();
						}
					}
				}
				else
				{
					puts("  ->  symlink too long");
				}
			}
			else
			{
				puts("");
			}
			printf(
				"  Size: %-15llu Blocks: %-10llu IO Block: %-6u ",
				buf.st_size,
				buf.st_blocks,
				buf.st_blksize
			);
			if (Lxss::S_ISLNK(buf.st_mode))
			{
				puts("symbolic link");
			}
			else if (Lxss::S_ISDIR(buf.st_mode))
			{
				puts("directory");
			}
			else if (Lxss::S_ISREG(buf.st_mode))
			{
				if (buf.st_size)
				{
					puts("regular file");
				}
				else
				{
					puts("regular empty file");
				}
			}
			else
			{
				puts("unknown");
			}
			printf(
				"Device: %uh/%ud   Inode: %llu  Links: %u\n",
				Lxss::major(buf.st_dev),
				Lxss::minor(buf.st_dev),
				buf.st_ino,
				buf.st_nlink
			);
			printf(
				"Access: (%u%u%u%u/%s)  Uid: (% 5u/--------)   Gid: (% 5u/--------)\n",
				((buf.st_mode & Lxss::S_ISVTX) ? 1 : 0) | ((buf.st_mode & Lxss::S_ISGID) ? 2 : 0) | ((buf.st_mode & Lxss::S_ISUID) ? 4 : 0),
				(buf.st_mode & Lxss::S_IRWXU) >> 6,
				(buf.st_mode & Lxss::S_IRWXG) >> 3,
				buf.st_mode & Lxss::S_IRWXO,
				Lxss::mode_tostring(buf.st_mode).data(),
				buf.st_uid,
				buf.st_gid
			);
			const struct _timespec64 (&mactime)[3] = { buf.st_atim, buf.st_mtim ,buf.st_ctim };
			const PCSTR mactime_string[] = { "Access", "Modify", "Change" };
			for (int j = 0; j < _countof(mactime); ++j)
			{
				char str[80];
				strftime(
					str,
					sizeof str,
					"%Y-%m-%d %T",
					gmtime(&mactime[j].tv_sec)
				);
				printf("%s: %s.%09lu +0000\n", mactime_string[j], str, mactime[j].tv_nsec);
			}
		}
	}
}