#define WIN32_LEAN_AND_MEAN
#define WIL_SUPPRESS_EXCEPTIONS
#define WIL_USE_STL 1
#define _CRT_SECURE_NO_WARNINGS
#define _CRTDBG_MAP_ALLOC
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <io.h>
#include <wil/resource.h>
#include <wil/result.h>
#include <crtdbg.h>
#include "lxsstat.hpp"

void PrintWindowsError(ULONG error = GetLastError())
{
	wil::unique_hlocal_string error_msg;
	FAIL_FAST_IF(!FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, error, 0, reinterpret_cast<PWSTR>(&error_msg), 0, nullptr));
	fputws(error_msg.get(), stderr);
}
int wmain(int argc, PWSTR argv[])
{
	FAIL_FAST_IF_WIN32_BOOL_FALSE(SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32));
	_CrtSetDbgFlag(_CrtSetDbgFlag(_CRTDBG_REPORT_FLAG) | _CRTDBG_LEAK_CHECK_DF);
	_CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDERR);
	_CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_DEBUG | _CRTDBG_MODE_FILE);
	(void)_setmode(_fileno(stdout), _O_U8TEXT);
	(void)_setmode(_fileno(stderr), _O_U8TEXT);
	if (argc <= 1)
	{
		fputws(L"lxsstat {<file>|<directory>} [...]\n", stderr);
		return EXIT_FAILURE;
	}

	for (int i = 1; i < argc; ++i)
	{
		struct Lxss::stat buf;
		if (Lxss::stat(argv[i], &buf) != 0)
		{
			ULONG error = GetLastError();
			if (error == STATUS_NO_EAS_ON_FILE)
			{
				fputws(argv[i], stderr);
				fputws(L"\nThis file is not under the control of the Windows Subsystem for Linux\n", stderr);
			}
			else
			{
				fputws(argv[i], stderr);
				fputws(L"\n", stderr);
				PrintWindowsError(error);
				_CrtDbgBreak();
			}
		}
		else
		{
			wprintf(L"  File: '%ls'", argv[i]);
			if (Lxss::S_ISLNK(buf.st_mode))
			{
				std::wstring target;
				if (Lxss::readlink(argv[i], &target) > 0)
				{
					wprintf(L"  ->  '%ls'\n", target.c_str());
				}
				else
				{
					fputws(L"  ->  ?\?\?\?\?\?\?\?\n", stderr);
					PrintWindowsError();
				}
			}
			else
			{
				_putws(L"");
			}
			wprintf(
				L"  Size: %-15llu Blocks: %-10llu IO Block: %-6u ",
				buf.st_size,
				buf.st_blocks,
				buf.st_blksize
			);
			if (Lxss::S_ISLNK(buf.st_mode))
			{
				_putws(L"symbolic link");
			}
			else if (Lxss::S_ISDIR(buf.st_mode))
			{
				_putws(L"directory");
			}
			else if (Lxss::S_ISREG(buf.st_mode))
			{
				if (buf.st_size)
				{
					_putws(L"regular file");
				}
				else
				{
					_putws(L"regular empty file");
				}
			}
			else if (Lxss::S_ISCHR(buf.st_mode))
			{
				_putws(L"character special file");
			}
			else if (Lxss::S_ISFIFO(buf.st_mode))
			{
				_putws(L"fifo");
			}
			else if (Lxss::S_ISBLK(buf.st_mode))
			{
				_putws(L"block special file");
			}
			else if (Lxss::S_ISSOCK(buf.st_mode))
			{
				_putws(L"socket");
			}
			else
			{
				_putws(L"unknown");
			}
			wprintf(
				L"                Inode: %llu  Links: %u\n",
				buf.st_ino,
				buf.st_nlink
			);
			wprintf(
				L"Access: (%04o/%hs)  Uid: (% 5u)   Gid: (% 5u)\n",
				buf.st_mode & 07777,
				Lxss::mode_tostring(buf.st_mode).data(),
				buf.st_uid,
				buf.st_gid
			);
			const timespec(&mactime)[3] = { buf.st_atim, buf.st_mtim ,buf.st_ctim };
			const PCSTR mactime_string[] = { "Access", "Modify", "Change" };
			for (size_t j = 0; j < _countof(mactime); ++j)
			{
				char str[80];
				strftime(
					str,
					sizeof str,
					"%F %T",
					gmtime(&mactime[j].tv_sec)
				);
				wprintf(L"%hs: %hs.%09lu +0000\n", mactime_string[j], str, mactime[j].tv_nsec);
			}
		}
	}
}