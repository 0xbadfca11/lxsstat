#define WIN32_LEAN_AND_MEAN
#define STRICT_GS_ENABLED
#define _ATL_NO_AUTOMATIC_NAMESPACE
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <pathcch.h>
#include <atlalloc.h>
#include <atlbase.h>
#include <atlconv.h>
#include <fcntl.h>
#include <io.h>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <crtdbg.h>
#include "lxsstat.hpp"
#include "fileopen.hpp"

std::unique_ptr<WCHAR[]> GetWindowsError(ULONG error_code = GetLastError())
{
	auto msg = std::make_unique<WCHAR[]>(USHRT_MAX);
	ATLENSURE(FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, error_code, 0, msg.get(), USHRT_MAX, nullptr));
	return msg;
}
int __cdecl wmain(int argc, wchar_t* argv[])
{
	ATLENSURE(SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32));
	_CrtSetDbgFlag(_CrtSetDbgFlag(_CRTDBG_REPORT_FLAG) | _CRTDBG_LEAK_CHECK_DF);
	(void)_setmode(_fileno(stdout), _O_U8TEXT);
	(void)_setmode(_fileno(stderr), _O_U8TEXT);
	if (argc <= 1)
	{
		fputws(L"lxsstat {POSIX_PATH|Windows_PATH} [...]\n", stderr);
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
				fwprintf(stderr, L"%ls\nThis file is not under the control of the Windows Subsystem for Linux\n", windows_path.c_str());
			}
			else
			{
				fwprintf(stderr, L"%ls\n%ls", windows_path.c_str(), GetWindowsError(error).get());
				_CrtDbgBreak();
			}
		}
		else
		{
			wprintf(L"  File: '%ls'", argv[i]);
			if (Lxss::S_ISLNK(buf.st_mode))
			{
				std::wstring target;
				if (Lxss::readlink(windows_path.c_str(), &target) > 0)
				{
					wprintf(L"  ->  '%ls'\n", target.c_str());
				}
				else
				{
					wprintf(L"  ->  ?\?\?\?\?\?\?\?\n%ls", GetWindowsError().get());
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
			const PCSTR user = Lxss::UserNameFromUID(buf.st_uid);
			const PCSTR group = Lxss::GroupNameFromGID(buf.st_gid);
			wprintf(
				L"Access: (%04o/%hs)  Uid: (% 5u/% 8hs)   Gid: (% 5u/% 8hs)\n",
				buf.st_mode & 07777,
				Lxss::mode_tostring(buf.st_mode).data(),
				buf.st_uid,
				user ? user : "--------",
				buf.st_gid,
				group ? group : "--------"
			);
			const struct _timespec64(&mactime)[3] = { buf.st_atim, buf.st_mtim ,buf.st_ctim };
			const PCSTR mactime_string[] = { "Access", "Modify", "Change" };
			for (uint32_t j = 0; j < _countof(mactime); ++j)
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