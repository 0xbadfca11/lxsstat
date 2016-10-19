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
#include "fileopen.hpp"

ATL::CHeapPtr<WCHAR> GetWindowsError(ULONG error_code = GetLastError())
{
	ATL::CHeapPtr<WCHAR> msg;
	ATLENSURE(msg.Allocate(USHRT_MAX));
	ATLENSURE(FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM, nullptr, error_code, 0, msg, USHRT_MAX, nullptr));
	return msg;
}
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
				fprintf(stderr, "%ls\nThis file is not under the control of the Ubuntu on Windows\n", windows_path.c_str());
			}
			else
			{
				fprintf(stderr, "%ls\n%ls", windows_path.c_str(), (PCWSTR)GetWindowsError(error));
			}
		}
		else
		{
			printf("  File: '%ls'", argv[i]);
			if (Lxss::S_ISLNK(buf.st_mode))
			{
				static_assert(PATHCCH_MAX_CCH <= ULONG_MAX, "");
				if (buf.st_size <= PATHCCH_MAX_CCH)
				{
					ATL::CTempBuffer<BYTE> buffer(buf.st_size);
					ULONG read_size;
					ATL::CHandle h(OpenFileCaseSensitive(windows_path.c_str()));
					if (h && ReadFile(h, buffer, (ULONG)buf.st_size, &read_size, nullptr))
					{
						printf("  ->  '%.*s'\n", read_size, (PBYTE)buffer);
					}
					else
					{
						printf("  ->  ?\?\?\?\?\?\?\?\n%ls", (PCWSTR)GetWindowsError());
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
			else if (Lxss::S_ISCHR(buf.st_mode))
			{
				puts("character special file");
			}
			else if (Lxss::S_ISFIFO(buf.st_mode))
			{
				puts("fifo");
			}
			else
			{
				puts("unknown");
			}
			printf(
				!Lxss::S_ISCHR(buf.st_mode)
				? "Device: %xh/%ud   Inode: %llu  Links: %u\n"
				: "Device: %xh/%ud   Inode: %llu  Links: %-5u Device type: %x,%x\n",
				buf.st_dev,
				buf.st_dev,
				buf.st_ino,
				buf.st_nlink,
				HIBYTE(buf.st_rdev),
				LOBYTE(buf.st_rdev)
			);
			printf(
				"Access: (%04o/%s)  Uid: (% 5u/% 8s)   Gid: (% 5u/% 8s)\n",
				buf.st_mode & 07777,
				Lxss::mode_tostring(buf.st_mode).data(),
				buf.st_uid,
				Lxss::UserNameFromUID(buf.st_uid),
				buf.st_gid,
				Lxss::GroupNameFromGID(buf.st_gid)
			);
			const struct _timespec64(&mactime)[3] = { buf.st_atim, buf.st_mtim ,buf.st_ctim };
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