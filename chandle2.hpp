#pragma once
namespace ATL
{
	struct CHandle2 : CHandle
	{
		CHandle2() = default;
		CHandle2(const CHandle2&) = delete;
		CHandle2(CHandle2&& h) noexcept
		{
			Attach(h.Detach());
		}
		CHandle2(const CHandle&) = delete;
		CHandle2(HANDLE h) noexcept
		{
			Attach(h);
		}
		CHandle2& operator=(const CHandle2&) = delete;
		CHandle2& operator=(CHandle2&& h) noexcept
		{
			Attach(h.Detach());
			return *this;
		}
		CHandle2& operator=(const CHandle&) = delete;
		CHandle2& operator=(HANDLE h) noexcept
		{
			Attach(h);
			return *this;
		}
		~CHandle2() = default;
		void Attach(HANDLE h) noexcept
		{
			Close();
			if (h != INVALID_HANDLE_VALUE)
			{
				CHandle::Attach(h);
			}
		}
	};
}