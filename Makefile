CXX = clang-cl
CXXFLAGS += -utf-8 -std:c++latest -EHsc -GR- -W4 -Werror=gnu -Wmicrosoft -Wno-missing-field-initializers -Wpedantic

lxsstat: main.cpp lxsstat.cpp fileopen.cpp
clean:
	rm lxsstat.exe