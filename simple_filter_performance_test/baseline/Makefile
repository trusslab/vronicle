Secrurity_Link_Flags := -Wno-attributes -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -pie
# CFlags := -O2 -D_FORTIFY_SOURCE=2 -fpic -fpie -fstack-protector -Wformat -Wformat-security -std=c++11 $(Secrurity_Link_Flags)
CFlags := -O3 # -D_FORTIFY_SOURCE=2 # -fpic -fpie -fstack-protector -Wformat -Wformat-security -std=c++11 $(Secrurity_Link_Flags)

all:
	g++ test.cpp $(CFlags)

clean:
	rm a.out