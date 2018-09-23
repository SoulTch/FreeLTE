ROOT := ..

include $(ROOT)/freelte

SRC_FILES := $(wildcard *.cpp)
OBJ_FILES := $(patsubst %.cpp, %.o, $(SRC_FILES))
FLT_FILES := $(wildcard $(ROOT)/freelte/*.o)

CPPFLAGS := -std=c++14
OBJFLAGS := -lpcap -lthread

all: $(ROOT)/bin/server

$(ROOT)/bin/server: OBJ_FILES
    g++ $(OBJFLAGS) -o $@ $< $(FLT_FILES)

%.o: %.cpp
   g++ $(CPPFLAGS) -c -o $@ $<