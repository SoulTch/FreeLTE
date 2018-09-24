ROOT := ..

include $(ROOT)/freelte/makefile

SRC_FILES := $(wildcard *.cpp)
OBJ_FILES := $(patsubst %.cpp, %.o, $(SRC_FILES))
FLT_FILES := $(wildcard $(ROOT)/freelte/*.o)

CPPFLAGS := -std=c++14
OBJFLAGS := -lpcap -lboost_system -pthread -lboost_thread

all: $(ROOT)/bin/server

clean:
	rm *.o
	rm $(ROOT)/bin/server

$(ROOT)/bin/server: $(OBJ_FILES)
	g++ $(OBJFLAGS) -o $@ $(OBJ_FILES) $(FLT_FILES)

%.o: %.cpp
	g++ $(CPPFLAGS) -I $(ROOT)/freelte -c -o $@ $<
