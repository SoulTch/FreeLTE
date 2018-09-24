SRC_FILES := $(wildcard *.cpp)
OBJ_FILES := $(patsubst %.cpp, %.o, $(SRC_FILES))

CPPFLAGS := -std=c++14

all: $(OBJ_FILES)

%.o: %.cpp
	g++ $(CPPFLAGS) -c -o $@ $<
