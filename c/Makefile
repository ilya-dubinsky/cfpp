LIBS := -lcrypto -lssl

LIB_PATH := /opt/homebrew/opt/openssl@1.1/lib
INCLUDES := /opt/homebrew/opt/openssl@1.1/include -I./src
COMPILE_FLAGS := -target arm64-apple-macos12 -std=c99 -I$(INCLUDES) -O0 -g3 -pedantic -Wall -Wextra -c -fmessage-length=0 -MMD -MP 
LINK_FLAGS := -target arm64-apple-macos12

SOURCES=$(wildcard src/*.c)
HEADERS=$(patsubst src/%.c, src/%.h, $(SOURCES))

OBJECTS=$(patsubst src/%.c, bin/%.o, $(SOURCES))

## fill this out automatically
TEST_SOURCES=$(wildcard test/*.c)
TEST_OBJECTS=$(patsubst test/%.c, bin/%.o, $(TEST_SOURCES))
TEST_TARGETS=$(patsubst test/%.c, bin/%, $(TEST_SOURCES))

all: cfpp tests

cfpp: $(OBJECTS) bin/cfpp.o
	gcc -L$(LIB_PATH) $(LIBS) $(LINK_FLAGS) -o "bin/CFPP" bin/cfpp.o $(OBJECTS) 
	@echo $(TEST_TARGETS): $(TEST_OBJECTS) $(OBJECTS)
	@echo $(TEST_OBJECTS)
	@echo $(TEST_TARGETS)
	@echo $(OBJECTS)
	
tests: $(TEST_TARGETS)

$(TEST_TARGETS): $(TEST_OBJECTS) $(OBJECTS)
	gcc -L$(LIB_PATH)  $(LINK_FLAGS) $(LIBS) -o "$@"  "$@.o" $(OBJECTS)

$(TEST_OBJECTS): $(TEST_SOURCES)

$(OBJECTS): $(SOURCES) $(HEADERS)

bin/%.o: src/%.c
	gcc $(COMPILE_FLAGS) -MF"$(@:%.o=%.d)" -MT"$@" -o "./$@" "$<"

bin/%.o: test/%.c
	gcc $(COMPILE_FLAGS) -MF"$(@:%.o=%.d)" -MT"$@" -o "./$@" "$<"


bin/%.o: %.c
	gcc $(COMPILE_FLAGS) -MF"$(@:%.o=%.d)" -MT"$@" -o "./$@" "$<"

clean: clean_cfpp 

clean_cfpp:
	rm -f bin/cfpp
	rm -f bin/*.o
	rm -f bin/*.d