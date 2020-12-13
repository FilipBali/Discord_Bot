# Compiler
CC = g++
# Compiler flags
CFLAGS  = -pedantic -Wall -Werror
# OpenSSL libraries
CLIBS = -lssl -lcrypto
# Name of target
TARGET = isabot

all: $(TARGET)
$(TARGET): $(TARGET).cpp
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).cpp $(CLIBS)

# Arguments test
test:
	make
	./isabot -h > Param.txt
	@if diff "Param.txt" "ParamTest1.txt" >/dev/null; then\
    echo "ParamTest1 Passed $x";\
	else\
    echo "ParamTest1 Failed $x";\
	fi
	$(RM) Param.txt

# Delete
clean:
	$(RM) $(TARGET)