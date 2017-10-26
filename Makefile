CFLAGS=-std=c++11  -lstdc++ -lpthread -Wall -Wextra -O0 -g
CC=gcc
SRC_DIR=src/
DIST_DIR=dist/
DOCS_DIR=dist/
BINARY_NAME=isamon
ZIPFILENAME=dist/isamon

MODULES=utils ipv4 ipv6 mac host interface arp_scanner icmp_scanner port_scanner tcp_scanner udp_scanner
OBJECT_FILE_PATTERN=$(DIST_DIR)%.o

.PHONY=run all build

all: build $(DIST_DIR)$(BINARY_NAME)
	@echo "██╗███████╗ █████╗ ███╗   ███╗ ██████╗ ███╗   ██╗"
	@echo "██║██╔════╝██╔══██╗████╗ ████║██╔═══██╗████╗  ██║"
	@echo "██║███████╗███████║██╔████╔██║██║   ██║██╔██╗ ██║"
	@echo "██║╚════██║██╔══██║██║╚██╔╝██║██║   ██║██║╚██╗██║      +-+-+ +-+-+-+-+-+-+-+-+"
	@echo "██║███████║██║  ██║██║ ╚═╝ ██║╚██████╔╝██║ ╚████║      |b|y| |x|h|a|n|z|e|1|0|"
	@echo "╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝      +-+-+ +-+-+-+-+-+-+-+-+"



docs: $(wildcard $(SRC_DIR)*)
	doxygen

stats:
	@echo -n "Lines of code: " && wc -l $(wildcard $(SRC_DIR)*.cpp $(SRC_DIR)*.h) | tail -n 1 | sed -r "s/[ ]*([0-9]+).*/\1/g"
	@echo -n "Size of code: " && du -hsc $(wildcard $(SRC_DIR)*.cpp $(SRC_DIR)*.h) | tail -n 1 | cut -f 1


# Link all the modules together
build: $(DIST_DIR)$(BINARY_NAME)

# Build binary
$(DIST_DIR)$(BINARY_NAME): $(SRC_DIR)main.cpp $(patsubst %,$(OBJECT_FILE_PATTERN), $(MODULES))
	$(CC) $(CFLAGS) \
		$(SRC_DIR)main.cpp $(patsubst %,$(OBJECT_FILE_PATTERN), $(MODULES)) \
	-o $(DIST_DIR)$(BINARY_NAME)

# Make modules independently
$(OBJECT_FILE_PATTERN): $(SRC_DIR)%.cpp $(SRC_DIR)%.h
	$(CC) $(CFLAGS) -c $(SRC_DIR)$*.cpp -o $(DIST_DIR)$*.o

run: build
	exec $(DIST_DIR)$(BINARY_NAME)
zip: $(SRC_DIR)*.c $(SRC_DIR)*.h Makefile Doxyfile
	zip $(ZIPFILENAME).zip $(SRC_DIR) Makefile Doxyfile
clean:
	rm -f $(DIST_DIR)$(BINARY_NAME) $(DIST_DIR)*.o $(DIST_DIR)*.a $(DIST_DIR)*.so $(SRC_DIR)*.gch $(ZIPFILENAME).zip $(DOCS_DIR)html ./*.o
