CFLAGS=-std=c++11  -lstdc++ -lpthread -Wall -Wextra -O0 -g3
CC=gcc
SRC_DIR=src/
DIST_DIR=dist/
DOCS_DIR=docs/
DOCS_SOURCES=$(DOCS_DIR)manual/isamon.tex $(DOCS_DIR)manual/czechiso.bst \
				$(DOCS_DIR)manual/references.bib $(DOCS_DIR)manual/Makefile $(DOCS_DIR)manual/images
BINARY_NAME=isamon
ARCHIVEFILENAME=dist/xhanze10.tar

MODULES=utils ipv4 ipv6 mac host interface arp_scanner icmp_scanner port_scanner tcp_scanner udp_scanner
OBJECT_FILE_PATTERN=$(DIST_DIR)%.o

.PHONY=run all build pack docs

all: build $(DIST_DIR)$(BINARY_NAME)
	@echo "██╗███████╗ █████╗ ███╗   ███╗ ██████╗ ███╗   ██╗"
	@echo "██║██╔════╝██╔══██╗████╗ ████║██╔═══██╗████╗  ██║"
	@echo "██║███████╗███████║██╔████╔██║██║   ██║██╔██╗ ██║"
	@echo "██║╚════██║██╔══██║██║╚██╔╝██║██║   ██║██║╚██╗██║      +-+-+ +-+-+-+-+-+-+-+-+"
	@echo "██║███████║██║  ██║██║ ╚═╝ ██║╚██████╔╝██║ ╚████║      |b|y| |x|h|a|n|z|e|1|0|"
	@echo "╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝      +-+-+ +-+-+-+-+-+-+-+-+"



documentation: $(wildcard $(SRC_DIR)*) $(DOCS_SOURCES)
	doxygen
	make -C $(DOCS_DIR)manual

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
pack: $(SRC_DIR)*.cpp $(SRC_DIR)*.h $(DOCS_SOURCES) Makefile Doxyfile
	make documentation
	mv docs/manual/manual.pdf manual.pdf
	make clean
	tar cf $(ARCHIVEFILENAME) $(SRC_DIR) $(DOCS_DIR) manual.pdf Makefile Doxyfile README.md Vagrantfile
clean:
	make -C $(DOCS_DIR)manual clean
	rm -rf ./*.o $(DIST_DIR)$(BINARY_NAME) $(DIST_DIR)*.o $(DIST_DIR)*.a $(DIST_DIR)*.so $(SRC_DIR)*.gch \
			$(ARCHIVEFILENAME) $(DOCS_DIR)doxygen \
			$(filter-out $(DOCS_SOURCES) , $(wildcard $(DOCS_DIR)manual/*))
