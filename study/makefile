TARGET=conversation
SRCDIR=./
SRCHDRDIR=./headers
OBJDIR=./obj
OBJHDRDIR=./obj/headers
SRCS=$(wildcard $(SRCDIR)/*.cpp) $(wildcard $(SRCHDRDIR)/*.cpp)
OBJS=$(patsubst $(SRCDIR)/%.cpp, $(OBJDIR)/%.o, $(SRCS))

CPPFLAGS=-Wall -Wextra -O2 -g
LDLIBS=-lpcap

all: $(TARGET)

$(OBJDIR):
	mkdir -p $(OBJDIR) $(OBJHDRDIR)

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp | $(OBJDIR)
	$(COMPILE.cpp) $(OUTPUT_OPTION) $<

$(TARGET): $(OBJS)
	$(LINK.cpp) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -rf $(TARGET) $(OBJDIR)