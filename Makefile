# Makefile - KCP-over-AF_PACKET
# Production-quality build system with automatic dependency tracking.

CC      := gcc

# -------------------- 目录 --------------------
SRCDIR  := src
OBJDIR  := obj
TARGET  := kcp-afpacket

# -------------------- 源文件 --------------------
SRCS := $(SRCDIR)/main.c \
        $(SRCDIR)/af_packet.c \
        $(SRCDIR)/myproto.c \
        $(SRCDIR)/crypto.c \
        $(SRCDIR)/kcp_wrap.c \
        $(SRCDIR)/channel.c \
        $(SRCDIR)/proxy.c \
        $(SRCDIR)/ikcp.c

# -------------------- 目标文件与依赖文件 --------------------
OBJS := $(SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
DEPS := $(OBJS:.o=.d)

# -------------------- 编译选项 --------------------
INCLUDES := -I$(SRCDIR)

CFLAGS_BASE  := -Wall -Wextra -Werror -std=gnu11 -D_GNU_SOURCE $(INCLUDES)

# Release (default)
CFLAGS       := $(CFLAGS_BASE) -O2

# LDFLAGS
LDFLAGS      := -ljson-c -lrt -lnettle

# -------------------- 安装路径 --------------------
PREFIX       ?= /usr/local
INSTALL_BIN  := $(PREFIX)/bin

# -------------------- 伪目标 --------------------
.PHONY: all clean debug install test test_clean

all: $(TARGET)

# -------------------- 链接 --------------------
$(TARGET): $(OBJS)
	@echo "  LD      $@"
	$(CC) $(OBJS) $(LDFLAGS) -o $@

# -------------------- 编译（含自动依赖生成） --------------------
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(@D)
	@echo "  CC      $<"
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

# -------------------- 包含自动生成的依赖 --------------------
-include $(DEPS)

# -------------------- Debug 构建 --------------------
debug: CFLAGS := $(CFLAGS_BASE) -g -O0 -DDEBUG
debug: all

# -------------------- 清理 --------------------
clean:
	@echo "  CLEAN"
	rm -rf $(OBJDIR) $(TARGET)

# -------------------- 安装 --------------------
install: $(TARGET)
	@echo "  INSTALL $(TARGET) -> $(INSTALL_BIN)/"
	install -d $(INSTALL_BIN)
	install -m 755 $(TARGET) $(INSTALL_BIN)/

# -------------------- 帮助 --------------------
help:
	@echo "KCP-over-AF_PACKET Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all       Build release binary (default)"
	@echo "  debug     Build debug binary (-g -O0 -DDEBUG)"
	@echo "  clean     Remove build artifacts"
	@echo "  install   Install to $(INSTALL_BIN)/"
	@echo "  test      Build and run unit tests"
	@echo "  help      Show this help"
	@echo ""
	@echo "Variables:"
	@echo "  CC        C compiler          (default: gcc)"
	@echo "  PREFIX    Install prefix      (default: /usr/local)"
	@echo ""
	@echo "Example:"
	@echo "  make debug && ./kcp-afpacket config.json"

# -------------------- 测试 --------------------
TEST_CFLAGS   := -Wall -Wextra -std=gnu11 -D_GNU_SOURCE -Isrc -O0 -g

# 单元测试
TEST_MYPROTO_SRC := tests/test_myproto.c src/myproto.c src/crypto.c
TEST_MYPROTO_LIBS := -lnettle
TEST_MYPROTO_BIN := tests/test_myproto

# 集成测试
TEST_INTEG_SRC   := tests/test_integration.c src/main.c src/af_packet.c src/myproto.c src/crypto.c src/kcp_wrap.c src/channel.c src/proxy.c src/ikcp.c
TEST_INTEG_BIN   := tests/test_integration
TEST_INTEG_FLAGS := $(TEST_CFLAGS) -DTEST_BUILD -Wno-unused-function
TEST_INTEG_LIBS  := -ljson-c -lrt -lnettle

# 对比测试（与原始项目 KCP-over-AF_PACKET 的交叉验证）
TEST_COMPARE_SRC  := tests/test_comparison.c src/myproto.c src/crypto.c src/channel.c src/kcp_wrap.c src/ikcp.c src/af_packet.c src/proxy.c
TEST_COMPARE_BIN  := tests/test_comparison
TEST_COMPARE_LIBS := -lrt -lnettle

# 扩展集成测试（20个新方法）
TEST_INTEG2_SRC  := tests/test_integration_v2.c src/myproto.c src/crypto.c src/channel.c src/kcp_wrap.c src/ikcp.c
TEST_INTEG2_BIN  := tests/test_integration_v2
TEST_INTEG2_LIBS := -lrt -lnettle

# 多会话功能集成测试（20个新方法）
TEST_INTEG3_SRC  := tests/test_integration_v3.c src/myproto.c src/crypto.c src/channel.c src/kcp_wrap.c src/ikcp.c
TEST_INTEG3_BIN  := tests/test_integration_v3
TEST_INTEG3_LIBS := -lrt -lnettle

# 通道热重载 & uint32 channel_id 集成测试
TEST_INTEG4_SRC  := tests/test_integration_v4.c src/myproto.c src/crypto.c src/channel.c src/kcp_wrap.c src/ikcp.c
TEST_INTEG4_BIN  := tests/test_integration_v4
TEST_INTEG4_LIBS := -lrt -lnettle

.PHONY: test test-unit test-integ test-integ2 test-integ3 test-integ4 test-compare test-clean

test: test-unit test-integ test-integ2 test-integ3 test-integ4

test-unit: $(TEST_MYPROTO_BIN)
	@echo "  RUN     $(TEST_MYPROTO_BIN)"
	@./$(TEST_MYPROTO_BIN)

test-integ: $(TEST_INTEG_BIN)
	@echo "  RUN     $(TEST_INTEG_BIN)"
	@./$(TEST_INTEG_BIN)

test-integ2: $(TEST_INTEG2_BIN)
	@echo "  RUN     $(TEST_INTEG2_BIN)"
	@./$(TEST_INTEG2_BIN)

test-integ3: $(TEST_INTEG3_BIN)
	@echo "  RUN     $(TEST_INTEG3_BIN)"
	@./$(TEST_INTEG3_BIN)

test-integ4: $(TEST_INTEG4_BIN)
	@echo "  RUN     $(TEST_INTEG4_BIN)"
	@./$(TEST_INTEG4_BIN)

$(TEST_MYPROTO_BIN): $(TEST_MYPROTO_SRC)
	@mkdir -p tests
	@echo "  CC      $@"
	$(CC) $(TEST_CFLAGS) -o $@ $(TEST_MYPROTO_SRC) $(TEST_MYPROTO_LIBS)

$(TEST_INTEG_BIN): $(TEST_INTEG_SRC)
	@mkdir -p tests
	@echo "  CC      $@"
	$(CC) $(TEST_INTEG_FLAGS) -o $@ $(TEST_INTEG_SRC) $(TEST_INTEG_LIBS)

test-clean:
	@echo "  CLEAN   tests"
	rm -f $(TEST_MYPROTO_BIN) $(TEST_INTEG_BIN) $(TEST_COMPARE_BIN)

test-compare: $(TEST_COMPARE_BIN)
	@echo "  RUN     $(TEST_COMPARE_BIN)"
	@./$(TEST_COMPARE_BIN)

$(TEST_COMPARE_BIN): $(TEST_COMPARE_SRC)
	@mkdir -p tests
	@echo "  CC      $@"
	$(CC) $(TEST_CFLAGS) -o $@ $(TEST_COMPARE_SRC) $(TEST_COMPARE_LIBS)

$(TEST_INTEG2_BIN): $(TEST_INTEG2_SRC)
	@mkdir -p tests
	@echo "  CC      $@"
	$(CC) $(TEST_CFLAGS) -o $@ $(TEST_INTEG2_SRC) $(TEST_INTEG2_LIBS)

$(TEST_INTEG3_BIN): $(TEST_INTEG3_SRC)
	@mkdir -p tests
	@echo "  CC      $@"
	$(CC) $(TEST_CFLAGS) -o $@ $(TEST_INTEG3_SRC) $(TEST_INTEG3_LIBS)

$(TEST_INTEG4_BIN): $(TEST_INTEG4_SRC)
	@mkdir -p tests
	@echo "  CC      $@"
	$(CC) $(TEST_CFLAGS) -o $@ $(TEST_INTEG4_SRC) $(TEST_INTEG4_LIBS)
