# inspiration from 
# https://www.lucavall.in/blog/crafting-clean-maintainable-understandable-makefile-for-c-project

NAME := disco
SRC_DIR := src
BUILD_DIR := build
INCLUDE_DIR := include
TESTS_DIR := tests
BIN_DIR := bin

OBJS := $(patsubst %.c,%.o, $(wildcard $(SRC_DIR)/*.c))
TEST_OBJS := $(patsubst %.c,%.o, $(wildcard $(TESTS_DIR)/*.c))
EXC_MAIN := $(filter-out src/main.o, $(OBJS))
#$(info objs: $(OBJS))
#$(info tests: $(TEST_OBJS))
#$(info exc: $(EXC_MAIN))

CC := gcc
CFLAGS := -Wall -Wextra -pedantic

$(NAME): dir $(OBJS)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $(patsubst %,$(BUILD_DIR)/%, $(OBJS))

$(OBJS):
	@$(CC) $(CFLAGS) -o $(BUILD_DIR)/$@ -c $*.c

test: dir $(TEST_OBJS) $(EXC_MAIN)
	@$(CC) $(CFLAGS) -o $(BIN_DIR)/$(TESTS_DIR)/run_all_tests \
	$(patsubst %,$(BUILD_DIR)/%, $(EXC_MAIN)) \
	$(patsubst %,$(BUILD_DIR)/%, $(TEST_OBJS))
	@$(BIN_DIR)/$(TESTS_DIR)/run_all_tests

$(TEST_OBJS):
	@$(CC) $(CFLAGS) -o $(BUILD_DIR)/$@ -c $*.c

$(EXC_MAIN):
	@$(CC) $(CFLAGS) -o $(BUILD_DIR)/$@ -c $*.c

dir:
	@mkdir -p $(BIN_DIR) $(BIN_DIR)/$(TESTS_DIR) $(BUILD_DIR)/$(SRC_DIR) \
	$(BUILD_DIR)/$(TESTS_DIR)

clean:
	@rm -rf $(BUILD_DIR) $(BIN_DIR)

.PHONY: dir test clean
