# inspiration from https://www.lucavall.in/blog/crafting-clean-maintainable-understandable-makefile-for-c-project

NAME := disco
SRC_DIR := src
BUILD_DIR := build
INCLUDE_DIR := include
TESTS_DIR := tests
BIN_DIR := bin

OBJS := $(patsubst %.c,%.o, $(wildcard $(SRC_DIR)/*.c))

CC := gcc
CFLAGS := -Wall -Wextra -pedantic

$(NAME): dir $(OBJS)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $(patsubst %, build/%, $(OBJS))


$(OBJS):
	@mkdir -p $(BUILD_DIR)/$(@D)
	@$(CC) $(CFLAGS) -o $(BUILD_DIR)/$@ -c $*.c

dir:
	@mkdir -p $(BIN_DIR) $(BUILD_DIR)

setup:
	@$(brew install cunit)

.PHONY: dir
