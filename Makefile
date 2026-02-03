NAME := disco
SRC_DIR := src
BUILD_DIR := build
INCLUDE_DIR := include
TESTS_DIR := tests
BIN_DIR := bin

OBJS := $(notdir $(patsubst %.c,%.o, $(wildcard $(SRC_DIR)/*.c)))
TEST_OBJS := $(notdir $(patsubst %.c,%.o, $(wildcard $(TESTS_DIR)/*.c)))

CC := gcc
CFLAGS := -Wall -Wextra -pedantic -Werror
CFLAGSTEST := -Wall -Wextra -pedantic -Werror -fsanitize=address -g
LDFLAGS := -lpcap -lpthread

$(NAME): dir $(OBJS)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $(patsubst %,$(BUILD_DIR)/%, $(OBJS)) $(LDFLAGS)

$(OBJS):
	@$(CC) $(CFLAGS) -o $(BUILD_DIR)/$@ -c $(SRC_DIR)/$*.c

test: dir $(TEST_OBJS) $(OBJS)
	@$(CC) $(CFLAGSTEST) -o $(TESTS_DIR)/$(BIN_DIR)/run_all_tests \
	$(patsubst %,$(BUILD_DIR)/%, $(filter-out main.o, $(OBJS))) \
	$(patsubst %,$(TESTS_DIR)/$(BUILD_DIR)/%, $(TEST_OBJS)) $(LDFLAGS)
	@sudo $(TESTS_DIR)/$(BIN_DIR)/run_all_tests
	@echo "-- SEPARATE LEAK TESTS --"
	@$(MAKE) leaks
	
$(TEST_OBJS):
	@$(CC) $(CFLAGSTEST) -o $(TESTS_DIR)/$(BUILD_DIR)/$@ -c $(TESTS_DIR)/$*.c

leaks: CFLAGS := $(CFLAGSTEST)
leaks: clean dir $(NAME)
	@sudo chmod +x $(TESTS_DIR)/leaks.sh
	@sudo $(TESTS_DIR)/leaks.sh
	@$(MAKE) clean

dir:
	@mkdir -p $(BIN_DIR) $(BUILD_DIR) $(TESTS_DIR)/$(BIN_DIR) \
	$(TESTS_DIR)/$(BUILD_DIR)

clean:
	@rm -rf $(BUILD_DIR) $(BIN_DIR) $(TESTS_DIR)/$(BIN_DIR) \
	$(TESTS_DIR)/$(BUILD_DIR)

.PHONY: dir test clean leaks
