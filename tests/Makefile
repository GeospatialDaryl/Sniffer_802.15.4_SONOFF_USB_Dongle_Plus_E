# Host-side tests. Run from this directory: `make test`
SRC := ../Sources
SSC := $(SRC)/SnifferSharedComponents
CFLAGS := -std=gnu11 -Wall -Wextra -Wno-unused-parameter -Wno-int-to-pointer-cast -g -fsanitize=address,undefined -fno-sanitize-recover=undefined \
  -Istubs -Ic -I$(SSC)/802.15.4 -I$(SSC)/Console -I$(SSC)/crc -I$(SSC)/json_parser
BUILD := build

.PHONY: test test-c test-py clean
test: test-c test-py

test-c: $(BUILD)/test_mac_unpack $(BUILD)/test_console_json
	$(BUILD)/test_mac_unpack
	$(BUILD)/test_console_json

$(BUILD)/test_mac_unpack: c/test_mac_unpack.c $(SSC)/802.15.4/mac_unpack.c $(SSC)/crc/crc.c c/minitest.h | $(BUILD)
	$(CC) $(CFLAGS) -o $@ c/test_mac_unpack.c $(SSC)/802.15.4/mac_unpack.c $(SSC)/crc/crc.c

$(BUILD)/test_console_json: c/test_console_json.c $(SSC)/Console/console.c $(SSC)/Console/printf.c c/minitest.h | $(BUILD)
	$(CC) $(CFLAGS) -o $@ c/test_console_json.c $(SSC)/Console/console.c $(SSC)/Console/printf.c

$(BUILD):
	mkdir -p $@

test-py:
	python3 -I -m unittest discover -s py -v

clean:
	rm -rf $(BUILD)
