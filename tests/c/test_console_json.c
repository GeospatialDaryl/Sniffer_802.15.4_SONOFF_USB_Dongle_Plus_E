#include "minitest.h"
#include "console.h"
#include "phy.h"

/* ---- stubs for HAL ---- */
static char tx[1024]; static int txn;
static uint8_t last_channel; static int channel_calls;
void _putchar(char c) { (void)c; }
void HAL_Console_Init(void) {}
void HAL_Console_Tx_Byte(uint8_t b) { if (txn < (int)sizeof tx - 1) tx[txn++] = (char)b; }
void HAL_SetRadioChannel(uint8_t c) { last_channel = c; channel_calls++; }
void BSP_RebootInBootloader(void) {}
bool Mac_RxMsgCallbackPreprocessPhyRx(PhyRx_t *p) { (void)p; return true; }

static void clear(void) { memset(tx, 0, sizeof tx); txn = 0; }

static void emit(uint8_t len, uint8_t lqi, int8_t rssi, uint8_t ch, const uint8_t *data)
{
    PhyRx_t p; memset(&p, 0, sizeof p);
    p.len = len; p.lqi = lqi; p.rssi = rssi; p.channel = ch;
    memcpy(p.payload, data, len);
    clear(); Console_PhyToJSONV2(&p);
}

static void feed(const char *s) { while (*s) Console_RxByte((uint8_t)*s++); Console_Process_Rx(); }

static void test_json_example_from_header(void)
{
    const uint8_t d[] = {0x41,0x88,0xA3};
    emit(3, 255, -94, 15, d);
    CHECK_STR(tx, "{\"L\":3,\"Q\":255,\"R\":-94,\"C\":15,\"S\":\"4188A3\"}\n\r");
}

static void test_json_rssi_extremes(void)
{
    const uint8_t d[] = {0};
    /* radios commonly report down to about -100 dBm */
    emit(1, 10, -100, 11, d);
    CHECK(strstr(tx, "\"R\":-100,") != NULL);
    emit(1, 10, -128, 11, d);
    CHECK(strstr(tx, "\"R\":-128,") != NULL);
    emit(1, 10, 0, 11, d);
    CHECK(strstr(tx, "\"R\":0,") != NULL);
}

static void test_json_len_boundaries(void)
{
    uint8_t d[127]; for (int i = 0; i < 127; i++) d[i] = (uint8_t)i;
    emit(127, 1, -50, 26, d);
    CHECK(strstr(tx, "\"L\":127,") != NULL);
    CHECK_EQ((int)strlen(strstr(tx, "\"S\":\"")) , 5 + 254 + 4);   /* "S":" + hex + "}\n\r + quote */
    CHECK(tx[txn-1] == '\r' && tx[txn-2] == '\n');
}

static void test_json_lqi_255(void)
{
    const uint8_t d[] = {0xAB};
    emit(1, 255, -1, 11, d);
    CHECK(strstr(tx, "\"Q\":255,") != NULL);
}

static void test_rx_channel_command(void)
{
    channel_calls = 0;
    feed("{\"C\":11}\r");  CHECK_EQ(channel_calls, 1); CHECK_EQ(last_channel, 11);
    feed("{\"C\":26}\r");  CHECK_EQ(last_channel, 26);
}

static void test_rx_channel_out_of_range_ignored(void)
{
    channel_calls = 0;
    feed("{\"C\":10}\r"); feed("{\"C\":27}\r"); feed("{\"C\":0}\r");
    CHECK_EQ(channel_calls, 0);
}

static void test_rx_garbage_then_valid(void)
{
    channel_calls = 0;
    feed("xx\r\n garbage ");
    feed("{\"C\":20}\r");
    CHECK_EQ(channel_calls, 1); CHECK_EQ(last_channel, 20);
}

static void test_rx_oversize_dropped_then_recovers(void)
{
    channel_calls = 0;
    feed("{\"C\":11,\"padding\":\"aaaaaaaaaaaaaaaaaaaaaaaa\"}\r");
    feed("{\"C\":15}\r");
    CHECK_EQ(last_channel, 15);
}

int main(void)
{
    Console_Init();
    RUN(test_json_example_from_header);
    RUN(test_json_rssi_extremes);
    RUN(test_json_len_boundaries);
    RUN(test_json_lqi_255);
    RUN(test_rx_channel_command);
    RUN(test_rx_channel_out_of_range_ignored);
    RUN(test_rx_garbage_then_valid);
    RUN(test_rx_oversize_dropped_then_recovers);
    MT_DONE();
}
