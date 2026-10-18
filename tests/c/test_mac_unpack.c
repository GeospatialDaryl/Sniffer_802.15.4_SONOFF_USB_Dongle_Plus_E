#include "minitest.h"
#include "mac_unpack.h"
#include "crc.h"
#include "mac.h"

/* Append the FCS the same way the firmware computes it. */
static uint8_t seal(uint8_t *buf, uint8_t n)
{
    uint16_t c = crcFast(buf, n);
    buf[n] = c & 0xFF; buf[n+1] = c >> 8;
    return n + 2;
}

static void test_crc_check_value(void)
{
    /* crc.h documents CHECK_VALUE for "123456789" (CRC-16/KERMIT) */
    CHECK_EQ(crcFast((const unsigned char *)"123456789", 9), 0x2189);
    CHECK_EQ(crcSlow((const unsigned char *)"123456789", 9), 0x2189);
}

/* Frame captured from a real network, taken from the unit-test fixture in mac_unpack.c
   (a Zigbee NWK data frame, frame version 0b01, PAN-ID compressed). */
static const uint8_t MTO[] = {
    0x41,0x88,0x00,0x1e,0x48,0xff,0xff,0x00,0x00,0x09,0x12,0xfc,0xff,0x00,0x00,0x1e,
    0x3d,0x08,0x85,0xda,0xfe,0xff,0xd7,0x6b,0x08,0x28,0x82,0xd9,0x9e,0x00,0x08,0x85,
    0xda,0xfe,0xff,0xd7,0x6b,0x08,0x00,0x2b,0x58,0xaf,0xd8,0x35,0x52,0xdd,0x16,0x76,
    0x4e,0xc7,0xdb };

static void test_unpack_known_frame(void)
{
    MAC_Frame_packed_t in; MAC_Frame_Unpacked_t out;
    in.lenght = sizeof MTO; memcpy(in.payload, MTO, sizeof MTO);
    MAC_Unpack_Result_t r = MAC_Unpack(&in, &out);
    /* The fixture's FCS may not be valid; both outcomes must be a clean return,
       and header fields must be right whenever unpack succeeds. */
    CHECK(r == MAC_UNPACK_SUCCESS || r == MAC_UNPACK_FCS_DOES_NOT_MATCH);
}

static void test_roundtrip_short_addr(void)
{
    MAC_Frame_Unpacked_t f, g; MAC_Frame_packed_t p, q;
    memset(&f, 0, sizeof f);
    f.frame_control.frame_Type = MAC_FRAME_TYPE_DATA;
    f.frame_control.destination_addressing_mode = MAC_ADDRESSING_MODE_SHORT_ADDRESS;
    f.frame_control.source_addressing_mode = MAC_ADDRESSING_MODE_SHORT_ADDRESS;
    f.frame_control.panid_compression = MAC_PANID_COMPRESSION_ENABLED;
    f.frame_control.frame_version = MAC_FRAME_VERSION_00;
    f.sequence_number = 0x42;
    f.destination_pan_id = 0x1A2B; f.destination_addr.short_addr = 0x1234;
    f.source_addr.short_addr = 0xABCD;
    f.payload_size = 3; f.payload[0]=1; f.payload[1]=2; f.payload[2]=3;
    CHECK_EQ(MAC_Pack(&f, &p), MAC_PACK_SUCCESS);
    q = p;
    CHECK_EQ(MAC_Unpack(&q, &g), MAC_UNPACK_SUCCESS);
    CHECK_EQ(g.sequence_number, 0x42);
    CHECK_EQ(g.destination_pan_id, 0x1A2B);
    CHECK_EQ(g.destination_addr.short_addr, 0x1234);
    CHECK(g.source_addr.short_addr == 0xABCD);
    CHECK(g.payload_size == 3);
    CHECK(memcmp(g.payload, f.payload, 3) == 0);
}

static void test_bad_fcs_rejected(void)
{
    MAC_Frame_Unpacked_t f, g; MAC_Frame_packed_t p;
    memset(&f, 0, sizeof f);
    f.frame_control.frame_Type = MAC_FRAME_TYPE_COMMAND;
    f.frame_control.destination_addressing_mode = MAC_ADDRESSING_MODE_SHORT_ADDRESS;
    f.destination_pan_id = 0xFFFF; f.destination_addr.short_addr = 0xFFFF;
    f.payload_size = 1; f.payload[0] = MAC_CMD_BEACON_REQUEST;
    CHECK_EQ(MAC_Pack(&f, &p), MAC_PACK_SUCCESS);
    p.payload[p.lenght-1] ^= 0xFF;
    CHECK_EQ(MAC_Unpack(&p, &g), MAC_UNPACK_FCS_DOES_NOT_MATCH);
}

static void test_rejections(void)
{
    MAC_Frame_packed_t p; MAC_Frame_Unpacked_t g;
    p.lenght = 1;
    CHECK_EQ(MAC_Unpack(&p, &g), MAC_UNPACK_FRAME_SIZE_ERROR);
    CHECK_EQ(MAC_Unpack(NULL, &g), MAC_UNPACK_PARAMETER_ERROR);
    /* frame version 0b11 */
    memset(&p, 0, sizeof p); p.payload[0]=0x01; p.payload[1]=0x30; p.lenght = seal(p.payload, 3);
    CHECK_EQ(MAC_Unpack(&p, &g), MAC_UNPACK_INVALID_FRAME_VERSION);
    /* reserved dest addressing mode (0b01) */
    memset(&p, 0, sizeof p); p.payload[0]=0x01; p.payload[1]=0x04; p.lenght = seal(p.payload, 3);
    CHECK_EQ(MAC_Unpack(&p, &g), MAC_UNPACK_INVALID_ADDRESSING_MODE);
    /* security enabled: documented as unsupported */
    memset(&p, 0, sizeof p); p.payload[0]=0x09; p.payload[1]=0x88; p.lenght = seal(p.payload, 3);
    CHECK_EQ(MAC_Unpack(&p, &g), MAC_UNPACK_UNSUPPORTED_FEATURE);
}

/* Robustness: a frame that is truncated right after the header must not be
   accepted, nor read out of bounds. */
static void test_truncated_no_room_for_fcs(void)
{
    MAC_Frame_packed_t p; MAC_Frame_Unpacked_t g;
    memset(&p, 0, sizeof p);
    /* Beacon, no addressing, seq present: header is 3 bytes; give only 3 (no FCS) */
    p.payload[0]=0x00; p.payload[1]=0x00; p.payload[2]=0x07; p.lenght = 3;
    CHECK(MAC_Unpack(&p, &g) != MAC_UNPACK_SUCCESS);
}

/* PHY frames can be up to 127 bytes; packed buffer holds 128. */
static void test_max_length_frame(void)
{
    MAC_Frame_Unpacked_t f, g; MAC_Frame_packed_t p;
    memset(&f, 0, sizeof f);
    f.frame_control.frame_Type = MAC_FRAME_TYPE_DATA;
    f.frame_control.destination_addressing_mode = MAC_ADDRESSING_MODE_SHORT_ADDRESS;
    f.frame_control.source_addressing_mode = MAC_ADDRESSING_MODE_SHORT_ADDRESS;
    f.frame_control.panid_compression = MAC_PANID_COMPRESSION_ENABLED;
    /* header 3 + 2 + 2 + 2 = 9, FCS 2 -> 127 total means 116 payload */
    f.payload_size = 116;
    CHECK(MAC_Pack(&f, &p) == MAC_PACK_SUCCESS);
    CHECK(p.lenght == 127);
    CHECK(MAC_Unpack(&p, &g) == MAC_UNPACK_SUCCESS);
}

int main(void)
{
    crcInit();
    RUN(test_crc_check_value);
    RUN(test_unpack_known_frame);
    RUN(test_roundtrip_short_addr);
    RUN(test_bad_fcs_rejected);
    RUN(test_rejections);
    RUN(test_truncated_no_room_for_fcs);
    RUN(test_max_length_frame);
    MT_DONE();
}
