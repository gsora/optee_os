#ifndef __IMX_DCP_H__
#define __IMX_DCP_H__

#include <imx-regs.h>
#include <stdint.h>

#define AES128      0x0
#define CBC         0x1
#define UNIQUE_KEY  0xfe
#define AES_BLOCK_SIZE 16

// inspired by https://github.com/RT-Thread/rt-thread/blob/7a9cdcd5c7991b9350f013d727eac9fd08c1104d/bsp/imx6sx/iMX6_Platform_SDK/sdk/include/mx6sl/registers/regsdcp.h
typedef union
{
    uint32_t  U;
    struct
    {
        unsigned INTERRUPT         :  1;
        unsigned DECR_SEMAPHORE    :  1;
        unsigned CHAIN             :  1;
        unsigned CHAIN_CONTIGUOUS  :  1;
        unsigned ENABLE_MEMCOPY    :  1;
        unsigned ENABLE_CIPHER     :  1;
        unsigned ENABLE_HASH       :  1;
        unsigned ENABLE_BLIT       :  1;
        unsigned CIPHER_ENCRYPT    :  1;
        unsigned CIPHER_INIT       :  1;
        unsigned OTP_KEY           :  1;
        unsigned PAYLOAD_KEY       :  1;
        unsigned HASH_INIT         :  1;
        unsigned HASH_TERM         :  1;
        unsigned CHECK_HASH        :  1;
        unsigned HASH_OUTPUT       :  1;
        unsigned CONSTANT_FILL     :  1;
        unsigned TEST_SEMA_IRQ     :  1;
        unsigned KEY_BYTESWAP      :  1;
        unsigned KEY_WORDSWAP      :  1;
        unsigned INPUT_BYTESWAP    :  1;
        unsigned INPUT_WORDSWAP    :  1;
        unsigned OUTPUT_BYTESWAP   :  1;
        unsigned OUTPUT_WORDSWAP   :  1;
        unsigned TAG               :  8;
    } B;
} hw_dcp_packet1_t;

typedef union
{
    uint32_t  U;
    struct
    {
        unsigned CIPHER_SELECT  :  4;
        unsigned CIPHER_MODE    :  4;
        unsigned KEY_SELECT     :  8;
        unsigned HASH_SELECT    :  4;
        unsigned RSVD           :  4;
        unsigned CIPHER_CFG     :  8;
    } B;
} hw_dcp_packet2_t;

struct dcp_work_packet {
	uint32_t *next_cmd_addr;
	hw_dcp_packet1_t control0;
	hw_dcp_packet2_t control1;
	uint32_t *src_buf_addr;
	uint32_t *dst_buf_addr;
	uint32_t buf_size;
	uint32_t *payload_pointer;
	uint32_t status;
};
typedef struct dcp_work_packet dcp_work_packet;

struct dcp_aes_data {
	uint8_t src[16];
	uint8_t dst[16];
	uint8_t iv[8];
};

typedef struct dcp_aes_data dcp_aes_data;
#endif /* __IMX_DCP_H__ */
