#ifndef __IMX_DCP_H__
#define __IMX_DCP_H__

#include <imx-regs.h>
#include <stdint.h>

#define DCP_CTRL0_OTP_KEY          10
#define DCP_CTRL0_CIPHER_INIT      9
#define DCP_CTRL0_CIPHER_ENCRYPT   8
#define DCP_CTRL0_ENABLE_CIPHER    5
#define DCP_CTRL0_DECR_SEMAPHORE   1
#define DCP_CTRL0_INTERRUPT_ENABL  0
#define DCP_CTRL1_KEY_SELECT     8
#define DCP_CTRL1_CIPHER_MODE    4
#define DCP_CTRL1_CIPHER_SELECT  0
#define AES128      0x0
#define CBC         0x1
#define UNIQUE_KEY  0xfe
#define KEY_SIZE 32

/*
 *	NextCmdAddr              uint32
	Control0                 uint32
	Control1                 uint32
	SourceBufferAddress      uint32
	DestinationBufferAddress uint32
	BufferSize               uint32
	PayloadPointer           uint32
	Status                   uint32
	Pad_cgo_0                [4]byte
 */

char diversifier[] = {
	0x21, 0x74, 0x68, 0x69, 
	0x73, 0x20, 0x69, 0x73, 
	0x20, 0x73, 0x65, 0x63, 
	0x75, 0x72, 0x65, 0x21 
};

char iv[] = { 
	0x71, 0x1, 0xE4, 0x83, 
	0x3D, 0x2, 0x20, 0xE2, 
	0xE8, 0x99, 0x9D, 0xE3, 
	0xB3, 0x9B, 0x9F, 0x82 
};

struct dcp_work_packet {
	uint32_t next_cmd_addr;
	uint32_t control0;
	uint32_t control1;
	uint32_t src_buf_addr;
	uint32_t dst_buf_addr;
	uint32_t buf_size;
	uint32_t payload_pointer;
	uint32_t status;
	uint8_t	padding[4];
} __packed;
typedef struct dcp_work_packet dcp_work_packet;

#endif /* __IMX_DCP_H__ */
