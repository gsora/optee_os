/*
 * Some of those parts (DCP initialization sequence, bit manipulation functions)
 * are inspired by https://github.com/f-secure-foundry/tamago/blob/master/imx6/dcp.go.
 */

#include <initcall.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <kernel/tee_common_otp.h>
#include <stdint.h>
#include <trace.h>
#include <mm/core_memprot.h>
#include <mm/tee_mmu.h>
#include <mm/core_mmu.h>
#include <tee/cache.h>

#include "imx_dcp.h"
#include "imx_uid.h"

#define GETVA(v) core_mmu_get_va(v, MEM_AREA_IO_SEC);

static uint8_t key[AES_BLOCK_SIZE] = {0};
static bool key_defined = false;

imx_uid d = {0};

dcp_aes_data dad = {0};

register_phys_mem_pgdir(MEM_AREA_IO_SEC, DCP_BASE, CORE_MMU_PGDIR_SIZE);

static void clear(vaddr_t v, int pos)
{
	uint32_t reg = io_read32(v);
	reg &= ~(1 << pos);
	io_write32(v, reg);
}

static void set(vaddr_t v, int pos)
{
	uint32_t reg = io_read32(v);
	reg |= (1 << pos);
	io_write32(v, reg);
}

static void setn(vaddr_t v, int pos, uint32_t mask, uint32_t val)
{
	uint32_t reg = io_read32(v);
	reg = (reg & (~(mask << pos))) | (val << pos);
	io_write32(v, reg);
}

static uint32_t get(vaddr_t v, int pos, int mask) {
	uint32_t reg = io_read32(v);
	return (reg >> pos) & mask;
}

static void wait(vaddr_t v, int pos, int mask, uint32_t val) {
	while(true) {
		uint32_t ov = get(v, pos, mask);
		if (ov == val) {
			DMSG("waiting done!");
			break;
		}
	}

	return;
}

static TEE_Result dcp_run_aes_cbc(uint8_t *plaintext, uint8_t *iv, uint8_t *dest)
{
	TEE_Result res = TEE_ERROR_SECURITY;

	dcp_work_packet *wp = malloc(1*sizeof(dcp_work_packet));
	memcpy(dad.src, plaintext, AES_BLOCK_SIZE);
	memcpy(dad.iv, iv, 8);

	wp->control0.U = 0;
	wp->control0.B.INTERRUPT = 1;
	wp->control0.B.DECR_SEMAPHORE = 1;
	wp->control0.B.ENABLE_CIPHER = 1;
	wp->control0.B.CIPHER_INIT = 1;
	wp->control0.B.CIPHER_ENCRYPT = 1;
	wp->control0.B.OTP_KEY = 1;

	wp->control1.U = 0;
	wp->control1.B.CIPHER_SELECT = AES128;
	wp->control1.B.CIPHER_MODE = CBC;
	wp->control1.B.KEY_SELECT = UNIQUE_KEY;

	wp->status = 0;

	wp->buf_size = AES_BLOCK_SIZE;

	wp->src_buf_addr = (uint32_t *)virt_to_phys(dad.src);
	cache_operation(TEE_CACHEINVALIDATE, dad.src, AES_BLOCK_SIZE);
	cache_operation(TEE_CACHEFLUSH, dad.src, AES_BLOCK_SIZE);
	
	wp->dst_buf_addr = (uint32_t *)virt_to_phys(dad.dst);
	cache_operation(TEE_CACHEFLUSH, dad.dst, AES_BLOCK_SIZE);
	cache_operation(TEE_CACHEINVALIDATE, dad.dst, AES_BLOCK_SIZE);

	wp->payload_pointer = (uint32_t *)virt_to_phys(dad.iv);
	cache_operation(TEE_CACHEFLUSH, dad.iv, 8);
	cache_operation(TEE_CACHEINVALIDATE, dad.iv, 8);
	
	vaddr_t chostatclr = GETVA(DCP_CH0STAT_CLR);
	if (!chostatclr) {
		DMSG("could not get chostatclr\n");
		return res;
	}
	io_write32(chostatclr, 0xffffffff);

	vaddr_t cmdptr = GETVA(DCP_CH0CMDPTR);
	if (!cmdptr) {
		DMSG("could not get cmdptr\n");
		return res;
	}
	
	vaddr_t ch0status = GETVA(DCP_CH0STAT);
	if (!ch0status) {
		DMSG("could not get ch0status\n");
		return res;
	}
	
	cache_operation(TEE_CACHEINVALIDATE, wp, AES_BLOCK_SIZE);
	cache_operation(TEE_CACHEFLUSH, wp, AES_BLOCK_SIZE);
	io_write32(cmdptr, virt_to_phys(wp));

	DMSG("imx_dcp.c: waiting for key derivation...\n");
	vaddr_t semaptr = GETVA(DCP_CH0SEMA);
	if (!semaptr) {
		DMSG("could not get semaptr\n");
		return res;
	}

	set(semaptr, 0);
	vaddr_t dcp_stat_v = GETVA(DCP_STAT);
	if (!dcp_stat_v) {
		DMSG("could not get dcp_stat_v!");
		return res;
	}

	// todo: might be changed to cpu_spin_lock?
	wait(dcp_stat_v, DCP_STAT_IRQ, 1, 1);
	DMSG("finished waiting");
	vaddr_t statclr = GETVA(DCP_STAT_CLR);
	if (!statclr) {
		DMSG("could not get statclr\n");
		return res;
	}

	set(statclr, 1);

	DMSG("ch0stat after: 0x%x", io_read32(ch0status));
	DMSG("work packet status: 0x%x", wp->status);
	uint32_t s = get(ch0status, 1, 0b111111);
	uint32_t code = get(ch0status, 16, 0xff);
	if (s != 0) { // some kind of error
		EMSG("DCP channel 0 error, status %#x code %#x\n", s, code);
		return res;
	}
	cache_operation(TEE_CACHEINVALIDATE, dad.dst, AES_BLOCK_SIZE);

	DMSG("derived key!");
	
	memcpy(dest, dad.dst, AES_BLOCK_SIZE);

	memset(dad.dst, 0, AES_BLOCK_SIZE);
	memset(dad.src, 0, AES_BLOCK_SIZE);
	memset(dad.iv, 0, 8);

	res = TEE_SUCCESS;
	return res;

}

static TEE_Result forge_huk(uint8_t *dest)
{
	uint8_t iv[8] = {0};
	
	// use serial components as little-endian
	uint8_t serial[AES_BLOCK_SIZE] = {0};
	serial[0] = d.cfg0 >> 24;
	serial[1] = d.cfg0 >> 16;
	serial[2] = d.cfg0 >>  8;
	serial[3] = d.cfg0;

	serial[4] = d.cfg1 >> 24;
	serial[5] = d.cfg1 >> 16;
	serial[6] = d.cfg1 >>  8;
	serial[7] = d.cfg1;

	serial[8] = d.cfg2 >> 24;
	serial[9] = d.cfg2 >> 16;
	serial[10] = d.cfg2 >>  8;
	serial[11] = d.cfg2;

	serial[12] = d.cfg3 >> 24;
	serial[13] = d.cfg3 >> 16;
	serial[14] = d.cfg3 >>  8;
	serial[15] = d.cfg3;

	return dcp_run_aes_cbc(serial, iv, dest);
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	int ret = TEE_ERROR_SECURITY;

	if (!key_defined) {
		ret = forge_huk(key);
		if (ret)
			return ret;
		key_defined = true;
	}

	memcpy(&hwkey->data, &key, sizeof(hwkey->data));
	dhex_dump("derivkey", 313, 4, &key, sizeof(hwkey->data));
	return TEE_SUCCESS;
}

static TEE_Result init_dcp(void)
{
	DMSG("init_dcp called");
	vaddr_t dcp_ctrl = GETVA(DCP_CTRL);
	DMSG("got dcp ctrl");
	if (!dcp_ctrl) return TEE_ERROR_GENERIC; // no such luck, DCP ctrl interface mapping failed
	
	vaddr_t ch_ctrl = GETVA(DCP_CHANNELCTRL);
	DMSG("got ch ctrl");
	if (!ch_ctrl) return TEE_ERROR_GENERIC;
	
	set(dcp_ctrl, DCP_CTRL_SFTRST);
	clear(dcp_ctrl, DCP_CTRL_SFTRST);
	DMSG("soft-resetted dcp 0x%x", io_read32(dcp_ctrl));

	clear(dcp_ctrl, DCP_CTRL_CLKGATE);
	DMSG("cleared clock gate");

	io_write32(ch_ctrl, 0x000100ff);
	DMSG("enabled merged irqs");

	setn(ch_ctrl, 0, 0xff, 0xff);
	DMSG("enabled all channel interrupts");

	// getting uid
	TEE_Result uid_res = imx_get_uid(&d);
	if (uid_res != TEE_SUCCESS) {
		DMSG("something went wrong reading the device uid");
	} else {
		DMSG("cfg registers:");
		DMSG("cfg0: 0x%x", d.cfg0);
		DMSG("cfg1: 0x%x", d.cfg1);
		DMSG("cfg2: 0x%x", d.cfg2);
		DMSG("cfg3: 0x%x", d.cfg3);
	}

	return TEE_SUCCESS;
}

early_init(init_dcp);

