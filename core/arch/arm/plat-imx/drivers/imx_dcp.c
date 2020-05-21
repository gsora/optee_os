#include <initcall.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <kernel/tee_common_otp.h>
#include <stdint.h>
#include <mm/core_memprot.h>
#include <mm/tee_mmu.h>
#include <tee/cache.h>

#include "imx_dcp.h"

#define MEM_TYPE_ZEROED BIT(0) /* Buffer filled with 0's */
#define MEM_TYPE_ALIGN  BIT(1)

#define GETVA(v) core_mmu_get_va(v, MEM_AREA_IO_SEC);

static uint8_t key[KEY_SIZE];
static bool key_defined = false;

register_phys_mem_pgdir(MEM_AREA_IO_SEC, DCP_BASE, CORE_MMU_PGDIR_SIZE);

static void clear(vaddr_t v, int pos)
{
	//uint32_t reg = io_read32(v);
	//reg &= ~(1 << pos);
	io_write32(v, (io_read32(v) & ~(1 << pos)));
}

static void set(vaddr_t v, int pos)
{
	//uint32_t reg = io_read32(v);
	//reg |= ~(1 << pos);
	io_write32(v, (io_read32(v) | ~(1 << pos)));
}

/*func SetN(addr uint32, pos int, mask int, val uint32) {
	reg := (*uint32)(unsafe.Pointer(uintptr(addr)))
	*reg = (*reg & (^(uint32(mask) << pos))) | (val << pos)
}*/

static void setn(vaddr_t v, int pos, uint32_t mask, uint32_t val)
{
	//uint32_t reg = io_read32(v);
	//reg = (reg & (~(mask << pos))) | (val << pos);
	io_write32(v, (io_read32(v) & ((~(mask << pos)) | (val << pos))));
}

/*
 * func Get(addr uint32, pos int, mask int) (val uint32) {
	reg := (*uint32)(unsafe.Pointer(uintptr(addr)))
	return uint32((int(*reg) >> pos) & mask)
}
*/

static uint32_t get(vaddr_t v, int pos, int mask) {
	uint32_t reg = io_read32(v);
	return (reg >> pos) & mask;
}

/*
func Wait(addr uint32, pos int, mask int, val uint32) {
	for Get(addr, pos, mask) != val {
		// tamago is single-threaded, give other goroutines a chance
		runtime.Gosched()
	}
}*/

static void wait(vaddr_t v, int pos, int mask, uint32_t val) {
	while(get(v, pos, mask) != val) {}
}

static uint32_t read_cacheline_size(void)
{
	uint32_t value = 0;

	value = read_ctr();
	value = CTR_WORD_SIZE
		<< ((value >> CTR_DMINLINE_SHIFT) & CTR_DMINLINE_MASK);
	//MEM_TRACE("System Cache Line size = %" PRIu32 " bytes", value);

	return value;
}

/*
 * Allocate an area of given size in bytes
 *
 * @size   Size in bytes to allocate
 * @type   Type of area to allocate (refer to MEM_TYPE_*)
 */
static void *mem_alloc(size_t size, uint8_t type)
{
	void *ptr = NULL;
	size_t alloc_size = size;
	uint32_t cacheline_size = 0;

	//MEM_TRACE("alloc (normal) %zu bytes of type %" PRIu8, size, type);

	if (type & MEM_TYPE_ALIGN) {
		cacheline_size = read_cacheline_size();
		if (ADD_OVERFLOW(alloc_size,
				 ROUNDUP(alloc_size, cacheline_size),
				 &alloc_size))
			return NULL;
	}

	ptr = malloc(alloc_size);
	if (!ptr) {
		//MEM_TRACE("alloc (normal) Error - NULL");
		return NULL;
	}

	if (type & MEM_TYPE_ZEROED)
		memset(ptr, 0, alloc_size);

	//MEM_TRACE("alloc (normal) returned %p", ptr);
	return ptr;
}

/*
 * Free allocated area
 *
 * @ptr  area to free
 */
static void mem_free(void *ptr)
{
	if (ptr) {
		//MEM_TRACE("free (normal) %p", ptr);
		free(ptr);
	}
}

static TEE_Result init_dcp(void)
{
	DMSG("init_dcp called");
	// grab the CTRL interface
	vaddr_t dcp_ctrl = GETVA(DCP_CTRL);
	DMSG("got dcp ctrl");
	if (!dcp_ctrl) return TEE_ERROR_GENERIC; // no such luck, DCP ctrl interface mapping failed
	
	// grab the channel CTRL interface
	vaddr_t ch_ctrl = GETVA(DCP_CHANNELCTRL);
	DMSG("got ch ctrl");
	if (!ch_ctrl) return TEE_ERROR_GENERIC;

	/*
	 *	// soft reset DCP
	reg.Set(HW_DCP_CTRL, HW_DCP_CTRL_SFTRST)
	reg.Clear(HW_DCP_CTRL, HW_DCP_CTRL_SFTRST)

	// enable clocks
	reg.Clear(HW_DCP_CTRL, HW_DCP_CTRL_CLKGATE)

	// enable all channels with merged IRQs
	reg.Write(HW_DCP_CHANNELCTRL, 0x000100ff)

	// enable all channel interrupts
	reg.SetN(HW_DCP_CHANNELCTRL, 0, 0xff, 0xff)
	 */
	
	// soft reset DCP
	io_write32(dcp_ctrl, DCP_CTRL_SFTRST);
	clear(dcp_ctrl, DCP_CTRL_SFTRST);
	DMSG("soft-resetted dcp");

	// enable clocks
	clear(dcp_ctrl, DCP_CTRL_CLKGATE);
	DMSG("cleared clock gate");

	// enable all channels with merged IRQs
	io_write32(ch_ctrl, 0x000100ff);
	DMSG("enabled merged irqs");

	// enable all channel interrupts
	setn(ch_ctrl, 0, 0xff, 0xff);
	DMSG("enabled all channel interrupts");

	return TEE_SUCCESS;
}

driver_init(init_dcp);

static TEE_Result forge_huk(uint8_t *dest)
{
	TEE_Result res = TEE_ERROR_SECURITY;

	void *div_ptr = mem_alloc(KEY_SIZE/2 , MEM_TYPE_ALIGN | MEM_TYPE_ZEROED);
	if (!div_ptr) {
		DMSG("could not allocate div_ptr\n");
		return res;
	}

	void *iv_ptr = mem_alloc(KEY_SIZE/2 , MEM_TYPE_ALIGN | MEM_TYPE_ZEROED);
	if (!iv_ptr) {
		DMSG("could not allocate iv_ptr\n");
		goto err_iv;
	}

	dcp_work_packet *wp = (dcp_work_packet *) mem_alloc(
			sizeof(dcp_work_packet),
			MEM_TYPE_ALIGN | MEM_TYPE_ZEROED);
	if (!wp) {
		DMSG("could not allocate wp\n");
		goto err_wp;
	}

	void *dest_ptr = mem_alloc(KEY_SIZE, MEM_TYPE_ALIGN | MEM_TYPE_ZEROED);
	if (!dest_ptr) {
		DMSG("could not allocate dest_ptr\n");
		goto err_dest;
	}

	memcpy(div_ptr, diversifier, KEY_SIZE/2);
	memcpy(iv_ptr, iv, KEY_SIZE/2);

	wp->control0 |= (1 << DCP_CTRL0_INTERRUPT_ENABL);
	wp->control0 |= (1 << DCP_CTRL0_DECR_SEMAPHORE);
	wp->control0 |= (1 << DCP_CTRL0_ENABLE_CIPHER);
	wp->control0 |= (1 << DCP_CTRL0_CIPHER_ENCRYPT);
	wp->control0 |= (1 << DCP_CTRL0_CIPHER_INIT);
	// Use device-specific hardware key, payload does not contain the key.
	wp->control0 |= (1 << DCP_CTRL0_OTP_KEY);

	wp->control1 |= (AES128 << DCP_CTRL1_CIPHER_SELECT);
	wp->control1 |= (CBC << DCP_CTRL1_CIPHER_MODE);
	wp->control1 |= (UNIQUE_KEY << DCP_CTRL1_KEY_SELECT);

	wp->buf_size = KEY_SIZE/2;

	wp->src_buf_addr = virt_to_phys(div_ptr);
	cache_operation(TEE_CACHEFLUSH, div_ptr, KEY_SIZE/2);

	wp->dst_buf_addr = virt_to_phys(dest_ptr);
	cache_operation(TEE_CACHEFLUSH, dest_ptr, KEY_SIZE);

	wp->payload_pointer = virt_to_phys(iv_ptr);
	cache_operation(TEE_CACHEFLUSH, iv_ptr, KEY_SIZE);

	vaddr_t chostat = GETVA(DCP_CH0STAT_CLR);
	if (!chostat) {
		DMSG("could not get chostat\n");
		goto err_dest;
	}
	io_write32(chostat, 0xffffffff);

	vaddr_t cmdptr = GETVA(DCP_CH0CMDPTR);
	if (!cmdptr) {
		DMSG("could not get cmdptr\n");
		goto err_dest;
	}

	io_write32(cmdptr, virt_to_phys(wp));

	vaddr_t semaptr = GETVA(DCP_CH0SEMA);
	if (!semaptr) {
		DMSG("could not get semaptr\n");
		goto err_dest;
	}
	set(semaptr, 0);

	DMSG("imx_dcp.c: waiting for key derivation...\n");

	wait(DCP_STAT, DCP_STAT_IRQ, 1, 1);
	
	vaddr_t statclr = GETVA(DCP_STAT_CLR);
	if (!statclr) {
		DMSG("could not get statclr\n");
		goto err_dest;
	}

	set(statclr, 1);

	vaddr_t ch0status = GETVA(DCP_CH0STAT);
	if (!ch0status) {
		DMSG("could not get ch0status\n");
		goto err_dest;
	}

	uint32_t s = get(DCP_CH0STAT, 1, 0b111111);
	if (s != 0) { // some kind of error
		uint32_t code = get(DCP_CH0STAT, 16, 0xff);
		EMSG("DCP channel 0 error, status %#x code %#x\n", s, code);
		goto err_dest;
	}

	memcpy(dest_ptr, dest, KEY_SIZE);

	return TEE_SUCCESS;


err_dest:
	mem_free(wp);
err_wp:
	mem_free(iv_ptr);
err_iv:	
	mem_free(div_ptr);

	return res;
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	/*int ret = TEE_ERROR_SECURITY;

	if (!key_defined) {
		ret = forge_huk(key);
		if (ret)
			return ret;
		key_defined = true;
	}
	memcpy(&hwkey->data, &key, sizeof(hwkey->data));
	return TEE_SUCCESS;*/

	// TODO: actually try to derive a key

	memcpy(&hwkey->data, diversifier, sizeof(hwkey->data));
	return TEE_SUCCESS;
}
