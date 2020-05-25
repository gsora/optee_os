#include <stdlib.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <imx-regs.h>
#include "imx_uid.h"

register_phys_mem_pgdir(MEM_AREA_IO_SEC, OCOTP_BASE, CORE_MMU_PGDIR_SIZE);

TEE_Result imx_get_uid(imx_uid *d)
{
	TEE_Result res = TEE_ERROR_SECURITY;
	if (!d) return res;

	vaddr_t cfg0 = core_mmu_get_va(OCOTP_CFG0, MEM_AREA_IO_SEC);
	if (!cfg0) return res;

	vaddr_t cfg1 = core_mmu_get_va(OCOTP_CFG1, MEM_AREA_IO_SEC);
	if (!cfg1) return res;

	vaddr_t cfg2 = core_mmu_get_va(OCOTP_CFG2, MEM_AREA_IO_SEC);
	if (!cfg2) return res;

	vaddr_t cfg3 = core_mmu_get_va(OCOTP_CFG3, MEM_AREA_IO_SEC);
	if (!cfg3) return res;

	d->cfg0 = io_read32(cfg0);
	d->cfg1 = io_read32(cfg1);
	d->cfg2 = io_read32(cfg2);
	d->cfg3 = io_read32(cfg3);
	
	res = TEE_SUCCESS;
	return res;
}

