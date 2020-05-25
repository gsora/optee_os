#ifndef __IMX_UID_H__
#define __IMX_UID_H__

struct imx_uid {
	uint32_t cfg0;
	uint32_t cfg1;
	uint32_t cfg2;
	uint32_t cfg3;
};

typedef struct imx_uid imx_uid;

TEE_Result imx_get_uid(imx_uid *d);

#endif /* __IMX_UID_H__ */
