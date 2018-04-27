/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (C) 2012
 * Ben Gray <bgray@freebsd.org>.
 * Copyright (C) 2018 The FreeBSD Foundation
 * This software was developed by Arshan Khanifar <arshankhanifar@gmail.com>
 * under sponsorship from the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in the
 *	  documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.	IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

/*
 * Microchip LAN78XX devices (http://www.microchip.com/)
 * 
 * The LAN78XX devices are stand-alone USB to Ethernet chips that
 * support USB 3.1 and 10/100/1000 Mbps Ethernet.
 *
 * This driver is closely modelled on the Linux driver written and copyrighted
 * by Microchip.
 *
 *
 * REMAINING FEATURES
 * ------------------
 * There are a bunch of features that the chip supports but have not been implemented
 * in this driver yet. This will serve as a TODO list for the author and other 
 * contributors to consider.
 * 1. RX/TX checksum offloading: nothing has been implemented yet for TX checksumming, 
 * RX checksumming works with ICMP messages, but its broken for TCP/UDP packets.
 * 2. Direct address translation filtering: implemented but not tested yet. 
 * 3. VLAN tag removal: not implemented yet.
 * 4. Reading MAC address from the device tree: this is specific to Raspberry PI.
 * 5. Support for USB interrupt endpoints.
 * 6. Latency Tolerance Messaging (LTM) support.
 * 7. TCP LSO support.
 *
 */

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/callout.h>
#include <sys/condvar.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/priv.h>
#include <sys/queue.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stddef.h>
#include <sys/stdint.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/unistd.h>

#include <net/if.h>
#include <net/if_var.h>

#include <netinet/in.h>
#include <netinet/ip.h>

#include "opt_platform.h"

/* For reading the mac address from device tree.*/
#ifdef FDT
#include <dev/fdt/fdt_common.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#endif

#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>
#include <dev/usb/usbdi_util.h>
#include "usbdevs.h"

#define USB_DEBUG lan78xx_debug
#include <dev/usb/usb_debug.h>
#include <dev/usb/usb_process.h>

#include <dev/usb/net/usb_ethernet.h>

#include <dev/usb/net/if_lan78xxreg.h>

#ifdef USB_DEBUG
static int lan78xx_debug = 0;

SYSCTL_NODE(_hw_usb, OID_AUTO, lan78xx, CTLFLAG_RW, 0, "USB lan78xx");
SYSCTL_INT(_hw_usb_lan78xx, OID_AUTO, debug, CTLFLAG_RWTUN, &lan78xx_debug, 0,
	"Debug level");
#endif

#define LAN78XX_DEFAULT_RX_CSUM_ENABLE (false)
#define LAN78XX_DEFAULT_TX_CSUM_ENABLE (false)
#define LAN78XX_DEFAULT_TSO_CSUM_ENABLE (false)

/*
 * Various supported device vendors/products.
 */
static const struct usb_device_id lan78xx_devs[] = {
#define LAN78XX_DEV(p,i) { USB_VPI(USB_VENDOR_SMC2, USB_PRODUCT_SMC2_##p, i) }
	LAN78XX_DEV(LAN7800, 0),
#undef LAN78XX_DEV
};

#ifdef USB_DEBUG
#define lan78xx_dbg_printf(sc, fmt, args...) \
	do { \
		if (lan78xx_debug > 0) \
			device_printf((sc)->sc_ue.ue_dev, "debug: " fmt, ##args); \
	} while(0)
#else
#define lan78xx_dbg_printf(sc, fmt, args...) do { } while (0)
#endif

#define lan78xx_warn_printf(sc, fmt, args...) \
	device_printf((sc)->sc_ue.ue_dev, "warning: " fmt, ##args)

#define lan78xx_err_printf(sc, fmt, args...) \
	device_printf((sc)->sc_ue.ue_dev, "error: " fmt, ##args)

#define ETHER_IS_ZERO(addr) \
	(!(addr[0] | addr[1] | addr[2] | addr[3] | addr[4] | addr[5]))
	
#define ETHER_IS_VALID(addr) \
	(!ETHER_IS_MULTICAST(addr) && !ETHER_IS_ZERO(addr))

/* USB endpoints. */

enum {
	LAN78XX_BULK_DT_RD,
	LAN78XX_BULK_DT_WR,
	/* the LAN78XX device does support interrupt endpoints,
	 * but they're not needed as we poll on MII status.
	 * LAN78XX_INTR_DT_WR,
	 * LAN78XX_INTR_DT_RD,
	 */
	LAN78XX_N_TRANSFER,
};

struct lan78xx_softc {
	struct usb_ether  sc_ue;
	struct mtx		  sc_mtx;
	struct usb_xfer  *sc_xfer[LAN78XX_N_TRANSFER];
	int				  sc_phyno;

	/* The following stores the settings in the mac control (MAC_CSR) register */
	uint32_t		  sc_rfe_ctl;
	uint32_t		  sc_mdix_ctl;
	uint32_t		  sc_rev_id;
	uint32_t		  sc_mchash_table[LAN78XX_DP_SEL_VHF_HASH_LEN];
	uint32_t		  sc_pfilter_table[LAN78XX_NUM_PFILTER_ADDRS_][2];

	uint32_t		  sc_flags;
#define LAN78XX_FLAG_LINK	0x0001
};

#define LAN78XX_IFACE_IDX		0

#define LAN78XX_LOCK(_sc)				mtx_lock(&(_sc)->sc_mtx)
#define LAN78XX_UNLOCK(_sc)				mtx_unlock(&(_sc)->sc_mtx)
#define LAN78XX_LOCK_ASSERT(_sc, t)		mtx_assert(&(_sc)->sc_mtx, t)


static device_probe_t lan78xx_probe;
static device_attach_t lan78xx_attach;
static device_detach_t lan78xx_detach;

static usb_callback_t lan78xx_bulk_read_callback;
static usb_callback_t lan78xx_bulk_write_callback;

static miibus_readreg_t lan78xx_miibus_readreg;
static miibus_writereg_t lan78xx_miibus_writereg;
static miibus_statchg_t lan78xx_miibus_statchg;

#if __FreeBSD_version > 1000000
static int lan78xx_attach_post_sub(struct usb_ether *ue);
#endif

static uether_fn_t lan78xx_attach_post;
static uether_fn_t lan78xx_init;
static uether_fn_t lan78xx_stop;
static uether_fn_t lan78xx_start;
static uether_fn_t lan78xx_tick;
static uether_fn_t lan78xx_setmulti;
static uether_fn_t lan78xx_setpromisc;

static int	lan78xx_ifmedia_upd(struct ifnet *);
static void lan78xx_ifmedia_sts(struct ifnet *, struct ifmediareq *);

static int lan78xx_chip_init(struct lan78xx_softc *sc);
static int lan78xx_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data);

static const struct usb_config lan78xx_config[LAN78XX_N_TRANSFER] = {

	[LAN78XX_BULK_DT_WR] = {
		.type = UE_BULK,
		.endpoint = UE_ADDR_ANY,
		.direction = UE_DIR_OUT,
		.frames = 16,
		.bufsize = 16 * (MCLBYTES + 16),
		.flags = {.pipe_bof = 1,.force_short_xfer = 1,},
		.callback = lan78xx_bulk_write_callback,
		.timeout = 10000,	/* 10 seconds */
	},

	[LAN78XX_BULK_DT_RD] = {
		.type = UE_BULK,
		.endpoint = UE_ADDR_ANY,
		.direction = UE_DIR_IN,
		.bufsize = 20480,	/* bytes */
		.flags = {.pipe_bof = 1,.short_xfer_ok = 1,},
		.callback = lan78xx_bulk_read_callback,
		.timeout = 0,	/* no timeout */
	},
	/* The LAN78XX chip supports interrupt endpoints, however they aren't
	 * needed as we poll on the MII status.
	 */
};

static const struct usb_ether_methods lan78xx_ue_methods = {
	.ue_attach_post = lan78xx_attach_post,
#if __FreeBSD_version > 1000000
	.ue_attach_post_sub = lan78xx_attach_post_sub,
#endif
	.ue_start = lan78xx_start,
	.ue_ioctl = lan78xx_ioctl,
	.ue_init = lan78xx_init,
	.ue_stop = lan78xx_stop,
	.ue_tick = lan78xx_tick,
	.ue_setmulti = lan78xx_setmulti,
	.ue_setpromisc = lan78xx_setpromisc,
	.ue_mii_upd = lan78xx_ifmedia_upd,
	.ue_mii_sts = lan78xx_ifmedia_sts,
};

/**
 *	lan78xx_read_reg - Reads a 32-bit register on the device
 *	@sc: driver soft context
 *	@off: offset of the register
 *	@data: pointer a value that will be populated with the register value
 *	
 *	LOCKING:
 *	The device lock must be held before calling this function.
 *
 *	RETURNS:
 *	0 on success, a USB_ERR_?? error code on failure.
 */

static int
lan78xx_read_reg(struct lan78xx_softc *sc, uint32_t off, uint32_t *data)
{
	struct usb_device_request req;
	uint32_t buf;
	usb_error_t err;

	LAN78XX_LOCK_ASSERT(sc, MA_OWNED);

	req.bmRequestType = UT_READ_VENDOR_DEVICE;
	req.bRequest = LAN78XX_UR_READ_REG;
	USETW(req.wValue, 0);
	USETW(req.wIndex, off);
	USETW(req.wLength, 4);

	err = uether_do_request(&sc->sc_ue, &req, &buf, 1000);
	if (err != 0)
		lan78xx_warn_printf(sc, "Failed to read register 0x%0x\n", off);

	*data = le32toh(buf);
	
	return (err);
}

/**
 *	lan78xx_write_reg - Writes a 32-bit register on the device
 *	@sc: driver soft context
 *	@off: offset of the register
 *	@data: the 32-bit value to write into the register
 *	
 *	LOCKING:
 *	The device lock must be held before calling this function.
 *
 *	RETURNS:
 *	0 on success, a USB_ERR_?? error code on failure.
 */
static int
lan78xx_write_reg(struct lan78xx_softc *sc, uint32_t off, uint32_t data)
{
	struct usb_device_request req;
	uint32_t buf;
	usb_error_t err;

	LAN78XX_LOCK_ASSERT(sc, MA_OWNED);
	
	buf = htole32(data);

	req.bmRequestType = UT_WRITE_VENDOR_DEVICE;
	req.bRequest = LAN78XX_UR_WRITE_REG;
	USETW(req.wValue, 0);
	USETW(req.wIndex, off);
	USETW(req.wLength, 4);

	err = uether_do_request(&sc->sc_ue, &req, &buf, 1000);
	if (err != 0)
		lan78xx_warn_printf(sc, "Failed to write register 0x%0x\n", off);

	return (err);
}

/**
 *	lan78xx_wait_for_bits - Polls on a register value until bits are cleared
 *	@sc: soft context
 *	@reg: offset of the register
 *	@bits: if the bits are clear the function returns
 *
 *	LOCKING:
 *	The device lock must be held before calling this function.
 *
 *	RETURNS:
 *	0 on success, or a USB_ERR_?? error code on failure.
 */
static int
lan78xx_wait_for_bits(struct lan78xx_softc *sc, uint32_t reg, uint32_t bits)
{
	usb_ticks_t start_ticks;
	const usb_ticks_t max_ticks = USB_MS_TO_TICKS(1000);
	uint32_t val;
	int err;
	
	LAN78XX_LOCK_ASSERT(sc, MA_OWNED);

	start_ticks = (usb_ticks_t)ticks;
	do {
		if ((err = lan78xx_read_reg(sc, reg, &val)) != 0)
			return (err);
		if (!(val & bits))
			return (0);
		uether_pause(&sc->sc_ue, hz / 100);
	} while (((usb_ticks_t)(ticks - start_ticks)) < max_ticks);

	return (USB_ERR_TIMEOUT);
}

/**
 *	lan78xx_eeprom_read_raw - Reads the attached EEPROM
 *	@sc: soft context
 *	@off: the eeprom address offset
 *	@buf: stores the bytes
 *	@buflen: the number of bytes to read
 *
 *	Simply reads bytes from an attached eeprom.
 *
 *	LOCKING:
 *	The function takes and releases the device lock if it is not already held.
 *
 *	RETURNS:
 *	0 on success, or a USB_ERR_?? error code on failure.
 */
static int
lan78xx_eeprom_read_raw(struct lan78xx_softc *sc, uint16_t off, uint8_t *buf, uint16_t buflen)
{
	usb_ticks_t start_ticks;
	const usb_ticks_t max_ticks = USB_MS_TO_TICKS(1000);
	int err, locked;
	uint32_t val, saved;
	uint16_t i;

	locked = mtx_owned(&sc->sc_mtx);
	if (!locked)
		LAN78XX_LOCK(sc);

	err = lan78xx_read_reg(sc, LAN78XX_HW_CFG, &val);
	saved = val;
	
	val &= ~(LAN78XX_HW_CFG_LEDO_EN_ | LAN78XX_HW_CFG_LED1_EN_);
	err = lan78xx_write_reg(sc, LAN78XX_HW_CFG, val);

	err = lan78xx_wait_for_bits(sc, LAN78XX_E2P_CMD, LAN78XX_E2P_CMD_BUSY_);

	if (err != 0) {
		lan78xx_warn_printf(sc, "eeprom busy, failed to read data\n");
		goto done;
	}

	/* start reading the bytes, one at a time */
	for (i = 0; i < buflen; i++) {
	
		val = LAN78XX_E2P_CMD_BUSY_ | LAN78XX_E2P_CMD_READ_;
		val |= (LAN78XX_E2P_CMD_ADDR_MASK & (off + i));
		if ((err = lan78xx_write_reg(sc, LAN78XX_E2P_CMD, val)) != 0)
			goto done;
		
		start_ticks = (usb_ticks_t)ticks;
		do {
			if ((err = lan78xx_read_reg(sc, LAN78XX_E2P_CMD, &val)) != 0)
				goto done;
			if (!(val & LAN78XX_E2P_CMD_BUSY_) || (val & LAN78XX_E2P_CMD_TIMEOUT_))
				break;

			uether_pause(&sc->sc_ue, hz / 100);
		} while (((usb_ticks_t)(ticks - start_ticks)) < max_ticks);

		if (val & (LAN78XX_E2P_CMD_BUSY_ | LAN78XX_E2P_CMD_TIMEOUT_)) {
			lan78xx_warn_printf(sc, "eeprom command failed\n");
			err = USB_ERR_IOERROR;
			break;
		}
			
		if ((err = lan78xx_read_reg(sc, LAN78XX_E2P_DATA, &val)) != 0)
			goto done;

		buf[i] = (val & 0xff);
	}
	
done:
	if (!locked)
		LAN78XX_UNLOCK(sc);
	lan78xx_write_reg(sc, LAN78XX_HW_CFG, saved);
	return (err);
}

/**
 *	lan78xx_eeprom_read - Reads the attached EEPROM, confirms that EEPROM is programmed
 *	@sc: soft context
 *	@off: the eeprom address offset
 *	@buf: stores the bytes
 *	@buflen: the number of bytes to read
 *
 *	RETURNS:
 *	0 on success, or a USB_ERR_?? error code on failure.
 */
static int
lan78xx_eeprom_read(struct lan78xx_softc *sc, uint16_t off, uint8_t *buf, uint16_t buflen)
{
	uint8_t sig;
	int ret;
	
	ret = lan78xx_eeprom_read_raw(sc, LAN78XX_E2P_INDICATOR_OFFSET, &sig, 1);

	if ((ret == 0) && (sig == LAN78XX_E2P_INDICATOR)) {
		ret = lan78xx_eeprom_read_raw(sc, off, buf, buflen);
		lan78xx_dbg_printf(sc, "EEPROM present\n");
	} else {
		ret = -EINVAL;
		lan78xx_dbg_printf(sc, "EEPROM not present\n");
	}
	return ret;
}

/**
 * lan78xx_otp_read_raw
 *	@sc: soft context
 *	@off: the otp address offset
 *	@buf: stores the bytes
 *	@buflen: the number of bytes to read
 *
 *	Simply reads bytes from the OTP.
 *
 *	LOCKING:
 *	The function takes and releases the device lock if it is not already held.
 *
 *	RETURNS:
 *	0 on success, or a USB_ERR_?? error code on failure.
 *
 */
static int
lan78xx_otp_read_raw(struct lan78xx_softc *sc, uint16_t off, uint8_t *buf, uint16_t buflen)
{
	int locked, err;
	uint32_t val;
	uint16_t i;
	locked = mtx_owned(&sc->sc_mtx);
	if (!locked)
		LAN78XX_LOCK(sc);

	err = lan78xx_read_reg(sc, LAN78XX_OTP_PWR_DN, &val);
	
	// checking if bit is set
	if (val & LAN78XX_OTP_PWR_DN_PWRDN_N) {
		// clearing it, then waiting for it to be cleared	
		lan78xx_write_reg(sc, LAN78XX_OTP_PWR_DN, 0);
		err = lan78xx_wait_for_bits(sc, LAN78XX_OTP_PWR_DN, LAN78XX_OTP_PWR_DN_PWRDN_N);
		if (err != 0) {
			lan78xx_warn_printf(sc, "OTP off? failed to read data\n");
			goto done;
		}
	}
	/* start reading the bytes, one at a time */
	for (i = 0; i < buflen; i++) {
		err = lan78xx_write_reg(sc, LAN78XX_OTP_ADDR1,
						((off + i) >> 8) & LAN78XX_OTP_ADDR1_15_11);
		err = lan78xx_write_reg(sc, LAN78XX_OTP_ADDR2,
						((off + i) & LAN78XX_OTP_ADDR2_10_3));
		err = lan78xx_write_reg(sc, LAN78XX_OTP_FUNC_CMD, LAN78XX_OTP_FUNC_CMD_READ_);
		err = lan78xx_write_reg(sc, LAN78XX_OTP_CMD_GO, LAN78XX_OTP_CMD_GO_GO_);

		err = lan78xx_wait_for_bits(sc, LAN78XX_OTP_STATUS, LAN78XX_OTP_STATUS_BUSY_);
		if (err != 0) {
			lan78xx_warn_printf(sc, "OTP busy failed to read data\n");
			goto done;
		}

		if ((err = lan78xx_read_reg(sc, LAN78XX_OTP_RD_DATA, &val)) != 0)
			goto done;

		buf[i] = (uint8_t)(val & 0xff);
	}
	
done:
	if (!locked)
		LAN78XX_UNLOCK(sc);
	return (err);

}

/**
 * lan78xx_otp_read
 *	@sc: soft context
 *	@off: the otp address offset
 *	@buf: stores the bytes
 *	@buflen: the number of bytes to read
 *
 *	Simply reads bytes from the otp.
 *
 *	LOCKING:
 *	The function takes and releases the device lock if it is not already held.
 *
 *	RETURNS:
 *	0 on success, or a USB_ERR_?? error code on failure.
 *
 */

static int
lan78xx_otp_read(struct lan78xx_softc *sc, uint16_t off, uint8_t *buf, uint16_t buflen) 
{
	uint8_t sig;
	int err;

	err = lan78xx_otp_read_raw(sc, LAN78XX_OTP_INDICATOR_OFFSET, &sig, 1);
	if (err == 0) {
		if (sig == LAN78XX_OTP_INDICATOR_1) {
		} else if (sig == LAN78XX_OTP_INDICATOR_2) {
			off += 0x100;
		} else {
			err = -EINVAL;
		}
		if(!err)
			err = lan78xx_otp_read_raw(sc, off, buf, buflen);
	}
	return err;
}

/**
 *	lan78xx_setmacaddress - Sets the mac address in the device
 *	@sc: driver soft context
 *	@addr: pointer to array contain at least 6 bytes of the mac
 *
 *	Writes the MAC address into the device, usually the MAC is programmed with
 *	values from the EEPROM.
 *
 *	LOCKING:
 *	Should be called with the LAN78XX lock held.
 *
 *	RETURNS:
 *	Returns 0 on success or a negative error code.
 */
static int
lan78xx_setmacaddress(struct lan78xx_softc *sc, const uint8_t *addr)
{
	int err;
	uint32_t val;

	lan78xx_dbg_printf(sc, "setting mac address to %02x:%02x:%02x:%02x:%02x:%02x\n",
					addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

	LAN78XX_LOCK_ASSERT(sc, MA_OWNED);

	val = (addr[3] << 24) | (addr[2] << 16) | (addr[1] << 8) | addr[0];
	if ((err = lan78xx_write_reg(sc, LAN78XX_RX_ADDRL, val)) != 0)
		goto done;
		
	val = (addr[5] << 8) | addr[4];
	err = lan78xx_write_reg(sc, LAN78XX_RX_ADDRH, val);
	
done:
	return (err);
}

/**
 *	lan78xx_set_rx_max_frame_length
 *	@sc: driver soft context
 *	@size: pointer to array contain at least 6 bytes of the mac
 *
 *	Sets the maximum frame length to be received. Frames bigger than
 *	this size are aborted.
 *
 *	RETURNS:
 *	Returns 0 on success or a negative error code.
 */

static int
lan78xx_set_rx_max_frame_length(struct lan78xx_softc *sc, int size)
{
	int err = 0;
	uint32_t buf;
	bool rxenabled;

	/* first we have to disable rx before changing the length */

	err = lan78xx_read_reg(sc, LAN78XX_MAC_RX, &buf);
	rxenabled = ((buf & LAN78XX_MAC_RX_EN_) != 0);

	if (rxenabled) {
		buf &= ~LAN78XX_MAC_RX_EN_;
		err = lan78xx_write_reg(sc, LAN78XX_MAC_RX, buf);
	}
	
	/* setting max frame length */
	
	buf &= ~LAN78XX_MAC_RX_MAX_FR_SIZE_MASK_;
	buf |= (((size + 4) << LAN78XX_MAC_RX_MAX_FR_SIZE_SHIFT_) & LAN78XX_MAC_RX_MAX_FR_SIZE_MASK_);
	err = lan78xx_write_reg(sc, LAN78XX_MAC_RX, buf);
	
	/* If it were enabled before, we enable it back. */

	if (rxenabled) {
		buf |= LAN78XX_MAC_RX_EN_;
		err = lan78xx_write_reg(sc, LAN78XX_MAC_RX, buf);
	}

	return 0;
}

/**
 *	lan78xx_miibus_readreg - Reads a MII/MDIO register
 *	@dev: usb ether device
 *	@phy: the number of phy reading from
 *	@reg: the register address
 *
 *	Attempts to read a PHY register indirectly through the USB controller registers.
 *
 *	LOCKING:
 *	Takes and releases the device mutex lock if not already held.
 *
 *	RETURNS:
 *	Returns the 16-bits read from the MII register, if this function fails 0
 *	is returned.
 */
static int
lan78xx_miibus_readreg(device_t dev, int phy, int reg) {

	struct lan78xx_softc *sc = device_get_softc(dev);
	int locked;
	uint32_t addr, val;

	val = 0;
	locked = mtx_owned(&sc->sc_mtx);
	if (!locked)
		LAN78XX_LOCK(sc);

	if (lan78xx_wait_for_bits(sc, LAN78XX_MII_ACCESS, LAN78XX_MII_BUSY_) != 0) {
		lan78xx_warn_printf(sc, "MII is busy\n");
		goto done;
	}

	addr = (phy << 11) | (reg << 6) | LAN78XX_MII_READ_ | LAN78XX_MII_BUSY_;
	lan78xx_write_reg(sc, LAN78XX_MII_ACCESS, addr);

	if (lan78xx_wait_for_bits(sc, LAN78XX_MII_ACCESS, LAN78XX_MII_BUSY_) != 0) {
		lan78xx_warn_printf(sc, "MII read timeout\n");
		goto done;
	}

	lan78xx_read_reg(sc, LAN78XX_MII_DATA, &val);
	val = le32toh(val);

done:
	if (!locked)
		LAN78XX_UNLOCK(sc);

	return (val & 0xFFFF);
}

/**
 *	lan78xx_miibus_writereg - Writes a MII/MDIO register
 *	@dev: usb ether device
 *	@phy: the number of phy writing to
 *	@reg: the register address
 *	@val: the value to write
 *
 *	Attempts to write to a PHY register through the usb controller registers.
 *
 *	LOCKING:
 *	Takes and releases the device mutex lock if not already held.
 *
 *	RETURNS:
 *	Always returns 0 regardless of success or failure.
 */
static int
lan78xx_miibus_writereg(device_t dev, int phy, int reg, int val)
{
	struct lan78xx_softc *sc = device_get_softc(dev);
	int locked;
	uint32_t addr;

	if (sc->sc_phyno != phy)
		return (0);

	locked = mtx_owned(&sc->sc_mtx);
	if (!locked)
		LAN78XX_LOCK(sc);

	if (lan78xx_wait_for_bits(sc, LAN78XX_MII_ACCESS, LAN78XX_MII_BUSY_) != 0) {
		lan78xx_warn_printf(sc, "MII is busy\n");
		goto done;
	}

	val = htole32(val);
	lan78xx_write_reg(sc, LAN78XX_MII_DATA, val);

	addr = (phy << 11) | (reg << 6) | LAN78XX_MII_WRITE_ | LAN78XX_MII_BUSY_;
	lan78xx_write_reg(sc, LAN78XX_MII_ACCESS, addr);

	if (lan78xx_wait_for_bits(sc, LAN78XX_MII_ACCESS, LAN78XX_MII_BUSY_) != 0)
		lan78xx_warn_printf(sc, "MII write timeout\n");

done:
	if (!locked)
		LAN78XX_UNLOCK(sc);
	return (0);
}

/*
 *	lan78xx_miibus_statchg - Called to detect phy status change
 *	@dev: usb ether device
 *
 *	This function is called periodically by the system to poll for status
 *	changes of the link.
 *
 *	LOCKING:
 *	Takes and releases the device mutex lock if not already held.
 */
static void
lan78xx_miibus_statchg(device_t dev)
{
	struct lan78xx_softc *sc = device_get_softc(dev);
	struct mii_data *mii = uether_getmii(&sc->sc_ue);
	struct ifnet *ifp;
	int locked;
	int err;
	uint32_t flow = 0;
	uint32_t fct_flow = 0;

	locked = mtx_owned(&sc->sc_mtx);
	if (!locked)
		LAN78XX_LOCK(sc);

	ifp = uether_getifp(&sc->sc_ue);
	if (mii == NULL || ifp == NULL ||
		(ifp->if_drv_flags & IFF_DRV_RUNNING) == 0)
		goto done;

	/* Use the MII status to determine link status */
	sc->sc_flags &= ~LAN78XX_FLAG_LINK;
	if ((mii->mii_media_status & (IFM_ACTIVE | IFM_AVALID)) ==
		(IFM_ACTIVE | IFM_AVALID)) {
		lan78xx_dbg_printf(sc, "media is active\n");
		switch (IFM_SUBTYPE(mii->mii_media_active)) {
			case IFM_10_T:
			case IFM_100_TX:
				sc->sc_flags |= LAN78XX_FLAG_LINK;
				lan78xx_dbg_printf(sc, "10/100 ethernet\n");
				break;
			case IFM_1000_T:
				sc->sc_flags |= LAN78XX_FLAG_LINK;
				lan78xx_dbg_printf(sc, "Gigabit ethernet\n");
				break;
			default:
				break;
		}
	} 
	/* Lost link, do nothing. */
	if ((sc->sc_flags & LAN78XX_FLAG_LINK) == 0) {
		lan78xx_dbg_printf(sc, "link flag not set\n");
		goto done;
	}

	err = lan78xx_read_reg(sc, LAN78XX_FCT_FLOW, &fct_flow);
	if (err) {
		lan78xx_warn_printf(sc, "failed to read initial flow control thresholds, error %d\n", err);
		goto done;
	}

	/* Enable/disable full duplex operation and TX/RX pause */
	if ((IFM_OPTIONS(mii->mii_media_active) & IFM_FDX) != 0) {
		lan78xx_dbg_printf(sc, "full duplex operation\n");

		/* enable transmit MAC flow control function */
		if ((IFM_OPTIONS(mii->mii_media_active) & IFM_ETH_TXPAUSE) != 0)
			flow |= LAN78XX_FLOW_CR_TX_FCEN_ | 0xFFFF;

		if ((IFM_OPTIONS(mii->mii_media_active) & IFM_ETH_RXPAUSE) != 0)
			flow |= LAN78XX_FLOW_CR_RX_FCEN_;
	}

	switch(usbd_get_speed(sc->sc_ue.ue_udev)) {
		case USB_SPEED_SUPER:	
			fct_flow = 0x817;
			break;
		case USB_SPEED_HIGH:	
			fct_flow = 0x211;
			break;
		default:
			break;
	}

	err += lan78xx_write_reg(sc, LAN78XX_FLOW, flow);
	err += lan78xx_write_reg(sc, LAN78XX_FCT_FLOW, fct_flow);
	if (err)
		lan78xx_warn_printf(sc, "media change failed, error %d\n", err);

done:
	if (!locked)
		LAN78XX_UNLOCK(sc);
}

/*
 *	lan78xx_set_mdix_auto - Configures the device to enable automatic crossover
 *	and polarity detection. LAN78XX provides HP Auto-MDIX functionality
 *	for seamless crossover and polarity detection. Linux's ethtool allows
 *	for manually forcing MDI or MDIX, but that feature is not preferred here.
 *
 *	@sc: driver soft context
 *
 *	LOCKING:
 *	Takes and releases the device mutex lock if not already held.
 */
static void
lan78xx_set_mdix_auto(struct lan78xx_softc *sc)
{
	uint32_t buf, err;

	err = lan78xx_miibus_writereg(sc->sc_ue.ue_dev, sc->sc_phyno,
					LAN78XX_EXT_PAGE_ACCESS, LAN78XX_EXT_PAGE_SPACE_1);
	
	buf = lan78xx_miibus_readreg(sc->sc_ue.ue_dev, sc->sc_phyno, LAN78XX_EXT_MODE_CTRL);
	buf &= ~LAN78XX_EXT_MODE_CTRL_MDIX_MASK_;
	buf |= LAN78XX_EXT_MODE_CTRL_AUTO_MDIX_;

	lan78xx_miibus_readreg(sc->sc_ue.ue_dev, sc->sc_phyno, MII_BMCR);
	err += lan78xx_miibus_writereg(sc->sc_ue.ue_dev, sc->sc_phyno,
					LAN78XX_EXT_MODE_CTRL, buf);

	err += lan78xx_miibus_writereg(sc->sc_ue.ue_dev, sc->sc_phyno,
					LAN78XX_EXT_PAGE_ACCESS, LAN78XX_EXT_PAGE_SPACE_0);

	if (err != 0)
		lan78xx_warn_printf(sc, "error setting PHY's MDIX status\n");

	sc->sc_mdix_ctl = buf;
}

/**
 *	lan78xx_phy_init - Initialises the in-built LAN78XX phy
 *	@sc: driver soft context
 *
 *	Resets the PHY part of the chip and then initialises it to default
 *	values.  The 'link down' and 'auto-negotiation complete' interrupts
 *	from the PHY are also enabled, however we don't monitor the interrupt
 *	endpoints for the moment.
 *
 *	RETURNS:
 *	Returns 0 on success or EIO if failed to reset the PHY.
 */
static int
lan78xx_phy_init(struct lan78xx_softc *sc)
{
	lan78xx_dbg_printf(sc, "Initializing PHY.\n");
	uint16_t bmcr;
	usb_ticks_t start_ticks;
	const usb_ticks_t max_ticks = USB_MS_TO_TICKS(1000);

	LAN78XX_LOCK_ASSERT(sc, MA_OWNED);

	/* Reset phy and wait for reset to complete */
	lan78xx_miibus_writereg(sc->sc_ue.ue_dev, sc->sc_phyno, MII_BMCR, BMCR_RESET);

	start_ticks = ticks;
	do {
		uether_pause(&sc->sc_ue, hz / 100);
		bmcr = lan78xx_miibus_readreg(sc->sc_ue.ue_dev, sc->sc_phyno, MII_BMCR);
	} while ((bmcr & BMCR_RESET) && ((ticks - start_ticks) < max_ticks));

	if (((usb_ticks_t)(ticks - start_ticks)) >= max_ticks) {
		lan78xx_err_printf(sc, "PHY reset timed-out\n");
		return (EIO);
	}

	/* Setup the phy to interrupt when the link goes down or autoneg completes */
	lan78xx_miibus_readreg(sc->sc_ue.ue_dev, sc->sc_phyno, LAN78XX_PHY_INTR_STAT);
	lan78xx_miibus_writereg(sc->sc_ue.ue_dev, sc->sc_phyno, LAN78XX_PHY_INTR_MASK,
						 (LAN78XX_PHY_INTR_ANEG_COMP | LAN78XX_PHY_INTR_LINK_CHANGE));

	/* Enabling Auto-MDIX for crossover and polarity detection. */
	lan78xx_set_mdix_auto(sc);

	lan78xx_miibus_writereg(sc->sc_ue.ue_dev, sc->sc_phyno, MII_ANAR,
						 ANAR_10 | ANAR_10_FD | ANAR_TX | ANAR_TX_FD |	/* all modes */
						 ANAR_CSMA | 
						 ANAR_FC |
						 ANAR_PAUSE_ASYM);

	/* Restart auto-negotation */
	bmcr |= BMCR_STARTNEG;
	bmcr |= BMCR_AUTOEN;
	lan78xx_miibus_writereg(sc->sc_ue.ue_dev, sc->sc_phyno, MII_BMCR, bmcr);
	bmcr = lan78xx_miibus_readreg(sc->sc_ue.ue_dev, sc->sc_phyno, MII_BMCR);
	return (0);
}


/**
 *	lan78xx_chip_init - Initialises the chip after power on
 *	@sc: driver soft context
 *
 *	This initialisation sequence is modelled on the procedure in the Linux
 *	driver.
 *
 *	RETURNS:
 *	Returns 0 on success or an error code on failure.
 */
static int
lan78xx_chip_init(struct lan78xx_softc *sc)
{
	int err;
	int locked;
	uint32_t buf;
	uint32_t burst_cap;

	locked = mtx_owned(&sc->sc_mtx);
	if (!locked)
		LAN78XX_LOCK(sc);

	/* Enter H/W config mode */
	lan78xx_write_reg(sc, LAN78XX_HW_CFG, LAN78XX_HW_CFG_LRST_);

	if ((err = lan78xx_wait_for_bits(sc, LAN78XX_HW_CFG, LAN78XX_HW_CFG_LRST_)) != 0) {
		lan78xx_warn_printf(sc, "timed-out waiting for lite reset to complete\n");
		goto init_failed;
	}

	/* Set the mac address */
	if ((err = lan78xx_setmacaddress(sc, sc->sc_ue.ue_eaddr)) != 0) {
		lan78xx_warn_printf(sc, "failed to set the MAC address\n");
		goto init_failed;
	}

	/* Read and display the revision register */
	if ((err = lan78xx_read_reg(sc, LAN78XX_ID_REV, &sc->sc_rev_id)) < 0) {
		lan78xx_warn_printf(sc, "failed to read ID_REV (err = %d)\n", err);
		goto init_failed;
	}

	device_printf(sc->sc_ue.ue_dev, "chip 0x%04lx, rev. %04lx\n", 
		(sc->sc_rev_id & LAN78XX_ID_REV_CHIP_ID_MASK_) >> 16, 
		(sc->sc_rev_id & LAN78XX_ID_REV_CHIP_REV_MASK_));

	/* respond to BULK-IN tokens with a NAK when RX FIFO is empty */

	if ((err = lan78xx_read_reg(sc, LAN78XX_USB_CFG0, &buf)) != 0) {
		lan78xx_warn_printf(sc, "failed to read LAN78XX_USB_CFG0: %d\n", err);
		goto init_failed;
	}
	buf |= LAN78XX_USB_CFG_BIR_;
	lan78xx_write_reg(sc, LAN78XX_USB_CFG0, buf);

	/*
	 * LTM support will go here.
	 */

	/* configuring the burst cap */
	switch(usbd_get_speed(sc->sc_ue.ue_udev)) {
		case USB_SPEED_SUPER:	
			burst_cap = LAN78XX_DEFAULT_BURST_CAP_SIZE/LAN78XX_SS_USB_PKT_SIZE;
			break;
		case USB_SPEED_HIGH:	
			burst_cap = LAN78XX_DEFAULT_BURST_CAP_SIZE/LAN78XX_HS_USB_PKT_SIZE;
			break;
		default:
			burst_cap = LAN78XX_DEFAULT_BURST_CAP_SIZE/LAN78XX_FS_USB_PKT_SIZE;
	}

	lan78xx_write_reg(sc, LAN78XX_BURST_CAP, burst_cap);

	/* Set the default bulk in delay (same value from Linux driver) */
	lan78xx_write_reg(sc, LAN78XX_BULK_IN_DLY, LAN78XX_DEFAULT_BULK_IN_DELAY);

	/* Multiple ethernet frames per USB packets */
	err = lan78xx_read_reg(sc, LAN78XX_HW_CFG, &buf);
	buf |= LAN78XX_HW_CFG_MEF_;
	err = lan78xx_write_reg(sc, LAN78XX_HW_CFG, buf);

	/* Enable burst cap */
	if ((err = lan78xx_read_reg(sc, LAN78XX_USB_CFG0, &buf)) < 0) {
		lan78xx_warn_printf(sc, "failed to read USB_CFG0: (err = %d)\n", err);
		goto init_failed;
	}
	buf |= LAN78XX_USB_CFG_BCE_;
	err = lan78xx_write_reg(sc, LAN78XX_USB_CFG0, buf);
 
	/*
	 *
	 * Set FCL's RX and TX FIFO sizes: according to data sheet this is already the 
	 * default value. But we initialize it to the same value anyways, as that's 
	 * what the Linux driver does.
	 *
	 */

	buf = (LAN78XX_MAX_RX_FIFO_SIZE - 512) / 512;
	err = lan78xx_write_reg(sc, LAN78XX_FCT_RX_FIFO_END, buf);

	buf = (LAN78XX_MAX_TX_FIFO_SIZE - 512) / 512;
	err = lan78xx_write_reg(sc, LAN78XX_FCT_TX_FIFO_END, buf);

	/* Enabling interrupts. (Not using them for now) */

	err = lan78xx_write_reg(sc, LAN78XX_INT_STS, LAN78XX_INT_STS_CLEAR_ALL_);

	/*
	 * Initializing flow control registers to 0. These registers are properly set 
	 * is handled in link-reset function in the Linux driver.
	 */

	err = lan78xx_write_reg(sc, LAN78XX_FLOW, 0);
	err = lan78xx_write_reg(sc, LAN78XX_FCT_FLOW, 0);

	/*
	 * Settings for the RFE, we enable broadcast and destination address perfect
	 * filtering.
	 */

	err = lan78xx_read_reg(sc, LAN78XX_RFE_CTL, &buf); 
	buf |= LAN78XX_RFE_CTL_BCAST_EN_ | LAN78XX_RFE_CTL_DA_PERFECT_;
	err = lan78xx_write_reg(sc, LAN78XX_RFE_CTL, buf);

	/*
	 * At this point the Linux driver writes multicast tables, and enables 
	 * checksum engines. But in FreeBSD that gets done in lan78xx_init,
	 * which gets called when the interface is brought up.
	 */

	/* Reset the PHY */
	lan78xx_write_reg(sc, LAN78XX_PMT_CTL, LAN78XX_PMT_CTL_PHY_RST_);
	if ((err = lan78xx_wait_for_bits(sc, LAN78XX_PMT_CTL, LAN78XX_PMT_CTL_PHY_RST_)) != 0) {
		lan78xx_warn_printf(sc, "timed-out waiting for phy reset to complete\n");
		goto init_failed;
	}

	/* Enable automatic duplex detection and automatic speed detection. */
	err = lan78xx_read_reg(sc, LAN78XX_MAC_CR, &buf);
	buf |= LAN78XX_MAC_CR_AUTO_DUPLEX_ | LAN78XX_MAC_CR_AUTO_SPEED_;
	err = lan78xx_write_reg(sc, LAN78XX_MAC_CR, buf);

	/*
	 * Enable PHY interrupts (Not really getting used for now)
	 * INT_EP_CTL: interrupt endpoint control register
	 * phy events cause interrupts to be issued
	 */
	err = lan78xx_read_reg(sc, LAN78XX_INT_EP_CTL, &buf);
	buf |= LAN78XX_INT_ENP_PHY_INT;
	err = lan78xx_write_reg(sc, LAN78XX_INT_EP_CTL, buf);

	/* 
	 * Enables mac's transmitter. it'll transmit frames 
	 * from the buffer onto the cable.
	 */
	err = lan78xx_read_reg(sc, LAN78XX_MAC_TX, &buf);
	buf |= LAN78XX_MAC_TX_TXEN_;
	err = lan78xx_write_reg(sc, LAN78XX_MAC_TX, buf);

	/*
	 * FIFO is capable of transmitting frames to MAC
	 */
	err = lan78xx_read_reg(sc, LAN78XX_FCT_TX_CTL, &buf);
	buf |= LAN78XX_FCT_TX_CTL_EN_;
	err = lan78xx_write_reg(sc, LAN78XX_FCT_TX_CTL, buf);

	/*
	 * Set max frame length:
	 * In linux this is dev->mtu (which by default is 1500) + VLAN_ETH_HLEN = 1518
	 */

	err = lan78xx_set_rx_max_frame_length(sc, ETHER_MAX_LEN);

	/*
	 * Initialise the PHY
	 */
	if ((err = lan78xx_phy_init(sc)) != 0)
		goto init_failed;

	/*
	 * enable MAC RX
	 */
	err = lan78xx_read_reg(sc, LAN78XX_MAC_RX, &buf);
	buf |= LAN78XX_MAC_RX_EN_;
	err = lan78xx_write_reg(sc, LAN78XX_MAC_RX, buf);

	/*
	 * enable FIFO controller RX
	 */
	err = lan78xx_read_reg(sc, LAN78XX_FCT_RX_CTL, &buf);
	buf |= LAN78XX_FCT_TX_CTL_EN_;
	err = lan78xx_write_reg(sc, LAN78XX_FCT_RX_CTL, buf);

	return 0;

init_failed:
	if (!locked)
		LAN78XX_UNLOCK(sc);

	lan78xx_err_printf(sc, "lan78xx_chip_init failed (err=%d)\n", err);
	return (err);
}

static void
lan78xx_bulk_read_callback(struct usb_xfer *xfer, usb_error_t error)
{
	struct lan78xx_softc *sc = usbd_xfer_softc(xfer);
	struct usb_ether *ue = &sc->sc_ue;
	struct ifnet *ifp = uether_getifp(ue);
	struct mbuf *m;
	struct usb_page_cache *pc;
	uint16_t pktlen;
	uint32_t rx_cmd_a, rx_cmd_b;
	uint16_t rx_cmd_c;
	int off;
	int actlen;

	usbd_xfer_status(xfer, &actlen, NULL, NULL, NULL);
	lan78xx_dbg_printf(sc, "rx : actlen %d\n", actlen);

	switch (USB_GET_STATE(xfer)) {
	case USB_ST_TRANSFERRED:

		/* There is always a zero length frame after bringing the IF up */
		if (actlen < (sizeof(rx_cmd_a) + ETHER_CRC_LEN))
			goto tr_setup;

		/* There maybe multiple packets in the USB frame, each will have a 
		 * header and each needs to have it's own mbuf allocated and populated
		 * for it.
		 */
		pc = usbd_xfer_get_frame(xfer, 0);
		off = 0;

		while (off < actlen) {

			/* The frame header is always aligned on a 4 byte boundary */
			off = ((off + 0x3) & ~0x3);

			/* extract RX CMD A */
			usbd_copy_out(pc, off, &rx_cmd_a, sizeof(rx_cmd_a));
			off += (sizeof(rx_cmd_a));
			rx_cmd_a = le32toh(rx_cmd_a);

			/* extract RX CMD B */
			usbd_copy_out(pc, off, &rx_cmd_b, sizeof(rx_cmd_b));
			off += (sizeof(rx_cmd_b));
			rx_cmd_b = le32toh(rx_cmd_b);

			/* extract RX CMD C */
			usbd_copy_out(pc, off, &rx_cmd_c, sizeof(rx_cmd_c));
			off += (sizeof(rx_cmd_c));
			rx_cmd_b = le32toh(rx_cmd_c);

			pktlen = (rx_cmd_a & LAN78XX_RX_CMD_A_LEN_MASK_);

			lan78xx_dbg_printf(sc, "rx : rx_cmd_a 0x%08x : rx_cmd_b 0x%08x :"
							" rx_cmd_c 0x%04x : pktlen %d : actlen %d : off %d\n",
							rx_cmd_a, rx_cmd_b, rx_cmd_c, pktlen, actlen, off);

			if (rx_cmd_a & LAN78XX_RX_CMD_A_RED_) {
				lan78xx_dbg_printf(sc, "rx error (hdr 0x%08x)\n", rx_cmd_a);
				if_inc_counter(ifp, IFCOUNTER_IERRORS, 1);
			} else {
				/* Check if the ethernet frame is too big or too small */
				if ((pktlen < ETHER_HDR_LEN) || (pktlen > (actlen - off)))
					goto tr_setup;

				/* Create a new mbuf to store the packet in */
				m = uether_newbuf();
				if (m == NULL) {
					lan78xx_warn_printf(sc, "failed to create new mbuf\n");
					if_inc_counter(ifp, IFCOUNTER_IQDROPS, 1);
					goto tr_setup;
				}
			
				usbd_copy_out(pc, off, mtod(m, uint8_t *), pktlen);

				/* Check if RX checksums are computed, and offload them */
				if ((ifp->if_capabilities & IFCAP_RXCSUM) &&
					!(rx_cmd_a & LAN78XX_RX_CMD_A_ICSM_)) {
					struct ether_header *eh;
					eh = mtod(m, struct ether_header *);
					/* Remove the extra 2 bytes of the csum */
					//pktlen -= 2; // is this even needed? :O

					/*
					 * The checksum appears to be simplistically calculated
					 * over the protocol headers up to the end of the eth frame. 
					 * Which means if the eth frame is padded the csum calculation 
					 * is incorrectly performed over the padding bytes as well.
					 * Therefore to be safe we ignore the H/W csum on 
					 * frames less than or equal to 64 bytes.
					 *
					 * Protocols checksummed TCP, UDP, ICMP, IGMP, IP
					 */
					if (pktlen > ETHER_MIN_LEN) {

						 /* Indicate the csum has been calculated */
						m->m_pkthdr.csum_flags |= CSUM_DATA_VALID;

						/* Copy the checksum from the last 2 bytes
						 * of the transfer and put in the csum_data field.
						 */
						usbd_copy_out(pc, (off + pktlen),
									  &m->m_pkthdr.csum_data, 2);

						/* The data is copied in network order, but the
						 * csum algorithm in the kernel expects it to be
						 * in host network order.
						 */
						m->m_pkthdr.csum_data = ntohs(m->m_pkthdr.csum_data);

						lan78xx_dbg_printf(sc, "RX checksum offloaded (0x%04x)\n",
										m->m_pkthdr.csum_data);
					}
				}

				/* Finally enqueue the mbuf on the receive queue */
				if (pktlen < (4 + ETHER_HDR_LEN)) {
					m_freem(m);
					goto tr_setup;
				}
				/* Remove 4 trailing bytes */
				uether_rxmbuf(ue, m, pktlen - 4);
			}

			/* Update the offset to move to the next potential packet */
			off += pktlen;
		}

		/* FALLTHROUGH */
		
	case USB_ST_SETUP:
tr_setup:
		usbd_xfer_set_frame_len(xfer, 0, usbd_xfer_max_len(xfer));
		usbd_transfer_submit(xfer);
		uether_rxflush(ue);
		return;

	default:
		if (error != USB_ERR_CANCELLED) {
			lan78xx_warn_printf(sc, "bulk read error, %s\n", usbd_errstr(error));
			usbd_xfer_set_stall(xfer);
			goto tr_setup;
		}
		return;
	}
}

/**
 *	lan78xx_bulk_write_callback - Write callback used to send ethernet frame(s)
 *	@xfer: the USB transfer
 *	@error: error code if the transfers is in an errored state
 *
 *	The main write function that pulls ethernet frames off the queue and sends
 *	them out.
 *	
 */

static void
lan78xx_bulk_write_callback(struct usb_xfer *xfer, usb_error_t error)
{
	struct lan78xx_softc *sc = usbd_xfer_softc(xfer);
	struct ifnet *ifp = uether_getifp(&sc->sc_ue);
	struct usb_page_cache *pc;
	struct mbuf *m;
	int nframes;
	uint32_t frm_len = 0, tx_cmd_a = 0, tx_cmd_b = 0;

	switch (USB_GET_STATE(xfer)) {
	case USB_ST_TRANSFERRED:
		lan78xx_dbg_printf(sc, "USB TRANSFER status: USB_ST_TRANSFERRED\n");
		ifp->if_drv_flags &= ~IFF_DRV_OACTIVE;
		/* FALLTHROUGH */
	case USB_ST_SETUP:
		lan78xx_dbg_printf(sc, "USB TRANSFER status: USB_ST_SETUP\n");
tr_setup:
		if ((sc->sc_flags & LAN78XX_FLAG_LINK) == 0 ||
			(ifp->if_drv_flags & IFF_DRV_OACTIVE) != 0) {
			lan78xx_dbg_printf(sc, "sc->sc_flags & LAN78XX_FLAG_LINK: %d\n",
							(sc->sc_flags & LAN78XX_FLAG_LINK));
			lan78xx_dbg_printf(sc, "ifp->if_drv_flags & IFF_DRV_OACTIVE: %d\n",
							(ifp->if_drv_flags & IFF_DRV_OACTIVE));
			lan78xx_dbg_printf(sc, "USB TRANSFER not sending: no link or controller is busy \n");
			/* Don't send anything if there is no link or controller is busy. */
			return;
		}
		for (nframes = 0; nframes < 16 &&
			!IFQ_DRV_IS_EMPTY(&ifp->if_snd); nframes++) {
			IFQ_DRV_DEQUEUE(&ifp->if_snd, m);
			if (m == NULL)
				break;
			usbd_xfer_set_frame_offset(xfer, nframes * MCLBYTES,
				nframes);
			frm_len = 0;
			pc = usbd_xfer_get_frame(xfer, nframes);
			
			/* Each frame is prefixed with two 32-bit values describing the
			 * length of the packet and buffer.
			 */
			tx_cmd_a = (m->m_pkthdr.len & LAN78XX_TX_CMD_A_LEN_MASK_) |
									LAN78XX_TX_CMD_A_FCS_;
			tx_cmd_a = htole32(tx_cmd_a);
			usbd_copy_in(pc, 0, &tx_cmd_a, sizeof(tx_cmd_a));
			
			tx_cmd_b = 0;
		/* TCP LSO Support will probably be implemented here. */
			tx_cmd_b = htole32(tx_cmd_b);
			usbd_copy_in(pc, 4, &tx_cmd_b, sizeof(tx_cmd_b));
			
			frm_len += 8;
			/* Next copy in the actual packet */
			usbd_m_copy_in(pc, frm_len, m, 0, m->m_pkthdr.len);
			frm_len += m->m_pkthdr.len;

			if_inc_counter(ifp, IFCOUNTER_OPACKETS, 1);
		
			/* If there's a BPF listener, bounce a copy of this frame to him */
			BPF_MTAP(ifp, m);
			m_freem(m);

			/* Set frame length. */
			usbd_xfer_set_frame_len(xfer, nframes, frm_len);
		}

		lan78xx_dbg_printf(sc, "USB TRANSFER nframes: %d\n", nframes);
		if (nframes != 0) {
			lan78xx_dbg_printf(sc, "USB TRANSFER submit attempt\n");
			usbd_xfer_set_frames(xfer, nframes);
			usbd_transfer_submit(xfer);
			ifp->if_drv_flags |= IFF_DRV_OACTIVE;
		}
		return;

	default:
		if_inc_counter(ifp, IFCOUNTER_OERRORS, 1);
		ifp->if_drv_flags &= ~IFF_DRV_OACTIVE;
		
		if (error != USB_ERR_CANCELLED) {
			lan78xx_err_printf(sc, "usb error on tx: %s\n", usbd_errstr(error));
			usbd_xfer_set_stall(xfer);
			goto tr_setup;
		}
		return;
	}
}

/**
 *	lan78xx_attach_post - Called after the driver attached to the USB interface
 *	@ue: the USB ethernet device
 *
 *	This is where the chip is intialised for the first time.  This is different
 *	from the lan78xx_init() function in that that one is designed to setup the
 *	H/W to match the UE settings and can be called after a reset.
 *
 */

static void
lan78xx_attach_post(struct usb_ether *ue)
{
	struct lan78xx_softc *sc = uether_getsc(ue);
	uint32_t mac_h, mac_l;
	//int err;
	lan78xx_dbg_printf(sc, "Calling lan78xx_attach_post.\n");

	/* Setup some of the basics */
	sc->sc_phyno = 1;

	/* Attempt to get the mac address, if an EEPROM is not attached this
	 * will just return FF:FF:FF:FF:FF:FF, so in such cases we invent a MAC
	 * address based on urandom.
	 */
	memset(sc->sc_ue.ue_eaddr, 0xff, ETHER_ADDR_LEN);

	uint32_t val;
	lan78xx_read_reg(sc, 0, &val);

	/* Check if there is already a MAC address in the register */
	if ((lan78xx_read_reg(sc, LAN78XX_RX_ADDRL, &mac_l) == 0) &&
		(lan78xx_read_reg(sc, LAN78XX_RX_ADDRH, &mac_h) == 0)) {
		sc->sc_ue.ue_eaddr[5] = (uint8_t)((mac_h >> 8) & 0xff);
		sc->sc_ue.ue_eaddr[4] = (uint8_t)((mac_h) & 0xff);
		sc->sc_ue.ue_eaddr[3] = (uint8_t)((mac_l >> 24) & 0xff);
		sc->sc_ue.ue_eaddr[2] = (uint8_t)((mac_l >> 16) & 0xff);
		sc->sc_ue.ue_eaddr[1] = (uint8_t)((mac_l >> 8) & 0xff);
		sc->sc_ue.ue_eaddr[0] = (uint8_t)((mac_l) & 0xff);
	}

	/* MAC address is not set so try to read from EEPROM, if that fails generate
	 * a random MAC address.
	 */
	if (!ETHER_IS_VALID(sc->sc_ue.ue_eaddr)) {
		if ((lan78xx_eeprom_read(sc, LAN78XX_E2P_MAC_OFFSET, sc->sc_ue.ue_eaddr, ETHER_ADDR_LEN) == 0) ||
			(lan78xx_otp_read(sc, LAN78XX_OTP_MAC_OFFSET, sc->sc_ue.ue_eaddr, ETHER_ADDR_LEN) == 0)) {
			if(ETHER_IS_VALID(sc->sc_ue.ue_eaddr)) {
				lan78xx_dbg_printf(sc, "MAC read from EEPROM\n");
			} else {
				lan78xx_dbg_printf(sc, "MAC assigned randomly\n");
				read_random(sc->sc_ue.ue_eaddr, ETHER_ADDR_LEN);
				sc->sc_ue.ue_eaddr[0] &= ~0x01;		/* unicast */
				sc->sc_ue.ue_eaddr[0] |=  0x02;		/* locally administered */
			}
		} else {
			lan78xx_dbg_printf(sc, "MAC assigned randomly\n");
			arc4rand(sc->sc_ue.ue_eaddr, ETHER_ADDR_LEN, 0);
			sc->sc_ue.ue_eaddr[0] &= ~0x01;		/* unicast */
			sc->sc_ue.ue_eaddr[0] |=  0x02;		/* locally administered */
		}
	} else {
		lan78xx_dbg_printf(sc, "MAC assigned from registers\n");
	}
	
	/* Initialise the chip for the first time */
	lan78xx_chip_init(sc);
}

/**
 *	lan78xx_attach_post_sub - Called after the driver attached to the USB interface
 *	@ue: the USB ethernet device
 *
 *	Most of this is boilerplate code and copied from the base USB ethernet
 *	driver.  It has been overriden so that we can indicate to the system that
 *	the chip supports H/W checksumming.
 *
 *	RETURNS:
 *	Returns 0 on success or a negative error code.
 */
#if __FreeBSD_version > 1000000
static int
lan78xx_attach_post_sub(struct usb_ether *ue)
{
	struct lan78xx_softc *sc;
	struct ifnet *ifp;
	int error;

	sc = uether_getsc(ue);
	lan78xx_dbg_printf(sc, "Calling lan78xx_attach_post_sub.\n");
	ifp = ue->ue_ifp;
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ifp->if_start = uether_start;
	ifp->if_ioctl = lan78xx_ioctl;
	ifp->if_init = uether_init;
	IFQ_SET_MAXLEN(&ifp->if_snd, ifqmaxlen);
	ifp->if_snd.ifq_drv_maxlen = ifqmaxlen;
	IFQ_SET_READY(&ifp->if_snd);

	/*
	 * The chip supports TCP/UDP checksum offloading on TX and RX paths, however
	 * currently only RX checksum is supported in the driver (see top of file).
	 */
	ifp->if_hwassist = 0;
	if (LAN78XX_DEFAULT_RX_CSUM_ENABLE)
		ifp->if_capabilities |= IFCAP_RXCSUM;

	if (LAN78XX_DEFAULT_TX_CSUM_ENABLE)
		ifp->if_capabilities |= IFCAP_TXCSUM;

	/* 
	 * In the Linux driver they also enable scatter/gather (NETIF_F_SG) here,
	 * that's something related to socket buffers used in Linux. FreeBSD doesn't
	 * have that as an interface feature.
	 */

	if (LAN78XX_DEFAULT_TSO_CSUM_ENABLE)
		ifp->if_capabilities |= IFCAP_TSO4 | IFCAP_TSO6;


	/* TX checksuming is disabled (for now?)
	ifp->if_capabilities |= IFCAP_TXCSUM;
	ifp->if_capenable |= IFCAP_TXCSUM;
	ifp->if_hwassist = CSUM_TCP | CSUM_UDP;
	*/

	ifp->if_capenable = ifp->if_capabilities;

	mtx_lock(&Giant);
	error = mii_attach(ue->ue_dev, &ue->ue_miibus, ifp,
		uether_ifmedia_upd, ue->ue_methods->ue_mii_sts,
		BMSR_DEFCAPMASK, sc->sc_phyno, MII_OFFSET_ANY, 0);
	mtx_unlock(&Giant);

	return 0;
}
#endif

/**
 *	lan78xx_start - Starts communication with the LAN78XX95xx chip
 *	@ue: USB ether interface
 *
 *	
 *
 */
static void
lan78xx_start(struct usb_ether *ue)
{
	struct lan78xx_softc *sc = uether_getsc(ue);

	/*
	 * start the USB transfers, if not already started:
	 */
	usbd_transfer_start(sc->sc_xfer[LAN78XX_BULK_DT_RD]);
	usbd_transfer_start(sc->sc_xfer[LAN78XX_BULK_DT_WR]);
}

/**
 *	lan78xx_ioctl - ioctl function for the device
 *	@ifp: interface pointer
 *	@cmd: the ioctl command
 *	@data: data passed in the ioctl call, typically a pointer to struct ifreq.
 *	
 *	The ioctl routine is overridden to detect change requests for the H/W
 *	checksum capabilities.
 *
 *	RETURNS:
 *	0 on success and an error code on failure.
 */
static int
lan78xx_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct usb_ether *ue = ifp->if_softc;
	struct lan78xx_softc *sc;
	struct ifreq *ifr;
	int rc;
	int mask;
	int reinit;
	
	if (cmd == SIOCSIFCAP) {

		sc = uether_getsc(ue);
		ifr = (struct ifreq *)data;

		LAN78XX_LOCK(sc);

		rc = 0;
		reinit = 0;

		mask = ifr->ifr_reqcap ^ ifp->if_capenable;

		/* Modify the RX CSUM enable bits */
		if ((mask & IFCAP_RXCSUM) != 0 &&
			(ifp->if_capabilities & IFCAP_RXCSUM) != 0) {
			ifp->if_capenable ^= IFCAP_RXCSUM;
			
			if (ifp->if_drv_flags & IFF_DRV_RUNNING) {
				ifp->if_drv_flags &= ~IFF_DRV_RUNNING;
				reinit = 1;
			}
		}
		
		LAN78XX_UNLOCK(sc);
		if (reinit)
#if __FreeBSD_version > 1000000
			uether_init(ue);
#else
			ifp->if_init(ue);
#endif

	} else {
		rc = uether_ioctl(ifp, cmd, data);
	}

	return (rc);
}

/**
 *	lan78xx_reset - Reset the SMSC chip
 *	@sc: device soft context
 *
 *	LOCKING:
 *	Should be called with the SMSC lock held.
 */
static void
lan78xx_reset(struct lan78xx_softc *sc)
{
	struct usb_config_descriptor *cd;
	usb_error_t err;

	cd = usbd_get_config_descriptor(sc->sc_ue.ue_udev);

	err = usbd_req_set_config(sc->sc_ue.ue_udev, &sc->sc_mtx,
							  cd->bConfigurationValue);
	if (err)
		lan78xx_warn_printf(sc, "reset failed (ignored)\n");

	/* Wait a little while for the chip to get its brains in order. */
	uether_pause(&sc->sc_ue, hz / 100);

	/* Reinitialize controller to achieve full reset. */
	lan78xx_chip_init(sc);
}

/**
 * lan78xx_set_addr_filter
 *
 *	@sc: device soft context
 *	@index: index of the entry to the perfect address table
 *	@addr: address to be written
 *
 */
static void
lan78xx_set_addr_filter(struct lan78xx_softc *sc, int index, uint8_t addr[ETHER_ADDR_LEN])
{
	uint32_t tmp;

	if ((sc) && (index > 0) && (index < LAN78XX_NUM_PFILTER_ADDRS_)) {
		tmp = addr[3];
		tmp |= addr[2] | (tmp << 8);
		tmp |= addr[1] | (tmp << 8);
		tmp |= addr[0] | (tmp << 8);
		sc->sc_pfilter_table[index][1] = tmp;
		tmp = addr[5];
		tmp |= addr[4] | (tmp << 8);
		tmp |= LAN78XX_PFILTER_ADDR_VALID_ | LAN78XX_PFILTER_ADDR_TYPE_DST_;
		sc->sc_pfilter_table[index][0] = tmp;	
	}
}

/**
 *	lan78xx_dataport_write - write to the selected RAM
 *	@sc: The device soft context.
 *	@ram_select: Select which RAM to access.
 *	@addr: Starting address to write to.
 *	@buf: word-sized buffer to write to RAM, starting at @addr.
 *	@length: length of @buf
 *
 *
 *	RETURNS:
 *	0 if write successful.
 */

static int
lan78xx_dataport_write(struct lan78xx_softc *sc, uint32_t ram_select, uint32_t addr,
									uint32_t length, uint32_t *buf)
{
	uint32_t dp_sel;
	int i, ret;

	LAN78XX_LOCK_ASSERT(sc, MA_OWNED);
	ret = lan78xx_wait_for_bits(sc, LAN78XX_DP_SEL, LAN78XX_DP_SEL_DPRDY_);
	if (ret < 0)
		goto done;

	ret = lan78xx_read_reg(sc, LAN78XX_DP_SEL, &dp_sel);

	dp_sel &= ~LAN78XX_DP_SEL_RSEL_MASK_;
	dp_sel |= ram_select;

	ret = lan78xx_write_reg(sc, LAN78XX_DP_SEL, dp_sel);

	for (i = 0; i < length; i++) {
		ret = lan78xx_write_reg(sc, LAN78XX_DP_ADDR, addr + i);

		ret = lan78xx_write_reg(sc, LAN78XX_DP_DATA, buf[i]);

		ret = lan78xx_write_reg(sc, LAN78XX_DP_CMD, LAN78XX_DP_CMD_WRITE_);

		ret = lan78xx_wait_for_bits(sc, LAN78XX_DP_SEL, LAN78XX_DP_SEL_DPRDY_);
		if (ret != 0)
			goto done;
	}

done:
	return ret;
}

/**
 * lan78xx_multicast_write
 * @sc: device's soft context
 *
 * Writes perfect addres filters and hash address filters to their 
 * corresponding registers and RAMs.
 *
 */

static void
lan78xx_multicast_write(struct lan78xx_softc *sc)
{
	int i, ret;
	lan78xx_dataport_write(sc, LAN78XX_DP_SEL_RSEL_VLAN_DA_,
					LAN78XX_DP_SEL_VHF_VLAN_LEN, LAN78XX_DP_SEL_VHF_HASH_LEN,
					sc->sc_mchash_table);
	
	for (i = 1; i < LAN78XX_NUM_PFILTER_ADDRS_; i++) {
		ret = lan78xx_write_reg(sc, LAN78XX_PFILTER_HI(i), 0);
		ret = lan78xx_write_reg(sc, LAN78XX_PFILTER_LO(i), 
						sc->sc_pfilter_table[i][1]);
		ret = lan78xx_write_reg(sc, LAN78XX_PFILTER_HI(i), 
						sc->sc_pfilter_table[i][0]);
	}
}

/**
 *	lan78xx_hash - Calculate the hash of a mac address
 *	@addr: The mac address to calculate the hash on
 *
 *	This function is used when configuring a range of m'cast mac addresses to
 *	filter on.	The hash of the mac address is put in the device's mac hash
 *	table.
 *
 *	RETURNS:
 *	Returns a value from 0-63 value which is the hash of the mac address.
 */
static inline uint32_t
lan78xx_hash(uint8_t addr[ETHER_ADDR_LEN])
{
	return (ether_crc32_be(addr, ETHER_ADDR_LEN) >> 26) & 0x3f;
}

/**
 *	lan78xx_setmulti - Setup multicast
 *	@ue: usb ethernet device context
 *
 *	Tells the device to either accept frames with a multicast mac address, a
 *	select group of m'cast mac addresses or just the devices mac address.
 *
 *	LOCKING:
 *	Should be called with the LAN78XX lock held.
 */
static void
lan78xx_setmulti(struct usb_ether *ue)
{
	struct lan78xx_softc *sc = uether_getsc(ue);
	struct ifnet *ifp = uether_getifp(ue);
	uint8_t i, *addr;
	struct ifmultiaddr *ifma;

	LAN78XX_LOCK_ASSERT(sc, MA_OWNED);

	sc->sc_rfe_ctl &= ~(LAN78XX_RFE_CTL_UCAST_EN_ | LAN78XX_RFE_CTL_MCAST_EN_ |
		LAN78XX_RFE_CTL_DA_PERFECT_ | LAN78XX_RFE_CTL_MCAST_HASH_);

	/* Initializing hash filter table */
	for (i = 0; i < LAN78XX_DP_SEL_VHF_HASH_LEN; i++)
		sc->sc_mchash_table[i] = 0;

	/* Initializing perfect filter table */
	for (i = 1; i < LAN78XX_NUM_PFILTER_ADDRS_; i++) {
		sc->sc_pfilter_table[i][0] =
		sc->sc_pfilter_table[i][1] = 0;
	}

	sc->sc_rfe_ctl |= LAN78XX_RFE_CTL_BCAST_EN_;

	if (ifp->if_flags & IFF_PROMISC) {
		lan78xx_dbg_printf(sc, "promiscuous mode enabled\n");
		sc->sc_rfe_ctl |= LAN78XX_RFE_CTL_MCAST_EN_ | LAN78XX_RFE_CTL_UCAST_EN_;
	} else if (ifp->if_flags & IFF_ALLMULTI){
		lan78xx_dbg_printf(sc, "receive all multicast enabled\n");
		sc->sc_rfe_ctl |= LAN78XX_RFE_CTL_MCAST_EN_;
	} else {
		/* Take the lock of the mac address list before hashing each of them */
		if_maddr_rlock(ifp);
		if (!TAILQ_EMPTY(&ifp->if_multiaddrs)) {
			i = 1;

			TAILQ_FOREACH(ifma, &ifp->if_multiaddrs, ifma_link) {
				/* first we fill up the perfect address table */
				addr = LLADDR((struct sockaddr_dl *)ifma->ifma_addr);
				if (i < 33) {
					lan78xx_set_addr_filter(sc, i, addr);
				} else {
					uint32_t bitnum = lan78xx_hash(addr);
					sc->sc_mchash_table[bitnum / 32] |=
									(1 << (bitnum % 32));
					sc->sc_rfe_ctl |= LAN78XX_RFE_CTL_MCAST_HASH_;
				}
				i++;
			}
		}
		if_maddr_runlock(ifp);
		lan78xx_multicast_write(sc);
	}
	lan78xx_write_reg(sc, LAN78XX_RFE_CTL, sc->sc_rfe_ctl);
}

/**
 *	lan78xx_setpromisc - Enables/disables promiscuous mode
 *	@ue: usb ethernet device context
 *
 *	LOCKING:
 *	Should be called with the LAN78XX lock held.
 */
static void
lan78xx_setpromisc(struct usb_ether *ue)
{
	struct lan78xx_softc *sc = uether_getsc(ue);
	struct ifnet *ifp = uether_getifp(ue);

	lan78xx_dbg_printf(sc, "promiscuous mode %sabled\n",
					(ifp->if_flags & IFF_PROMISC) ? "en" : "dis");

	LAN78XX_LOCK_ASSERT(sc, MA_OWNED);

	if (ifp->if_flags & IFF_PROMISC)
		sc->sc_rfe_ctl |= LAN78XX_RFE_CTL_MCAST_EN_ | LAN78XX_RFE_CTL_UCAST_EN_;
	else
		sc->sc_rfe_ctl &= ~(LAN78XX_RFE_CTL_MCAST_EN_);

	lan78xx_write_reg(sc, LAN78XX_RFE_CTL, sc->sc_rfe_ctl);
}

/**
 *	lan78xx_sethwcsum - Enable or disable H/W UDP and TCP checksumming
 *	@sc: driver soft context
 *
 *	LOCKING:
 *	Should be called with the LAN78XX lock held.
 *
 *	RETURNS:
 *	Returns 0 on success or a negative error code.
 */
static int lan78xx_sethwcsum(struct lan78xx_softc *sc)
{
	struct ifnet *ifp = uether_getifp(&sc->sc_ue);
	int err;

	if (!ifp)
		return (-EIO);

	LAN78XX_LOCK_ASSERT(sc, MA_OWNED);

	if (ifp->if_capabilities & IFCAP_RXCSUM) {
		sc->sc_rfe_ctl |= LAN78XX_RFE_CTL_IGMP_COE_ | LAN78XX_RFE_CTL_ICMP_COE_;
		sc->sc_rfe_ctl |= LAN78XX_RFE_CTL_TCPUDP_COE_ | LAN78XX_RFE_CTL_IP_COE_;
	} else {
		sc->sc_rfe_ctl &= ~(LAN78XX_RFE_CTL_IGMP_COE_ | LAN78XX_RFE_CTL_ICMP_COE_);
		sc->sc_rfe_ctl &= ~(LAN78XX_RFE_CTL_TCPUDP_COE_ | LAN78XX_RFE_CTL_IP_COE_);
	}

	sc->sc_rfe_ctl &= ~LAN78XX_RFE_CTL_VLAN_FILTER_;

	err = lan78xx_write_reg(sc, LAN78XX_RFE_CTL, sc->sc_rfe_ctl);

	if (err != 0) {
		lan78xx_warn_printf(sc, "failed to write LAN78XX_RFE_CTL (err=%d)\n", err);
		return (err);
	}

	return (0);
}

/**
 *	lan78xx_ifmedia_upd - Set media options
 *	@ifp: interface pointer
 *
 *	Basically boilerplate code that simply calls the mii functions to set the
 *	media options.
 *
 *	LOCKING:
 *	The device lock must be held before this function is called.
 *
 *	RETURNS:
 *	Returns 0 on success or a negative error code.
 */
static int
lan78xx_ifmedia_upd(struct ifnet *ifp)
{
	struct lan78xx_softc *sc = ifp->if_softc;
	lan78xx_dbg_printf(sc, "Calling lan78xx_ifmedia_upd.\n");
	struct mii_data *mii = uether_getmii(&sc->sc_ue);
	struct mii_softc *miisc;
	int err;

	LAN78XX_LOCK_ASSERT(sc, MA_OWNED);

	LIST_FOREACH(miisc, &mii->mii_phys, mii_list)
		PHY_RESET(miisc);
	err = mii_mediachg(mii);
	return (err);
}

/**
 *	lan78xx_init - Initialises the LAN95xx chip
 *	@ue: USB ether interface
 *
 *	Called when the interface is brought up (i.e. ifconfig ue0 up), this
 *	initialise the interface and the rx/tx pipes.
 *
 *	LOCKING:
 *	Should be called with the LAN78XX lock held.
 */
static void
lan78xx_init(struct usb_ether *ue)
{
	struct lan78xx_softc *sc = uether_getsc(ue);
	lan78xx_dbg_printf(sc, "Calling lan78xx_init.\n");
	struct ifnet *ifp = uether_getifp(ue);
	LAN78XX_LOCK_ASSERT(sc, MA_OWNED);

	if (lan78xx_setmacaddress(sc, IF_LLADDR(ifp)))
		lan78xx_dbg_printf(sc, "setting MAC address failed\n");

	if ((ifp->if_drv_flags & IFF_DRV_RUNNING) != 0)
		return;

	/* Cancel pending I/O */
	lan78xx_stop(ue);
#if __FreeBSD_version <= 1000000
	/* On earlier versions this was the first place we could tell the system
	 * that we supported h/w csuming, however this is only called after the
	 * the interface has been brought up - not ideal.  
	 */

	ifp->if_hwassist = 0;
	if (LAN78XX_DEFAULT_RX_CSUM_ENABLE)
		ifp->if_capabilities |= IFCAP_RXCSUM;

	if (LAN78XX_DEFAULT_TX_CSUM_ENABLE)
		ifp->if_capabilities |= IFCAP_TXCSUM;
	/* TX checksuming is disabled for now
	ifp->if_capabilities |= IFCAP_TXCSUM;
	ifp->if_capenable |= IFCAP_TXCSUM;
	ifp->if_hwassist = CSUM_TCP | CSUM_UDP;
	*/
	
	ifp->if_capenable = ifp->if_capabilities;
#endif

	/* Reset the ethernet interface. */
	lan78xx_reset(sc);

	/* Load the multicast filter. */
	lan78xx_setmulti(ue);

	/* TCP/UDP checksum offload engines. */
	lan78xx_sethwcsum(sc);

	usbd_xfer_set_stall(sc->sc_xfer[LAN78XX_BULK_DT_WR]);

	/* Indicate we are up and running. */
	ifp->if_drv_flags |= IFF_DRV_RUNNING;

	/* Switch to selected media. */
	lan78xx_ifmedia_upd(ifp);
	lan78xx_start(ue);
}

/**
 *	lan78xx_stop - Stops communication with the LAN78xx chip
 *	@ue: USB ether interface
 *
 *	
 *
 */
static void
lan78xx_stop(struct usb_ether *ue)
{
	struct lan78xx_softc *sc = uether_getsc(ue);
	struct ifnet *ifp = uether_getifp(ue);

	LAN78XX_LOCK_ASSERT(sc, MA_OWNED);

	ifp->if_drv_flags &= ~(IFF_DRV_RUNNING | IFF_DRV_OACTIVE);
	sc->sc_flags &= ~LAN78XX_FLAG_LINK;

	/*
	 * stop all the transfers, if not already stopped:
	 */
	usbd_transfer_stop(sc->sc_xfer[LAN78XX_BULK_DT_WR]);
	usbd_transfer_stop(sc->sc_xfer[LAN78XX_BULK_DT_RD]);
}


/**
 *	lan78xx_tick - Called periodically to monitor the state of the LAN95xx chip
 *	@ue: USB ether interface
 *
 *	Simply calls the mii status functions to check the state of the link.
 *
 *	LOCKING:
 *	Should be called with the LAN78XX lock held.
 */
static void
lan78xx_tick(struct usb_ether *ue)
{

	struct lan78xx_softc *sc = uether_getsc(ue);
	struct mii_data *mii = uether_getmii(&sc->sc_ue);

	LAN78XX_LOCK_ASSERT(sc, MA_OWNED);

	mii_tick(mii);
	if ((sc->sc_flags & LAN78XX_FLAG_LINK) == 0) {
		lan78xx_miibus_statchg(ue->ue_dev);
		if ((sc->sc_flags & LAN78XX_FLAG_LINK) != 0)
			lan78xx_start(ue);
	}
}

/**
 *	lan78xx_ifmedia_sts - Report current media status
 *	@ifp: inet interface pointer
 *	@ifmr: interface media request
 *
 *	Basically boilerplate code that simply calls the mii functions to get the
 *	media status.
 *
 *	LOCKING:
 *	Internally takes and releases the device lock.
 */
static void
lan78xx_ifmedia_sts(struct ifnet *ifp, struct ifmediareq *ifmr)
{
	struct lan78xx_softc *sc = ifp->if_softc;
	struct mii_data *mii = uether_getmii(&sc->sc_ue);

	LAN78XX_LOCK(sc);
	mii_pollstat(mii);
	ifmr->ifm_active = mii->mii_media_active;
	ifmr->ifm_status = mii->mii_media_status;
	LAN78XX_UNLOCK(sc);
}

/**
 *	lan78xx_probe - Probe the interface. 
 *	@dev: lan78xx device handle
 *
 *	Checks if the device is a match for this driver.
 *
 *	RETURNS:
 *	Returns 0 on success or an error code on failure.
 */
static int
lan78xx_probe(device_t dev)
{
	struct usb_attach_arg *uaa = device_get_ivars(dev);

	if (uaa->usb_mode != USB_MODE_HOST)
		return (ENXIO);
	if (uaa->info.bConfigIndex != LAN78XX_CONFIG_INDEX)
		return (ENXIO);
	if (uaa->info.bIfaceIndex != LAN78XX_IFACE_IDX)
		return (ENXIO);
	return (usbd_lookup_id_by_uaa(lan78xx_devs, sizeof(lan78xx_devs), uaa));
}

/**
 *	lan78xx_attach - Attach the interface. 
 *	@dev: lan78xx device handle
 *
 *	Allocate softc structures, do ifmedia setup and ethernet/BPF attach.
 *
 *	RETURNS:
 *	Returns 0 on success or a negative error code.
 */
static int
lan78xx_attach(device_t dev)
{
	struct usb_attach_arg *uaa = device_get_ivars(dev);
	struct lan78xx_softc *sc = device_get_softc(dev);
	struct usb_ether *ue = &sc->sc_ue;
	uint8_t iface_index;
	int err;

	sc->sc_flags = USB_GET_DRIVER_INFO(uaa);

	device_set_usb_desc(dev);

	mtx_init(&sc->sc_mtx, device_get_nameunit(dev), NULL, MTX_DEF);

	/* Setup the endpoints for the Microchip LAN78xx device(s) */
	iface_index = LAN78XX_IFACE_IDX;
	err = usbd_transfer_setup(uaa->device, &iface_index, sc->sc_xfer,
							  lan78xx_config, LAN78XX_N_TRANSFER, sc, &sc->sc_mtx);
	if (err) {
		device_printf(dev, "error: allocating USB transfers failed\n");
		goto detach;
	}

	ue->ue_sc = sc;
	ue->ue_dev = dev;
	ue->ue_udev = uaa->device;
	ue->ue_mtx = &sc->sc_mtx;
	ue->ue_methods = &lan78xx_ue_methods;

	err = uether_ifattach(ue);
	if (err) {
		device_printf(dev, "error: could not attach interface\n");
		goto detach;
	}
	return (0);			/* success */

detach:
	lan78xx_detach(dev);
	return (ENXIO);		/* failure */
}

/**
 *	lan78xx_detach - Detach the interface. 
 *	@dev: lan78xx device handle
 *
 *	RETURNS:
 *	Returns 0.
 */
static int
lan78xx_detach(device_t dev)
{
	
	struct lan78xx_softc *sc = device_get_softc(dev);
	struct usb_ether *ue = &sc->sc_ue;

	usbd_transfer_unsetup(sc->sc_xfer, LAN78XX_N_TRANSFER);
	uether_ifdetach(ue);
	mtx_destroy(&sc->sc_mtx);

	return (0);
}

static device_method_t lan78xx_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe, lan78xx_probe),
	DEVMETHOD(device_attach, lan78xx_attach),
	DEVMETHOD(device_detach, lan78xx_detach),

	///* bus interface */
	DEVMETHOD(bus_print_child, bus_generic_print_child),
	DEVMETHOD(bus_driver_added, bus_generic_driver_added),

	///* MII interface */
	DEVMETHOD(miibus_readreg, lan78xx_miibus_readreg),
	DEVMETHOD(miibus_writereg, lan78xx_miibus_writereg),
	DEVMETHOD(miibus_statchg, lan78xx_miibus_statchg),

	DEVMETHOD_END
};

static driver_t lan78xx_driver = {
	.name = "lan78xx",
	.methods = lan78xx_methods,
	.size = sizeof(struct lan78xx_softc),
};

static devclass_t lan78xx_devclass;

DRIVER_MODULE(lan78xx, uhub, lan78xx_driver, lan78xx_devclass, NULL, 0);
DRIVER_MODULE(miibus, lan78xx, miibus_driver, miibus_devclass, 0, 0);
MODULE_DEPEND(lan78xx, uether, 1, 1, 1);
MODULE_DEPEND(lan78xx, usb, 1, 1, 1);
MODULE_DEPEND(lan78xx, ether, 1, 1, 1);
MODULE_DEPEND(lan78xx, miibus, 1, 1, 1);
MODULE_VERSION(lan78xx, 1);
USB_PNP_HOST_INFO(lan78xx_devs);

