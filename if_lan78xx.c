#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/stdint.h>
#include <sys/stddef.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/bus.h>
#include <sys/module.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/condvar.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/sx.h>
#include <sys/unistd.h>
#include <sys/callout.h>
#include <sys/malloc.h>
#include <sys/priv.h>
#include <sys/random.h>

#include <net/if.h>
#include <net/if_var.h>

#include <netinet/in.h>
#include <netinet/ip.h>

#include "opt_platform.h"

#ifdef FDT
#include <dev/fdt/fdt_common.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#endif

#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>
#include <dev/usb/usbdi_util.h>
#include "usbdevs.h"

#define	USB_DEBUG_VAR lan78xx_debug
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

	

#define USB_VENDOR_MICROCHIP  0x0424
#define USB_PRODUCT_MICROCHIP_LAN7800  0x7800

/*
 * Various supported device vendors/products.
 */
static const struct usb_device_id lan78xx_devs[] = {
#define	LAN78XX_DEV(p,i) { USB_VPI(USB_VENDOR_MICROCHIP, USB_PRODUCT_MICROCHIP_##p, i) }
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

static device_probe_t lan78xx_probe;
static device_attach_t lan78xx_attach;
static device_detach_t lan78xx_detach;

static usb_callback_t lan78xx_bulk_read_callback;
static usb_callback_t lan78xx_bulk_write_callback;

//static miibus_readreg_t lan78xx_miibus_readreg;
//static miibus_writereg_t lan78xx_miibus_writereg;
//static miibus_statchg_t lan78xx_miibus_statchg;

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
static void	lan78xx_ifmedia_sts(struct ifnet *, struct ifmediareq *);

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

//	/* The LAN78XX chip supports an interrupt endpoints, however they aren't
//	 * needed as we poll on the MII status.
//	 */
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
lan78xx_read_reg(struct lan78xx_softc *sc, uint32_t off, uint32_t *data) {
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
	int err;
	int locked;
	uint32_t val;
	uint16_t i;

	locked = mtx_owned(&sc->sc_mtx);
	if (!locked)
		LAN78XX_LOCK(sc);
	
	err = lan78xx_wait_for_bits(sc, LAN78XX_E2P_CMD, LAN78XX_E2P_CMD_BUSY);
	if (err != 0) {
		lan78xx_warn_printf(sc, "eeprom busy, failed to read data\n");
		goto done;
	}

	/* start reading the bytes, one at a time */
	for (i = 0; i < buflen; i++) {
	
		val = LAN78XX_E2P_CMD_BUSY | (LAN78XX_E2P_CMD_ADDR_MASK & (off + i));
		if ((err = lan78xx_write_reg(sc, LAN78XX_E2P_CMD, val)) != 0)
			goto done;
		
		start_ticks = (usb_ticks_t)ticks;
		do {
			if ((err = lan78xx_read_reg(sc, LAN78XX_E2P_CMD, &val)) != 0)
				goto done;
			if (!(val & LAN78XX_E2P_CMD_BUSY) || (val & LAN78XX_E2P_CMD_TIMEOUT))
				break;

			uether_pause(&sc->sc_ue, hz / 100);
		} while (((usb_ticks_t)(ticks - start_ticks)) < max_ticks);

		if (val & (LAN78XX_E2P_CMD_BUSY | LAN78XX_E2P_CMD_TIMEOUT)) {
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

	return (err);
}

/**
 *	lan78xx_eeprom_read - Reads the attached EEPROM, confirms that EEPROM is programmed
 *	@sc: soft context
 *	@off: the eeprom address offset
 *	@buf: stores the bytes
 *	@buflen: the number of bytes to read
 *
 *	Simply reads bytes from an attached eeprom (if present).
 *
 *	RETURNS:
 *	0 on success, or a USB_ERR_?? error code on failure.
 */
static int
lan78xx_eeprom_read(struct lan78xx_softc *sc, uint16_t off, uint8_t *buf, uint16_t buflen)
{
	uint8_t sig;
	int ret;
	
	printf("reading from eeprom\n");
	ret = lan78xx_eeprom_read_raw(sc, LAN78XX_E2P_INDICATOR_OFFSET, &sig, 1);
	printf("eeprom sig: %d\n", sig);

	if ((ret == 0) && (sig == LAN78XX_E2P_INDICATOR)) {
		ret = lan78xx_eeprom_read_raw(sc, off, buf, buflen);
		lan78xx_dbg_printf(sc, "EEPROM present");
		printf("EEPROM is present\n");
	} else {
		ret = -EINVAL;
		lan78xx_dbg_printf(sc, "EEPROM not present");
		printf("EEPROM is not present\n");
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
lan78xx_otp_read_raw(struct lan78xx_softc *sc, uint16_t off, uint8_t *buf, uint16_t buflen) {
	int locked, err;
	uint32_t val;
	uint16_t i;
	printf("lan78xx_otp_read_raw: begin\n");
	locked = mtx_owned(&sc->sc_mtx);
	if (!locked)
		LAN78XX_LOCK(sc);

	printf("reading LAN78XX_OTP_PWR_DN register\n");
	err = lan78xx_read_reg(sc, LAN78XX_OTP_PWR_DN, &val);
	printf("LAN78XX_OTP_PWR_DN: 0x%x\n", val);
	
	// checking if bit is set
	if (val & LAN78XX_OTP_PWR_DN_PWRDN_N) {
		// clearing it, then waiting for it to be cleared	
		printf("clearing LAN78XX_OTP_PWR_DN register\n");
		lan78xx_write_reg(sc, LAN78XX_OTP_PWR_DN, 0);
		printf("waiting to be cleared LAN78XX_OTP_PWR_DN register\n");
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
lan78xx_otp_read(struct lan78xx_softc *sc, uint16_t off, uint8_t *buf, uint16_t buflen) {
	uint8_t sig;
	int err;
	printf("reading from otp\n");

	err = lan78xx_otp_read_raw(sc, LAN78XX_OTP_INDICATOR_OFFSET, &sig, 1);
	printf("otp sig: %d\n", sig);
	if (err == 0) {
		if (sig == LAN78XX_OTP_INDICATOR_1) {
			printf("otp present: 1\n");
		} else if (sig == LAN78XX_OTP_INDICATOR_2) {
			printf("otp present: 2\n");
			off += 0x100;
		} else {
			printf("otp not present!\n");
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
 *	Should be called with the SMSC lock held.
 *
 *	RETURNS:
 *	Returns 0 on success or a negative error code.
 */
//static int
//lan78xx_setmacaddress(struct lan78xx_softc *sc, const uint8_t *addr)
//{
//	int err;
//	uint32_t val;
//
//	lan78xx_dbg_printf(sc, "setting mac address to %02x:%02x:%02x:%02x:%02x:%02x\n",
//	                addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
//
//	LAN78XX_LOCK_ASSERT(sc, MA_OWNED);
//
//	val = (addr[3] << 24) | (addr[2] << 16) | (addr[1] << 8) | addr[0];
//	if ((err = lan78xx_write_reg(sc, LAN78XX_RX_ADDRL, val)) != 0)
//		goto done;
//		
//	val = (addr[5] << 8) | addr[4];
//	err = lan78xx_write_reg(sc, LAN78XX_RX_ADDRH, val);
//	
//done:
//	return (err);
//}

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
	printf("lan78xx_chip_init: returning early\n");
	return 0;
//	int err;
//	int locked;
//	uint32_t reg_val;
//	int burst_cap;
//
//	locked = mtx_owned(&sc->sc_mtx);
//	if (!locked)
//		LAN78XX_LOCK(sc);
//
//	/* Enter H/W config mode */
//	lan78xx_write_reg(sc, LAN78XX_HW_CFG, LAN78XX_HW_CFG_LRST);
//
//	if ((err = lan78xx_wait_for_bits(sc, LAN78XX_HW_CFG, LAN78XX_HW_CFG_LRST)) != 0) {
//		lan78xx_warn_printf(sc, "timed-out waiting for reset to complete\n");
//		goto init_failed;
//	}
//
//	/* Reset the PHY */
//	lan78xx_write_reg(sc, LAN_78XX_PMT_CTL, LAN78XX_PMT_CTL_PHY_RST);
//
//	if ((err = lan78xx_wait_for_bits(sc, LAN_78XX_PMT_CTL, LAN78XX_PMT_CTL_PHY_RST)) != 0) {
//		lan78xx_warn_printf(sc, "timed-out waiting for phy reset to complete\n");
//		goto init_failed;
//	}
//
//	/* Set the mac address */
//	if ((err = lan78xx_setmacaddress(sc, sc->sc_ue.ue_eaddr)) != 0) {
//		lan78xx_warn_printf(sc, "failed to set the MAC address\n");
//		goto init_failed;
//	}
//
//	/* Don't know what the HW_CFG_BIR bit is, but following the reset sequence
//	 * as used in the Linux driver.
//	 */
//	if ((err = lan78xx_read_reg(sc, LAN78XX_HW_CFG, &reg_val)) != 0) {
//		lan78xx_warn_printf(sc, "failed to read LAN78XX_HW_CFG: %d\n", err);
//		goto init_failed;
//	}
//	reg_val |= SMSC_HW_CFG_BIR;
//	lan78xx_write_reg(sc, SMSC_HW_CFG, reg_val);
//
//	/* There is a so called 'turbo mode' that the linux driver supports, it
//	 * seems to allow you to jam multiple frames per Rx transaction.  By default
//	 * this driver supports that and therefore allows multiple frames per URB.
//	 *
//	 * The xfer buffer size needs to reflect this as well, therefore based on
//	 * the calculations in the Linux driver the RX bufsize is set to 18944,
//	 *     bufsz = (16 * 1024 + 5 * 512)
//	 *
//	 * Burst capability is the number of URBs that can be in a burst of data/
//	 * ethernet frames.
//	 */
//	switch(usbd_get_speed(sc->sc_ue.ue_udev)) {
//		case USB_SPEED_SUPER:	
//			burst_cap = 1024;
//			break;
//		case USB_SPEED_HIGH:	
//			burst_cap = 512;
//			break;
//		default:
//			burst_cap = 64;
//	}
//
//	lan78xx_write_reg(sc, LAN78XX_BURST_CAP, burst_cap);
//
//	/* Set the default bulk in delay (magic value from Linux driver) */
//	lan78xx_write_reg(sc, LAN78XX_BULK_IN_DLY, 0x00002000);
//
//	/*
//	 * Initialise the RX interface
//	 */
//	if ((err = lan78xx_read_reg(sc, LAN78XX_HW_CFG, &reg_val)) < 0) {
//		lan78xx_warn_printf(sc, "failed to read HW_CFG: (err = %d)\n", err);
//		goto init_failed;
//	}
//
//	/* Adjust the packet offset in the buffer (designed to try and align IP
//	 * header on 4 byte boundary)
//	 */
//	reg_val &= ~SMSC_HW_CFG_RXDOFF;
//	reg_val |= (ETHER_ALIGN << 9) & SMSC_HW_CFG_RXDOFF;
//	
//	/* The following setings are used for 'turbo mode', a.k.a multiple frames
//	 * per Rx transaction (again info taken form Linux driver).
//	 */
//	reg_val |= (SMSC_HW_CFG_MEF | SMSC_HW_CFG_BCE);
//
//	lan78xx_write_reg(sc, SMSC_HW_CFG, reg_val);
//
//	/* Clear the status register ? */
//	lan78xx_write_reg(sc, SMSC_INTR_STATUS, 0xffffffff);
//
//	/* Read and display the revision register */
//	if ((err = lan78xx_read_reg(sc, SMSC_ID_REV, &sc->sc_rev_id)) < 0) {
//		lan78xx_warn_printf(sc, "failed to read ID_REV (err = %d)\n", err);
//		goto init_failed;
//	}
//
//	device_printf(sc->sc_ue.ue_dev, "chip 0x%04lx, rev. %04lx\n", 
//	    (sc->sc_rev_id & SMSC_ID_REV_CHIP_ID_MASK) >> 16, 
//	    (sc->sc_rev_id & SMSC_ID_REV_CHIP_REV_MASK));
//
//	/* GPIO/LED setup */
//	reg_val = SMSC_LED_GPIO_CFG_SPD_LED | SMSC_LED_GPIO_CFG_LNK_LED | 
//	          SMSC_LED_GPIO_CFG_FDX_LED;
//	lan78xx_write_reg(sc, SMSC_LED_GPIO_CFG, reg_val);
//
//	/*
//	 * Initialise the TX interface
//	 */
//	lan78xx_write_reg(sc, SMSC_FLOW, 0);
//
//	lan78xx_write_reg(sc, SMSC_AFC_CFG, AFC_CFG_DEFAULT);
//
//	/* Read the current MAC configuration */
//	if ((err = lan78xx_read_reg(sc, SMSC_MAC_CSR, &sc->sc_mac_csr)) < 0) {
//		lan78xx_warn_printf(sc, "failed to read MAC_CSR (err=%d)\n", err);
//		goto init_failed;
//	}
//	
//	/* Vlan */
//	lan78xx_write_reg(sc, SMSC_VLAN1, (uint32_t)ETHERTYPE_VLAN);
//
//	/*
//	 * Initialise the PHY
//	 */
//	if ((err = lan78xx_phy_init(sc)) != 0)
//		goto init_failed;
//
//
//	/*
//	 * Start TX
//	 */
//	sc->sc_mac_csr |= SMSC_MAC_CSR_TXEN;
//	lan78xx_write_reg(sc, SMSC_MAC_CSR, sc->sc_mac_csr);
//	lan78xx_write_reg(sc, SMSC_TX_CFG, SMSC_TX_CFG_ON);
//
//	/*
//	 * Start RX
//	 */
//	sc->sc_mac_csr |= SMSC_MAC_CSR_RXEN;
//	lan78xx_write_reg(sc, SMSC_MAC_CSR, sc->sc_mac_csr);
//
//	if (!locked)
//		SMSC_UNLOCK(sc);
//
//	return (0);
//	
//init_failed:
//	if (!locked)
//		SMSC_UNLOCK(sc);
//
//	lan78xx_err_printf(sc, "lan78xx_chip_init failed (err=%d)\n", err);
//	return (err);
}


static void
lan78xx_bulk_read_callback(struct usb_xfer *xfer, usb_error_t error)
{
	// will figure out
}

static void
lan78xx_bulk_write_callback(struct usb_xfer *xfer, usb_error_t error)
{
	// will figure out
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

	lan78xx_dbg_printf(sc, "lan78xx_attach_post\n");

	/* Setup some of the basics */
	sc->sc_phyno = 1;

	/* Attempt to get the mac address, if an EEPROM is not attached this
	 * will just return FF:FF:FF:FF:FF:FF, so in such cases we invent a MAC
	 * address based on urandom.
	 */
	memset(sc->sc_ue.ue_eaddr, 0xff, ETHER_ADDR_LEN);

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
				printf("ether MAC is valid!\n");
			} else {
				printf("ether MAC is invalid!\n");
				read_random(sc->sc_ue.ue_eaddr, ETHER_ADDR_LEN);
				sc->sc_ue.ue_eaddr[0] &= ~0x01;     /* unicast */
				sc->sc_ue.ue_eaddr[0] |=  0x02;     /* locally administered */
			}
		}
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
	printf("lan78xx_attach_post_sub\n");
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
	return 0;
}

/**
 *	lan78xx_init - Initialises the LAN95xx chip
 *	@ue: USB ether interface
 *
 *	Called when the interface is brought up (i.e. ifconfig ue0 up), this
 *	initialise the interface and the rx/tx pipes.
 *
 *	LOCKING:
 *	Should be called with the SMSC lock held.
 */
static void
lan78xx_init(struct usb_ether *ue)
{
}

/**
 *	lan78xx_phy_init - Initialises the in-built SMSC phy
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
//static int
//lan78xx_phy_init(struct lan78xx_softc *sc)
//{
//	return 0;
//}


/**
 *	lan78xx_stop - Stops communication with the LAN95xx chip
 *	@ue: USB ether interface
 *
 *	
 *
 */
static void
lan78xx_stop(struct usb_ether *ue)
{
}


/**
 *	lan78xx_tick - Called periodically to monitor the state of the LAN95xx chip
 *	@ue: USB ether interface
 *
 *	Simply calls the mii status functions to check the state of the link.
 *
 *	LOCKING:
 *	Should be called with the SMSC lock held.
 */
static void
lan78xx_tick(struct usb_ether *ue)
{
}

/**
 *	lan78xx_setmulti - Setup multicast
 *	@ue: usb ethernet device context
 *
 *	Tells the device to either accept frames with a multicast mac address, a
 *	select group of m'cast mac addresses or just the devices mac address.
 *
 *	LOCKING:
 *	Should be called with the SMSC lock held.
 */
static void
lan78xx_setmulti(struct usb_ether *ue)
{
}

/**
 *	lan78xx_setpromisc - Enables/disables promiscuous mode
 *	@ue: usb ethernet device context
 *
 *	LOCKING:
 *	Should be called with the SMSC lock held.
 */
static void
lan78xx_setpromisc(struct usb_ether *ue)
{
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
	return 0;
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
	//DEVMETHOD(bus_print_child, bus_generic_print_child),
	//DEVMETHOD(bus_driver_added, bus_generic_driver_added),

	///* MII interface */
	//DEVMETHOD(miibus_readreg, lan78xx_miibus_readreg),
	//DEVMETHOD(miibus_writereg, lan78xx_miibus_writereg),
	//DEVMETHOD(miibus_statchg, lan78xx_miibus_statchg),

	DEVMETHOD_END
};

static driver_t lan78xx_driver = {
	.name = "lan78xx",
	.methods = lan78xx_methods,
	.size = sizeof(struct lan78xx_softc),
};

static devclass_t lan78xx_devclass;

DRIVER_MODULE(lan78xx, uhub, lan78xx_driver, lan78xx_devclass, NULL, 0);
//DRIVER_MODULE(miibus, lan78xx, miibus_driver, miibus_devclass, 0, 0);
MODULE_DEPEND(lan78xx, uether, 1, 1, 1);
MODULE_DEPEND(lan78xx, usb, 1, 1, 1);
MODULE_DEPEND(lan78xx, ether, 1, 1, 1);
//MODULE_DEPEND(lan78xx, miibus, 1, 1, 1);
MODULE_VERSION(lan78xx, 1);
USB_PNP_HOST_INFO(lan78xx_devs);

