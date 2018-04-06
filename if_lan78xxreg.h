#define LAN78XX_ID_REV           (0x000)

#define INT_STS          (0x00C)
#define LAN78XX_HW_CFG           (0x010)
#define LAN_78XX_PMT_CTL          (0x014)
#define GPIO_CFG0        (0x018)
#define GPIO_CFG1        (0x01C)
#define GPIO_WAKE        (0x020)
#define DP_SEL           (0x024)
#define DP_CMD           (0x028)
#define DP_ADDR          (0x02C)
#define DP_DATA          (0x030)

#define LAN78XX_E2P_CMD          (0x040)
#define LAN78XX_E2P_DATA         (0x044)

#define LAN78XX_OTP_BASE_ADDR	 (0x01000)

#define LAN78XX_OTP_PWR_DN 		 		 (LAN78XX_OTP_BASE_ADDR + 4 * 0x00)
#define LAN78XX_OTP_PWR_DN_PWRDN_N 		 (0x01)

#define LAN78XX_OTP_ADDR1 		 		 (LAN78XX_OTP_BASE_ADDR + 4 * 0x01)
#define LAN78XX_OTP_ADDR1_15_11 		 		 (0x1F)

#define LAN78XX_OTP_ADDR2 		 		 (LAN78XX_OTP_BASE_ADDR + 4 * 0x02)
#define LAN78XX_OTP_ADDR2_10_3					 (0xFF)

#define LAN78XX_OTP_ADDR3 		 		 (LAN78XX_OTP_BASE_ADDR + 4 * 0x03)
#define LAN78XX_OTP_ADDR3_2_0 		 		 (0x03)

#define LAN78XX_OTP_RD_DATA				 (LAN78XX_OTP_BASE_ADDR + 4 * 0x06)

#define LAN78XX_OTP_FUNC_CMD 				 (LAN78XX_OTP_BASE_ADDR + 4 * 0x08)
#define LAN78XX_OTP_FUNC_CMD_RESET				 (0x04)
#define LAN78XX_OTP_FUNC_CMD_PROGRAM_			 (0x02)
#define LAN78XX_OTP_FUNC_CMD_READ_				 (0x01)

#define LAN78XX_OTP_MAC_OFFSET 	 		 		(0x01)
#define LAN78XX_OTP_INDICATOR_OFFSET			(0x00)
#define LAN78XX_OTP_INDICATOR_1					(0xF3)
#define LAN78XX_OTP_INDICATOR_2					(0xF7)

#define LAN78XX_OTP_CMD_GO  			 (LAN78XX_OTP_BASE_ADDR + 4 * 0x0A)
#define LAN78XX_OTP_CMD_GO_GO_				 (0x01)

#define LAN78XX_OTP_STATUS 				 (LAN78XX_OTP_BASE_ADDR + 4 * 0x0A)
#define LAN78XX_OTP_STATUS_OTP_LOCK_ 		(0x10)
#define LAN78XX_OTP_STATUS_BUSY_			(0x01)

#define LAN78XX_E2P_MAC_OFFSET 	 		 (0x01)
#define LAN78XX_E2P_INDICATOR_OFFSET 	 (0x00)




#define BOS_ATTR         (0x050)
#define SS_ATTR          (0x054)
#define HS_ATTR          (0x058)
#define FS_ATTR          (0x05C)
#define STRNG_ATTR0      (0x060)
#define STRNG_ATTR1      (0x064)
#define FLAG_ATTR        (0x068)
#define SW_GP_1          (0x06C)
#define SW_GP_2          (0x070)
#define SW_GP_3          (0x074)
#define USB_CFG0         (0x080)
#define USB_CFG1         (0x084)
#define USB_CFG2         (0x088)
#define LAN78XX_BURST_CAP        (0x090)
#define LAN78XX_BULK_IN_DLY      (0x094)
#define INT_EP_CTL       (0x098)
#define PIPE_CTL         (0x09C)
#define U1_LATENCY       (0x0A0)
#define U2_LATENCY       (0x0A4)
#define USB_STATUS       (0x0A8)
#define RFE_CTL          (0x0B0)
#define VLAN_TYPE        (0x0B4)
#define FCT_RX_CTL       (0x0C0)
#define FCT_TX_CTL       (0x0C4)
#define FCT_RX_FIFO_END  (0x0C8)
#define FCT_TX_FIFO_END  (0x0CC)
#define FCT_FLOW         (0x0D0)
#define RX_DP_STOR       (0x0D4)
#define TX_DP_STOR       (0x0D8)
#define LTM_BELT_IDLE0   (0x0E0)
#define LTM_BELT_IDLE1   (0x0E4)
#define LTM_BELT_ACT0    (0x0E8)
#define LTM_BELT_ACT1    (0x0EC)
#define LTM_INACTIVE0    (0x0F0)
#define LTM_INACTIVE1    (0x0F4)
#define MAC_CR           (0x100)
#define MAC_RX           (0x104)
#define MAC_TX           (0x108)
#define FLOW             (0x10C)
#define RAND_SEED        (0x110)
#define ERR_STS          (0x114)
#define LAN78XX_RX_ADDRH         (0x118)
#define LAN78XX_RX_ADDRL         (0x11C)
#define MII_ACCESS       (0x120)
#define MII_DATA         (0x124)
#define EEE_TX_LPI_REQUEST_DELAY_CNT  (0x130)
#define EEE_TW_TX_SYS                 (0x134)
#define EEE_TX_LPI_AUTO_REMOVAL_DELAY (0x138)
#define WUCSR1                      (0x140)
#define WK_SRC                      (0x144)
 /*
  * wake up config registers: 32 total
  * range:0x150 - 0x1CC
  * WUF_CFGX: in the manual
  */
#define WUF_CFG_BASE         (0x150)
 /*
  * each wake up config registers has a 128bit byte-mask: 32 total
  * range: 0x200 - 0x3FC
  * it's basically 4 words
  * WUF_MASKX: in the manual
  */
#define WUF_MASK_BASE        (0x200)
 /*
  * mac address for perfect filtering:
  * range: 0x400 - 0x504
  * it's basically 4 words
  * ADDR_FILTx: in the manual
  */
#define ADDR_FILTx                  (0x400)
#define WUCSR2                      (0x600)

#define NSx_IPV6_ADDR_DEST_0          (0x610)
#define NSx_IPV6_ADDR_DEST_1          (0x614)
#define NSx_IPV6_ADDR_DEST_2          (0x618)
#define NSx_IPV6_ADDR_DEST_3          (0x61C)

#define NSx_IPV6_ADDR_SRC_0          (0x620)
#define NSx_IPV6_ADDR_SRC_1          (0x624)
#define NSx_IPV6_ADDR_SRC_2          (0x628)
#define NSx_IPV6_ADDR_SRC_3          (0x62C)

#define NSx_ICMPV6_ADDR0_0          (0x630)
#define NSx_ICMPV6_ADDR0_1          (0x634)
#define NSx_ICMPV6_ADDR0_2          (0x638)
#define NSx_ICMPV6_ADDR0_3          (0x63C)

#define NSx_ICMPV6_ADDR1_0          (0x640)
#define NSx_ICMPV6_ADDR1_1          (0x644)
#define NSx_ICMPV6_ADDR1_2          (0x648)
#define NSx_ICMPV6_ADDR1_3          (0x64C)

/*
 * same thing is mapped over range 0x650-ox68C idk why :/
 */

#define NSx_IPV6_ADDR_DEST          (0x650)
#define NSx_IPV6_ADDR_SRC           (0x660)
#define NSx_ICMPV6_ADDR0            (0x670)
#define NSx_ICMPV6_ADDR1            (0x680)

#define SYN_IPV4_ADDR_SRC           (0x690)
#define SYN_IPV4_ADDR_DEST          (0x694)
#define SYN_IPV4_TCP_PORTS          (0x698)

#define SYN_IPV6_ADDR_SRC_0           (0x69C)
#define SYN_IPV6_ADDR_SRC_1           (0x6A0)
#define SYN_IPV6_ADDR_SRC_2           (0x6A4)
#define SYN_IPV6_ADDR_SRC_3           (0x6A8)

#define SYN_IPV6_ADDR_DEST_0           (0x6AC)
#define SYN_IPV6_ADDR_DEST_1           (0x6B0)
#define SYN_IPV6_ADDR_DEST_2           (0x6B4)
#define SYN_IPV6_ADDR_DEST_3           (0x6B8)

#define SYN_IPV6_TCP_PORTS          (0x6BC)
#define ARP_SPA                     (0x6C0)
#define ARP_TPA                     (0x6C4)
#define PHY_DEV_ID                  (0x700)

/*
 * USB endpoints.
 */
enum {
	LAN78XX_BULK_DT_RD,
	LAN78XX_BULK_DT_WR,
	/* the LAN9514 device does support interrupt endpoints, however I couldn't
	 * get then to work reliably and since they are unneeded (poll the mii
	 * status) they are unused.
	 * LAN78XX_INTR_DT_WR,
	 * LAN78XX_INTR_DT_RD,
	 */
	LAN78XX_N_TRANSFER,
};

struct lan78xx_softc {
	struct usb_ether  sc_ue;
	struct mtx        sc_mtx;
	struct usb_xfer  *sc_xfer[LAN78XX_N_TRANSFER];
	int               sc_phyno;

	/* The following stores the settings in the mac control (MAC_CSR) register */
	uint32_t          sc_mac_csr;
	uint32_t          sc_rev_id;

	uint32_t          sc_flags;
#define	LAN78XX_FLAG_LINK      0x0001
#define	LAN_FLAG_LAN9514   0x1000	/* LAN9514 */
};

/* USB Vendor Requests */
#define LAN78XX_UR_WRITE_REG   0xA0
#define LAN78XX_UR_READ_REG    0xA1
#define LAN78XX_UR_GET_STATS   0xA2

#define	LAN78XX_CONFIG_INDEX	0	/* config number 1 */
#define	LAN78XX_IFACE_IDX		0

#ifndef _IF_LAN78XXREG_H_
#define _IF_LAN78XXREG_H_

#define	LAN78XX_LOCK(_sc)             mtx_lock(&(_sc)->sc_mtx)
#define	LAN78XX_UNLOCK(_sc)           mtx_unlock(&(_sc)->sc_mtx)
#define	LAN78XX_LOCK_ASSERT(_sc, t)   mtx_assert(&(_sc)->sc_mtx, t)

#endif  /* _IF_LAN78XXREG_H_ */

#define LAN78XX_E2P_INDICATOR 		(0xA5)

#define LAN78XX_E2P_CMD_BUSY        (0x1UL << 31)
#define LAN78XX_E2P_CMD_MASK        (0x7UL << 28)
#define LAN78XX_E2P_CMD_READ        (0x0UL << 28)
#define LAN78XX_E2P_CMD_WRITE       (0x3UL << 28)
#define LAN78XX_E2P_CMD_ERASE       (0x5UL << 28)
#define LAN78XX_E2P_CMD_RELOAD      (0x7UL << 28)
#define LAN78XX_E2P_CMD_TIMEOUT     (0x1UL << 10)
#define LAN78XX_E2P_CMD_ADDR_MASK   0x000001FFUL

#define LAN78XX_HW_CFG_MEF             (0x1UL << 4)
#define LAN78XX_HW_CFG_ETC             (0x1UL << 3)
#define LAN78XX_HW_CFG_LRST            (0x1UL << 1)    /* Lite reset */
#define LAN78XX_HW_CFG_SRST            (0x1UL << 0)

#define LAN78XX_PMT_CTL_PHY_RST        (0x1UL << 4)    /* PHY reset */

