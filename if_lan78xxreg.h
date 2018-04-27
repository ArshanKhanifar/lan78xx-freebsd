/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
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

/*
 * Definitions for the Microchip LAN78XX USB to ethernet controllers.
 *
 * This information was mostly brought from the LAN7800 manual. However,
 * some undocumented registers come from the lan78xx driver in Linux.
 *
 */

#ifndef _IF_LAN78REG_H_
#define _IF_LAN78REG_H_

/* USB Vendor Requests */

#define LAN78XX_UR_WRITE_REG	0xA0
#define LAN78XX_UR_READ_REG	0xA1
#define LAN78XX_UR_GET_STATS	0xA2

/* Device ID and revision register */

#define LAN78XX_ID_REV			0x000
#define LAN78XX_ID_REV_CHIP_ID_MASK_	0xFFFF0000UL
#define LAN78XX_ID_REV_CHIP_REV_MASK_	0x0000FFFFUL

/* Device interrupt status register. */

#define LAN78XX_INT_STS				0x00C
#define LAN78XX_INT_STS_CLEAR_ALL_		0xFFFFFFFFUL

/* Hardware Configuration Register. */

#define LAN78XX_HW_CFG			0x010
#define LAN78XX_HW_CFG_LED3_EN_		(0x1UL << 23)
#define LAN78XX_HW_CFG_LED2_EN_		(0x1UL << 22)
#define LAN78XX_HW_CFG_LED1_EN_		(0x1UL << 21)
#define LAN78XX_HW_CFG_LEDO_EN_		(0x1UL << 20)
#define LAN78XX_HW_CFG_MEF_		(0x1UL << 4)
#define LAN78XX_HW_CFG_ETC_		(0x1UL << 3)
#define LAN78XX_HW_CFG_LRST_		(0x1UL << 1)	/* Lite reset */
#define LAN78XX_HW_CFG_SRST_		(0x1UL << 0)	/* Soft reset */

/* Power Management Control Register. */

#define LAN78XX_PMT_CTL			0x014
#define LAN78XX_PMT_CTL_PHY_RST_	(0x1UL << 4)	/* PHY reset */
#define LAN78XX_PMT_CTL_WOL_EN_		(0x1UL << 3)	/* PHY wake-on-lan enable */
#define LAN78XX_PMT_CTL_PHY_WAKE_EN_	(0x1UL << 2)	/* PHY interrupt as a wake up event*/

/* GPIO Configuration 0 Register. */

#define GPIO_CFG0				0x018

/* GPIO Configuration 1 Register. */

#define GPIO_CFG1				0x01C

/* GPIO wake enable and polarity register. */

#define GPIO_WAKE				0x020

/* RX Command A */

#define LAN78XX_RX_CMD_A_RED_		(0x1UL << 22)	/* Receive Error Detected */
#define LAN78XX_RX_CMD_A_ICSM_		(0x1UL << 14)
#define LAN78XX_RX_CMD_A_LEN_MASK_	0x00003FFFUL

/* TX Command A */

#define LAN78XX_TX_CMD_A_LEN_MASK_	0x000FFFFFUL
#define LAN78XX_TX_CMD_A_FCS_		(0x1UL << 22)

/* Data Port Select Register */

#define LAN78XX_DP_SEL			0x024
#define LAN78XX_DP_SEL_DPRDY_		(0x1UL << 31)
#define LAN78XX_DP_SEL_RSEL_VLAN_DA_	(0x1UL << 0)	/* RFE VLAN and DA Hash Table */
#define LAN78XX_DP_SEL_RSEL_MASK_	0x0000000F
#define LAN78XX_DP_SEL_VHF_HASH_LEN	16
#define LAN78XX_DP_SEL_VHF_VLAN_LEN	128

/* Data Port Command Register */

#define LAN78XX_DP_CMD			0x028
#define LAN78XX_DP_CMD_WRITE_		(0x1UL << 0)		/* 1 for write */
#define LAN78XX_DP_CMD_READ_		(0x0UL << 0)		/* 0 for read */

/* Data Port Address Register */

#define LAN78XX_DP_ADDR		0x02C

/* Data Port Data Register */

#define LAN78XX_DP_DATA		0x030

/* EEPROM Command Register */

#define LAN78XX_E2P_CMD			0x040
#define LAN78XX_E2P_CMD_MASK_		0x70000000UL
#define LAN78XX_E2P_CMD_ADDR_MAS	0x000001FFUL
#define LAN78XX_E2P_CMD_BUSY_		(0x1UL << 31)
#define LAN78XX_E2P_CMD_READ_		(0x0UL << 28)
#define LAN78XX_E2P_CMD_WRITE_		(0x3UL << 28)
#define LAN78XX_E2P_CMD_ERASE_		(0x5UL << 28)
#define LAN78XX_E2P_CMD_RELOAD_		(0x7UL << 28)
#define LAN78XX_E2P_CMD_TIMEOUT_	(0x1UL << 10)
#define LAN78XX_E2P_MAC_OFFSET		0x01
#define LAN78XX_E2P_INDICATOR_OFFSET	0x00

/* EEPROM Data Register */

#define LAN78XX_E2P_DATA		0x044
#define LAN78XX_E2P_INDICATOR		0xA5	/* Indicates an EEPROM is present */

/* Packet sizes. */

#define LAN78XX_SS_USB_PKT_SIZE		1024
#define LAN78XX_HS_USB_PKT_SIZE		512
#define LAN78XX_FS_USB_PKT_SIZE		64

/* Receive Filtering Engine Control Register */

#define LAN78XX_RFE_CTL			0x0B0
#define LAN78XX_RFE_CTL_IGMP_COE_	(0x1U << 14)
#define LAN78XX_RFE_CTL_ICMP_COE_	(0x1U << 13)
#define LAN78XX_RFE_CTL_TCPUDP_COE_	(0x1U << 12)
#define LAN78XX_RFE_CTL_IP_COE_		(0x1U << 11)
#define LAN78XX_RFE_CTL_BCAST_EN_	(0x1U << 10)
#define LAN78XX_RFE_CTL_MCAST_EN_	(0x1U << 9)
#define LAN78XX_RFE_CTL_UCAST_EN_	(0x1U << 8)
#define LAN78XX_RFE_CTL_VLAN_FILTER_	(0x1U << 5)
#define LAN78XX_RFE_CTL_MCAST_HASH_	(0x1U << 3)
#define LAN78XX_RFE_CTL_DA_PERFECT_	(0x1U << 1)

/* End address of the RX FIFO */

#define LAN78XX_FCT_RX_FIFO_END		0x0C8
#define LAN78XX_FCT_RX_FIFO_END_MASK_	0x0000007FUL
#define LAN78XX_MAX_RX_FIFO_SIZE	(12 * 1024)

/* End address of the TX FIFO */

#define LAN78XX_FCT_TX_FIFO_END		0x0CC
#define LAN78XX_FCT_TX_FIFO_END_MASK_	0x0000003FUL
#define LAN78XX_MAX_TX_FIFO_SIZE	(12 * 1024)

/* USB Configuration Register 0 */

#define LAN78XX_USB_CFG0	0x080
#define LAN78XX_USB_CFG_BIR_	(0x1U << 6)	/* Bulk-In Empty response */
#define LAN78XX_USB_CFG_BCE_	(0x1U << 5)	/* Burst Cap Enable */

/* USB Configuration Register 1 */

#define LAN78XX_USB_CFG1	0x084

/* USB Configuration Register 2 */

#define LAN78XX_USB_CFG2	0x088

/* USB bConfigIndex: it only has one configuration. */

#define LAN78XX_CONFIG_INDEX	0

/* Burst Cap Register */

#define LAN78XX_BURST_CAP		0x090
#define LAN78XX_DEFAULT_BURST_CAP_SIZE	LAN78XX_MAX_TX_FIFO_SIZE

/* Bulk-In Delay Register */

#define LAN78XX_BULK_IN_DLY		0x094
#define LAN78XX_DEFAULT_BULK_IN_DELAY	0x0800

/* Interrupt Endpoint Control Register */

#define LAN78XX_INT_EP_CTL		0x098
#define LAN78XX_INT_ENP_PHY_INT		(0x1U << 17)	/* PHY Enable */

/* Registers on the phy, accessed via MII/MDIO */

#define LAN78XX_PHY_INTR_STAT		25
#define LAN78XX_PHY_INTR_MASK		26
#define LAN78XX_PHY_INTR_LINK_CHANGE	(0x1U << 13)
#define LAN78XX_PHY_INTR_ANEG_COMP	(0x1U << 10)
#define LAN78XX_EXT_PAGE_ACCESS		0x1F
#define LAN78XX_EXT_PAGE_SPACE_0	0x0000
#define LAN78XX_EXT_PAGE_SPACE_1	0x0001
#define LAN78XX_EXT_PAGE_SPACE_2	0x0002

/* Extended Register Page 1 Space */

#define LAN78XX_EXT_MODE_CTRL			0x0013
#define LAN78XX_EXT_MODE_CTRL_MDIX_MASK_	0x000C
#define LAN78XX_EXT_MODE_CTRL_AUTO_MDIX_	0x0000

/* FCT Flow Control Threshold Register */

#define LAN78XX_FCT_FLOW			0x0D0

/* FCT RX FIFO Control Register */

#define LAN78XX_FCT_RX_CTL			0x0C0

/* FCT TX FIFO Control Register */

#define LAN78XX_FCT_TX_CTL			0x0C4
#define LAN78XX_FCT_TX_CTL_EN_			(0x1U << 31)

/* MAC Control Register */

#define LAN78XX_MAC_CR				0x100
#define LAN78XX_MAC_CR_AUTO_DUPLEX_		(0x1U << 12)	/* Automatic Duplex Detection */
#define LAN78XX_MAC_CR_AUTO_SPEED_		(0x1U << 11)

/* MAC Receive Register */

#define LAN78XX_MAC_RX				0x104
#define LAN78XX_MAC_RX_MAX_FR_SIZE_MASK_	0x3FFF0000
#define LAN78XX_MAC_RX_MAX_FR_SIZE_SHIFT_	16
#define LAN78XX_MAC_RX_EN_			(0x1U << 0)	/* Enable Receiver */

/* MAC Transmit Register */

#define LAN78XX_MAC_TX				0x108
#define LAN78XX_MAC_TX_TXEN_			(0x1U << 0)	/* Enable Transmitter */

/* Flow Control Register */

#define LAN78XX_FLOW				0x10C
#define LAN78XX_FLOW_CR_TX_FCEN_		(0x1U << 30)	/* TX Flow Control Enable */
#define LAN78XX_FLOW_CR_RX_FCEN_		(0x1U << 29)	/* RX Flow Control Enable */

/* MAC Receive Address Registers */

#define LAN78XX_RX_ADDRH			0x118	/* High */
#define LAN78XX_RX_ADDRL			0x11C	/* Low */

/* MII Access Register */

#define LAN78XX_MII_ACCESS			0x120
#define LAN78XX_MII_BUSY_			(0x1UL << 0)
#define LAN78XX_MII_READ_			(0x0UL << 1)
#define LAN78XX_MII_WRITE_			(0x1UL << 1)

/* MII Data Register */

#define LAN78XX_MII_DATA			0x124

 /* MAC address perfect filter registers (ADDR_FILTx) */

#define LAN78XX_PFILTER_BASE			0x400
#define LAN78XX_PFILTER_HIX			0x00
#define LAN78XX_PFILTER_LOX			0x04
#define LAN78XX_NUM_PFILTER_ADDRS_		33
#define LAN78XX_PFILTER_ADDR_VALID_		(0x1UL << 31)
#define LAN78XX_PFILTER_ADDR_TYPE_SRC_		(0x1UL << 30)
#define LAN78XX_PFILTER_ADDR_TYPE_DST_		(0x0UL << 30)
#define LAN78XX_PFILTER_HI(index)		(LAN78XX_PFILTER_BASE + (8 * (index)) + (LAN78XX_PFILTER_HIX))
#define LAN78XX_PFILTER_LO(index)		(LAN78XX_PFILTER_BASE + (8 * (index)) + (LAN78XX_PFILTER_LOX))

/*
 * These registers are not documented in the datasheet. Stolen
 * from the Linux driver.
 */

#define LAN78XX_OTP_BASE_ADDR			0x01000
#define LAN78XX_OTP_PWR_DN			(LAN78XX_OTP_BASE_ADDR + 4 * 0x00)
#define LAN78XX_OTP_PWR_DN_PWRDN_N		0x01
#define LAN78XX_OTP_ADDR1			(LAN78XX_OTP_BASE_ADDR + 4 * 0x01)
#define LAN78XX_OTP_ADDR1_15_11			0x1F
#define LAN78XX_OTP_ADDR2			(LAN78XX_OTP_BASE_ADDR + 4 * 0x02)
#define LAN78XX_OTP_ADDR2_10_3			0xFF
#define LAN78XX_OTP_ADDR3			(LAN78XX_OTP_BASE_ADDR + 4 * 0x03)
#define LAN78XX_OTP_ADDR3_2_0			0x03
#define LAN78XX_OTP_RD_DATA			(LAN78XX_OTP_BASE_ADDR + 4 * 0x06)
#define LAN78XX_OTP_FUNC_CMD			(LAN78XX_OTP_BASE_ADDR + 4 * 0x08)
#define LAN78XX_OTP_FUNC_CMD_RESET		0x04
#define LAN78XX_OTP_FUNC_CMD_PROGRAM_		0x02
#define LAN78XX_OTP_FUNC_CMD_READ_		0x01
#define LAN78XX_OTP_MAC_OFFSET			0x01
#define LAN78XX_OTP_INDICATOR_OFFSET		0x00
#define LAN78XX_OTP_INDICATOR_1			0xF3
#define LAN78XX_OTP_INDICATOR_2			0xF7
#define LAN78XX_OTP_CMD_GO			(LAN78XX_OTP_BASE_ADDR + 4 * 0x0A)
#define LAN78XX_OTP_CMD_GO_GO_			0x01
#define LAN78XX_OTP_STATUS			(LAN78XX_OTP_BASE_ADDR + 4 * 0x0A)
#define LAN78XX_OTP_STATUS_OTP_LOCK_		0x10
#define LAN78XX_OTP_STATUS_BUSY_		0x01

/* Some unused registers, from the data sheet. */

#define LAN78XX_BOS_ATTR			0x050
#define LAN78XX_SS_ATTR				0x054
#define LAN78XX_HS_ATTR				0x058
#define LAN78XX_FS_ATTR				0x05C
#define LAN78XX_STRNG_ATTR0			0x060
#define LAN78XX_STRNG_ATTR1			0x064
#define LAN78XX_FLAG_ATTR			0x068
#define LAN78XX_SW_GP_1				0x06C
#define LAN78XX_SW_GP_2				0x070
#define LAN78XX_SW_GP_3				0x074
#define LAN78XX_VLAN_TYPE			0x0B4
#define LAN78XX_RX_DP_STOR			0x0D4
#define LAN78XX_TX_DP_STOR			0x0D8
#define LAN78XX_LTM_BELT_IDLE0			0x0E0
#define LAN78XX_LTM_BELT_IDLE1			0x0E4
#define LAN78XX_LTM_BELT_ACT0			0x0E8
#define LAN78XX_LTM_BELT_ACT1			0x0EC
#define LAN78XX_LTM_INACTIVE0			0x0F0
#define LAN78XX_LTM_INACTIVE1			0x0F4

#define LAN78XX_RAND_SEED			0x110
#define LAN78XX_ERR_STS				0x114

#define LAN78XX_EEE_TX_LPI_REQUEST_DELAY_CNT	0x130
#define LAN78XX_EEE_TW_TX_SYS			0x134
#define LAN78XX_EEE_TX_LPI_AUTO_REMOVAL_DELAY	0x138

#define LAN78XX_WUCSR1				0x140
#define LAN78XX_WK_SRC				0x144
#define LAN78XX_WUF_CFG_BASE			0x150
#define LAN78XX_WUF_MASK_BASE			0x200
#define LAN78XX_WUCSR2				0x600

#define LAN78XX_NSx_IPV6_ADDR_DEST_0		0x610
#define LAN78XX_NSx_IPV6_ADDR_DEST_1		0x614
#define LAN78XX_NSx_IPV6_ADDR_DEST_2		0x618
#define LAN78XX_NSx_IPV6_ADDR_DEST_3		0x61C

#define LAN78XX_NSx_IPV6_ADDR_SRC_0		0x620
#define LAN78XX_NSx_IPV6_ADDR_SRC_1		0x624
#define LAN78XX_NSx_IPV6_ADDR_SRC_2		0x628
#define LAN78XX_NSx_IPV6_ADDR_SRC_3		0x62C

#define LAN78XX_NSx_ICMPV6_ADDR0_0		0x630
#define LAN78XX_NSx_ICMPV6_ADDR0_1		0x634
#define LAN78XX_NSx_ICMPV6_ADDR0_2		0x638
#define LAN78XX_NSx_ICMPV6_ADDR0_3		0x63C

#define LAN78XX_NSx_ICMPV6_ADDR1_0		0x640
#define LAN78XX_NSx_ICMPV6_ADDR1_1		0x644
#define LAN78XX_NSx_ICMPV6_ADDR1_2		0x648
#define LAN78XX_NSx_ICMPV6_ADDR1_3		0x64C

#define LAN78XX_NSx_IPV6_ADDR_DEST		0x650
#define LAN78XX_NSx_IPV6_ADDR_SRC		0x660
#define LAN78XX_NSx_ICMPV6_ADDR0		0x670
#define LAN78XX_NSx_ICMPV6_ADDR1		0x680

#define LAN78XX_SYN_IPV4_ADDR_SRC		0x690
#define LAN78XX_SYN_IPV4_ADDR_DEST		0x694
#define LAN78XX_SYN_IPV4_TCP_PORTS		0x698

#define LAN78XX_SYN_IPV6_ADDR_SRC_0		0x69C
#define LAN78XX_SYN_IPV6_ADDR_SRC_1		0x6A0
#define LAN78XX_SYN_IPV6_ADDR_SRC_2		0x6A4
#define LAN78XX_SYN_IPV6_ADDR_SRC_3		0x6A8

#define LAN78XX_SYN_IPV6_ADDR_DEST_0		0x6AC
#define LAN78XX_SYN_IPV6_ADDR_DEST_1		0x6B0
#define LAN78XX_SYN_IPV6_ADDR_DEST_2		0x6B4
#define LAN78XX_SYN_IPV6_ADDR_DEST_3		0x6B8

#define LAN78XX_SYN_IPV6_TCP_PORTS		0x6BC
#define LAN78XX_ARP_SPA				0x6C0
#define LAN78XX_ARP_TPA				0x6C4
#define LAN78XX_PHY_DEV_ID			0x700

#endif /* _IF_LAN78REG_H_ */
