/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2012
 *  Ben Gray <bgray@freebsd.org>.
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
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
 * This information was gleaned from the LAN78XX driver in the linux kernel, where
 * it is Copyrighted (C) 2007-2008 SMSC.
 *
 */

#ifndef _IF_LAN78REG_H_
#define _IF_LAN78REG_H_
#define BIT(n)   ((1) << (n))

/* Device ID and revision register */

#define LAN78XX_ID_REV                      (0x000)
#define LAN78XX_ID_REV_CHIP_ID_MASK_        (0xFFFF0000UL)
#define LAN78XX_ID_REV_CHIP_REV_MASK_       (0x0000FFFFUL)

/* Device interrupt status register. */

#define LAN78XX_INT_STS                 (0x00C)
#define LAN78XX_INT_STS_CLEAR_ALL_      (0xffffffff)

#define LAN78XX_HW_CFG            (0x010)
#define LAN_78XX_PMT_CTL          (0x014)
#define GPIO_CFG0                 (0x018)
#define GPIO_CFG1                 (0x01C)
#define GPIO_WAKE                 (0x020)

/* RX Command A */
#define LAN78XX_RX_CMD_A_RED_      (0x00400000)
#define LAN78XX_RX_CMD_A_LEN_MASK_ (0x00003FFF)
#define LAN78XX_RX_CMD_A_ICSM_ 	   (0x00004000)

/* TX Command A */
#define LAN78XX_TX_CMD_A_LEN_MASK_  (0x000FFFFF)
#define LAN78XX_TX_CMD_A_FCS_       (0x00400000)


#define LAN78XX_DP_SEL_VHF_HASH_LEN (16)

#define LAN78XX_DP_SEL           		(0x024)
#define LAN78XX_DP_SEL_DPRDY_       	(0x80000000)
#define LAN78XX_DP_SEL_RSEL_MASK_		(0x0000000F)
#define LAN78XX_DP_SEL_RSEL_VLAN_DA_	(0x00000001)
#define LAN78XX_DP_SEL_VHF_HASH_LEN 	(16)
#define LAN78XX_DP_SEL_VHF_VLAN_LEN 	(128)

#define LAN78XX_DP_CMD        	    (0x028)
#define LAN78XX_DP_CMD_WRITE_ 	    (0x00000001)


#define LAN78XX_DP_ADDR          (0x02C)
#define LAN78XX_DP_DATA          (0x030)

#define LAN78XX_E2P_CMD          (0x040)
#define LAN78XX_E2P_DATA         (0x044)

#define LAN78XX_OTP_BASE_ADDR    (0x01000)

#define LAN78XX_OTP_PWR_DN               (LAN78XX_OTP_BASE_ADDR + 4 * 0x00)
#define LAN78XX_OTP_PWR_DN_PWRDN_N       (0x01)

#define LAN78XX_OTP_ADDR1                (LAN78XX_OTP_BASE_ADDR + 4 * 0x01)
#define LAN78XX_OTP_ADDR1_15_11          (0x1F)

#define LAN78XX_OTP_ADDR2                (LAN78XX_OTP_BASE_ADDR + 4 * 0x02)
#define LAN78XX_OTP_ADDR2_10_3           (0xFF)

#define LAN78XX_OTP_ADDR3                (LAN78XX_OTP_BASE_ADDR + 4 * 0x03)
#define LAN78XX_OTP_ADDR3_2_0            (0x03)

#define LAN78XX_OTP_RD_DATA              (LAN78XX_OTP_BASE_ADDR + 4 * 0x06)

#define LAN78XX_OTP_FUNC_CMD                     (LAN78XX_OTP_BASE_ADDR + 4 * 0x08)
#define LAN78XX_OTP_FUNC_CMD_RESET               (0x04)
#define LAN78XX_OTP_FUNC_CMD_PROGRAM_            (0x02)
#define LAN78XX_OTP_FUNC_CMD_READ_               (0x01)

#define LAN78XX_OTP_MAC_OFFSET                  (0x01)
#define LAN78XX_OTP_INDICATOR_OFFSET            (0x00)
#define LAN78XX_OTP_INDICATOR_1                 (0xF3)
#define LAN78XX_OTP_INDICATOR_2                 (0xF7)

#define LAN78XX_OTP_CMD_GO               (LAN78XX_OTP_BASE_ADDR + 4 * 0x0A)
#define LAN78XX_OTP_CMD_GO_GO_           (0x01)

#define LAN78XX_OTP_STATUS               (LAN78XX_OTP_BASE_ADDR + 4 * 0x0A)
#define LAN78XX_OTP_STATUS_OTP_LOCK_     (0x10)
#define LAN78XX_OTP_STATUS_BUSY_         (0x01)

#define LAN78XX_E2P_MAC_OFFSET           (0x01)
#define LAN78XX_E2P_INDICATOR_OFFSET     (0x00)




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

#define LAN78XX_SS_USB_PKT_SIZE (1024)
#define LAN78XX_HS_USB_PKT_SIZE (512)
#define LAN78XX_FS_USB_PKT_SIZE (64)

#define LAN78XX_MAX_RX_FIFO_SIZE        (12 * 1024)
#define LAN78XX_MAX_TX_FIFO_SIZE        (12 * 1024)
#define LAN78XX_DEFAULT_BURST_CAP_SIZE  (LAN78XX_MAX_TX_FIFO_SIZE)

#define LAN78XX_DEFAULT_BULK_IN_DELAY (0x0800)

#define LAN78XX_USB_CFG0     (0x080)
#define LAN78XX_USB_CFG_BIR_ (0x040)
#define LAN78XX_USB_CFG_BCE_ (0x020)

#define USB_CFG1         (0x084)
#define USB_CFG2         (0x088)
#define LAN78XX_BURST_CAP        (0x090)
#define LAN78XX_BULK_IN_DLY      (0x094)

#define LAN78XX_INT_EP_CTL       (0x098)
#define LAN78XX_INT_ENP_PHY_INT  BIT(17)

#define PIPE_CTL         (0x09C)
#define U1_LATENCY       (0x0A0)
#define U2_LATENCY       (0x0A4)
#define USB_STATUS       (0x0A8)

#define LAN78XX_RFE_CTL                    (0x0B0)
#define LAN78XX_RFE_CTL_IGMP_COE_          (0x4000)
#define LAN78XX_RFE_CTL_ICMP_COE_          (0x2000)
#define LAN78XX_RFE_CTL_TCPUDP_COE_        (0x1000)
#define LAN78XX_RFE_CTL_IP_COE_            (0x800)
#define LAN78XX_RFE_CTL_BCAST_EN_          (0x400)
#define LAN78XX_RFE_CTL_MCAST_EN_          (0x200)
#define LAN78XX_RFE_CTL_UCAST_EN_          (0x100)
#define LAN78XX_RFE_CTL_VLAN_FILTER_       (0x020)
#define LAN78XX_RFE_CTL_MCAST_HASH_        (0x008)
#define LAN78XX_RFE_CTL_DA_PERFECT_        (0x002)


/* Registers on the phy, accessed via MII/MDIO */
#define LAN78XX_PHY_INTR_STAT          (25)
#define LAN78XX_PHY_INTR_MASK          (26)
#define LAN78XX_EXT_PAGE_ACCESS        (0x1F)
#define LAN78XX_EXT_PAGE_SPACE_0       (0x0000)
#define LAN78XX_EXT_PAGE_SPACE_1       (0x0001)
#define LAN78XX_EXT_PAGE_SPACE_2       (0x0002)

/* Extended Register Page 1 space */
#define LAN78XX_EXT_MODE_CTRL                 (0x0013)
#define LAN78XX_EXT_MODE_CTRL_MDIX_MASK_      (0x000C)
#define LAN78XX_EXT_MODE_CTRL_AUTO_MDIX_      (0x0000)

#define LAN78XX_PHY_INTR_LINK_CHANGE   (0x1U << 13)
#define LAN78XX_PHY_INTR_ANEG_COMP     (0x1U << 10)

#define VLAN_TYPE        (0x0B4)

#define LAN78XX_FCT_FLOW            (0x0D0)
#define LAN78XX_FCT_RX_CTL          (0x0C0)
#define LAN78XX_FCT_TX_CTL          (0x0C4)
#define LAN78XX_FCT_TX_CTL_EN_      (0x80000000)


#define LAN78XX_FCT_RX_FIFO_END        (0x0C8)
#define LAN78XX_FCT_RX_FIFO_END_MASK_  (0x0000007F)

#define LAN78XX_FCT_TX_FIFO_END        (0x0CC)
#define LAN78XX_FCT_TX_FIFO_END_MASK_  (0x0000003F)

#define RX_DP_STOR       (0x0D4)
#define TX_DP_STOR       (0x0D8)
#define LTM_BELT_IDLE0   (0x0E0)
#define LTM_BELT_IDLE1   (0x0E4)
#define LTM_BELT_ACT0    (0x0E8)
#define LTM_BELT_ACT1    (0x0EC)
#define LTM_INACTIVE0    (0x0F0)
#define LTM_INACTIVE1    (0x0F4)

#define LAN78XX_MAC_CR                  (0x100)
#define LAN78XX_MAC_CR_AUTO_DUPLEX_     (0x00001000)
#define LAN78XX_MAC_CR_AUTO_SPEED_      (0x00000800)


#define LAN78XX_MAC_RX                       (0x104)
#define LAN78XX_MAC_RX_MAX_FR_SIZE_MASK_     (0x3FFF0000)
#define LAN78XX_MAC_RX_MAX_FR_SIZE_SHIFT_    (16)
#define LAN78XX_MAC_RX_EN_                   (0x01)



#define LAN78XX_MAC_TX                  (0x108)
#define LAN78XX_MAC_TX_TXEN_            (0x00000001)

#define LAN78XX_FLOW                    (0x10C)
#define LAN78XX_FLOW_CR_TX_FCEN_        (0x40000000)
#define LAN78XX_FLOW_CR_RX_FCEN_        (0x20000000)

#define RAND_SEED                       (0x110)
#define ERR_STS                         (0x114)
#define LAN78XX_RX_ADDRH                (0x118)
#define LAN78XX_RX_ADDRL                (0x11C)
#define LAN78XX_MII_ACCESS              (0x120)
#define LAN78XX_MII_BUSY_               (0x1UL << 0)
#define LAN78XX_MII_READ_               (0x0UL << 1)
#define LAN78XX_MII_WRITE_              (0x1UL << 1)
#define LAN78XX_MII_DATA                (0x124)
#define EEE_TX_LPI_REQUEST_DELAY_CNT    (0x130)
#define EEE_TW_TX_SYS                   (0x134)
#define EEE_TX_LPI_AUTO_REMOVAL_DELAY   (0x138)
#define WUCSR1                          (0x140)
#define WK_SRC                          (0x144)


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

#define LAN78XX_PFILTER_BASE 			(0x400)
#define LAN78XX_PFILTER_HIX				(0x00)
#define LAN78XX_PFILTER_LOX				(0x04)
#define LAN78XX_PFILTER_HI(index)		(LAN78XX_PFILTER_BASE + (8 * (index)) + (LAN78XX_PFILTER_HIX))
#define LAN78XX_PFILTER_LO(index)		(LAN78XX_PFILTER_BASE + (8 * (index)) + (LAN78XX_PFILTER_LOX))
#define LAN78XX_NUM_PFILTER_ADDRS_ 	 	(33)
#define LAN78XX_PFILTER_ADDR_VALID_ 	(0x80000000)
#define LAN78XX_PFILTER_ADDR_TYPE_SRC_ 	(0x40000000)
#define LAN78XX_PFILTER_ADDR_TYPE_DST_ 	(0x00000000)


#define WUCSR2                      (0x600)

#define NSx_IPV6_ADDR_DEST_0        (0x610)
#define NSx_IPV6_ADDR_DEST_1        (0x614)
#define NSx_IPV6_ADDR_DEST_2        (0x618)
#define NSx_IPV6_ADDR_DEST_3        (0x61C)

#define NSx_IPV6_ADDR_SRC_0         (0x620)
#define NSx_IPV6_ADDR_SRC_1         (0x624)
#define NSx_IPV6_ADDR_SRC_2         (0x628)
#define NSx_IPV6_ADDR_SRC_3         (0x62C)

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
    uint32_t          sc_rfe_ctl;
    uint32_t          sc_mdix_ctl;
    uint32_t          sc_rev_id;
    uint32_t          sc_mchash_table[LAN78XX_DP_SEL_VHF_HASH_LEN];
	uint32_t		  sc_pfilter_table[LAN78XX_NUM_PFILTER_ADDRS_][2];

    uint32_t          sc_flags;
#define LAN78XX_FLAG_LINK      0x0001
};

/* USB Vendor Requests */
#define LAN78XX_UR_WRITE_REG   0xA0
#define LAN78XX_UR_READ_REG    0xA1
#define LAN78XX_UR_GET_STATS   0xA2

#define LAN78XX_CONFIG_INDEX    0   /* config number 1 */
#define LAN78XX_IFACE_IDX       0

#define LAN78XX_LOCK(_sc)             mtx_lock(&(_sc)->sc_mtx)
#define LAN78XX_UNLOCK(_sc)           mtx_unlock(&(_sc)->sc_mtx)
#define LAN78XX_LOCK_ASSERT(_sc, t)   mtx_assert(&(_sc)->sc_mtx, t)

#define LAN78XX_E2P_INDICATOR       (0xA5)

#define LAN78XX_E2P_CMD_BUSY        (0x1UL << 31)
#define LAN78XX_E2P_CMD_MASK        (0x7UL << 28)
#define LAN78XX_E2P_CMD_READ        (0x0UL << 28)
#define LAN78XX_E2P_CMD_WRITE       (0x3UL << 28)
#define LAN78XX_E2P_CMD_ERASE       (0x5UL << 28)
#define LAN78XX_E2P_CMD_RELOAD      (0x7UL << 28)
#define LAN78XX_E2P_CMD_TIMEOUT     (0x1UL << 10)
#define LAN78XX_E2P_CMD_ADDR_MASK   (0x000001FFUL)

#define LAN78XX_HW_CFG_LED3_EN_        (0x00800000)
#define LAN78XX_HW_CFG_LED2_EN_        (0x00400000)
#define LAN78XX_HW_CFG_LED1_EN_        (0x00200000)
#define LAN78XX_HW_CFG_LEDO_EN_        (0x00100000)
#define LAN78XX_HW_CFG_MEF_            (0x1UL << 4)
#define LAN78XX_HW_CFG_ETC             (0x1UL << 3)
#define LAN78XX_HW_CFG_LRST            (0x1UL << 1)    /* Lite reset */
#define LAN78XX_HW_CFG_SRST            (0x1UL << 0)

#define LAN78XX_PMT_CTL_PHY_RST        (0x1UL << 4)    /* PHY reset */

#endif /* _IF_LAN78REG_H_ */
