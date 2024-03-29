#ifndef _LINUX_UDP_H
#define _LINUX_UDP_H

/* UDP socket options */
#define UDP_CORK	1	/* Never send partially complete segments */
#define UDP_ENCAP	100	/* Set the socket to accept encapsulated packets */
#define UDP_NO_CHECK6_TX 101	/* Disable sending checksum for UDP6X */
#define UDP_NO_CHECK6_RX 102	/* Disable accpeting checksum for UDP6 */
#define UDP_SEGMENT	103	/* Set GSO segmentation size */
#define UDP_GRO		104	/* This socket can receive UDP GRO packets */

/* UDP encapsulation types */
#define UDP_ENCAP_ESPINUDP_NON_IKE	1 /* draft-ietf-ipsec-nat-t-ike-00/01 */
#define UDP_ENCAP_ESPINUDP	2 /* draft-ietf-ipsec-udp-encaps-06 */
#define UDP_ENCAP_L2TPINUDP	3 /* rfc2661 */
#define UDP_ENCAP_GTP0		4 /* GSM TS 09.60 */
#define UDP_ENCAP_GTP1U		5 /* 3GPP TS 29.060 */
#define UDP_ENCAP_RXRPC		6
#define TCP_ENCAP_ESPINTCP	7 /* Yikes, this is really xfrm encap types. */

#endif /* _LINUX_UDP_H */