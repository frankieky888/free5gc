#ifndef __PFCP_TYPES_H__
#define __PFCP_TYPES_H__

#include "utlt_3gppTypes.h"
#include "utlt_network.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


#define PFCP_VERSION    1

//$ CAUSE
#define PFCP_CAUSE_REQUEST_ACCEPTED                     1
#define PFCP_CAUSE_REQUEST_REJECTED                     64
#define PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND            65
#define PFCP_CAUSE_MANDATORY_IE_MISSING                 66
#define PFCP_CAUSE_CONDITIONAL_IE_MISSING               67
#define PFCP_CAUSE_INVALID_LENGTH                       68
#define PFCP_CAUSE_MANDATORY_IE_INCORRECT               69
#define PFCP_CAUSE_INVALID_FORWARDING_POLICY            70
#define PFCP_CAUSE_INVALID_F_TEID_ALLOCATION_OPTION     71
#define PFCP_CAUSE_NO_ESTABLISHED_PFCP_ASSOCIATION      72
#define PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE   73
#define PFCP_CAUSE_PFCP_ENTITY_IN_CONGESTION            74
#define PFCP_CAUSE_NO_RESOURCES_AVAILABLE               75
#define PFCP_CAUSE_SERVICE_NOT_SUPPORTED                76
#define PFCP_CAUSE_SYSTEM_FAILURE                       77
char* PfcpCauseGetName(uint8_t cause);


//$ Apply Action
#define PFCP_FAR_APPLY_ACTION_DROP      1
#define PFCP_FAR_APPLY_ACTION_FORW      2
#define PFCP_FAR_APPLY_ACTION_BUFF      4
#define PFCP_FAR_APPLY_ACTION_NOCP      8
#define PFCP_FAR_APPLY_ACTION_DUPL     16

//$ destination interface
#define PFCP_FAR_DEST_INTF_ACCESS       0   //$ DL traffic
#define PFCP_FAR_DEST_INTF_CORE         1   //$ UL traffic
#define PFCP_FAR_DEST_INTF_SGILAN       2   //$ SGi-LAN
#define PFCP_FAR_DEST_INTF_CPF          3   //$ CP-Function
#define PFCP_FAR_DEST_INTF_LIF          4   //$ LI Function

//$ Precedence
#define PGWC_PRECEDENCE_BASE  31

//$ outer header remove
#define PFCP_OUTER_HDR_RMV_DESC_GTPU_IP4    0
#define PFCP_OUTER_HDR_RMV_DESC_GTPU_IP6    1
#define PFCP_OUTER_HDR_RMV_DESC_UDP_IP4     2
#define PFCP_OUTER_HDR_RMV_DESC_UDP_IP6     3
#define PFCP_OUTER_HDR_RMV_DESC_NULL        0xFF  

//$ source interface
#define PFCP_SRC_INTF_ACCESS    0  //$ UL traffic
#define PFCP_SRC_INTF_CORE      1  //$ DL traffic
#define PFCP_SRC_INTF_SGILAN    2  //$ SGi-LAN
#define PFCP_SRC_INTF_CP_F      3  //$ CP-function

//$ PDN type
#define PFCP_PDN_TYPE_IPV4      1
#define PFCP_PDN_TYPE_IPV6      2
#define PFCP_PDN_TYPE_IPV4V6    3
#define PFCP_PDN_TYPE_NONIP     4


#define PFCP_UE_IP_ADDR_HDR_LEN                      1
#define PFCP_UE_IP_ADDR_IPV4_LEN                     IPV4_LEN+PFCP_UE_IP_ADDR_HDR_LEN
#define PFCP_UE_IP_ADDR_IPV6_LEN                     IPV6_LEN+PFCP_UE_IP_ADDR_HDR_LEN
#define PFCP_UE_IP_ADDR_IPV4V6_LEN                   IPV4V6_LEN+PFCP_UE_IP_ADDR_HDR_LEN

#define PFCP_UE_IP_ADDR_SOURCE                  0
#define PFCP_UE_IP_ADDR_DESITINATION            1


#define PFCP_F_TEID_HDR_LEN                      5
#define PFCP_F_TEID_IPV4_LEN                     IPV4_LEN+PFCP_F_TEID_HDR_LEN
#define PFCP_F_TEID_IPV6_LEN                     IPV6_LEN+PFCP_F_TEID_HDR_LEN
#define PFCP_F_TEID_IPV4V6_LEN                   IPV4V6_LEN+PFCP_F_TEID_HDR_LEN


#define PFCP_F_SEID_HDR_LEN                      9
#define PFCP_F_SEID_IPV4_LEN                     IPV4_LEN+PFCP_F_SEID_HDR_LEN
#define PFCP_F_SEID_IPV6_LEN                     IPV6_LEN+PFCP_F_SEID_HDR_LEN
#define PFCP_F_SEID_IPV4V6_LEN                   IPV4V6_LEN+PFCP_F_SEID_HDR_LEN


typedef struct _PfcpUeIpAddr {
    ENDIAN5(uint8_t         spare:4;,
            uint8_t         ipv6d:1;,
            uint8_t         sd:1;,            /* 0: source or 1: destination*/
            uint8_t         v4:1;,
            uint8_t         v6:1;)
    union {
        /* GTP_F_TEID_IPV4 */
        struct in_addr      addr4;
        /* GTP_F_TEID_IPV6 */
        struct in6_addr     addr6;
        /* GTP_F_TEID_BOTH */
        struct {
            struct in_addr  addr4;
            struct in6_addr addr6;
        } dualStack;
    };
    uint8_t ipv6PrefixDelegationBit;
} __attribute__ ((packed)) PfcpUeIpAddr;

typedef struct _PfcpFTeid {
    ENDIAN5(uint8_t         spare:4;,
            uint8_t         chid:1;,
            uint8_t         ch:1;,
            uint8_t         v6:1;,
            uint8_t         v4:1;)
    uint32_t      teid;
    union {
        union {
            /* GTP_F_TEID_IPV4 */
            struct in_addr      addr4;
            /* GTP_F_TEID_IPV6 */
            struct in6_addr     addr6;
            /* GTP_F_TEID_BOTH */
            struct {
                struct in_addr  addr4;
                struct in6_addr addr6;
            } dualStack;
        };
        uint8_t chooseId;
    };
} __attribute__ ((packed)) PfcpFTeid;

typedef struct _PfcpFSeid {
    ENDIAN3(uint8_t         spare:6;,
            uint8_t         v4:1;,
            uint8_t         v6:1;)
    uint64_t      seid;
    union {
        /* PFCP_F_TEID_IPV4 */
        struct in_addr      addr4;
        /* PFCP_F_TEID_IPV6 */
        struct in6_addr     addr6;
        /* PFCP_F_TEID_BOTH */
        struct {
            struct in_addr  addr4;
            struct in6_addr addr6;
        } dualStack;
    };
} __attribute__ ((packed)) PfcpFSeid;

typedef struct _PfcpNodeId {
    ENDIAN2(uint8_t spare:4;,
            uint8_t type:4;)
#define PFCP_NODE_ID_IPV4   0
#define PFCP_NODE_ID_IPV6   1
#define PFCP_NODE_ID_FQDN   2
#define PFPC_NODE_ID_LEN(__nid) 1 + (__nid.type & 2) ? \
            -1 : ((__nid.type & 1) ? IPV6_LEN : IPV4_LEN)
    union {
        /* IPV4 */
        struct in_addr      addr4;
        /* IPV6 */
        struct in6_addr     addr6;
    };
} __attribute__ ((packed)) PfcpNodeId;

typedef struct _PfcpOuterHdr {
    ENDIAN8(uint8_t         sTag:1;,
            uint8_t         cTag:1;,
            uint8_t         ipv6:1;,
            uint8_t         ipv4:1;,
            uint8_t         udpIpv6:1;,
            uint8_t         udpIpv4:1;,
            uint8_t         gtpuIpv6:1;,
            uint8_t         gtpuIpv4:1;)
            uint8_t         void0;
            uint32_t        teid;
    union {
        /* PFCP_F_TEID_IPV4 */
        struct in_addr      addr4;
        /* PFCP_F_TEID_IPV6 */
        struct in6_addr     addr6;
        /* PFCP_F_TEID_BOTH */
        struct {
            struct in_addr  addr4;
            struct in6_addr addr6;
        } dualStack;
    };
    uint8_t     port;
    uint16_t    cTagValue;
    uint16_t    sTagValue;
} __attribute__ ((packed)) PfcpOuterHdr;

typedef struct _PfcpReportType {
    ENDIAN5(uint8_t       spare:4;,
            uint8_t       upir:1;,            /* User Plane Inactivity Report */
            uint8_t       erir:1;,            /* Error Indication Report */
            uint8_t       usar:1;,            /* Usage Report */
            uint8_t       dldr:1;)            /* Downlink Data Report */
} __attribute__ ((packed)) PfcpReportType;

typedef struct _PfcpDownlinkDataServiceInformation {
#define PfcpDownlinkDataServiceInformationLen(__data) \
    sizeof(struct _PfcpDownlinkDataServiceInformation) - (__data).ppi - (__data).qfii
    ENDIAN3(uint8_t       spare0:6;,
            uint8_t       qfii:1;,
            uint8_t       ppi:1;)            /* Paging Policy Indication */
    ENDIAN2(uint8_t       spare1:2;,
            uint8_t       pagingPolicyIndicationValue:6;)
    ENDIAN2(uint8_t       spare2:2;,
            uint8_t       qfi:6;)
} __attribute__ ((packed)) PfcpDownlinkDataServiceInformation;

typedef struct _PfcpUserPlaneIpResourceInformation {
    ENDIAN6(uint8_t       spare0:1;,
            uint8_t       assosi:1;,
            uint8_t       assoni:1;,
            uint8_t       teidri:3;,
            uint8_t       v6:1;,
            uint8_t       v4:1;)

    uint8_t             teidRange;
    //union {
        struct in_addr      addr4;
        //struct in6_addr     addr6;
    //};
    uint8_t             networkInstance[MAX_DNN_LEN+1];
    ENDIAN2(uint8_t       spare1:4;,
            uint8_t       sourceInterface:4;)
} __attribute__ ((packed)) PfcpUserPlaneIpResourceInformation;

typedef struct _PfcpSDFFilterDescription {
    ENDIAN6(uint8_t       spare0:3;,
            uint8_t       bid:1;,
            uint8_t       fl:1;,
            uint8_t       spi:1;,
            uint8_t       ttc:1;,
            uint8_t       fd:1;)
    uint8_t             spare;
} __attribute__ ((packed)) PfcpSDFFilterDescription;


typedef struct _UpFunctionFeatures{
     ENDIAN8(uint8_t      treu:1;,
             uint8_t      heeu:1;,
             uint8_t      pfdm:1;,
             uint8_t      ftup:1;,
             uint8_t      trst:1;,
             uint8_t      dlbd:1;,
             uint8_t      ddnd:1;,
             uint8_t      bucp:1;)
     ENDIAN8(uint8_t      epfar:1;,
             uint8_t      pfde:1;,
             uint8_t      frrt:1;,
             uint8_t      trace:1;,
             uint8_t      quoac:1;,
             uint8_t      udbc:1;,
             uint8_t      pdiu:1;,
             uint8_t      empu:1;)
     ENDIAN8(uint8_t      gcom:1;,
             uint8_t      bundl:1;,
             uint8_t      mte:1;,
             uint8_t      mnop:1;,
             uint8_t      sset:1;,
             uint8_t      ueip:1;,
             uint8_t      adpdp:1;,
             uint8_t      dpdra:1;)
     ENDIAN8(uint8_t      mptcp:1;,
             uint8_t      tscu:1;,
             uint8_t      ip6pl:1;,
             uint8_t      iptv:1;,
             uint8_t      norp:1;,
             uint8_t      vtime:1;,
             uint8_t      rttl:1;,
             uint8_t      mpas:1;)
} __attribute__ ((packed)) UpFunctionFeatures;
typedef struct _HuaWei{
     ENDIAN8(uint8_t      byte08:8;,
             uint8_t      byte07:8;,
             uint8_t      byte06:8;,
             uint8_t      byte05:8;,
             uint8_t      byte04:8;,
             uint8_t      byte03:8;,
             uint8_t      byte02:8;,
             uint8_t      byte01:8;)
     ENDIAN8(uint8_t      byte16:8;,
             uint8_t      byte15:8;,
             uint8_t      byte14:8;,
             uint8_t      byte13:8;,
             uint8_t      byte12:8;,
             uint8_t      byte11:8;,
             uint8_t      byte10:8;,
             uint8_t      byte09:8;)
     ENDIAN8(uint8_t      byte24:8;,
             uint8_t      byte23:8;,
             uint8_t      byte22:8;,
             uint8_t      byte21:8;,
             uint8_t      byte20:8;,
             uint8_t      byte19:8;,
             uint8_t      byte18:8;,
             uint8_t      byte17:8;)
     ENDIAN8(uint8_t      byte32:8;,
             uint8_t      byte31:8;,
             uint8_t      byte30:8;,
             uint8_t      byte29:8;,
             uint8_t      byte28:8;,
             uint8_t      byte27:8;,
             uint8_t      byte26:8;,
             uint8_t      byte25:8;)
     ENDIAN8(uint8_t      byte40:8;,
             uint8_t      byte39:8;,
             uint8_t      byte38:8;,
             uint8_t      byte37:8;,
             uint8_t      byte36:8;,
             uint8_t      byte35:8;,
             uint8_t      byte34:8;,
             uint8_t      byte33:8;)
     ENDIAN8(uint8_t      byte48:8;,
             uint8_t      byte47:8;,
             uint8_t      byte46:8;,
             uint8_t      byte45:8;,
             uint8_t      byte44:8;,
             uint8_t      byte43:8;,
             uint8_t      byte42:8;,
             uint8_t      byte41:8;)
     ENDIAN8(uint8_t      byte56:8;,
             uint8_t      byte55:8;,
             uint8_t      byte54:8;,
             uint8_t      byte53:8;,
             uint8_t      byte52:8;,
             uint8_t      byte51:8;,
             uint8_t      byte50:8;,
             uint8_t      byte49:8;)
     ENDIAN8(uint8_t      byte64:8;,
             uint8_t      byte63:8;,
             uint8_t      byte62:8;,
             uint8_t      byte61:8;,
             uint8_t      byte60:8;,
             uint8_t      byte59:8;,
             uint8_t      byte58:8;,
             uint8_t      byte57:8;)
     ENDIAN8(uint8_t      byte72:8;,
             uint8_t      byte71:8;,
             uint8_t      byte70:8;,
             uint8_t      byte69:8;,
             uint8_t      byte68:8;,
             uint8_t      byte67:8;,
             uint8_t      byte66:8;,
             uint8_t      byte65:8;)
     ENDIAN8(uint8_t      byte80:8;,
             uint8_t      byte79:8;,
             uint8_t      byte78:8;,
             uint8_t      byte77:8;,
             uint8_t      byte76:8;,
             uint8_t      byte75:8;,
             uint8_t      byte74:8;,
             uint8_t      byte73:8;)
     ENDIAN8(uint8_t      byte88:8;,
             uint8_t      byte87:8;,
             uint8_t      byte86:8;,
             uint8_t      byte85:8;,
             uint8_t      byte84:8;,
             uint8_t      byte83:8;,
             uint8_t      byte82:8;,
             uint8_t      byte81:8;)
     ENDIAN8(uint8_t      byte96:8;,
             uint8_t      byte95:8;,
             uint8_t      byte94:8;,
             uint8_t      byte93:8;,
             uint8_t      byte92:8;,
             uint8_t      byte91:8;,
             uint8_t      byte90:8;,
             uint8_t      byte89:8;)
     ENDIAN6(uint8_t      byte102:8;,
             uint8_t      byte101:8;,
             uint8_t      byte100:8;,
             uint8_t      byte99:8;,
             uint8_t      byte98:8;,
             uint8_t      byte97:8;)
} __attribute__ ((packed)) HuaWei;
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __PFCP_TYPES_H__ */

