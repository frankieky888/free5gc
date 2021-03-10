#define TRACE_MODULE _n4_pfcp_build

#include <stdint.h>
#include <endian.h>
#include <string.h>
#include <arpa/inet.h>

#include "upf_context.h"
#include "utlt_buff.h"
#include "pfcp_message.h"
#include "pfcp_convert.h"

#include "n4_pfcp_build.h"

#include "updk/env.h"

Status UpfN4BuildSessionEstablishmentResponse(Bufblk **bufBlk, uint8_t type,
                                              UpfSession *session, uint8_t cause,
                                              PFCPSessionEstablishmentRequest *establishRequest) {
    Status status;
    PfcpMessage pfcpMessage;
    PFCPSessionEstablishmentResponse *response = NULL;
    PfcpFSeid fSeid;
    PfcpNodeId nodeId;
    PfcpFTeid fTeid;
    int len;

    response = &pfcpMessage.pFCPSessionEstablishmentResponse;
    memset(&pfcpMessage, 0, sizeof(pfcpMessage));

    /* Node Id */
    response->nodeID.presence = 1;
    /* TODO: IPv6 */
    nodeId.type = PFCP_NODE_ID_IPV4;
    nodeId.addr4 = Self()->pfcpAddr->s4.sin_addr;
    response->nodeID.value = &nodeId;
    response->nodeID.len = 1+4;

    /* cause */
    response->cause.presence = 1;
    response->cause.len = 1;
    response->cause.value = &cause;

    /* Condition or Option */
    if (cause == PFCP_CAUSE_REQUEST_ACCEPTED) {
        /* F-SEID */
        response->uPFSEID.presence = 1;
        response->uPFSEID.value = &fSeid;
        fSeid.seid = htobe64(session->upfSeid);
        status = PfcpSockaddrToFSeid(Self()->pfcpAddr,
                                     Self()->pfcpAddr, &fSeid, &len);
        response->uPFSEID.len = len;

        /*CreatedPDR*/
        PfcpFTeid *tempfTeid = (PfcpFTeid *)establishRequest->createPDR[0].pDI.localFTEID.value;

            if(tempfTeid->ch == 1){
                // retrieve pdrID
                response->createdPDR.presence = 1;
                response->createdPDR.pDRID.presence = 1;
                response->createdPDR.pDRID = establishRequest->createPDR[0].pDRID;
                
                // assign FTEID
                response->createdPDR.localFTEID.presence = 1;
                response->createdPDR.localFTEID.value = &fTeid;
                response->createdPDR.localFTEID.len = sizeof(fTeid.teid) + 5;
        
                fTeid.chid = 0;
                fTeid.ch = 0;
                fTeid.v4 = 1;
                fTeid.v6 = 0;
                fTeid.teid = htobe32(1);
                UTLT_Debug("teid: %d",&fTeid.teid);
                inet_pton(AF_INET,"10.144.175.51", &fTeid.addr4);
    } 
            else {
                response->createdPDR.presence = 0;
                //response->createdPDR.localFTEID = establishRequest->createPDR[0].pDI.localFTEID;
    }
    }

    pfcpMessage.header.type = type;
    status = PfcpBuildMessage(bufBlk, &pfcpMessage);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
                "build msg faild");

    UTLT_Debug("PFCP session establishment response built!");
    return STATUS_OK;
}

Status UpfN4BuildSessionModificationResponse(Bufblk **bufBlkPtr, uint8_t type,
                                             UpfSession *session,
                                             PFCPSessionModificationRequest *modifyRequest) {
    Status status;
    PfcpMessage pfcpMessage;
    PFCPSessionModificationResponse *response = NULL;
    uint8_t cause;

    response = &pfcpMessage.pFCPSessionModificationResponse;
    memset(&pfcpMessage, 0, sizeof(pfcpMessage));

    /* cause */
    response->cause.presence = 1;
    cause = PFCP_CAUSE_REQUEST_ACCEPTED;
    response->cause.value = &cause;
    response->cause.len = 1;

    /* TODO: Set Offending IE, Create PDR, Load Control Information, Overload Control Information, Usage Report, Failed Rule ID, Additional Usage Reports Information, Created/Updated Traffic Endpoint */

    pfcpMessage.header.type = type;
    pfcpMessage.header.seidP = 1;
    pfcpMessage.header.seid = session->smfSeid;
    status = PfcpBuildMessage(bufBlkPtr, &pfcpMessage);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR, "PFCP build error");

    UTLT_Debug("PFCP session modification response built!");
    return STATUS_OK;
}

Status UpfN4BuildSessionDeletionResponse(Bufblk **bufBlkPtr, uint8_t type,
                                         UpfSession *session,
                                         PFCPSessionDeletionRequest *deletionRequest) {
    Status status;
    PfcpMessage pfcpMessage;
    PFCPSessionDeletionResponse *response = NULL;
    uint8_t cause;

    response = &pfcpMessage.pFCPSessionDeletionResponse;
    memset(&pfcpMessage, 0, sizeof(PfcpMessage));

    /* cause */
    response->cause.presence = 1;
    cause = PFCP_CAUSE_REQUEST_ACCEPTED;
    response->cause.value = &cause;
    response->cause.len = 1;

    /* TODO: Set Offending IE, Load Control Information, Overload Control Information, Usage Report */

    pfcpMessage.header.type = type;
    status = PfcpBuildMessage(bufBlkPtr, &pfcpMessage);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR, "PFCP build error");

    UTLT_Debug("PFCP session deletion response built!");
    return STATUS_OK;
}

Status UpfN4BuildSessionReportRequestDownlinkDataReport(Bufblk **bufBlkPtr,
                                                        uint8_t type,
                                                        UpfSession *session,
                                                        uint16_t pdrId) {
    Status status;
    PfcpMessage pfcpMessage;
    PFCPSessionReportRequest *request = NULL;
    PfcpReportType reportType;
    PfcpDownlinkDataServiceInformation downlinkDataServiceInformationValue;

    request = &pfcpMessage.pFCPSessionReportRequest;
    memset(&pfcpMessage, 0, sizeof(PfcpMessage));
    memset(&reportType, 0, sizeof(PfcpReportType));
    memset(&downlinkDataServiceInformationValue, 0,
           sizeof(PfcpDownlinkDataServiceInformation));

    reportType.dldr = 1;

    request->reportType.presence = 1;
    request->reportType.value = &reportType;
    request->reportType.len = sizeof(PfcpReportType);

    /* TODO: fill in downlinkDataReport */
    DownlinkDataReport *downlinkDataReport = &request->downlinkDataReport;
    downlinkDataReport->presence = 1;

    downlinkDataReport->pDRID.presence = 1;
    // This value is store in network type
    pdrId = htons(pdrId);
    downlinkDataReport->pDRID.value = &pdrId;
    downlinkDataReport->pDRID.len = sizeof(pdrId);
    // not support yet, TODO
    downlinkDataReport->downlinkDataServiceInformation.presence = 0;

    /* fill in downlinkDataServiceInformation in downlinkDataReport */
    /*
      DownlinkDataServiceInformation *downlinkDataServiceInformation =
      &downlinkDataReport->downlinkDataServiceInformation;
      // fill in value of downlinkDataServiceInformation
      downlinkDataServiceInformationValue.ppi = 0;
      downlinkDataServiceInformationValue.qfii = 0;
      downlinkDataServiceInformationValue.pagingPolicyIndicationValue = 0;
      downlinkDataServiceInformationValue.qfi = 0;
      // fill value back to ServiceInformation
      downlinkDataServiceInformation->presence = 1;
      downlinkDataServiceInformation->value =
      &downlinkDataServiceInformationValue;
      downlinkDataServiceInformation->len =
      PfcpDownlinkDataServiceInformationLen(downlinkDataServiceInformationValue);
    */

    pfcpMessage.header.type = type;
    status = PfcpBuildMessage(bufBlkPtr, &pfcpMessage);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR, "PFCP build error");

    UTLT_Debug("PFCP session report request downlink data report built!");
    return STATUS_OK;
}

Status UpfN4BuildAssociationSetupResponse(Bufblk **bufBlkPtr, uint8_t type) {
    Status status;
    PfcpMessage pfcpMessage;
    PFCPAssociationSetupResponse *response = NULL;
    uint8_t cause;
    //uint16_t upFunctionFeature;

    response = &pfcpMessage.pFCPAssociationSetupResponse;
    memset(&pfcpMessage, 0, sizeof(PfcpMessage));
    pfcpMessage.pFCPAssociationSetupResponse.presence = 1;

    /* node id */
    // TODO: IPv6
    response->nodeID.presence = 1;
    PfcpNodeId nodeId;
    nodeId.spare = 0;
    nodeId.type = PFCP_NODE_ID_IPV4;
    nodeId.addr4 = Self()->pfcpAddr->s4.sin_addr;
    response->nodeID.len = 1+4;
    response->nodeID.value = &nodeId;

    /* cause */
    cause = PFCP_CAUSE_REQUEST_ACCEPTED;
    response->cause.presence = 1;
    response->cause.value = &cause;
    response->cause.len = 1;

    /* Recovery Time Stamp */
    response->recoveryTimeStamp.presence = 1;
    response->recoveryTimeStamp.value = &Self()->recoveryTime;
    response->recoveryTimeStamp.len = 4;

    // TODO: support UP Function Feature report
    /* UP Function Feature (Condition) */
    UpFunctionFeatures upFunctionFeatures;
	upFunctionFeatures.treu = 1;
	upFunctionFeatures.ftup = 0;
	upFunctionFeatures.dlbd = 1;
	upFunctionFeatures.ddnd = 0;
	upFunctionFeatures.quoac = 1;
	upFunctionFeatures.pdiu = 0;
	upFunctionFeatures.empu = 1;
	upFunctionFeatures.adpdp = 0;

	upFunctionFeatures.heeu = 0;
	upFunctionFeatures.pfdm = 0;
	upFunctionFeatures.trst = 0;
	upFunctionFeatures.bucp = 0;
	upFunctionFeatures.epfar = 0;
	upFunctionFeatures.pfde = 0;
	upFunctionFeatures.frrt = 0;
	upFunctionFeatures.trace = 0;
	upFunctionFeatures.udbc = 0;
	upFunctionFeatures.gcom = 0;
	upFunctionFeatures.bundl = 0;
	upFunctionFeatures.mte =0;
	upFunctionFeatures.mnop =0;
	upFunctionFeatures.sset =0;
	upFunctionFeatures.ueip = 0;
	upFunctionFeatures.dpdra =0;
	upFunctionFeatures.mptcp =0;
	upFunctionFeatures.tscu =0;
	upFunctionFeatures.ip6pl =0;
	upFunctionFeatures.iptv =0;
	upFunctionFeatures.norp =0;
	upFunctionFeatures.vtime =0;
	upFunctionFeatures.rttl =0;
	upFunctionFeatures.mpas =0;
	    response->uPFunctionFeatures.presence = 1;
        response->uPFunctionFeatures.value = &upFunctionFeatures;
        response->uPFunctionFeatures.len = sizeof(UpFunctionFeatures);//4
    

	HuaWei huaWei;
	huaWei.byte102 = 0x4e;
	huaWei.byte101 = 0x50;
	huaWei.byte100 = 0x56;
	huaWei.byte99 = 0x5f;
	huaWei.byte98 = 0x6e;
	huaWei.byte97 = 0x47;

	huaWei.byte96 = 0x2d;
	huaWei.byte95 = 0x62;
	huaWei.byte94 = 0x61;
	huaWei.byte93 = 0x4c;
	huaWei.byte92 = 0xd1;
	huaWei.byte91 = 0x5d;
	huaWei.byte90 = 0x90; 
	huaWei.byte89 = 0x0a;

	huaWei.byte88 = 0x0b;
	huaWei.byte87 = 0x06;
	huaWei.byte86 = 0xdb;
	huaWei.byte85 = 0x07;
	huaWei.byte84 = 0x12;
	huaWei.byte83 = 0x00;
	huaWei.byte82 = 0x8f; 
	huaWei.byte81 = 0x80;

	huaWei.byte80 = 0x4e;
	huaWei.byte79 = 0x50;
	huaWei.byte78 = 0x56;
	huaWei.byte77 = 0x5f;
	huaWei.byte76 = 0x6e;
	huaWei.byte75 = 0x47;
	huaWei.byte74 = 0x2d; 
	huaWei.byte73 = 0x62;

	huaWei.byte72 = 0x61;
	huaWei.byte71 = 0x4c;
	huaWei.byte70 = 0xd0;
	huaWei.byte69 = 0x5d;
	huaWei.byte68 = 0x90;
	huaWei.byte67 = 0x0a;
	huaWei.byte66 = 0x09; 
	huaWei.byte65 = 0x06;

	huaWei.byte64 = 0xdb;
	huaWei.byte63 = 0x07;
	huaWei.byte62 = 0x12;
	huaWei.byte61 = 0x00;
	huaWei.byte60 = 0x8f;
	huaWei.byte59 = 0x80;
	huaWei.byte58 = 0x4e; 
	huaWei.byte57 = 0x50;
	
	huaWei.byte56 = 0x56;
	huaWei.byte55 = 0x5f;
	huaWei.byte54 = 0x32;
	huaWei.byte53 = 0x58;
	huaWei.byte52 = 0x2d;
	huaWei.byte51 = 0x31;
	huaWei.byte50 = 0x53; 
	huaWei.byte49 = 0x2d;

	huaWei.byte48 = 0x62;
	huaWei.byte47 = 0x61;
	huaWei.byte46 = 0x4c;
	huaWei.byte45 = 0x33;
	huaWei.byte44 = 0xaf;
	huaWei.byte43 = 0x90;
	huaWei.byte42 = 0x0a; 
	huaWei.byte41 = 0x08;

	huaWei.byte40 = 0x06;
	huaWei.byte39 = 0xdb;
	huaWei.byte38 = 0x07;
	huaWei.byte37 = 0x15;
	huaWei.byte36 = 0x00;
	huaWei.byte35 = 0x8f;
	huaWei.byte34 = 0x80; 
	huaWei.byte33 = 0x4e;

	huaWei.byte32 = 0x50;
	huaWei.byte31 = 0x56;
	huaWei.byte30 = 0x5f;
	huaWei.byte29 = 0x6e;
	huaWei.byte28 = 0x47;
	huaWei.byte27 = 0x2d;
	huaWei.byte26 = 0x62; 
	huaWei.byte25 = 0x61;

	huaWei.byte24 = 0x4c;
	huaWei.byte23 = 0xd0;
	huaWei.byte22 = 0x5d;
	huaWei.byte21 = 0x90;
	huaWei.byte20 = 0x0a;
	huaWei.byte19 = 0x03;
	huaWei.byte18 = 0x06; 
	huaWei.byte17 = 0xdb;

        huaWei.byte16 = 0x07;
	huaWei.byte15 = 0x12;
	huaWei.byte14 = 0x00;
	huaWei.byte13 = 0x8f;
	huaWei.byte12 = 0x80;
	huaWei.byte11 = 0x74;
	huaWei.byte10 = 0x69; 
	huaWei.byte09 = 0x75;

	huaWei.byte08 = 0x73;
	huaWei.byte07 = 0x70;
	huaWei.byte06 = 0x69;
	huaWei.byte05 = 0x06;
	huaWei.byte04 = 0x00;
	huaWei.byte03 = 0x00;
	huaWei.byte02 = 0xdb; // enterprise ID
	huaWei.byte01 = 0x07; // enterprise ID

	response->huawei.presence = 1;
	response->huawei.value = &huaWei;
	response->huawei.len = sizeof(HuaWei);//
    //UTLT_Info("*********HUAWEI******************");
    //UTLT_Info("huawei Len: %d",response->huawei.len);
    //UTLT_Info("%d",pfcpMessage.pFCPAssociationSetupResponse.huawei.len);//1



    PfcpUserPlaneIpResourceInformation upIpResourceInformation;
    memset(&upIpResourceInformation, 0,
           sizeof(PfcpUserPlaneIpResourceInformation));

    // teid
    upIpResourceInformation.teidri = 1;
    upIpResourceInformation.teidRange = 0;

    // network instence
    upIpResourceInformation.assoni = 1;
    DNN *dnn;
    uint8_t dnnLen = 0;
    EnvParamsForEachDNN(dnn, Self()->envParams) {
        dnnLen = strlen(dnn->name);
        memcpy(upIpResourceInformation.networkInstance, &dnnLen, 1);
        memcpy(upIpResourceInformation.networkInstance + 1, dnn->name, dnnLen + 1);
        break;
    }

    // TODO: better algo. to select establish IP
    int isIpv6 = 0;
    VirtualPort *port;
    VirtualDeviceForEachVirtualPort(port, Self()->envParams->virtualDevice) {
        isIpv6 = (strchr(port->ipStr, ':') ? 1 : 0);
        if (!upIpResourceInformation.v4 && !isIpv6) {
            UTLT_Assert(inet_pton(AF_INET, port->ipStr, &upIpResourceInformation.addr4) == 1,
                continue, "IP address[%s] in VirtualPort is invalid", port->ipStr);
            upIpResourceInformation.v4 = 1;
        }
        /* TODO: IPv6
        if (!upIpResourceInformation.v6 && isIpv6) {
            UTLT_Assert(inet_pton(AF_INET6, port->ipStr, &upIpResourceInformation.addr6) == 1,
                continue, "IP address[%s] in VirtualPort is invalid", port->ipStr);
            upIpResourceInformation.v6 = 1;
        }
        */
        if (upIpResourceInformation.v4 && upIpResourceInformation.v6)
            break;
    }

    response->userPlaneIPResourceInformation.presence = 1;
    response->userPlaneIPResourceInformation.value = &upIpResourceInformation;
    // TODO: this is only IPv4, no network instence, no source interface
    response->userPlaneIPResourceInformation.len = 2+4+1+dnnLen;
    // HACK: sizeof(Internet) == 8, hardcord
    //response->userPlaneIPResourceInformation.len =
    //sizeof(PfcpUserPlaneIpResourceInformation);

    pfcpMessage.header.type = type;
    status = PfcpBuildMessage(bufBlkPtr, &pfcpMessage);
    UTLT_Assert(*bufBlkPtr, , "buff NULL");
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR, "PFCP build error");

    UTLT_Debug("PFCP association session setup response built!");
    return STATUS_OK;
}

Status UpfN4BuildAssociationReleaseResponse(Bufblk **bufBlkPtr, uint8_t type) {
    Status status;
    PfcpMessage pfcpMessage;
    PFCPAssociationReleaseResponse *response = NULL;
    PfcpNodeId nodeId;
    uint8_t cause;

    response = &pfcpMessage.pFCPAssociationReleaseResponse;
    memset(&pfcpMessage, 0, sizeof(PfcpMessage));
    response->presence = 0;

    /* nodeId */
    response->nodeID.presence = 1;
    nodeId.type = PFCP_NODE_ID_IPV4;
    // TODO: IPv6 version
    nodeId.addr4 = Self()->pfcpAddr->s4.sin_addr;
    response->nodeID.value = &nodeId;
    response->nodeID.len = 1+4; // ???

    /* cause */
    response->cause.presence = 1;
    cause = PFCP_CAUSE_REQUEST_ACCEPTED;
    response->cause.value = &cause;
    response->cause.len = 1;

    pfcpMessage.header.type = type;
    status = PfcpBuildMessage(bufBlkPtr, &pfcpMessage);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR, "PFCP build error");

    UTLT_Debug("PFCP association release response built!");
    return STATUS_OK;
}

Status UpfN4BuildHeartbeatResponse(Bufblk **bufBlkPtr, uint8_t type) {
    Status status;
    PfcpMessage pfcpMessage;
    HeartbeatResponse *response;
    
    response = &pfcpMessage.heartbeatResponse;
    memset(&pfcpMessage, 0, sizeof(PfcpMessage));

    /* Set Recovery Time Stamp */
    response->recoveryTimeStamp.presence = 1;
    response->recoveryTimeStamp.value = &Self()->recoveryTime;
    response->recoveryTimeStamp.len = 4;

    pfcpMessage.header.type = type;
    status = PfcpBuildMessage(bufBlkPtr, &pfcpMessage);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR, "PFCP build error");

    UTLT_Debug("PFCP heartbeat response built!");
    return STATUS_OK;
}
