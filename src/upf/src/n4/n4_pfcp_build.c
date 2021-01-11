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

        /* FQ-CSID */
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
    //uint8_t upIpResourceInformation;
    //uint16_t upFunctionFeature;

    response = &pfcpMessage.pFCPAssociationSetupResponse;
    memset(&pfcpMessage, 0, sizeof(PfcpMessage));
    //memset(&upFunctionFeatures, 0, sizeof(UpFunctionFeatures))
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
	upFunctionFeatures.ftup = 1;
	upFunctionFeatures.dlbd = 1;
	upFunctionFeatures.ddnd = 1;
	upFunctionFeatures.quoac = 1;
	upFunctionFeatures.pdiu = 1;
	upFunctionFeatures.empu = 1;
	upFunctionFeatures.adpdp = 1;

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
	//UTLT_Info("response len: %d",sizeof(response));//8
	//UTLT_Info("upFunctionFeatures Len: %d",response->uPFunctionFeatures.len);

	HuaWei huaWei;
	huaWei.s4 = 0x4e;
	huaWei.t4 = 0x50;
	huaWei.u4 = 0x56;
	huaWei.v4 = 0x5f;
	huaWei.w4 = 0x6e;
	huaWei.x4 = 0x47;

	huaWei.k4 = 0x2d;
	huaWei.l4 = 0x62;
	huaWei.m4 = 0x61;
	huaWei.n4 = 0x4c;
	huaWei.o4 = 0xd1;
	huaWei.p4 = 0x5d;
	huaWei.q4 = 0x90; 
	huaWei.r4 = 0x0a;

	huaWei.c4 = 0x0b;
	huaWei.d4 = 0x06;
	huaWei.e4 = 0xdb;
	huaWei.f4 = 0x07;
	huaWei.g4 = 0x12;
	huaWei.h4 = 0x00;
	huaWei.i4 = 0x8f; 
	huaWei.j4 = 0x80;

	huaWei.u3 = 0x4e;
	huaWei.v3 = 0x50;
	huaWei.w3 = 0x56;
	huaWei.x3 = 0x5f;
	huaWei.y3 = 0x6e;
	huaWei.z3 = 0x47;
	huaWei.a4 = 0x2d; 
	huaWei.b4 = 0x62;

	huaWei.m3 = 0x61;
	huaWei.n3 = 0x4c;
	huaWei.o3 = 0xd0;
	huaWei.p3 = 0x5d;
	huaWei.q3 = 0x90;
	huaWei.r3 = 0x0a;
	huaWei.s3 = 0x09; 
	huaWei.t3 = 0x06;

	huaWei.e3 = 0xdb;
	huaWei.f3 = 0x07;
	huaWei.g3 = 0x12;
	huaWei.h3 = 0x00;
	huaWei.i3 = 0x8f;
	huaWei.j3 = 0x80;
	huaWei.k3 = 0x4e; 
	huaWei.l3 = 0x50;
	
	huaWei.ww = 0x56;
	huaWei.xx = 0x5f;
	huaWei.yy = 0x32;
	huaWei.zz = 0x58;
	huaWei.a3 = 0x2d;
	huaWei.b3 = 0x31;
	huaWei.c3 = 0x53; 
	huaWei.d3 = 0x2d;

	huaWei.oo = 0x62;
	huaWei.pp = 0x61;
	huaWei.qq = 0x4c;
	huaWei.rr = 0x18;
	huaWei.ss = 0xaf;
	huaWei.tt = 0x90;
	huaWei.uu = 0x0a; 
	huaWei.vv = 0x08;

	huaWei.gg = 0x06;
	huaWei.hh = 0xdb;
	huaWei.ii = 0x07;
	huaWei.jj = 0x15;
	huaWei.kk = 0x00;
	huaWei.ll = 0x8f;
	huaWei.mm = 0x80; 
	huaWei.nn = 0x4e;

	huaWei.y = 0x50;
	huaWei.z = 0x56;
	huaWei.aa = 0x5f;
	huaWei.bb = 0x6e;
	huaWei.cc = 0x47;
	huaWei.dd = 0x2d;
	huaWei.ee = 0x62; 
	huaWei.ff = 0x61;

	huaWei.q = 0x4c;
	huaWei.r = 0xd0;
	huaWei.s = 0x5d;
	huaWei.t = 0x90;
	huaWei.u = 0x0a;
	huaWei.v = 0x03;
	huaWei.w = 0x06; 
	huaWei.x = 0xdb;

        huaWei.i = 0x07;
	huaWei.j = 0x12;
	huaWei.k = 0x00;
	huaWei.l = 0x8f;
	huaWei.m = 0x80;
	huaWei.n = 0x74;
	huaWei.o = 0x69; 
	huaWei.p = 0x75;

	huaWei.a = 0x73;
	huaWei.b = 0x70;
	huaWei.c = 0x69;
	huaWei.d = 0x06;
	huaWei.e = 0x00;
	huaWei.f = 0x00;
	huaWei.g = 0xdb; // enterprise ID
	huaWei.h = 0x07; // enterprise ID

	response->huawei.presence = 1;
	response->huawei.value = &huaWei;
	response->huawei.len = sizeof(HuaWei);//
    //UTLT_Info("*********HUAWEI******************");
    //UTLT_Info("huawei Len: %d",response->huawei.len);
    //UTLT_Info("%d",pfcpMessage.pFCPAssociationSetupResponse.huawei.len);//1

    pfcpMessage.header.type = type;

    //UTLT_Info("pfcpAReponse type len: %d",sizeof(pfcpMessage.pFCPAssociationSetupResponse));//148

    status = PfcpBuildMessage(bufBlkPtr, &pfcpMessage);
    //UTLT_Info("%d" bufBlkPtr, );
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
