// Copyright (C) 2015 Salaheddin Darwish; Department of Computer Science, Brunel University London, UK
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
//

#ifndef __AUTHNAGENT_H__
#define __AUTHNAGENT_H__

#include <omnetpp.h>
#include "UDPAppBase.h"
#include "InetSimpleBattery.h"
#include "IPvXAddress.h"
#include "ChannelControl.h"
#include "BasicMobility.h" // test
#include "ManetManager.h"
#include "mainUnit.h"
#include "aodv_uu_omnet.h"
#include "AAMDynamicNetworkConfigurator.h"


/**
 * TODO - Generated class
 */
class INET_API AuthNAgent  : public UDPAppBase
{

public:
  AuthNAgent() ;
  virtual ~AuthNAgent();

  enum AuthNUserStates
  {
    AuthenIdle , // not yet request to authentication
    AuthenInProgress , // already requested and waiting a reply
    SucAuthNUser,// successful authentication
    UnscAuthNUser, // Unsccessful authentication
    FailedAuthN, // fail to reach the authenticator after 3 tries
    FailedAuthNMig,
    ErrAuthN,
   } ;

  enum AuthNProtocolStates
  {
    state_MsgIdle =0,
    State_Msg1 =1 ,
    State_Msg2 =2 ,
    State_Msg3 =3,
    State_DAS =4,
    State_Data =5,
    State_End =6,
    State_DAS_END,
    State_Err = 100,
  } ;

  enum Process_State
  {
    Process_Idle,
    ProtoMsg_Process ,
    DataMsg_Process ,
    Error_Process ,

  };

  enum AttribCertiType
  {
    RootAc = 0 ,
    ThresholdAc =1,
    DelegThresAc =2 ,
    PartialThresAC=3,
    Peer = 4,


  };

  struct ServLst
  {
    int ID ; // id module
    opp_string SrvName;
    //   IPvXAddress SrvAdress ;
    opp_string SrvAdress ;
    int sPort;
    std::string ServerName;

  };

  struct MsgInfo
  {
    int indX ;
    std::string msgProtName;
    double sizeMsg;
    double generatingProcessDelay;
    double validateProcessDelay ;
    int fieldNum;
  };

  typedef std::vector <MsgInfo> MsgProtocolProfileDef;

  struct AuthnType
  {
    int  authTypeId;
    std::string AuthnName;
    int numMsg;
    MsgProtocolProfileDef MsgProtProf  ;
  };

 struct serverAddrs
  {
   // const char * AddressServer;
    std::string AddressServer;
    int ServerType ;
    std::string serverTypeName ;
  };

  struct AttribCertifRec
  {
    int id ;
    std::string Name ;
    AttribCertiType CertifType ;
    double Trust;
  };
   struct SrvRec
	{
		int iS;
		double Srtt ;
	};


  typedef std::vector<ServLst *> SrvLst;

  IPvXAddress AuthnManAddr;
  AuthNUserStates AuthNUserState;
  AuthNProtocolStates AuthNProtocolState;

  std::vector <AuthnType> MsgProtocolProfiles;
  std::vector<serverAddrs> AuthnManAddresses;
  std::vector <std::string> CertiClasses ;
  std::vector<AttribCertifRec> AttribCertifVec ;


  typedef SrvRec SrvRecVar;
  std::vector <SrvRecVar> srvIndx ;

  cMessage *AuthNExptimer;
  cMessage *MigTimer ;
  cMessage *CombinPocessTimer ;

  AAMDynamicNetworkConfigurator * AAMDNC ;

  SrvLst netServices;


  InetSimpleBattery *bat ;
  BasicMobility *BM ;
  ManetManager *MM;
  mainUnit *MP ;
  AODVUU *AODVUU_PTR;

  // Scalar Variables
  std::string hostState ;// salah

  int ManNum ;
  int msgByteLength;
  int ResponMsgByteLength ;
  int TotalByteCom;
  int AuthnManPort,localAuthnAgentPort;
  simtime_t WTime;
  simtime_t timeToStart; // Joining Time ;
  simtime_t TTimer ;
  simtime_t sendMsgtime;
  simtime_t sendMsgtimeTemp;
  simtime_t recMsgtime;
  simtime_t rtt ;
  simtime_t MigrationTripTime;
  simtime_t DecryptValidateDelay ;
  simtime_t  CombinPocessDelay ;
  simtime_t TotalSrcTime ;
  simtime_t timeToStartMIG;

  int RandomGSeed ;
  bool Authenticated;
  bool AuthNReq;
  bool WaitingWindowEnable ;
  bool LockFlag ;
  bool DF ;
  std::string Certif ;
  opp_string MembershipCertificate ;


  unsigned int ThreshSrvNum ;
  unsigned int TotthreshCount ;

  int Counter;
  int NumRequestInProgress ;
  int numRequestsDrop;
  int numSuccessRequests;
  int AgentErrMsg;
  int UdpErrMsg;
  int T_Counter ;
  int I_Phase_MIG ;
  int MaxReAuthNCounter ;
  int fix_Exp_WT;
  int TotalByteDrop;

//  cLongHistogram  SucessReqHist;
//  cLongHistogram  DropReqHist;
//  cLongHistogram  InProgReqHist;
  cOutVector rttVec;
  cOutVector SrcTimes ;

  std::vector<cOutVector *> MigStateRec ;
  std::vector<cOutVector *> TotalSendByteRec ;
  std::vector<cOutVector *> TotalReceiveByteRec ;
  std::vector<cOutVector *> RTTVec ;

  bool EnabledMigr;
  bool DisconnectFlag;
  int MigAttempNum ;
  int AuthenticationType;
  int SrvTypTestCase ;
  int NonceVal ;
  int sNonceVal ;
  int sSeqVal ;
  int RoSrvCount ;

  std::string sCertif ;
  int  strategyType;
  bool TriggerFlag ;
  bool TrigAlreadyCalled;
  std::vector<int> inAr;
  bool SetMobilMod;


  struct  sSecRecord
  {
    int AuthNTypeRec;
    int cNonceValRec ;
    int cSeq ;
    IPvXAddress ServerAddressRec ;
    int sPort;
    int sNonceValRec ;
    int sSeqValRec ;
    std::string sCertifRec;
    int TotalBytesSendRec ;
    int TotalByteReceivRec ;
    int TotalByteDropped ;
    AuthNProtocolStates AuthNProtocolStateRec ;
    AuthNUserStates AuthNUserStateRec ;
    Process_State Proces_State ;

    bool sReachable;
    std::string attribCertiSRec;
    std::string attrThreshCertiRec;
    std::string ServerName ;
    int SrvTypeCod ;
    int ReqCounter ;
    int T_ReqCounter ;
    int DASReqCounter ;
    bool ProtoCompleted ;
    bool TimerReAuthN;
    bool SucessDAS ;


    simtime_t sendMsgtime ;
    simtime_t ReciMsgtime;
    simtime_t SSRTT;
    simtime_t TTimeWait;
    cMessage *ExprTimer;
    cMessage *ProProcessTimer ;
    cMessage *DataProcessTimer;
  };

  struct  sSecRecordLog
  {
    int TimerTypeLog;
    int MsgtypeLog;
    std::string ServerNameLog ;
    std::string MsgNameLog ;
    int SrvTypeCodLog ;
    AuthNProtocolStates AuthNProtocolStateRecLog ;
    AuthNUserStates AuthNUserStateRecLog ;
    Process_State Proces_StateLog ;
    bool sReachableLog;
    int AuthNTypeRecLog;
    int TotalBytesSendRecLog ;
    int TotalByteReceivRecLog ;
    int TotalByteDroppedLog ;
    int SeqNumLog;
    int SeqNumMsgLog;
    int DASReqNumLog;
    bool DASSuccess;

  };

  std::vector<sSecRecord> ServSecurVec ;
  std::vector<sSecRecordLog> ServSecurVecLog ;



protected:
  virtual int numInitStages() const {return 7;}
  virtual void initialize(int stage);
  virtual void handleMessage(cMessage *msg);
  virtual void finish();

  virtual void handleTimer(cMessage *msg);
  virtual void sendAuthnRequest(int idx);
  virtual void AuthnStateDataProcess(int st, bool SucceFlag,bool ReAFlag);
  virtual void CancelTimer (unsigned int it) ;
  virtual void processAuthnResponse(cPacket *msg);
  virtual void chooseCertiClasse();
  virtual void delaySendToUDP(cPacket *msg, int srcPort, const IPvXAddress& destAddr, int destPort, simtime_t processdelay );
  virtual void processManSrvAddr( const char * TokenPar, int srvType );
  virtual void MigrationTimer ();
  virtual void SchduleAuthnRequest (int strgSvrType ,simtime_t xTime);
  virtual void UserTrafficTrigger ();
  virtual int DataProcessInProgress(int SrvIndxP);
  virtual bool IsCASAuthnReqInProg ();


};

class INET_API AuthNAgentAccess : public ModuleAccess<AuthNAgent>
   {
     public:
    	 AuthNAgentAccess() : ModuleAccess<AuthNAgent>("AuthNAgent") {}
   };
#endif
