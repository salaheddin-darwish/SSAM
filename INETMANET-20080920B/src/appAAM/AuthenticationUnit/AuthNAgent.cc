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
//

#include "AuthNAgent.h"
#include "UDPControlInfo_m.h"
#include "CommonAAM_m.h"
#include "IPAddressResolver.h"
#include "TraffGenHostMan.h"
#include <fstream>

#define MSGKIND_START_REQ  		0
#define MSGKIND_ReREQ    		1
#define MSGKIND_MIGRATE_PrepReq 2
#define MSGKIND_MIGRATE_REREQ 	3
#define MSGKIND_PR_PROS_TIMER 	4
#define MSGKIND_DATA_PROS_TIMER 5
#define MSGKIND_COMBINPR_TIMER 	6
#define MSGKIND_DAS_REQ 		7
#define MSGKIND_DAS_ReREQ		8
#define MSGKIND_DAS_PROS_TIMER  9
#define MSGKIND_SRCH_FOR_CONN  10
#define MSGKIND_SRCH_CONN_MIG  11



#define MaxSimTime STR_SIMTIME(ev.getConfig()->getConfigValue("sim-time-limit"))

Define_Module(AuthNAgent);

inline std::ostream& operator<<(std::ostream& out, const AuthNAgent::ServLst& d) {
    out << " SourceModule=" 	<< d.ID
		<< " Service Name:" 	<< d.SrvName
        << " Srv Address=" 		<< d.SrvAdress
        << " port=" 			<< d.sPort
        << " Server_Name="		<< d.ServerName ;
    return out;
}

inline std::ostream& operator<<(std::ostream& out, const AuthNAgent::MsgInfo& d) {

	 out <<d.indX  		<<"  "	<< d.msgProtName 	<<"  "
		 <<d.fieldNum	<<"  "	<< d.sizeMsg 		<<"  "
		 <<d.generatingProcessDelay					<<"  "
		 <<d.validateProcessDelay;
	return out;
}

inline std::ostream& operator<<(std::ostream& out, const AuthNAgent::AuthnType& d) {

	 out <<d.AuthnName 		<<"  "
		 << d.authTypeId 	<<"  "
		 <<d.numMsg 		<<"  "
		 <<d.MsgProtProf.size();
	return out;
}

inline std::ostream& operator<<(std::ostream& out, const AuthNAgent::sSecRecord& d)
{
   out <<" AuthType="			<<d.AuthNTypeRec
	   <<" SrvName="			<<d.ServerName
	   <<" Addr="				<<d.ServerAddressRec.str()
	   <<" AuthPSt="			<<d.AuthNProtocolStateRec
       <<" CliNonce="			<<d.cNonceValRec
       <<" cliSeq=" 			<<d.cSeq
       <<" SrvCer="				<<d.sCertifRec
       <<" SrvNonce="			<<d.sNonceValRec
       <<" SrvSeq="				<<d.sSeqValRec
       <<" TByteSend="			<<d.TotalBytesSendRec
       <<" TByteReciev="		<<d.TotalByteReceivRec
       <<" TByteRecDrop="		<<d.TotalByteDropped
       <<" SrvReach=" 			<<(d.sReachable? "True":"False")
       <<" ProtocolCompleted="	<<(d.ProtoCompleted? "True":"False")
       <<" TimerReAuthn="		<<(d.TimerReAuthN ? "True":"False")
       <<" DASSuccess="			<<(d.SucessDAS? "True":"False")
       <<" S_AC="				<<d.attribCertiSRec
       <<" S_Thr_AC="			<<d.attrThreshCertiRec
       <<" SrvTypeCod ="		<<d.SrvTypeCod
       <<" AutUserStat="		<<d.AuthNUserStateRec
       <<" ProState="			<<d.Proces_State
       <<" DASReqCounter="		<<d.DASReqCounter
       <<" (TimeSend="			<<d.sendMsgtime
       <<", NumReq="			<<d.ReqCounter
       <<", NumRecq="			<<d.T_ReqCounter
       <<", TTimeWait=" 		<<d.TTimeWait
       <<", RTT="				<<d.ReciMsgtime-d.sendMsgtime<<")";
  return out;
}

inline std::ostream& operator<<(std::ostream& out, const AuthNAgent::serverAddrs& d)
{
   out <<" Addr="			<<d.AddressServer
	   <<" ServerTypeName="	<<d.serverTypeName
	   <<" SrvTypeCode="	<<d.ServerType ;
   return out;
}

inline std::ostream& operator<<(std::ostream& out, const AuthNAgent::AttribCertifRec& d)
{
   out <<" IDCer="		<<d.id
	   <<" CertifName="	<<d.Name
	   <<" CertifType="	<<d.CertifType
	   <<" Trust="		<<d.Trust ;
   return out;
}

inline std::ostream& operator<<(std::ostream& out, const AuthNAgent::sSecRecordLog& sX)
{
  out <<" AuthProType=" 	<< sX.AuthNProtocolStateRecLog 	<<
        " AuthTyp=" 		<< sX.AuthNTypeRecLog 			<<
        " AuthUse=" 		<< sX.AuthNUserStateRecLog 		<<
        " AuthProces=" 		<< sX.Proces_StateLog			<<
        " ServerName=" 		<< sX.ServerNameLog				<<
        " Msg_Name="		<< sX.MsgNameLog				<<
        " ServerCod=" 		<< sX.SrvTypeCodLog				<<
        " Timer_Type=" 		<< sX.TimerTypeLog				<<
        " Msg_Type="		<< sX.MsgtypeLog				<<
        " TByteRec=" 		<< sX.TotalByteReceivRecLog		<<
        " TByteSen=" 		<< sX.TotalBytesSendRecLog		<<
        " TByteDrop="		<< sX.TotalByteDroppedLog		<<
        " Reachable=" 		<< sX.sReachableLog				<<
        " SeqNum="			<< sX.SeqNumLog					<<
        " SeqNumMsg="		<< sX.SeqNumMsgLog 				<<
		" DASReqNumL="		<< sX.DASReqNumLog				<<
	    " DASSuccess=" 		<< sX.DASSuccess				;

  return out;
}

AuthNAgent::AuthNAgent()
{

  AuthNExptimer 		= NULL;
  CombinPocessTimer 	= NULL ;
  AgentErrMsg 			= 0;
  UdpErrMsg				= 0;
//ResponMsgByteLength 	= 0;
  MigTimer 				= NULL;
  TotalByteCom 			= 0 ;
  Certif 				= "NOT AVAILABLE";
  MembershipCertificate = "NOT AVAILABLE";
  rtt 					= 0;
  AuthNReq 				= false;
  RoSrvCount 			= 0;
  TotthreshCount 		= 0;
  TrigAlreadyCalled 	= false ;
  DF 					= false ;

  //CERTIFICATE TYPES
  CertiClasses.push_back("CorruptedIDCert");
  CertiClasses.push_back("GoldenIDCert");
  CertiClasses.push_back("SilverIDCert");
  CertiClasses.push_back("BronzeIDCert");


  MsgInfo msgRec1 ;
  MsgProtocolProfileDef MsgProtProfV ;
  struct AuthnType AnRec ;

  // One Pass X509 ------------------------------//
  msgRec1.indX 			= 1 ;
  msgRec1.msgProtName 	= "Msg_1";
  msgRec1.fieldNum 		= 2 ;
  msgRec1.sizeMsg 		= 1100; //512 ;
  msgRec1.generatingProcessDelay 	= uniform(0.8,1); //normal (1, 0.2);
  msgRec1.validateProcessDelay 		= uniform(0.8,1); //normal (1, 0.2);
  MsgProtProfV.push_back(msgRec1);

  AnRec.AuthnName 	= "X509_One_Pass";
  AnRec.authTypeId 	= 1 ;
  AnRec.numMsg 		= 1;
  AnRec.MsgProtProf = MsgProtProfV;
  MsgProtocolProfiles.push_back(AnRec);

  // Two Pass X509 -----------------------------//
  msgRec1.indX 			= 2 ;
  msgRec1.msgProtName 	= "Msg_2";
  msgRec1.fieldNum	 	= 2 ;
  msgRec1.sizeMsg 		= 1100 ;
  msgRec1.generatingProcessDelay = uniform(0.8,1); //normal (1, 0.2);
  msgRec1.validateProcessDelay 	 = uniform(0.8,1); //normal (1, 0.2);
  MsgProtProfV.push_back(msgRec1);

  AnRec.AuthnName 	= "X509_Two_Pass";
  AnRec.authTypeId 	= 2 ;
  AnRec.numMsg 		= 2;
  AnRec.MsgProtProf = MsgProtProfV;
  MsgProtocolProfiles.push_back(AnRec);

  //Three Pass X509----------------------------//
  msgRec1.indX 			= 3 ;
  msgRec1.msgProtName 	= "Msg_3";
  msgRec1.fieldNum 		= 2 ;
  msgRec1.sizeMsg 		= 512 ;
  msgRec1.generatingProcessDelay = uniform(0.8,1); //normal (1, 0.2);
  msgRec1.validateProcessDelay 	 = uniform(0.8,1); //normal (1, 0.2);
  MsgProtProfV.push_back(msgRec1);

  AnRec.AuthnName 	= "X509_Three_Pass";
  AnRec.authTypeId 	= 3 ;
  AnRec.numMsg 		= 3;
  AnRec.MsgProtProf = MsgProtProfV;
  MsgProtocolProfiles.push_back(AnRec);
}// Constructor End

void AuthNAgent::initialize(int stage)
{
  // because of IPAddressResolver, we need to wait until interfaces are registered,
  // address auto-assignment takes place etc.

  if (stage != 6)
    return;

  cDisplayString* display_string = &getParentModule()->getDisplayString();
  std::stringstream HistName1,HistName2,HistName3 ;

  Counter 				= 0;
  T_Counter 			= 0;
  I_Phase_MIG 	  		= 0; // Max Migrate Phases

  Authenticated   		= false;
  SetMobilMod			= par("SetMobilModOn").boolValue();

  AuthNUserState  		= AuthenIdle; // IDLE State to Start Authenticating

  numSuccessRequests	= 0;
  NumRequestInProgress 	= 0;
  numRequestsDrop 		= 0;
  TotalByteDrop			= 0;
  TotalSrcTime			= 0;

//   // Histogram Graph for collecting Successful , Dropped and In-progress Request Counters
//  HistName1 <<getParentModule()->getName()<<"-SucessfullReqNum" ;
//  SucessReqHist.setName(HistName1.str().c_str());
//  // SucessReqHist.setNumFirstVals(5);
//
//  HistName2 <<getParentModule()->getName()<<"-DropReqNum" ;
//  DropReqHist.setName(HistName2.str().c_str());
//  // DropReqHist.setNumFirstVals(3);
//
//  HistName3 <<getParentModule()->getName()<<"-InProgReqNum" ;
//  InProgReqHist.setName(HistName3.str().c_str());
//  // InProgReqHist.setNumFirstVals(5);

  // Authentication Managers
  const char *RootSrvAddrs 	= par("AuthNMANAddr");
  const char *SrvThreAddrs 	= par("AuthNMANThreAddr");
  SrvTypTestCase 			= par("SrvTypeOptions");
  ThreshSrvNum 				= par("ThresholdServer") ;

  if (SrvTypTestCase==1 ) processManSrvAddr(RootSrvAddrs , 1) ;
  else if (SrvTypTestCase==2 )  processManSrvAddr(SrvThreAddrs, 2) ;
  else if ( SrvTypTestCase ==3 ||SrvTypTestCase ==4 )
  {
   if (!par("disableCAS").boolValue()) processManSrvAddr(RootSrvAddrs, 1) ;
    processManSrvAddr(SrvThreAddrs, 2) ;
  }

  if ((SrvTypTestCase==2||SrvTypTestCase==3 || SrvTypTestCase ==4 ) &&TotthreshCount <= ThreshSrvNum)
	  error ("Error in Threshold Server Parameters ToThreNum: %d - thrNum %d", TotthreshCount ,ThreshSrvNum);

  // AuthnManAddr = IPAddressResolver().resolve(par("AuthNMANAddr"));
  AuthnManPort 			= par("AuthnManPort");
  localAuthnAgentPort 	= par("localAuthnAgentPort");
  WaitingWindowEnable 	= par("WaitingWindowEnable"); // Flag for Re-Authentication Request activation
  WTime 				= par("AWaitInterval"); 	  // Waiting Time Unit
  fix_Exp_WT			= par ("Fix_Exp_WT");
  DisconnectFlag		= par("DisconnectFlag");
  TTimer 				= par("time_begin");
  timeToStart 			= simTime(); // The time of the joining or accessing Network
  //msgByteLength = par("messageLength");//MsgReply to MembCertit
  RandomGSeed 	= par("GeneratorSeed");

  EnabledMigr 			= par("EnabledMigr");
  MigAttempNum 			= par("MigAttempNum");
  MigrationTripTime 	= par("MigrationTripTime");

  AuthenticationType 	= par("AuthenticationType");
  CombinPocessDelay 	= par ("CombinPocessDelay");
  MaxReAuthNCounter 	= par("MaxReAuthNCounter") ;
  DecryptValidateDelay 	= par("DecryptValidateDelay");

  sSecRecord sSecrecTemp ;

  for ( int i =0 ; i <ManNum ; i++ )
  {
	  NonceVal = intuniform(1000, 100000);
	  sSecrecTemp.AuthNTypeRec 				= AuthenticationType ;
	  sSecrecTemp.AuthNProtocolStateRec 	= state_MsgIdle ;
	  sSecrecTemp.cNonceValRec 				= NonceVal;
	  sSecrecTemp.cSeq 						= 0 ;
	  sSecrecTemp.ServerAddressRec 			= IPAddressResolver().resolve((AuthnManAddresses[i].AddressServer).c_str());
	  sSecrecTemp.ServerName 				= AuthnManAddresses[i].AddressServer ;
	  sSecrecTemp.sPort 					= AuthnManPort;
	  sSecrecTemp.TotalByteReceivRec 		= 0;
	  sSecrecTemp.TotalBytesSendRec 		= 0;
	  sSecrecTemp.TotalByteDropped			= 0;
	  sSecrecTemp.sCertifRec 				= "NA" ;
	  sSecrecTemp.attrThreshCertiRec 		= "NA" ;
	  sSecrecTemp.attribCertiSRec 			= "NA";
	  sSecrecTemp.sNonceValRec 				= 0 ;
	  sSecrecTemp.sSeqValRec 				= 0 ;
	  sSecrecTemp.sReachable 				= false ;
	  sSecrecTemp.ProtoCompleted 			= false;
	  sSecrecTemp.SucessDAS					= false;
	  sSecrecTemp.TimerReAuthN 				= WaitingWindowEnable ;
	  sSecrecTemp.SrvTypeCod 				= AuthnManAddresses[i].ServerType ;
	  sSecrecTemp.ReqCounter 				= 0 ;
	  sSecrecTemp.T_ReqCounter 				= 0;
	  sSecrecTemp.ExprTimer 				= NULL ;
	  sSecrecTemp.ProProcessTimer 			= NULL;
	  sSecrecTemp.DataProcessTimer 			= NULL;
	  sSecrecTemp.sendMsgtime 				= 0;
	  sSecrecTemp.ReciMsgtime 				= 0 ;
	  sSecrecTemp.SSRTT 					= 0 ;
	  sSecrecTemp.TTimeWait					=0;
	  sSecrecTemp.AuthNUserStateRec 		= AuthenIdle ;
	  sSecrecTemp.Proces_State 				= Process_Idle;
	  sSecrecTemp.DASReqCounter 			= 0 ;

	  if (AuthnManAddresses[i].serverTypeName =="Broadcast")
		  sSecrecTemp.ServerAddressRec = IPAddress::ALLONES_ADDRESS;

	  else if (SrvTypTestCase == AuthnManAddresses[i].ServerType || SrvTypTestCase==3 || SrvTypTestCase==4  )
		  sSecrecTemp.ServerAddressRec = IPAddressResolver().resolve((AuthnManAddresses[i].AddressServer).c_str());

	  ServSecurVec.push_back(sSecrecTemp);

	  std::stringstream vecName1,vecName2,vecName3,vecName4;

	  vecName1<<AuthnManAddresses[i].AddressServer<<"-T"<<AuthnManAddresses[i].ServerType<<"-StateProtocol";
	  cOutVector * MigStateR = new cOutVector();
	  MigStateR->setName(vecName1.str().c_str());
	  MigStateR->enable() ;
	  MigStateRec.push_back(MigStateR);

	  vecName2<<AuthnManAddresses[i].AddressServer<<"-T"<<AuthnManAddresses[i].ServerType<<"-TotalSendByte";
	  cOutVector * TotalSendByteR = new cOutVector();
	  TotalSendByteR->setName(vecName2.str().c_str() );
	  TotalSendByteR->enable();
	  TotalSendByteRec.push_back(TotalSendByteR);

	  vecName3<<AuthnManAddresses[i].AddressServer<<"-T"<<AuthnManAddresses[i].ServerType<<"-TotalReceiveByte";
	  cOutVector *  TotalReceiveByteR = new cOutVector();
	  TotalReceiveByteR->setName(vecName3.str().c_str() );
	  TotalReceiveByteR->enable();
	  TotalReceiveByteRec.push_back(TotalReceiveByteR);

	  vecName4<<AuthnManAddresses[i].AddressServer<<"-T"<<AuthnManAddresses[i].ServerType<<"-RTT_ServerCalling";
	  cOutVector *  RTTVecR = new cOutVector();
	  RTTVecR->setName(vecName4.str().c_str());
	  RTTVecR->enable();
	  RTTVec.push_back(RTTVecR);

	  // end Servers Information Initialisation
	  if (AuthnManAddresses[i].serverTypeName =="Broadcast")  break;
  }

  /*  Setup Module within the Host -------------------------*/
  bat = InetSimpleBatteryAccess().getIfExists(); // Battery
  if (!bat)
    hostState = "NO Battery"; //   error("Batter is not registered");
  else
    hostState = bat->getHostSate();

  BM = BasicMobilityAccess().getIfExists(); // access to mobility module
  if (!BM)
    error("BasicMobility is not registered");

  // BM->Registration(false);

  MM = ManetManagerAccess().getIfExists(); // access to mobility module
  if (!MM)
    error("ManetManager is not registered");

  // MM->SetManetActive(false);

  display_string->setTagArg("i", 1, "#000000");

  MP = mainUnitAccess().getIfExists();

  if (!MP)
    error("Error in Main Unit");

  AODVUU_PTR = AODVUUAccess().getIfExists();

  AAMDNC = AAMDynamicNetworkConfigurator::getAAMDynNetConfig();

//  if (!AODVUU_PTR)
//    error("AODV is not Installed in ManetRouting Unit %s", AODVUU_PTR);

  /* - Setup Module within the Host ---------------------------------*/

  Certif = MP->getCertFromUnit();

 //Certif = "CorruptedIDCert" ; for test
 //chooseCertiClasse(); for Test

  WATCH(hostState);
  WATCH(ManNum);
  WATCH(Certif);
  WATCH(Authenticated);
  WATCH(AuthNUserState);

  //WATCH(AuthNProtocolState);
  WATCH(AuthNReq);
  WATCH(rtt);
  WATCH(Counter);
  WATCH(NumRequestInProgress) ;
  WATCH(numRequestsDrop);
  WATCH(TotalByteDrop);
  WATCH(numSuccessRequests);
  WATCH(MembershipCertificate);
  WATCH(timeToStart);
  WATCH(AgentErrMsg);
  WATCH(UdpErrMsg);
  WATCH(sendMsgtime);
  WATCH(recMsgtime);
  WATCH(TriggerFlag);
  //WATCH(T_Counter);
  WATCH(I_Phase_MIG);
  WATCH_VECTOR(MsgProtocolProfiles);
  WATCH_VECTOR(ServSecurVec);
  WATCH_VECTOR(AuthnManAddresses);
  WATCH_VECTOR(AttribCertifVec);
  WATCH_PTRVECTOR(netServices);
  WATCH_VECTOR(ServSecurVecLog);
  WATCH_VECTOR(inAr);

  bindToPort(localAuthnAgentPort);

  // Set timer strategy  to start authentication requests

  strategyType = par("strategyType");

  if(par("SearchForConnection").boolValue() && !BM->isAnyNeighbourAround())
  {
	std::stringstream Natimer;
	Natimer<<"Serch4Conne-"<<getParentModule()->getFullName();
	cMessage * SearcForConnection = new cMessage(Natimer.str().c_str(), MSGKIND_SRCH_FOR_CONN);
	scheduleAt(simtime_t (simTime()+par("updateSearchTimer").doubleValue()), SearcForConnection);
  }
  else if (TTimer >= 0)
  {
  // either using start AuthN without searching for Connection OR user has already neighbors to start AuthN
	SchduleAuthnRequest(strategyType,TTimer);
  }

  if(!SetMobilMod) {BM->Registration(false);MM->SetManetActive(false);}

  rttVec.setName("Round Trip Time");
  rttVec.enable();

  SrcTimes.setName("SearchTimes4Node");
  SrcTimes.enable();

  if (ev.isGUI())
    {
      char buf[40];
      sprintf(buf, "Authentication\nAgent");
      getDisplayString().setTagArg("t", 0, buf);
    }

}

void AuthNAgent::handleMessage(cMessage *msg)
{
	// TODO - Generated method body

	if (!(hostState =="NO Battery"))  hostState = bat->getHostSate();
	if ((hostState =="ACTIVE" || hostState =="NO Battery"))
	{
		if (msg->isSelfMessage()) handleTimer(msg);
		else if (AuthNUserState !=FailedAuthNMig)
			processAuthnResponse(PK(msg));       // receive Authentication Response from Authentication Manager
		else delete msg;
	}
	else
	{
		ev<<"Delete msg Name>>>>>>>>>>>>>>>"<< msg->getName();
		delete msg;
	}

}

void AuthNAgent::handleTimer(cMessage *msg)
{
  cDisplayString* display_string = &getParentModule()->getDisplayString();
  std::stringstream msgnam,msgname ;
  msgnam <<"AuthNWExpireTime-";

  if(AuthNUserState == AuthenIdle || AuthNUserState==AuthenInProgress ||DataProcessInProgress(-1)> 0)
    {
     switch (msg->getKind())
     {

     case MSGKIND_SRCH_FOR_CONN : // Search for nearby node to access

    	 if(!SetMobilMod) BM->Registration(true);
    	    if (!BM->isAnyNeighbourAround())
    		scheduleAt(simtime_t (simTime()+par("updateSearchTimer").doubleValue()), msg);
    	    else
    	    	{
					SchduleAuthnRequest(strategyType,TTimer);
					delete msg;
    	    	}
    	    TotalSrcTime = simTime()- timeToStart;
    	    if (!SetMobilMod) BM->Registration(false);
    	 break;

     case MSGKIND_START_REQ : // Begin to authenticate

        EV<<"--starting Authentication Call----------------------------------- \n";
        int * indx ;int inpx;
        indx = (int *)msg->getContextPointer();
        inpx = *indx ;

        if (!AuthNReq )
          {
        	SrcTimes.record(TotalSrcTime.dbl());
            if(!SetMobilMod)
            {
            	BM->Registration(true);
            	MM->SetManetActive(true);
            }// activate Manetrouting
            display_string->setTagArg("i", 1, "#FFFFFF"); //#7F7F7F
          }

        AuthNReq		= true; // flag for start Authentication Process
        AuthNUserState 	= AuthenInProgress; // for host in Total
        NumRequestInProgress++ ; // Number of threads in progress for athentication

        ServSecurVec[inpx].AuthNUserStateRec = AuthenInProgress ; // server host Connection State
        ServSecurVec[inpx].AuthNProtocolStateRec = State_Msg1 ; // First State of the Protocol
        RTTVec[inpx]->record(ServSecurVec[inpx].AuthNProtocolStateRec); // trace times of server calls

        sendAuthnRequest(inpx); // start Handshaking

         Counter++ ; // start counting the total number of authentication requests

        ServSecurVec[inpx].ReqCounter++; // start counting times of authentication request

        if (WaitingWindowEnable) // check to trigger Timer for waiting for Authentication completion
          {
            msgnam <<getParentModule()->getName()<<"_"<<ServSecurVec[inpx].ServerName;
            ServSecurVec[inpx].ExprTimer  = new cMessage((msgnam.str()).c_str(),MSGKIND_ReREQ);
            ServSecurVec[inpx].ExprTimer->setContextPointer(indx);

            ServSecurVec[inpx].TTimeWait += WTime*pow(2,(ServSecurVec[inpx].ReqCounter -1)*fix_Exp_WT);

            scheduleAt(simTime()+(WTime*pow(2,(ServSecurVec[inpx].ReqCounter -1)*fix_Exp_WT)), ServSecurVec[inpx].ExprTimer);
          }
        else delete indx ;
        delete msg ;

        break;

      case MSGKIND_ReREQ :  // another try to authenticate

        int * indxx ; int inp;
        indxx = (int *)msg->getContextPointer() ;
        inp = *indxx ;

        if(ServSecurVec[inp].ReqCounter < MaxReAuthNCounter)
          {
            EV << "starting Re-Authentication Call \n";
            // Reset to First State of the Protocol
            ServSecurVec[inp].AuthNProtocolStateRec = State_Msg1;

            sendAuthnRequest(inp);

            Counter++; // counting the total number of authentication requests
            ServSecurVec[inp].ReqCounter++ ;
            ServSecurVec[inp].TTimeWait += WTime*pow(2,(ServSecurVec[inp].ReqCounter -1)*fix_Exp_WT);
            scheduleAt(simTime()+ (WTime*pow(2,(ServSecurVec[inp].ReqCounter-1)*fix_Exp_WT)),msg);
          }
        else
          {
            ServSecurVec[inp].ReqCounter =0 ;
            ServSecurVec[inp].T_ReqCounter ++;
            ServSecurVec[inp].AuthNUserStateRec = FailedAuthN ;
            ServSecurVec[inp].sReachable = false ;
            AuthnStateDataProcess(inp, false, false);

            // rttVec.record(0);

        	if ((SrvTypTestCase == 3||SrvTypTestCase == 4) && ServSecurVec[inp].SrvTypeCod == 1 && strategyType == 1) // Priority Strategy
        		{
        		 SchduleAuthnRequest(2,TTimer/2);
        		 getParentModule()->bubble("Start Sending Request to the TAS/DAS");
        		}
  			else if(SrvTypTestCase == 3 && NumRequestInProgress+inAr.size()<ThreshSrvNum
  					&& !IsCASAuthnReqInProg() && numSuccessRequests>0 && !CombinPocessTimer)
  			  {

  			    CancelTimer(inp) ; // Modified Recent

  			    if (par("SetTAStoDAS").boolValue())
  			      {
  			        SchduleAuthnRequest(3,TTimer);
  			        getParentModule()->bubble("Start Sending Separate Request DAS");
  			      }
  			    else
  			      {

  			        Authenticated = true ;
  			        AuthNUserState = SucAuthNUser;



  			        // Setup Certificate Records
  			        // search for Valid Delegated certif in ServSecurVec ;
  			        for (unsigned int i=0 ; i < ServSecurVec.size();i++)
  			          if(!(ServSecurVec[i].attribCertiSRec=="NA"))
  			            {
  			              MembershipCertificate = ServSecurVec[i].attribCertiSRec ;

  			              AttribCertifRec cerRec ;
  			              cerRec.id = SrvTypTestCase  ;
  			              cerRec.Name = ServSecurVec[i].attribCertiSRec ;
  			              cerRec.CertifType =DelegThresAc;
  			              cerRec.Trust = 1.0 ;
  			              AttribCertifVec.push_back(cerRec) ;

  			              cerRec.id = SrvTypTestCase  ;
  			              cerRec.Name = ServSecurVec[i].attrThreshCertiRec ;
  			              cerRec.CertifType =PartialThresAC ;
  			              cerRec.Trust = 0.0 ;
  			              AttribCertifVec.push_back(cerRec) ;
  			              break;
  			            }

  			        EV<<" Certificate Type is "<<MembershipCertificate<<endl ;

  			        display_string->setTagArg("i", 1, "#FF00FF");
  			        getParentModule()->bubble("Successful Authentication using DAS");

  			        if(rtt == 0)
  			          {
  			            recMsgtime = simTime() ;
  			            rtt = recMsgtime- sendMsgtime; // Round Trip Time
  			            rttVec.record(rtt); // record Final Round Trip Time
  			            AAMDNC->UpdateStatistic(rtt.dbl(),TotalSrcTime.dbl(),TotalByteCom, 0,(int) DelegThresAc, Counter);

  			            if (par("SetNodeLifeTime").boolValue())
  			            	DF =  AAMDNC->scheduleToDelete(getParentModule(),0,true);
  			          }

  			    //    CancelTimer(inp) ;

  			        if(par("TriggerTraffic").boolValue() && !TrigAlreadyCalled) UserTrafficTrigger (); // Trigger Traffic

  			      }
  			  }
  			 else	// check User host for authentication Failure
  				 if((SrvTypTestCase == 2  && NumRequestInProgress+inAr.size()< ThreshSrvNum && !CombinPocessTimer)
  					//|| (SrvTypTestCase == 1 && RoSrvCount >= NumRequestInProgress)
  					|| (SrvTypTestCase == 1 &&  NumRequestInProgress <=0) // updated line after exp for the DAS case
  					|| (SrvTypTestCase == 3 && NumRequestInProgress < 1 && !CombinPocessTimer)
  					|| (SrvTypTestCase == 4 && NumRequestInProgress+inAr.size()< ThreshSrvNum
  							&& !IsCASAuthnReqInProg() && !CombinPocessTimer)) // threshold Server Call
  				 {
  					 CancelTimer (inp) ;
  					 AuthNUserState = FailedAuthN;
  					 Authenticated = false ;
  					 display_string->setTagArg("i", 1, "#FFFF00");
  					 getParentModule()->bubble("Failed Authentication in one Server");
  					 //  Deactivate some Modules in the host
                     // error(" Server No. and Authn Prog  %d %d %d %d", inp,NumRequestInProgress,SrvTypTestCase, RoSrvCount);

  					AAMDNC->UpdateStatistic(0,0,0, 1, -1, Counter); // Update Statistics

  					 if (DisconnectFlag)
  					 {
  						 BM->Registration(false); // disconnect from MANETs Network
  						 MM->SetManetActive(false);
  						 if(AODVUU_PTR)
  						 AODVUU_PTR->activationSelfModule(false); // cancel Timer in AODV
  					 }

  					 DF = false ;
  					 if (par("DeleteToFail").boolValue()) // Delete Node
  					 {
  						 if (par("ProDeletToFail").doubleValue() < 0)
  						 {
  							 AAMDNC->scheduleToDelete(getParentModule(),0,false);
  							 DF = true;
  						 }
  						 else if(par("ProDeletToFail").doubleValue() > uniform(0,1))
  						 {
  							 AAMDNC->scheduleToDelete(getParentModule(),0,false);
  							 DF = true;
  						 }

  					 }

  					 if(!DF && EnabledMigr && I_Phase_MIG < MigAttempNum) MigrationTimer( ) ;
  				 }
        	delete msg ;
        	delete indxx;
        	ServSecurVec[inp].ExprTimer = NULL ;

            // no scheduleAt(): next request will be sent when reply to this one
            // arrives (see socketDataArrived())
          }
        break;

      case MSGKIND_MIGRATE_PrepReq  : // prepare to start Authentication after Migration

        AuthNUserState 				 = AuthenIdle ; // IDLE State to Start Request Authentication
        Authenticated 				 = false;
        numSuccessRequests 			 = 0 ;
        numRequestsDrop 			 = 0;
        NumRequestInProgress 		 = 0 ;
        sendMsgtime =sendMsgtimeTemp = 0 ;
        AuthNReq = false;
        timeToStartMIG = simTime();

        for ( int j =0 ; j<ManNum ; j++)
          {
            NonceVal = intuniform(1000, 100000);

            ServSecurVec[j].AuthNProtocolStateRec 	= state_MsgIdle ;
            ServSecurVec[j].cNonceValRec 			= NonceVal;
            ServSecurVec[j].cSeq 					= 0 ;
//          ServSecurVec[j].TotalByteReceivRec 		= 0 ;
//          ServSecurVec[j].TotalBytesSendRec 		= 0;
            ServSecurVec[j].sNonceValRec 			= 0 ;
            ServSecurVec[j].sSeqValRec 				= 0 ;
            ServSecurVec[j].sReachable 				= false ;
            ServSecurVec[j].ProtoCompleted 			= false;
            ServSecurVec[j].DASReqCounter			=0;
            ServSecurVec[j].SucessDAS				= false;
            ServSecurVec[j].ReqCounter				=0;
          }

        if(DisconnectFlag)
           {
        		BM->Registration(true);
        		MM->SetManetActive(true);
        	}

        if(par("SearchForConnection").boolValue() && !BM->isAnyNeighbourAround())
        {
      	std::stringstream Natimer;
      	Natimer<<"Serch4ConneAFM-"<<getParentModule()->getFullName();
      	cMessage * SearcForConnection = new cMessage(Natimer.str().c_str(), MSGKIND_SRCH_CONN_MIG);
      	scheduleAt(simtime_t (simTime()+par("updateSearchTimer").doubleValue()), SearcForConnection);
        }
        else if (TTimer >= 0)
        {
        // either using start AuthN without Search for Connection OR user has already neighbors to start AuthN
      	SchduleAuthnRequest(strategyType,TTimer);
        }

    	if(!SetMobilMod) {BM->Registration(false);MM->SetManetActive(false);}

        delete msg ;
        MigTimer=NULL ;
        break;

      case MSGKIND_SRCH_CONN_MIG : // search for node after migration

     	 if(!SetMobilMod) BM->Registration(true);
     	    if (!BM->isAnyNeighbourAround())
     		scheduleAt(simtime_t (simTime()+par("updateSearchTimer").doubleValue()), msg);
     	    else
     	    	{
 					SchduleAuthnRequest(strategyType,TTimer);
 					delete msg;
     	    	}
     	    TotalSrcTime = simTime()- timeToStartMIG;
     	    if (!SetMobilMod) BM->Registration(false);
     	 break;

    	  break;

      case MSGKIND_MIGRATE_REREQ : // Begin to authenticate after Migration

        EV << "starting Authentication Call After Migration \n";

        int * indxm ;
        int inpm;
        indxm = (int *)msg->getContextPointer();
        inpm = *indxm ;

        if (!AuthNReq )
        {
        	SrcTimes.record(TotalSrcTime.dbl());
        	if(!SetMobilMod)
        	{
        		BM->Registration(true);
        		MM->SetManetActive(true); // activate Manetrouting
        	}
        	if(AODVUU_PTR)
        		AODVUU_PTR->activationSelfModule(true); // activate AODV
        	display_string->setTagArg("i", 1, "#FFFFFF"); //#7F7F7F
        }

        AuthNReq = true;
        NumRequestInProgress++;
        ServSecurVec[inpm].AuthNProtocolStateRec = State_Msg1 ;

        AuthNUserState = AuthenInProgress; // for host
        ServSecurVec[inpm].AuthNUserStateRec = AuthenInProgress ; // server host Connection
        ServSecurVec[inpm].AuthNProtocolStateRec = State_Msg1 ; // First State of the Protocol
        RTTVec[inpm]->record(ServSecurVec[inpm].AuthNProtocolStateRec);

        sendAuthnRequest(inpm);

        //Counter++ ; // start counting times of authentication request

        ServSecurVec[inpm].ReqCounter++;

        // Setup timer for Re-Authentication
        if (WaitingWindowEnable) // check to trigger Timer for waiting for Authentication completion
          {
            msgnam <<getParentModule()->getName()<<"_"<<ServSecurVec[inpm].ServerName ;
            AuthNExptimer  = new cMessage((msgnam.str()).c_str(),MSGKIND_ReREQ);
            AuthNExptimer->setContextPointer(indxm) ;
            scheduleAt(simTime()+(WTime*pow(2,(ServSecurVec[inpm].ReqCounter -1)*fix_Exp_WT)),AuthNExptimer);
          }
        else delete indxm ;
        delete msg;
        break;

      case MSGKIND_PR_PROS_TIMER:

          int * indxmmx ;
          indxmmx = (int *)msg->getContextPointer();
          RTTVec[*indxmmx]->record(ServSecurVec[*indxmmx].AuthNProtocolStateRec);

          ServSecurVec[*indxmmx].ProProcessTimer = NULL;
		  delete indxmmx ;
		  delete msg;
		  break ;

      case MSGKIND_DATA_PROS_TIMER:

    	  int * indxmm ;
    	  unsigned int inpmm;
    	  indxmm = (int *)msg->getContextPointer();
    	  inpmm = *indxmm;
    	  ServSecurVec[inpmm].ProtoCompleted = true ;


    	  // X509  OneWay, TwoWay, ThreeWay Pass Authentication
    	  if( ServSecurVec[inpmm].AuthNTypeRec==1 || ServSecurVec[inpmm].AuthNTypeRec== 3
    			  || ServSecurVec[inpmm].AuthNTypeRec== 2 )
    	  {
    		  //EV<<"88 "<<SrvTypTestCase<<"  0000"<<ServSecurVec[inpmm].AuthNTypeRec<<endl;
    		  // Root Server Call for One Server
    		  if((SrvTypTestCase == 1 || SrvTypTestCase ==3 ||SrvTypTestCase ==4) && ServSecurVec[inpmm].SrvTypeCod ==1 )
    		  {
    			  AuthnStateDataProcess(inpmm, true,true);

    			  AuthNUserState	= SucAuthNUser;  //Authentication State Host

    			 if(!Authenticated)
    			 {
    			  display_string->setTagArg("i", 1, "#FF0000");
    			  getParentModule()->bubble("Successful Authentication");
    			 }

    			 Authenticated	= true ;

    			 if(rtt == 0)
  				  {
  					recMsgtime = simTime() ;
  					rtt = recMsgtime- sendMsgtime; // Round Trip Time
  					rttVec.record(rtt); // record Final Round Trip Time
  					MembershipCertificate = ServSecurVec[inpmm].attribCertiSRec ;
  					EV<<" Certificate Type is "<<MembershipCertificate<<endl;

  					AAMDNC->UpdateStatistic(rtt.dbl(),TotalSrcTime.dbl(),TotalByteCom, 0, (int) RootAc, Counter);
			        if (par("SetNodeLifeTime").boolValue())
			            	DF =  AAMDNC->scheduleToDelete(getParentModule(),0,true);
  				  }

    			  AttribCertifRec cerRec ;
    			  cerRec.id 			= SrvTypTestCase  ;
    			  cerRec.Name 			= ServSecurVec[inpmm].attribCertiSRec ;
    			  cerRec.CertifType 	= RootAc ;
    			  cerRec.Trust 			= 1.0 ;
    			  AttribCertifVec.push_back(cerRec) ;

    			  // cancell all Server Timers for connection
    			  CancelTimer(inpmm) ;

    			  if(par("TriggerTraffic").boolValue() && !TrigAlreadyCalled) UserTrafficTrigger (); // Trigger Traffic

    		  }
    		  // Threshold Servers Call for Number of Server
    		  else if ((SrvTypTestCase == 2 || SrvTypTestCase ==3 ||SrvTypTestCase ==4)&& ServSecurVec[inpmm].SrvTypeCod ==2 )
    		  {
    			  AuthnStateDataProcess(inpmm,true,true);

    			  std::stringstream msgn ;

    			  if(inAr.size()<ThreshSrvNum)inAr.push_back(inpmm); // save the index of SucessAuthNServer;

    			  // check Threshold number of valid Server in oder to create the certificate
    			  if(inAr.size() == ThreshSrvNum)                   //(numSuccessRequests == ThreshSrvNum)
    			  {
    				  // setup timer for combining Process
    				  if(CombinPocessTimer && CombinPocessTimer->isScheduled()) break;

    				  CancelTimer(inpmm) ;

    				  msgn <<"CombinProcess_"<<getParentModule()->getName();
    				  CombinPocessTimer = new cMessage (msgn.str().c_str(),MSGKIND_COMBINPR_TIMER);
    				  scheduleAt (simTime()+CombinPocessDelay,CombinPocessTimer);
    				  // cancel all Server Timers for connection

    			  }
    			  else if((NumRequestInProgress+inAr.size() < ThreshSrvNum && SrvTypTestCase == 2)
    					  || (SrvTypTestCase ==4 && (NumRequestInProgress+inAr.size() < ThreshSrvNum && !IsCASAuthnReqInProg ()))) // no enough shared Certificate to create AC -
    			  {
    				  AuthNUserState = FailedAuthN;
    				  Authenticated = false ;
    				  display_string->setTagArg("i", 1, "#FFFF00");
    				  getParentModule()->bubble("Failed Authentication in one Server");
    				  //  Deactivate some Modules in the host

    				  AAMDNC->UpdateStatistic(0,0,0,1, -1,Counter); // Update Statistics

    	               if (DisconnectFlag)
    	               {
						  BM->Registration(false); // disconnect from MANETs Network
						  MM->SetManetActive(false);
						  if(AODVUU_PTR)
						  AODVUU_PTR->activationSelfModule(false); // cancel Timer in AODV
    	               }

    				  // Cancel all Server Timers for connection
    				  CancelTimer(inpmm) ;

    				  // if (MigTimer && MigTimer->isScheduled()) { cancelEvent(MigTimer);  delete MigTimer; MigTimer=NULL; }
   					  DF = false ;
   					 if (par("DeleteToFail").boolValue()) // Delete Node
   					 {
   						 if (par("ProDeletToFail").doubleValue() < 0)
   						 {
   							 AAMDNC->scheduleToDelete(getParentModule(),0, false);
   							 DF = true;
   						 }
   						 else if(par("ProDeletToFail").doubleValue() > uniform(0,1))
   						 {
   							 AAMDNC->scheduleToDelete(getParentModule(),0,false);
   							 DF = true;
   						 }

   					 }

   					 if(!DF && EnabledMigr && I_Phase_MIG < MigAttempNum) MigrationTimer( ) ;

    			  }

    			  else if(NumRequestInProgress+inAr.size() < ThreshSrvNum && SrvTypTestCase == 3 && !IsCASAuthnReqInProg ()
    					    && numSuccessRequests>0 && !par("SetTAStoDAS").boolValue() )
    			  {

    				  AuthNUserState = SucAuthNUser;

    				  // Setup Certificate Records

    				  AttribCertifRec cerRec ;
    				  cerRec.id = SrvTypTestCase  ;
    				  cerRec.Name = ServSecurVec[inpmm].attribCertiSRec ;
    				  cerRec.CertifType =DelegThresAc;
    				  cerRec.Trust = 1.0 ;
    				  AttribCertifVec.push_back(cerRec) ;

    				  cerRec.id = SrvTypTestCase  ;
    				  cerRec.Name = ServSecurVec[inpmm].attribCertiSRec ;
    				  cerRec.CertifType =PartialThresAC ;
    				  cerRec.Trust = 0.0 ;
    				  AttribCertifVec.push_back(cerRec) ;


    				  if (!Authenticated)
    				  {
    					  display_string->setTagArg("i", 1, "#FF00FF");
    					  getParentModule()->bubble("Successful Authentication using ThreshServer - DAS");
    				  }

    				  Authenticated = true ;

    				  if(rtt==0)
    				  {
    				  recMsgtime = simTime();
    				  rtt = recMsgtime- sendMsgtime; // Round Trip Time
    				  rttVec.record(rtt); // record Final Round Trip Time

    				  MembershipCertificate = ServSecurVec[inpmm].attribCertiSRec ;
    				  EV<<" Certificate Type is "<<MembershipCertificate<<endl ;
    				  AAMDNC->UpdateStatistic(rtt.dbl(),TotalSrcTime.dbl(),TotalByteCom, 0,(int) DelegThresAc, Counter);

    				  if (par("SetNodeLifeTime").boolValue())
			            	DF =  AAMDNC->scheduleToDelete(getParentModule(),0,true);
    				  }

    				  CancelTimer(inpmm) ;

    				  if(par("TriggerTraffic").boolValue() && !TrigAlreadyCalled) UserTrafficTrigger (); // Trigger Traffic
    			  }
    		  }
    	  }

    	  EV<<"************"<<SrvTypTestCase<<"&&&&&&&&&&&&&&&&&&"<<ServSecurVec[inpmm].AuthNTypeRec<<endl;
    	  delete msg ;
    	  delete indxmm ;
    	  ServSecurVec[inpmm].DataProcessTimer = NULL;
    	  break;

      case MSGKIND_COMBINPR_TIMER:

         {

         std::stringstream CertName ;
         for(unsigned int i=0 ; i <inAr.size(); i++)
             CertName<<ServSecurVec[inAr[i]].attrThreshCertiRec<<"-TS"<<inAr[i]<<"+" ;


//         for(unsigned int i=0 ; i <ServSecurVec.size(); i++)
//            {
//              if(ServSecurVec[i].AuthNUserStateRec ==SucAuthNUser && ServSecurVec[i].ProtoCompleted
//            		  && ServSecurVec[i].ServSecurVec[inpmm].SrvTypeCod ==2 )
//                {
//                   CertName<<ServSecurVec[i].attrThreshCertiRec<<"-TS"<<i<<"+" ;
//                }
//            }

          AttribCertifRec cerRecS ;
          cerRecS.id 		= SrvTypTestCase  ;
          cerRecS.Name 		= CertName.str() ;
          cerRecS.CertifType=ThresholdAc ;
          cerRecS.Trust 	= 0.75 ;
          AttribCertifVec.push_back(cerRecS) ;

          AuthNUserState 	= SucAuthNUser;

          if(!Authenticated)
          {
          display_string->setTagArg("i", 1, "#00FF40"); // #FF8000 , #FF0001, #800000
          getParentModule()->bubble("Successful Authentication");
          }

          Authenticated 	= true ;

          if(rtt ==0)
          {
        	  recMsgtime = simTime();
        	  rtt = recMsgtime- sendMsgtime; // Round Trip Time
        	  rttVec.record(rtt); // record Final Round Trip Time

        	  MembershipCertificate =  CertName.str() ;
        	  EV<<" Certificate Type is "<<MembershipCertificate<<endl;
        	  AAMDNC->UpdateStatistic(rtt.dbl(),TotalSrcTime.dbl(),TotalByteCom, 0, (int) ThresholdAc, Counter);
	            if (par("SetNodeLifeTime").boolValue())
	            	DF =  AAMDNC->scheduleToDelete(getParentModule(),0,true);
          }
          //if(EnabledMigr && I_Phase_MIG < MigAttempNum) MigrationTimer( ) ;
          //if (MigTimer && MigTimer->isScheduled()) { cancelEvent(MigTimer);  delete MigTimer; }

          if(par("TriggerTraffic").boolValue() && !TrigAlreadyCalled) UserTrafficTrigger (); // Trigger Traffic

          delete msg;
          CombinPocessTimer = NULL;
          }
          break;


      case MSGKIND_DAS_REQ :

    	  int * indxDAS ;
    	  unsigned int inpDAS;
    	  indxDAS = (int *)msg->getContextPointer();
    	  inpDAS = *indxDAS;

          ServSecurVec[inpDAS].AuthNProtocolStateRec = State_DAS ; // First State of the Protocol
          RTTVec[inpDAS]->record(ServSecurVec[inpDAS].AuthNProtocolStateRec); // trace times of server calls

          sendAuthnRequest(inpDAS);

          ServSecurVec[inpDAS].DASReqCounter++;

          NumRequestInProgress++ ;

          if (WaitingWindowEnable) // check to trigger Timer for waiting for DAS Response
            {
              msgnam <<getParentModule()->getName()<<"_"<<ServSecurVec[inpDAS].ServerName;
              ServSecurVec[inpDAS].ExprTimer  = new cMessage((msgnam.str()).c_str(),MSGKIND_DAS_ReREQ);
              ServSecurVec[inpDAS].ExprTimer->setContextPointer(indxDAS);
              ServSecurVec[inpDAS].TTimeWait += WTime*pow(2,(ServSecurVec[inpDAS].ReqCounter -1)*fix_Exp_WT);
              scheduleAt(simTime()+(WTime*pow(2,(ServSecurVec[inpDAS].ReqCounter -1)*fix_Exp_WT)), ServSecurVec[inpDAS].ExprTimer);
            }
          else delete indxDAS;
          delete msg ;
    	  break;

      case  MSGKIND_DAS_ReREQ:

          int * indxxDAS ; int inppDAS;
          indxxDAS = (int *)msg->getContextPointer() ;
          inppDAS = *indxxDAS ;

          if(ServSecurVec[inppDAS].DASReqCounter < MaxReAuthNCounter)
            {
              EV << "starting Re-RequestDAS Call \n";
              // Reset to First State of the Protocol
              ServSecurVec[inppDAS].AuthNProtocolStateRec = State_DAS;

              sendAuthnRequest(inppDAS);

              //  Counter++;
              ServSecurVec[inppDAS].DASReqCounter++;
              ServSecurVec[inppDAS].TTimeWait += WTime*pow(2,(ServSecurVec[inppDAS].ReqCounter -1)*fix_Exp_WT);
              scheduleAt(simTime()+ (WTime*pow(2,(ServSecurVec[inppDAS].ReqCounter-1)*fix_Exp_WT)),msg);
            }
          else
            {
        	  ServSecurVec[inppDAS].SucessDAS = false ;
        	  AuthnStateDataProcess(inppDAS, false, false);

        	  CancelTimer (inppDAS) ;
        	  AuthNUserState = FailedAuthN;
        	  Authenticated = false ;
        	  display_string->setTagArg("i", 1, "#FFFF00");
        	  getParentModule()->bubble("Failed Authentication in one Server");
        	  //  Deactivate some Modules in the host

        	  AAMDNC->UpdateStatistic(0,0,0,1,-1, Counter); // Update Statistics

        	  if (DisconnectFlag)
        	  {
        		  BM->Registration(false); // disconnect from MANETs Network
        		  MM->SetManetActive(false);
        		  if(AODVUU_PTR)
        		  AODVUU_PTR->activationSelfModule(false); // cancel Timer in AODV
        	  }

				 DF = false ;
				 if (par("DeleteToFail").boolValue()) // Delete Node
				 {
					 if (par("ProDeletToFail").doubleValue() < 0)
					 {
						 AAMDNC->scheduleToDelete(getParentModule(),0,false);
						 DF = true;
					 }
					 else if(par("ProDeletToFail").doubleValue() > uniform(0,1))
					 {
						 AAMDNC->scheduleToDelete(getParentModule(),0,false);
						 DF = true;
					 }

				 }

				 if(!DF && EnabledMigr && I_Phase_MIG < MigAttempNum) MigrationTimer( ) ;

            delete indxxDAS;
            delete msg ;
            ServSecurVec[inppDAS].ExprTimer = NULL ;
            }
    	  break;


      case MSGKIND_DAS_PROS_TIMER : // successful reply from DAS

    	  int * indDAS ;
    	  indDAS = (int *)msg->getContextPointer();

    	  RTTVec[*indDAS]->record(ServSecurVec[*indDAS].AuthNProtocolStateRec);
    	  ServSecurVec[*indDAS].ProProcessTimer = NULL;

    	  AuthnStateDataProcess(*indDAS, true,true);

		  Authenticated = true ;
		  AuthNUserState = SucAuthNUser;

		  // Setup Certificate Records
		  MembershipCertificate = ServSecurVec[*indDAS].attribCertiSRec ;
		  AttribCertifRec cerRec ;
		  cerRec.id = SrvTypTestCase  ;
		  cerRec.Name = ServSecurVec[*indDAS].attribCertiSRec ;
		  cerRec.CertifType =DelegThresAc;
		  cerRec.Trust = 1.0 ;
		  AttribCertifVec.push_back(cerRec) ;

		  cerRec.id = SrvTypTestCase  ;
		  cerRec.Name = ServSecurVec[*indDAS].attrThreshCertiRec ;
		  cerRec.CertifType =PartialThresAC ;
		  cerRec.Trust = 0.0 ;
		  AttribCertifVec.push_back(cerRec) ;

		  EV<<" Certificate Type is "<<MembershipCertificate<<endl ;

		  display_string->setTagArg("i", 1, "#FF00FF");
		  getParentModule()->bubble("Successful Authentication using DAS");

		  recMsgtime = simTime() ;
		  rtt = recMsgtime- sendMsgtime; // Round Trip Time
		  rttVec.record(rtt); // record Final Round Trip Time
		  CancelTimer(*indDAS) ;

		  AAMDNC->UpdateStatistic(rtt.dbl(),TotalSrcTime.dbl(),TotalByteCom, 0, (int) DelegThresAc,Counter);

           if (par("SetNodeLifeTime").boolValue())
            	DF =  AAMDNC->scheduleToDelete(getParentModule(),0,true);

		  if(par("TriggerTraffic").boolValue()&& !TrigAlreadyCalled) UserTrafficTrigger (); // Trigger Traffic


		  ServSecurVec[*indDAS].DataProcessTimer = NULL;
		  delete indDAS ;
    	  delete msg;


		  break;
     }
    }
  else
    {
	  //  Error in the Timer
     if( !(msg->getKind() == MSGKIND_COMBINPR_TIMER))
     {
      int * indxm ;
      int inpm;
      indxm = (int *)msg->getContextPointer();
      inpm = *indxm ;

      // log timer details
      sSecRecordLog sX ;
      sX.AuthNProtocolStateRecLog 	= ServSecurVec[inpm].AuthNProtocolStateRec;
      sX.AuthNTypeRecLog 			= ServSecurVec[inpm].AuthNTypeRec ;
      sX.AuthNUserStateRecLog 		= ServSecurVec[inpm].AuthNUserStateRec ;
      sX.Proces_StateLog 			= ServSecurVec[inpm].Proces_State ;
      sX.ServerNameLog 				= ServSecurVec[inpm].ServerName ;
      sX.MsgNameLog				 	= msg->getFullName();
      sX.SrvTypeCodLog 				= ServSecurVec[inpm].SrvTypeCod;
      sX.TimerTypeLog 				= msg->getKind() ;
      sX.MsgtypeLog                 = -1 ;
      sX.TotalByteReceivRecLog 		= ServSecurVec[inpm].TotalByteReceivRec ;
      sX.TotalBytesSendRecLog 		= ServSecurVec[inpm].TotalBytesSendRec ;
      sX.TotalByteDroppedLog 		= ServSecurVec[inpm].TotalByteDropped;
      sX.sReachableLog 				= ServSecurVec[inpm].sReachable ;
      sX.SeqNumLog 					= ServSecurVec[inpm].cSeq;
      sX.SeqNumMsgLog				= -1;
      ServSecurVecLog.push_back (sX);

      if (ServSecurVec[inpm].ExprTimer && ServSecurVec[inpm].ExprTimer->isScheduled())
    	  cancelAndDelete((cMessage *) ServSecurVec[inpm].ExprTimer);
      if (ServSecurVec[inpm].ProProcessTimer && ServSecurVec[inpm].ProProcessTimer->isScheduled())
    	  cancelAndDelete((cMessage *) ServSecurVec[inpm].ProProcessTimer);
      if (ServSecurVec[inpm].DataProcessTimer && ServSecurVec[inpm].DataProcessTimer->isScheduled())
    	  cancelAndDelete((cMessage *) ServSecurVec[inpm].DataProcessTimer);

      delete msg ;

    //  error(" Timer Part");

     }

    }
}

void AuthNAgent::processAuthnResponse(cPacket *msg)
{

	cDisplayString* display_string = &getParentModule()->getDisplayString();
	DataMsg *DataPacket ;
	AuthenProtocolMsg *AResProtMsg ;
	unsigned int indxSrvv;
	std::stringstream TimerNam,TimerNam1;

	if (msg->getKind() == UDP_I_ERROR || AuthNUserState != AuthenInProgress)
	{
		sSecRecordLog sX1 ;

		if (msg->getKind() == UDP_I_ERROR )
		{
			UdpErrMsg++;
			// log msg details
			sX1.AuthNProtocolStateRecLog 	= State_Err;
			sX1.AuthNTypeRecLog 			= -1;
			sX1.AuthNUserStateRecLog 		= ErrAuthN;
			sX1.Proces_StateLog 			=  Error_Process ;
			sX1.ServerNameLog 				= "NA";
			sX1.MsgNameLog				 	= msg->getName();
			sX1.SrvTypeCodLog 				= -1;
			sX1.MsgtypeLog 					= msg->getKind();
			sX1.TimerTypeLog 				= -1;
			sX1.TotalByteReceivRecLog 		= -1;
			sX1.TotalBytesSendRecLog 		= -1 ;
			sX1.TotalByteDroppedLog 		= -1;
			sX1.sReachableLog 				= false;

			TotalByteDrop += msg->getByteLength();
			ServSecurVecLog.push_back (sX1);
		}
		else
		{
			AgentErrMsg++;

			CommonAAM *ErRootPacket = check_and_cast<CommonAAM *>(msg);
			int ERindxSrvv =  ErRootPacket->getIndxSrv();

			std::string xxx = ErRootPacket->getName() ;
			getParentModule()->bubble(("Drop Messages-"+xxx).c_str());

			//TotalByteCom += ErRootPacket->getByteLength();

			ServSecurVec[ERindxSrvv].TotalByteDropped += ErRootPacket->getByteLength();
			TotalByteDrop += ErRootPacket->getByteLength();

			// log msg details
			sX1.AuthNProtocolStateRecLog 	= ServSecurVec[ERindxSrvv].AuthNProtocolStateRec;
			sX1.AuthNTypeRecLog 			= ServSecurVec[ERindxSrvv].AuthNTypeRec ;
			sX1.AuthNUserStateRecLog 		= ServSecurVec[ERindxSrvv].AuthNUserStateRec ;
			sX1.Proces_StateLog 			= ServSecurVec[ERindxSrvv].Proces_State ;
			sX1.ServerNameLog 				= ServSecurVec[ERindxSrvv].ServerName ;
			sX1.MsgNameLog				 	= ErRootPacket->getName();
			sX1.SrvTypeCodLog 				= ServSecurVec[ERindxSrvv].SrvTypeCod;
			sX1.MsgtypeLog 					= ErRootPacket->getMsgType() ;
			sX1.TimerTypeLog 				= -1;
			sX1.TotalByteReceivRecLog 		= ServSecurVec[ERindxSrvv].TotalByteReceivRec+ErRootPacket->getByteLength();
			sX1.TotalBytesSendRecLog 		= ServSecurVec[ERindxSrvv].TotalBytesSendRec ;
			sX1.TotalByteDroppedLog 		= ServSecurVec[ERindxSrvv].TotalByteDropped;
			sX1.sReachableLog 				= ServSecurVec[ERindxSrvv].sReachable ;
			sX1.SeqNumLog 					= ServSecurVec[ERindxSrvv].cSeq;
			sX1.SeqNumMsgLog				= ErRootPacket->getSeqNum();
			ServSecurVecLog.push_back (sX1);
		}

		delete msg;
		recMsgtime = simTime() ;
		return;
	}


	CommonAAM *rootPacket = check_and_cast<CommonAAM *>(msg);
	indxSrvv =  rootPacket->getIndxSrv();

	switch (rootPacket->getMsgType() )
	{
		case AAM_AUTHN_PROT_MSG2 :

			AResProtMsg = check_and_cast<AuthenProtocolMsg *>(msg);
			indxSrvv 	=  AResProtMsg->getIndxSrv();

			if (ServSecurVec[indxSrvv].cSeq <= AResProtMsg->getSeqNum() &&
				ServSecurVec[indxSrvv].AuthNProtocolStateRec == State_Msg1 &&
				ServSecurVec[indxSrvv].AuthNUserStateRec == AuthenInProgress)
			{
				// TwoWay Pass Protocol => in the Second Phase of the Protocol
				if (ServSecurVec[indxSrvv].AuthNTypeRec == 2)
				{
					ServSecurVec[indxSrvv].sNonceValRec = AResProtMsg->getNonce() ;
					ServSecurVec[indxSrvv].sSeqValRec   = AResProtMsg->getSeqNum() ;
					ServSecurVec[indxSrvv].sCertifRec   = AResProtMsg->getIdCertificate();

					RTTVec[indxSrvv]->record(ServSecurVec[indxSrvv].AuthNProtocolStateRec);
					ServSecurVec[indxSrvv].TotalByteReceivRec +=AResProtMsg->getByteLength();
					//ServSecurVec[indxSrvv].AuthNProtocolStateRec =  State_Msg2;
					TotalByteCom += AResProtMsg->getByteLength();

					TotalReceiveByteRec[indxSrvv]->record(ServSecurVec[indxSrvv].TotalByteReceivRec);
					MigStateRec[indxSrvv]->record((int) ServSecurVec[indxSrvv].AuthNProtocolStateRec);

					// setup timer for simulating Process Delay for validation
					int * indxxSrv = new int ()  ;
					*indxxSrv = indxSrvv;

					TimerNam<<"ProtoTimer_T2_N1"<<getParentModule()->getName();
					ServSecurVec[indxSrvv].ProProcessTimer = new cMessage (TimerNam.str().c_str() , MSGKIND_PR_PROS_TIMER);
					ServSecurVec[indxSrvv].ProProcessTimer->setContextPointer(indxxSrv) ;
					ServSecurVec[indxSrvv].Proces_State = ProtoMsg_Process;

					scheduleAt( simTime() + MsgProtocolProfiles[ServSecurVec[indxSrvv].AuthNTypeRec-1].MsgProtProf[1].validateProcessDelay,
							    (cMessage *) ServSecurVec[indxSrvv].ProProcessTimer);
				}
				else if (ServSecurVec[indxSrvv].AuthNTypeRec  == 3) // ThreeWay Pass Protocol => in the Second Phase of the Protocol
				{

					ServSecurVec[indxSrvv].sNonceValRec = AResProtMsg->getNonce() ;
					ServSecurVec[indxSrvv].sSeqValRec  	=  AResProtMsg->getSeqNum() ;
					ServSecurVec[indxSrvv].sCertifRec 	= AResProtMsg->getIdCertificate();


					RTTVec[indxSrvv]->record(ServSecurVec[indxSrvv].AuthNProtocolStateRec);
					ServSecurVec[indxSrvv].TotalByteReceivRec +=AResProtMsg->getByteLength();
					ServSecurVec[indxSrvv].AuthNProtocolStateRec = State_Msg2 ;
					TotalByteCom += AResProtMsg->getByteLength();

					TotalReceiveByteRec[indxSrvv]->record(ServSecurVec[indxSrvv].TotalByteReceivRec);
					MigStateRec[indxSrvv]->record((int) ServSecurVec[indxSrvv].AuthNProtocolStateRec);

					sendAuthnRequest(indxSrvv) ;
				}
				else error (" Check Authentication Protocol Type");
			}
			else
			{
				AgentErrMsg++;

				std::string xxy = msg->getName() ;
				getParentModule()->bubble(("Drop Messages-"+xxy).c_str());
				// TotalByteCom += rootPacket->getByteLength() ;
				ServSecurVec[indxSrvv].TotalByteDropped += rootPacket->getByteLength();
				TotalByteDrop += rootPacket->getByteLength();

				// log msg details
				sSecRecordLog sX2 ;
				sX2.AuthNProtocolStateRecLog 	= ServSecurVec[indxSrvv].AuthNProtocolStateRec;
				sX2.AuthNTypeRecLog 			= ServSecurVec[indxSrvv].AuthNTypeRec ;
				sX2.AuthNUserStateRecLog 		= ServSecurVec[indxSrvv].AuthNUserStateRec ;
				sX2.Proces_StateLog 			= ServSecurVec[indxSrvv].Proces_State ;
				sX2.ServerNameLog 				= ServSecurVec[indxSrvv].ServerName ;
				sX2.SrvTypeCodLog 				= ServSecurVec[indxSrvv].SrvTypeCod;
				sX2.MsgtypeLog 					= rootPacket->getMsgType() ;
				sX2.MsgNameLog				 	= msg->getName();
				sX2.TimerTypeLog 				= -1;
				sX2.TotalByteReceivRecLog 		= ServSecurVec[indxSrvv].TotalByteReceivRec+rootPacket->getByteLength();
				sX2.TotalBytesSendRecLog 		= ServSecurVec[indxSrvv].TotalBytesSendRec ;
				sX2.TotalByteDroppedLog 		= ServSecurVec[indxSrvv].TotalByteDropped;
				sX2.sReachableLog 				= ServSecurVec[indxSrvv].sReachable ;
				sX2.SeqNumLog 					= ServSecurVec[indxSrvv].cSeq;
				sX2.SeqNumMsgLog				= rootPacket->getSeqNum();
				ServSecurVecLog.push_back (sX2);
				recMsgtime = simTime() ;
			}

			break;

		case AAM_AUTHN_ACK :
		{
			DataPacket 	= check_and_cast<DataMsg *>(msg);
			// indxSrvv 	= DataPacket->getIndxSrv();

			if((ServSecurVec[indxSrvv].AuthNTypeRec == 2 && ServSecurVec[indxSrvv].Proces_State != ProtoMsg_Process)||
			   (ServSecurVec[indxSrvv].cSeq > DataPacket->getSeqNum()&& ServSecurVec[indxSrvv].AuthNTypeRec != 1)||
			   (ServSecurVec[indxSrvv].DataProcessTimer != NULL &&ServSecurVec[indxSrvv].DataProcessTimer->isScheduled())||
			    ServSecurVec[indxSrvv].ProtoCompleted || ServSecurVec[indxSrvv].AuthNUserStateRec != AuthenInProgress )
				{
					// error ("Error in Authentication Handshaking TwoWay")OR Error in Sequence Number;

					AgentErrMsg++;

					std::string xxy = msg->getName() ;
					getParentModule()->bubble(("Drop-Message-"+xxy).c_str());
					// TotalByteCom += DataPacket->getByteLength() ;
					ServSecurVec[indxSrvv].TotalByteDropped += DataPacket->getByteLength();
					TotalByteDrop += DataPacket->getByteLength();

					// log msg details
					sSecRecordLog sXx ;
					sXx.AuthNProtocolStateRecLog 	= ServSecurVec[indxSrvv].AuthNProtocolStateRec;
					sXx.AuthNTypeRecLog 			= ServSecurVec[indxSrvv].AuthNTypeRec ;
					sXx.AuthNUserStateRecLog 		= ServSecurVec[indxSrvv].AuthNUserStateRec ;
					sXx.Proces_StateLog 			= ServSecurVec[indxSrvv].Proces_State ;
					sXx.ServerNameLog 				= ServSecurVec[indxSrvv].ServerName ;
					sXx.SrvTypeCodLog 				= ServSecurVec[indxSrvv].SrvTypeCod;
					sXx.MsgtypeLog 					= AAM_AUTHN_ACK ;
					sXx.MsgNameLog				 	= msg->getName();
					sXx.TimerTypeLog 				= -1;
					sXx.TotalByteReceivRecLog 		= ServSecurVec[indxSrvv].TotalByteReceivRec+rootPacket->getByteLength();
					sXx.TotalBytesSendRecLog 		= ServSecurVec[indxSrvv].TotalBytesSendRec ;
					sXx.TotalByteDroppedLog 		= ServSecurVec[indxSrvv].TotalByteDropped;
					sXx.sReachableLog 				= ServSecurVec[indxSrvv].sReachable ;
					sXx.SeqNumLog 					= ServSecurVec[indxSrvv].cSeq;
					sXx.SeqNumMsgLog				= DataPacket->getSeqNum();
					ServSecurVecLog.push_back (sXx);
					recMsgtime = simTime() ;
				}
			else
			{
				ServSecurVec[indxSrvv].TotalByteReceivRec +=DataPacket->getByteLength();
				ServSecurVec[indxSrvv].AuthNProtocolStateRec = State_Data ;
				int iC = 1 ;

				netServices.clear();

				EV<<" ************************ Service List ****************************"<<endl;
				for ( unsigned int i = 0 ; i < DataPacket->getServicesListArraySize();i++ )
				{
					ServLst *t = new ServLst ();
					t->ID = DataPacket->getServicesList(i).ID;
					t->SrvAdress = DataPacket->getServicesList(i).ServiceAddress;
					t->SrvName = DataPacket->getServicesList(i).ServiceName;
					t->sPort = DataPacket->getServicesList(i).ServicePort;
					t->ServerName = ServSecurVec[indxSrvv].ServerName ;
					netServices.push_back (t) ;

					EV<< DataPacket->getServicesList(i).ID<<"   "<<DataPacket->getServicesList(i).ServiceAddress
					<<"    "<<DataPacket->getServicesList(i).ServiceName<<"     "<<DataPacket->getServicesList(i).ServicePort<<"\n";
				}
				EV<<" ***************** Service List *************************************"<<"\n";

				if ( (SrvTypTestCase == 1 || SrvTypTestCase ==4) && ServSecurVec[indxSrvv].SrvTypeCod ==1 ) // Root Server

					ServSecurVec[indxSrvv].attribCertiSRec = DataPacket->getAttrbCert();

				else if ((SrvTypTestCase == 2 || SrvTypTestCase ==4) && ServSecurVec[indxSrvv].SrvTypeCod ==2 ) // Threshold Servers

					ServSecurVec[indxSrvv].attrThreshCertiRec = DataPacket->getThreshAttrCert();

				else if ( SrvTypTestCase == 3 ) // Root & Threshold Servers
				{
					if (ServSecurVec[indxSrvv].SrvTypeCod ==1)

						ServSecurVec[indxSrvv].attribCertiSRec = DataPacket->getAttrbCert();

					else
					{
						if(!par("SetTAStoDAS").boolValue())
						{
							ServSecurVec[indxSrvv].attribCertiSRec = DataPacket->getAttrbCert() ;
							iC++;
						}
					    ServSecurVec[indxSrvv].attrThreshCertiRec = DataPacket->getThreshAttrCert();
					}
				}

				ServSecurVec[indxSrvv].sReachable = true;
				TotalByteCom += DataPacket->getByteLength();

				// Checking Timers
				// if (CombinPocessTimer && CombinPocessTimer->isScheduled()) break;
				if(ServSecurVec[indxSrvv].ExprTimer && ServSecurVec[indxSrvv].ExprTimer->isScheduled())
				{
					cancelEvent((cMessage *)ServSecurVec[indxSrvv].ExprTimer);
					delete ServSecurVec[indxSrvv].ExprTimer ;
					ServSecurVec[indxSrvv].ExprTimer =NULL ;
				}



				ServSecurVec[indxSrvv].Proces_State			= DataMsg_Process ;
				ServSecurVec[indxSrvv].AuthNUserStateRec 	= SucAuthNUser;


				// setup timer for simulating Process Delay for validation

				int *indxxSrvv 	=  new int();
				*indxxSrvv 		= indxSrvv ;

				TimerNam1<<"ProTimer_Data_"<<getParentModule()->getName()<<"-S"<<DataPacket->getSeqNum();

				ServSecurVec[indxSrvv].DataProcessTimer = new cMessage(TimerNam1.str().c_str() , MSGKIND_DATA_PROS_TIMER);
				ServSecurVec[indxSrvv].DataProcessTimer->setContextPointer(indxxSrvv) ;
				scheduleAt(simTime()+(DecryptValidateDelay*iC), (cMessage *) ServSecurVec[indxSrvv].DataProcessTimer);
			}
		}
		break;

		case AAM_AUTHN_NOACK :

			// Unsuccessful  Authentication Reply due to Corrupt Certificate

			DataPacket = check_and_cast<DataMsg *>(msg);
			indxSrvv =DataPacket->getIndxSrv();

			ServSecurVec[indxSrvv].TotalByteReceivRec 	= rootPacket->getByteLength();
			ServSecurVec[indxSrvv].AuthNUserStateRec 	= UnscAuthNUser ;
			ServSecurVec[indxSrvv].sReachable 			= true; // user is reachable even the
			TotalByteCom += rootPacket->getByteLength();

			AuthnStateDataProcess(indxSrvv, false,true);

			if ((NumRequestInProgress+numSuccessRequests < ThreshSrvNum && SrvTypTestCase == 2) ||
			   ( SrvTypTestCase == 1 && RoSrvCount <2  ) || ( SrvTypTestCase == 3 &&  numSuccessRequests ==0))// no enough shared Certificate to create AC
			{
				display_string->setTagArg("i", 1, "#0000FF");
				getParentModule()->bubble("Unsuccessful Authentication");
				AuthNUserState = UnscAuthNUser ;

				if (DisconnectFlag)
				{
				  BM->Registration(false); // disconnect to the MANETs Network
				  MM->SetManetActive(false);
				  if(AODVUU_PTR)
				  AODVUU_PTR->activationSelfModule(false);//  Deactivate some Modules in the host

				}

				recMsgtime = simTime() ;
				rtt = recMsgtime- sendMsgtime; // Round Trip Time
				rttVec.record(rtt);
				EV << "RTT: " << rtt << "\n" ;
				CancelTimer(indxSrvv) ;

				AAMDNC->UpdateStatistic(rtt.dbl(),0,0,1,-1,Counter);

				DF = false ;
				if (par("DeleteToFail").boolValue()) // Delete Node
				{
					if (par("ProDeletToFail").doubleValue() < 0)
					{
						AAMDNC->scheduleToDelete(getParentModule(),0,false);
						DF = true;
					}
					else if(par("ProDeletToFail").doubleValue() > uniform(0,1))
					{
						AAMDNC->scheduleToDelete(getParentModule(),0,false);
						DF = true;
					}

				}

				if(!DF && EnabledMigr && I_Phase_MIG < MigAttempNum) MigrationTimer( ) ;
			}
			break;

		case AAM_AUTHN_PROT_MSG4 : AuthNProtocolState = State_Msg3;  break; // TBA

		case AAM_DAS_RESP		 :

			DataPacket 	= check_and_cast<DataMsg *>(msg);
			if(!ServSecurVec[indxSrvv].SucessDAS)
			{
				ServSecurVec[indxSrvv].TotalByteReceivRec +=DataPacket->getByteLength();
				ServSecurVec[indxSrvv].AuthNProtocolStateRec = State_DAS_END;

				ServSecurVec[indxSrvv].attribCertiSRec = DataPacket->getAttrbCert() ;


				ServSecurVec[indxSrvv].sReachable = true;
				ServSecurVec[indxSrvv].SucessDAS = true;

				TotalByteCom += DataPacket->getByteLength();

				if(ServSecurVec[indxSrvv].ExprTimer && ServSecurVec[indxSrvv].ExprTimer->isScheduled())
				{
					cancelEvent((cMessage *)ServSecurVec[indxSrvv].ExprTimer);
					delete ServSecurVec[indxSrvv].ExprTimer ;
					ServSecurVec[indxSrvv].ExprTimer =NULL ;
				}

				ServSecurVec[indxSrvv].Proces_State			= DataMsg_Process ;
				ServSecurVec[indxSrvv].AuthNUserStateRec 	= SucAuthNUser;


				int *indxDAS 	=  new int();
				*indxDAS 		= indxSrvv ;

				TimerNam1<<"DASTimer_Data_"<<getParentModule()->getName()<<"-S"<<DataPacket->getSeqNum();

				ServSecurVec[indxSrvv].DataProcessTimer = new cMessage(TimerNam1.str().c_str(),MSGKIND_DAS_PROS_TIMER);
				ServSecurVec[indxSrvv].DataProcessTimer->setContextPointer(indxDAS) ;
				scheduleAt(simTime()+(DecryptValidateDelay*2), (cMessage *) ServSecurVec[indxSrvv].DataProcessTimer);

			}
			else
			{
				// error ("Error in Authentication Handshaking TwoWay")OR Error in Sequence Number;

				AgentErrMsg++;
				std::string xxy = msg->getName() ;
				getParentModule()->bubble(("Drop-Message-"+xxy).c_str());

				// TotalByteCom += DataPacket->getByteLength() ;

				ServSecurVec[indxSrvv].TotalByteDropped += DataPacket->getByteLength();
				TotalByteDrop += DataPacket->getByteLength();

				// log msg details
				sSecRecordLog sXx ;
				sXx.AuthNProtocolStateRecLog 	= ServSecurVec[indxSrvv].AuthNProtocolStateRec;
				sXx.AuthNTypeRecLog 			= ServSecurVec[indxSrvv].AuthNTypeRec ;
				sXx.AuthNUserStateRecLog 		= ServSecurVec[indxSrvv].AuthNUserStateRec ;
				sXx.Proces_StateLog 			= ServSecurVec[indxSrvv].Proces_State ;
				sXx.ServerNameLog 				= ServSecurVec[indxSrvv].ServerName ;
				sXx.SrvTypeCodLog 				= ServSecurVec[indxSrvv].SrvTypeCod;
				sXx.MsgtypeLog 					= AAM_DAS_RESP ;
				sXx.MsgNameLog				 	= msg->getName();
				sXx.TimerTypeLog 				= -1;
				sXx.TotalByteReceivRecLog 		= ServSecurVec[indxSrvv].TotalByteReceivRec+rootPacket->getByteLength();
				sXx.TotalBytesSendRecLog 		= ServSecurVec[indxSrvv].TotalBytesSendRec ;
				sXx.TotalByteDroppedLog 		= ServSecurVec[indxSrvv].TotalByteDropped;
				sXx.sReachableLog 				= ServSecurVec[indxSrvv].sReachable ;
				sXx.SeqNumLog 					= ServSecurVec[indxSrvv].cSeq;
				sXx.SeqNumMsgLog				= DataPacket->getSeqNum();
				ServSecurVecLog.push_back (sXx);
				recMsgtime = simTime() ;
			}
			break ;
	}
	delete msg ;
	//   EV<<" Authentication Request Timer in"<< getParentModule()->getFullPath()<<"
	//   is scheduled "<<AuthNExptimer->isScheduled()<<"\n";
}

void AuthNAgent::sendAuthnRequest(int idx)
{

 AuthenProtocolMsg *AReqProtMsg;
 std::stringstream 	MNam ;

switch (ServSecurVec[idx].AuthNProtocolStateRec)
 {
  case State_Msg1 :  // begin to send a Request for Authentication for any type of Authentication protocols

				  ServSecurVec[idx].cSeq++; // Setup Seq Counter

				   switch(ServSecurVec[idx].AuthNTypeRec)
				   {
					   case 1 : // one way Authentication
						 MNam <<"X509OneWayPass_MSG1_H"<<BM->nodeIndx<<"_S"<<ServSecurVec[idx].SrvTypeCod<<"_N"<<idx;
						 AReqProtMsg  = new AuthenProtocolMsg(MNam.str().c_str());
						 AReqProtMsg->setByteLength(MsgProtocolProfiles[AuthenticationType-1].MsgProtProf[0].sizeMsg);
						 break;

					   case 2 : // Two way Pass Authentication
						 MNam <<"X509TwoWayPass_MSG1_H"<<BM->nodeIndx<<"_S"<<ServSecurVec[idx].SrvTypeCod<<"_N"<<idx;
						 AReqProtMsg  = new AuthenProtocolMsg(MNam.str().c_str());
						 AReqProtMsg->setByteLength(MsgProtocolProfiles[AuthenticationType-1].MsgProtProf[0].sizeMsg);
						 break;

					   case 3 : // Two way Pass Authentication
						 MNam<<"X509ThreeWayPass_MSG1_H"<<BM->nodeIndx<<"_S"<<ServSecurVec[idx].SrvTypeCod<<"_N"<<idx;
						 AReqProtMsg  = new AuthenProtocolMsg(MNam.str().c_str());
						 AReqProtMsg->setByteLength(MsgProtocolProfiles[AuthenticationType-1].MsgProtProf[0].sizeMsg);
						 break ;

					   default :  error("Check Authentication Protocol Type");

				   }

				   AReqProtMsg->setMsgType(AAM_AUTHN_PROT_MSG1);
				   AReqProtMsg->addPar("sourceId") = getId();
				   AReqProtMsg->setIndxSrv(idx) ;
				   AReqProtMsg->setAuthNType(ServSecurVec[idx].AuthNTypeRec);

				   AReqProtMsg->setSeqNum(ServSecurVec[idx].cSeq); // set Seq
				   AReqProtMsg->setNonce(ServSecurVec[idx].cNonceValRec) ; // set Nonce
				   AReqProtMsg->setTimestamp(SIMTIME_STR(simTime()));
				   AReqProtMsg->setIdCertificate(Certif.c_str()); // Certificate is here is String Variable
				   AReqProtMsg->setSignature("##############");

				   delaySendToUDP(AReqProtMsg,localAuthnAgentPort, ServSecurVec[idx].ServerAddressRec,
						          ServSecurVec[idx].sPort, MsgProtocolProfiles[AuthenticationType-1].MsgProtProf[0].generatingProcessDelay);

				   ServSecurVec[idx].TotalBytesSendRec +=  AReqProtMsg->getByteLength() ;
				   TotalSendByteRec[idx]->record(ServSecurVec[idx].TotalBytesSendRec);
				   ServSecurVec[idx].sendMsgtime =simTime();

				   if (sendMsgtime == 0) sendMsgtime = sendMsgtimeTemp = simTime();
				   TotalByteCom +=  AReqProtMsg->getByteLength();
				   break;

  case State_Msg2 : // This state is only for the Three Way Authentication Protocol

				   MNam<<"X509ThreeWayPass_MSG3_H"<<BM->nodeIndx<<"_S"<<ServSecurVec[idx].SrvTypeCod<<"_N"<<idx;
				   AReqProtMsg  = new AuthenProtocolMsg(MNam.str().c_str());
				   AReqProtMsg->setMsgType(AAM_AUTHN_PROT_MSG3);
				   AReqProtMsg->setByteLength(MsgProtocolProfiles[AuthenticationType-1].MsgProtProf[2].sizeMsg);
				   AReqProtMsg->setAuthNType(ServSecurVec[idx].AuthNTypeRec);
				   AReqProtMsg->addPar("sourceId") = getId();
				   AReqProtMsg->setSeqNum(ServSecurVec[idx].cSeq);
				   AReqProtMsg->setNonce(ServSecurVec[idx].sNonceValRec);
				   AReqProtMsg->setIndxSrv(idx) ;

				   //  AReqProtMsg->setTimestamp(SIMTIME_STR(simTime()));
				   AReqProtMsg->setSignature("######$$$$$$$$$$$$########");
				   //  if (Counter > 2 ) AReqMsg->setAutNhBlock("CorruptedIDCert" ) ; // just for testing corrupted certificate with another call
				   //  else
				   //   AReqProtMsg->setIdCertificate(Certif.c_str()); // Certificate is here is String Variable

				   ServSecurVec[idx].TotalBytesSendRec +=  AReqProtMsg->getByteLength() ;
				   TotalSendByteRec[idx]->record(ServSecurVec[idx].TotalBytesSendRec);
				   TotalByteCom +=  AReqProtMsg->getByteLength() ;

				   delaySendToUDP(AReqProtMsg,localAuthnAgentPort, ServSecurVec[idx].ServerAddressRec, ServSecurVec[idx].sPort,
								  (MsgProtocolProfiles[AuthenticationType-1].MsgProtProf[2].generatingProcessDelay
								   +MsgProtocolProfiles[AuthenticationType-1].MsgProtProf[1].validateProcessDelay));

				   sendMsgtimeTemp = simTime() + MsgProtocolProfiles[AuthenticationType-1].MsgProtProf[2].generatingProcessDelay;
				   break;

  case State_DAS : // Send Separate Request to DAS
				  MNam<<"DAS_Certif_Req_H"<<BM->nodeIndx<<"_N"<<idx;
				  AReqProtMsg  = new AuthenProtocolMsg(MNam.str().c_str());
				  AReqProtMsg->setMsgType(AAM_DAS_REQ);
				  AReqProtMsg->setByteLength((int)par("DASReqLen"));
				  AReqProtMsg->addPar("sourceId") = getId();
				  AReqProtMsg->setAuthNType(ServSecurVec[idx].AuthNTypeRec);
				  AReqProtMsg->setIndxSrv(idx) ;
				  AReqProtMsg->setSeqNum(ServSecurVec[idx].DASReqCounter);
				  AReqProtMsg->setSignature("NA");

				  ServSecurVec[idx].TotalBytesSendRec +=  AReqProtMsg->getByteLength() ;
				  TotalSendByteRec[idx]->record(ServSecurVec[idx].TotalBytesSendRec);
				  TotalByteCom +=  AReqProtMsg->getByteLength() ;

				  delaySendToUDP(AReqProtMsg,localAuthnAgentPort, ServSecurVec[idx].ServerAddressRec, ServSecurVec[idx].sPort,
						  par("EncryptAndProcessDASReq").doubleValue());
				  break;

  default:
         MNam<<"Error in" <<ServSecurVec[idx].ServerName<<"Server connection in the state ="<<ServSecurVec[idx].AuthNProtocolStateRec;
         error((const char *)MNam.str().c_str()) ;
 }
}

void AuthNAgent::delaySendToUDP(cPacket *msg, int srcPort, const IPvXAddress& destAddr, int destPort, simtime_t processdelay )
{
    // send message to UDP, with the appropriate control info attached
    msg->setKind(UDP_C_DATA);

    UDPControlInfo *ctrl = new UDPControlInfo();
    ctrl->setSrcPort(srcPort);
    ctrl->setDestAddr(destAddr);
    ctrl->setDestPort(destPort);

    if ( destAddr ==IPAddress::ALLONES_ADDRESS ) ctrl->setInterfaceId(101);

    msg->setControlInfo(ctrl);

    EV << "Sending packet: "<<msg->getName();
    printPacket(msg);

    sendDelayed(msg,processdelay, "udpOut");
}

void AuthNAgent::AuthnStateDataProcess( int st, bool SucceFlag,bool ReAFlag)
{


  if (SucceFlag)
	  {
	  numSuccessRequests++;
	  ServSecurVec[st].ReciMsgtime = simTime();
	  ServSecurVec[st].SSRTT = simTime() - ServSecurVec[st].sendMsgtime;
	  }
  else
    {
      numRequestsDrop++;
      if ( ServSecurVec[st].AuthNUserStateRec == FailedAuthN) { ServSecurVec[st].ReciMsgtime = 0; ServSecurVec[st].SSRTT =0;}
    }

  if (NumRequestInProgress > 0) NumRequestInProgress -- ;


  if(ServSecurVec[st].ExprTimer && ServSecurVec[st].ExprTimer->isScheduled()&& ReAFlag)
    {
     cancelEvent((cMessage *)ServSecurVec[st].ExprTimer);
     delete ServSecurVec[st].ExprTimer ;
     ServSecurVec[st].ExprTimer =NULL ;
    }

  if(ServSecurVec[st].DataProcessTimer && ServSecurVec[st].DataProcessTimer->isScheduled()&& !ReAFlag)
    {
     cancelEvent((cMessage *)ServSecurVec[st].DataProcessTimer);
     delete ServSecurVec[st].DataProcessTimer ;
     ServSecurVec[st].DataProcessTimer =NULL ;
    }

  if(ServSecurVec[st].ProProcessTimer && ServSecurVec[st].ProProcessTimer->isScheduled()&& !ReAFlag)
    {
     cancelEvent((cMessage *)ServSecurVec[st].ProProcessTimer);
     delete ServSecurVec[st].ProProcessTimer ;
     ServSecurVec[st].ProProcessTimer =NULL ;
    }

  TotalReceiveByteRec[st]->record(ServSecurVec[st].TotalByteReceivRec);
  TotalSendByteRec[st]->record(ServSecurVec[st].TotalBytesSendRec);
  MigStateRec[st]->record((int) ServSecurVec[st].AuthNProtocolStateRec);
  RTTVec[st]->record(ServSecurVec[st].AuthNProtocolStateRec);

//  SucessReqHist.collect(numSuccessRequests);
//  DropReqHist.collect(numRequestsDrop);
//  InProgReqHist.collect(NumRequestInProgress);

}

void AuthNAgent::CancelTimer (unsigned int it)
{
  // Cancel all server timers for connection
  for ( unsigned int i = 0 ; i < ServSecurVec.size(); i++)
    {
     if ( i==it) continue ;

      if (ServSecurVec[i].AuthNUserStateRec ==  AuthenInProgress &&
          ServSecurVec[i].ExprTimer && ServSecurVec[i].ExprTimer->isScheduled())
        {
          cancelEvent((cMessage *)ServSecurVec[i].ExprTimer);
          delete ServSecurVec[i].ExprTimer;
          ServSecurVec[i].ExprTimer =NULL ;
        }
      if ((ServSecurVec[i].ProProcessTimer && ServSecurVec[i].ProProcessTimer->isScheduled()) &&
    	   !(ServSecurVec[i].DataProcessTimer && ServSecurVec[i].DataProcessTimer->isScheduled()))
        {
          cancelEvent((cMessage *)ServSecurVec[i].ProProcessTimer);
          delete ServSecurVec[i].ProProcessTimer;
          ServSecurVec[i].ProProcessTimer = NULL;
        }

//      if(ServSecurVec[i].DataProcessTimer && ServSecurVec[i].DataProcessTimer->isScheduled())
//        {
//         cancelEvent((cMessage *)ServSecurVec[i].DataProcessTimer);
//         delete ServSecurVec[i].DataProcessTimer ;
//         ServSecurVec[i].DataProcessTimer =NULL ;
//        }
    }
}

void AuthNAgent::processManSrvAddr( const char * TokenPar, int srvType )
{

  unsigned int sToNum = par ("TotalNumServers") ;
  cStringTokenizer tokenizer(TokenPar);
  const char *token ;
  serverAddrs x ;

  ev<<TokenPar <<endl;

  while ((token = tokenizer.nextToken())!=NULL)
    {

      if ( strstr (token,"Broadcast")!=NULL)
        {
          x.AddressServer 	= token; // IPAddress::ALLONES_ADDRESS ;
          x.ServerType 		= 0 ;
          x.serverTypeName 	= token ;
          AuthnManAddresses.push_back(x);
          break;
        }
      else
        {
          if (srvType == 1)
            {
              x.AddressServer 	= token ;
              x.ServerType 		= 1 ;
              x.serverTypeName 	= "CentralisedServer" ;
              AuthnManAddresses.push_back(x);
              RoSrvCount++ ;
              ev<<"-------------------------------> "<<token <<endl;
            }
          else if (srvType == 2)
            {
              x.AddressServer 	= token ;
              x.ServerType 		= 2 ;
              x.serverTypeName 	= "DistributedThresServer" ;
              AuthnManAddresses.push_back(x);
              TotthreshCount++ ;
              ev<<"-------------------------------> "<<token <<endl;
            }
          else error("Error in Server Type Initialisation");
        }
    }
  if (AuthnManAddresses.empty()) error("No Manager Addresses Initialisation") ;
  if (AuthnManAddresses.size() > sToNum) error("Error in Total Manager Addresses Numbers Initialisation") ;

  ManNum = AuthnManAddresses.size();
}

void AuthNAgent::finish()
{
  simtime_t t = simTime();

  if (t==0) return;

  for (unsigned int i = 0; i < MigStateRec.size();i++)
    {
      MigStateRec[i]->record((int) ServSecurVec[i].AuthNProtocolStateRec);
      TotalSendByteRec[i]->record(ServSecurVec[i].TotalBytesSendRec);
      TotalReceiveByteRec[i]->record(ServSecurVec[i].TotalByteReceivRec);
    }

  std::stringstream  x1 ;
  for ( unsigned int j=0 ; j < MsgProtocolProfiles.size() ; j++ ) // records Generating, Signing and Validating  Protocols Msgs
  {
	  x1<<j+1;

	  recordScalar((const char *)((std::string)"AuthnAgent Gen_Sign Msg"+x1.str()).c_str(),
				   (double) MsgProtocolProfiles [2].MsgProtProf[j].generatingProcessDelay);
	  recordScalar((const char *)((std::string)"AuthnAgent Validate Msg"+x1.str()).c_str(),
			       (double)  MsgProtocolProfiles [2].MsgProtProf[j].validateProcessDelay);
      x1.str("");
  }


  recordScalar("AuthnAgent Authentication lifeCycle", (int) AuthNUserState);
  recordScalar("AuthnAgent Round Trip Time",rtt.dbl());
  recordScalar("AuthnAgent User EndTime",		recMsgtime.dbl());
  recordScalar("AuthnAgent User SendingTime", 	sendMsgtime.dbl());
  recordScalar("AuthnAgent User EndLifeTimeNode",		t.dbl());

  recordScalar("AuthnAgent User JoiningTime", 	timeToStart.dbl());
  recordScalar("AuthnAgent User TotalByteCom",  TotalByteCom);
  recordScalar("AuthnAgent User ErrMsgCounter",	AgentErrMsg);
  recordScalar("AuthnAgent User UDPErrMsgCounter",	UdpErrMsg);
  recordScalar("AuthnAgent User CombiningProcessingTime",CombinPocessDelay.dbl());
  recordScalar("AuthnAgent User DecryptValidProcessingTime",DecryptValidateDelay.dbl());
  recordScalar("AuthnAgent User EncryptValidProcessingTime",par("EncryptAndProcessDASReq").doubleValue());
  recordScalar("AuthnAgent TotalByteDrop", TotalByteDrop);
  recordScalar("AuthnAgent TotalSrchTime",TotalSrcTime.dbl());
  recordScalar("AuthnAgent DeletFlag", (DF? 1:0));
  recordScalar("AuthnAgent MigrateAttemps", I_Phase_MIG);
  recordScalar("AuthnAgent TotalReqCount", Counter);



  if(par("TriggerTraffic").boolValue())
	  recordScalar("AuthnAgent TrafficTriggerActivation", (TriggerFlag? 0 : 1));


  if(t<MaxSimTime)
  {
	  double dV = t.dbl()-timeToStart.dbl();
	  recordScalar("AuthnAgent User LifeTime", dV);
	  if(AuthNUserState !=2)
	     AAMDNC->UpdateStatistic(dV,TotalSrcTime.dbl(),0,2,-1,Counter); // update statistics
	  else
		  AAMDNC->UpdateStatistic(dV,TotalSrcTime.dbl(),1,2,-1,Counter); // update statistics
  }
  else recordScalar("AuthnAgent User StayingTime", t.dbl()-timeToStart.dbl());

  // recordScalar("AuthnAgent TotalAuthnReqs Current Session",Counter);

	//  double x ;
	//  for (int i = 0 ; i<ServSecurVec[i].ReqCounter ;i++)
	//    x += pow( 2, i)*WTime.dbl() ;

 for (unsigned int i= 0 ; i< ServSecurVec.size(); i++)
   {
//	recordScalar((const char *)((std::string) "AuthnAgent TotalAuthnReqs PrevSessions-Srv-"+ServSecurVec[i].ServerName).c_str(),
//				 (int)ServSecurVec[i].T_ReqCounter*MaxReAuthNCounter);

    recordScalar((const char *)((std::string) "AuthnAgent TotalAuthnReqs AllSessions-Srv-"+ServSecurVec[i].ServerName).c_str(),
				 (int)ServSecurVec[i].T_ReqCounter*MaxReAuthNCounter+ServSecurVec[i].ReqCounter);

	recordScalar((const char *)((std::string) "AuthnAgent TotalDASReqs AllSessions-Srv-"+ServSecurVec[i].ServerName).c_str(),
								 ServSecurVec[i].DASReqCounter);

    recordScalar((const char *)((std::string) "AuthnAgent Total WaitingTime-Srv-"+ServSecurVec[i].ServerName).c_str(),
				 ServSecurVec[i].TTimeWait.dbl());

    recordScalar((const char *)((std::string)"AuthnAgent Authentication Protocol State-Srv-"+ServSecurVec[i].ServerName).c_str(),
				 (int)   ServSecurVec[i].AuthNProtocolStateRec);

    recordScalar((const char *)((std::string)"AuthnAgent Authentication ServerConnection State-Srv-"+ServSecurVec[i].ServerName).c_str(),
				 (int) ServSecurVec[i].AuthNUserStateRec);

    if (AuthNUserState==2) {
    	                      recordScalar((const char *)((std::string)"AuthnAgent  TotalRequest2Success-Srv-"+ServSecurVec[i].ServerName).c_str(),
    	                    		  (int) ServSecurVec[i].T_ReqCounter*MaxReAuthNCounter+ServSecurVec[i].ReqCounter);

    	                      recordScalar((const char *)((std::string) "AuthnAgent TotalDASReqs2Success-Srv-"+ServSecurVec[i].ServerName).c_str(),
    	                  								 (int)ServSecurVec[i].DASReqCounter);

                            }


    recordScalar((const char *)((std::string)"AuthnAgent TotalBytesSend-Srv-"+ServSecurVec[i].ServerName).c_str(),
				 (int)   ServSecurVec[i].TotalBytesSendRec);
    recordScalar((const char *)((std::string)"AuthnAgent TotalByteReceive-Srv-"+ServSecurVec[i].ServerName).c_str(),
				 (int)   ServSecurVec[i].TotalByteReceivRec);
    recordScalar((const char *)((std::string)"AuthnAgent TotalByteDropped-Srv-"+ServSecurVec[i].ServerName).c_str(),
				 (int)   ServSecurVec[i].TotalByteDropped);

    if (ServSecurVec[i].ReciMsgtime !=0)recordScalar((const char *)((std::string)"AuthnAgent  RTT-Srv-"+ServSecurVec[i].ServerName).c_str(),
													 (double)(ServSecurVec[i].ReciMsgtime-ServSecurVec[i].sendMsgtime).dbl()) ;
   }

 if(AuthNUserState==2 && ServSecurVec[0].AuthNUserStateRec ==1)
	 recordScalar("AuthnAgent AuthenticatedwithoutCAS", 1);


  for ( unsigned int it= 0 ; it < CertiClasses.size(); it++)
    {
      if (Certif == CertiClasses[it])
        {
          recordScalar("AuthnAgent IdCertificate Type", (int)it);
          break;
        }
    }

  for ( unsigned int i=0; i < AttribCertifVec.size();i++)
    {
      recordScalar((const char *)((std::string)"AuthnAgent Certif Type-Srv-"+ServSecurVec[i].ServerName).c_str(),
				   (int) AttribCertifVec[i].CertifType );
      recordScalar((const char *)((std::string)"AuthnAgent Certif Trust-Srv-"+ServSecurVec[i].ServerName).c_str(),
				   (double)AttribCertifVec[i].Trust);
    }

	if (AttribCertifVec.size()>0)
		{
		recordScalar("AuthnAgent Membership Certificate",(int) AttribCertifVec[0].CertifType );
		recordScalar("AuthnAgent Settling time", TotalSrcTime.dbl()+rtt.dbl());
		}

  // Write to the file ServSecurVecLog
    std::ofstream myServSecurVecLogFile;
  	std::stringstream fileNam;

  	fileNam << "Error-R"<< ev.getConfigEx()->getActiveRunNumber()<<"-"<< getParentModule()->getName()<<".txt";

  	if (ServSecurVecLog.size() !=0)
  	{
  		myServSecurVecLogFile.open(fileNam.str().c_str());

  		for( unsigned int i=0 ; i < ServSecurVecLog.size() ; i++)
  		{
			myServSecurVecLogFile<<" AuthProType=" <<ServSecurVecLog[i].AuthNProtocolStateRecLog<<

			" AuthTyp= " 		<< ServSecurVecLog[i].AuthNTypeRecLog 			<<
			" AuthUse= " 		<< ServSecurVecLog[i].AuthNUserStateRecLog 		<<
			" AuthProces= "		<< ServSecurVecLog[i].Proces_StateLog			<<
			" ServerNam= " 		<< ServSecurVecLog[i].ServerNameLog				<<
			" Msg_Name= "		<< ServSecurVecLog[i].MsgNameLog				<<
			" ServerCod= " 		<< ServSecurVecLog[i].SrvTypeCodLog				<<
			" Timer_Type= "		<< ServSecurVecLog[i].TimerTypeLog				<<
			" Msg_Type= "		<< ServSecurVecLog[i].MsgtypeLog				<<
			" TByteRecv= " 		<< ServSecurVecLog[i].TotalByteReceivRecLog		<<
			" TByteSend= " 		<< ServSecurVecLog[i].TotalBytesSendRecLog		<<
			" TByteDrop= "		<< ServSecurVecLog[i].TotalByteDroppedLog		<<
			" Reachable= " 		<< ServSecurVecLog[i].sReachableLog				<<
			" DASReqNum= "		<< ServSecurVecLog[i].DASReqNumLog				<<
		    " DASSuccess= " 	<< ServSecurVecLog[i].DASSuccess				<<
	        " SeqNum= "			<< ServSecurVecLog[i].SeqNumLog					<<
	        " SeqNumMsg= "		<< ServSecurVecLog[i].SeqNumMsgLog				<<"\n";
  		}
  		myServSecurVecLogFile.close();
  	}


//  SucessReqHist.recordAs("AuthnAgent NumberSucReq");
//  DropReqHist.recordAs	("AuthnAgent NumberDropReq");
//  InProgReqHist.recordAs("AuthnAgent NumberReqInProgress");

//  recordScalar("AuthnAgent AuthNReqMessage Length",msgByteLength);
//  recordScalar("AuthnAgent BytesSent", msgByteLength*(T_Counter*3+Counter));
//  recordScalar("AuthnAgent AuthNResponMessage Length",ResponMsgByteLength);

}

AuthNAgent::~AuthNAgent()
{
  MP 	= NULL ;
  bat	= NULL ;
  BM	= NULL ;
  MM	= NULL;

  for (unsigned int i=0; i<netServices.size(); i++)
      delete netServices[i];

  for (unsigned int i=0; i<MigStateRec.size();i++)
    {
      delete MigStateRec[i] ;
      delete TotalSendByteRec[i] ;
      delete TotalReceiveByteRec[i] ;
      delete RTTVec[i];
    }
}

// This Function is not in use any more

void AuthNAgent::chooseCertiClasse()
{
   // int k = intrand(destAddresses.size());
    int k 	=	genk_intrand(RandomGSeed,CertiClasses.size());
    Certif 	=	CertiClasses[k];
}

void AuthNAgent::MigrationTimer( )
{
  std::stringstream msgname ;
  cDisplayString* display_string = &getParentModule()->getDisplayString();
 // if  ( EnabledMigr && I_Phase_MIG < MigAttempNum)
 // {
    msgname <<"MIGRATE_Timer-"<<getParentModule()->getName();
    MigTimer  = new cMessage( (msgname.str()).c_str(),MSGKIND_MIGRATE_PrepReq );
    scheduleAt(simTime()+ MigrationTripTime,MigTimer);
    display_string->setTagArg("i", 1, "#FFA500");
    getParentModule()->bubble("Migration to Authentication");

    I_Phase_MIG++;
    AuthNUserState = AuthenIdle ;// FailedAuthNMig;
    AuthNReq = false;
 // }
}

void AuthNAgent::SchduleAuthnRequest (int strgSvrType , simtime_t xTime)
{


	switch(strgSvrType)
   {
   case 0 : // call all at once whatever type we are tackling .
	   for ( int j =0 ; j<ManNum ; j++)
	   {
		   double threshDT = 0;
		   std::stringstream msgnam;
		   int * indxContext = new int();
		   * indxContext = j;

		   // if ((SrvTypTestCase ==3 && ServSecurVec[j].SrvTypeCod == 1)
		   //   || j==ManNum-1 || j==ManNum-2 )threshDT = j+30 ;
		   // IPvXAddress * IpContext = new IPvXAddress (ServSecurVec[j].ServerAddressRec);

		   msgnam<<"AutReqStart--"<<getParentModule()->getName()<<"_"<<ServSecurVec[j].ServerName ;
		   EV<<"call all at once whatever type we are tackling .................." ;

		   cMessage * StartTimer = new cMessage((msgnam.str()).c_str(),  MSGKIND_START_REQ) ;
		   StartTimer->setContextPointer(indxContext) ;

		   scheduleAt(simTime()+xTime+0.5, StartTimer );
	   }
	   break;
   case 1 : // Send Request to CAS
	   for ( int j =0 ; j<ManNum ; j++)
	   {
		if (ServSecurVec[j].SrvTypeCod ==1)
		{
		   std::stringstream msgnam;
		   int * indxContext = new int();
		   * indxContext = j;

		   // if ((SrvTypTestCase ==3 && ServSecurVec[j].SrvTypeCod == 1)
		   //   || j==ManNum-1 || j==ManNum-2 )threshDT = j+30 ;
		   // IPvXAddress * IpContext = new IPvXAddress (ServSecurVec[j].ServerAddressRec);

		   msgnam<<"AutReqStart--"<<getParentModule()->getName()<<"_"<<ServSecurVec[j].ServerName ;
		   EV<<"Send Request to CAS -"<<msgnam ;
		   cMessage * StartTimer = new cMessage((msgnam.str()).c_str(),  MSGKIND_START_REQ) ;
		   StartTimer->setContextPointer(indxContext) ;

		   scheduleAt(simTime()+xTime, StartTimer);
		}
	   }
	   break;

   case 2 : // Send Request to TAS or DAS
	   for ( int j =0 ; j<ManNum ; j++)
	   {
		if (ServSecurVec[j].SrvTypeCod ==2)
		{
		   std::stringstream msgnam ;
		   int * indxContext = new int() ;
		   * indxContext = j;

		   // if ((SrvTypTestCase ==3 && ServSecurVec[j].SrvTypeCod == 1)
		   //   || j==ManNum-1 || j==ManNum-2 )threshDT = j+30 ;
		   // IPvXAddress * IpContext = new IPvXAddress (ServSecurVec[j].ServerAddressRec);

		   msgnam<<"AutReqStart--"<<getParentModule()->getName()<<"_"<<ServSecurVec[j].ServerName ;
		   EV<<"Send Request to TAS/DAS -"<<msgnam ;
		   cMessage * StartTimer = new cMessage((msgnam.str()).c_str(),  MSGKIND_START_REQ) ;
		   StartTimer->setContextPointer(indxContext) ;
		   scheduleAt(simTime()+xTime, StartTimer);
		}
	   }
	   break;
   case 3 :
   {

	   double MinRTT = 0.0 ;
	   int Sind ;
	   bool Smin = par("StMin").boolValue() ;

	   for ( int j =0 ; j<ManNum ; j++)
		   if(ServSecurVec[j].SrvTypeCod ==2 && ServSecurVec[j].sReachable && ServSecurVec[j].SSRTT!= 0)
			 {
			   SrvRecVar R ;
			   R.iS = j;
			   R.Srtt = (ServSecurVec[j].SSRTT).dbl();
			   srvIndx.push_back(R);
			  }

	   if (srvIndx.empty()) error ("Error In CALL DAS - check ServSecurVec vector");

	   if(Smin)
	   {   // find the MIN RTT of available DASs to in order to call it
		   MinRTT = srvIndx[0].Srtt ;
		   Sind = srvIndx[0].iS;
		   for(unsigned int i ;i <srvIndx.size();i++)
			   if(MinRTT > srvIndx[i].Srtt)
			   {
				   MinRTT = srvIndx[i].Srtt;
				   Sind = srvIndx[i].iS ;
			   }
	   }
	   else // Choose a random DAS to call
	   Sind = srvIndx[genk_intrand(0,srvIndx.size())].iS;


	   std::stringstream msgnam ;
	   int * indxContext = new int() ;
	   * indxContext = Sind;

	   msgnam<<"DAS_Req--"<<getParentModule()->getName()<<"_"<<ServSecurVec[Sind].ServerName ;
	   EV<<"Send Separate Request to DAS -"<<msgnam ;
	   cMessage * StartTimer = new cMessage((msgnam.str()).c_str(), MSGKIND_DAS_REQ) ;
	   StartTimer->setContextPointer(indxContext) ;
	   scheduleAt(simTime()+(xTime/2), StartTimer);
   }
	break;


   default : error ("Error in Strategy Types");
   }

}

void AuthNAgent::UserTrafficTrigger ()
{

	double cU = uniform (0.6,1);
	TriggerFlag = false ;
	TrigAlreadyCalled = true ;

	if ( cU > par("ProSeclectionGT").doubleValue())
	{
		TraffGenHostMan * TGHMan = TraffGenHostManAccess().getIfExists() ;

		if (!TGHMan) error ("Error in Accessing TraffGenHostMan  ") ;


		TriggerFlag = true ;
		ev<<endl;
		ev<<endl;
		ev<< ">>>>>>>>>>>>>>> Trigger Traffic from "<<getParentModule()->getFullName()<<"<<<<<<<<<<<<<<<<"<<endl;
		ev<<endl;
		ev<<endl;

		TGHMan->TriggerTraffic(MembershipCertificate.c_str(), true) ;

	}
}

int AuthNAgent::DataProcessInProgress(int SrvIndxP )
{

	int iCount = 0 ;
	for (unsigned int j = 0 ; j<ServSecurVec.size();j++)
	{

	 if (SrvIndxP != -1 && j==SrvIndxP)
		 continue ;
	 else
	 if (ServSecurVec[j].DataProcessTimer) iCount++;
	}

	if (CombinPocessTimer) iCount++ ;

	return iCount ;
}
bool AuthNAgent::IsCASAuthnReqInProg ()
{
	bool cF = false;
	for (unsigned int j = 0 ; j<ServSecurVec.size();j++)
	{
	  if(ServSecurVec[j].SrvTypeCod ==1 && // CAS type
		 (ServSecurVec[j].AuthNUserStateRec==AuthenIdle ||
		  ServSecurVec[j].AuthNUserStateRec==AuthenInProgress ||
		  ServSecurVec[j].DataProcessTimer))cF = true ;
	}
	return cF;

}

