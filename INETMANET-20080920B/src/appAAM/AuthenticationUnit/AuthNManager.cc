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

#include "AuthNManager.h"
#include "UDPControlInfo_m.h"
#include <fstream>

Define_Module(AuthNManager);

std::ostream& operator<<(std::ostream& out, const AuthNManager::UserRecord& d) {

	out<<"UserName= " 						<<d.UserName
       <<"\tAuthenProtType= "    		   	<<d.userAuthNType
       <<"\tUsrNonce= "						<<d.userNonceVal
       <<"\tUserSeq= "						<<d.userSeq
       <<"\tServerNonce= "       			<<d.ServerNonceVal
       <<"\tServerSeq= "					<<d.ServerSeqVal
       <<"\tUser_Address= "					<<d.UserAddr
       <<"\tUser_port= "       				<<d.UsrPort
       <<"\tTrust_Level= " 					<<d.TrustLevel
       <<"\tProtocolState= "				<<d.AuthNProtocolStateSrv
       <<"\tID_Cert= "         				<<d.IdCert
       <<"\tAttributes_Certif= "			<<d.RootAttribCertificate
       <<"\tThresholdAC= "					<<d.ThresAttribCertificate
       <<"\tDelegAttribCertif= " 			<<d.DelegAttribCertificate
       <<"\tACProcDelay= "					<<d.AttrProcDelay
       <<"\tAuthnProtInProgress= "			<<(d.AuthnProcessInProgress? "InProgress":"Completed")
       <<"\tAuthenProtocolSt= "				<<(d.AuthnState? "Success":"Failure")
       <<"\tAuthenCompleted= "				<<(d.AuthnCompleted? "Completed" : "Not Completed")
       <<"\tDASRequsted= "					<<(d.DASReq? "Completed" : "Not Completed")
       <<"\tTime_To_Live= "					<<d.TTL.dbl()
       <<"\tAUthN Attempt= "                <<d.AuthNAtmpt
       <<"\tAuthenCompleted= "				<<(d.AuthnCompleted? "Completed" : "Not Completed")
       <<"\tDASReqAtmpt= "					<<d.DASReqNum
       <<"\tAuthNCompAtmpt= "				<<d.AuthNCompAtmpt
       <<"\tAuthN_Drop="					<<d.DropAuthN
       <<"\tSize_ofSentServiceList=" 		<<d.SentSrvListSize
       <<"\tTotalSendByte= "				<<d.TotalBytesSendSrv
       <<"\tTotalReceiveByte= "				<<d.TotalByteReceivSrv;
	   return out;
}

std::ostream& operator<<(std::ostream& out, const AuthNManager::mServicesList& d) {
    out <<"Service ID = " 			<< d.ID
		<<"Service Name = " 		<< d.ServiceName
		<<"Service Address = "		<< d.ServiceAddress
		<<"Service port = " 		<< d.ServicePort
		<<"\t Class Level = " 		<<d.Clss;
		return out;
}

inline std::ostream& operator<<(std::ostream& out, const AuthNManager::AttrCertLst& d) {
      out <<" Certificate_ID="			<<d.cId
		  <<" Certificate="				<<d.RootCert
		  <<" ThresholdCertificate="	<<d.ThresholdCert
		  <<" Processing_Time="			<<d.procTime;
      return out;
}

inline std::ostream& operator<<(std::ostream& out, const AuthNManager::UserMsgLog& d) {

      out << "ID_User= "		<<d.UserName
		  <<"\tAddr= "			<<d.UserAddr
		  <<"\tPort= " 			<<d.UsrPort
		  <<"\tAuthNType= "		<<d.userAuthNType
		  <<"\tMsgtype= "		<<d.MsgType
		  <<"\tArrivalTime= " 	<<d.arrivalTime
          <<"\tProcesstime= "	<<d.processtime
          <<"\tMsgSeq= "		<<d.userSeq
          <<"\tMsgSize= "		<<d.TotalByteReceivLog
          <<"\tErrType= "		<<d.ErrorType;
	 return out ;
}

AuthNManager::AuthNManager()
{
  UsersNum =SucAuth = UnscAuth = 0;
  servicesListChanged 		= false;
  TotalServicesNumber 		= 6;
  currentReqVerfThreads 	= 0;
  currentAtrrCreaThreads 	= 0;

  ThroughputCounter		= 0;
  numCertiReqsDropped 	= 0;
  numReqsDropped 		= 0;
  TotalAuthNRequest 	= 0;
  TotalAuthNResponse 	= 0;
  TotalReceivedBytes 	= 0;
  TotalSentBytes 		= 0;
  verifTimeDuration 	= 0;
  DelProTemp = 0;

  startSign		= false;
  LastTime 		= 0;
  ProcessTimer 	= NULL;
  ErrMsg 		= 0;
  TotaltimeSytemInWorking = 0 ;
  BusySystemTimeSt1 = 0 ;
  TotaltimeSytemInWorking1 = 0 ;


//  mServicesListRef x = (mServicesListRef)malloc(sizeof(mServicesListRef*)) ;

  struct mServicesList x;

  x.ID				= 111;
  x.ServiceName		="News Feeds";
  x.ServiceAddress	= "TrafGenSrvHost[0]";
  x.ServicePort 	= 1324;
  x.Clss 			= 3;
  cNetServices.push_back(x);

  x.ID 				= 112 ;
  x.ServiceName		="Email Gateway SMTP";
  x.ServiceAddress 	= "TrafGenSrvHost[1]";
  x.ServicePort 	= 1278;
  x.Clss 			= 3;
  cNetServices.push_back (x);
//
//  x.ID 				= 113;
//  x.ServiceName		="Web Browsing HTTP";
//  x.ServiceAddress 	= "TrafGenSrvHost[2]";
//  x.ServicePort 	= 80;
//  x.Clss 			= 2;
//  cNetServices.push_back(x);
//
//  x.ID 				= 114;
//  x.ServiceName		= "Files Sharing FTP";
//  x.ServiceAddress 	= "TrafGenSrvHost[3]";
//  x.ServicePort 	= 21;
//  x.Clss 			= 2;
//  cNetServices.push_back(x);
//
//  x.ID 				= 115;
//  x.ServiceName		= "Multimedia Streaming";
//  x.ServiceAddress 	= "TrafGenHost[4]";
//  x.ServicePort 	= 1600 ;
//  x.Clss 			= 1 ;
//  cNetServices.push_back (x);
//
//  x.ID 				= 116;
//  x.ServiceName		= "VOIP";
//  x.ServiceAddress 	= "TrafGenHost[5]";
//  x.ServicePort 	=  5060;
//  x.Clss 			= 1;
//  cNetServices.push_back (x);

  //delete x ;

  volatile double pt =  uniform(2,3); // normal(3,1);

  struct AttrCertLst y;
  y.RootCert 		= "Golden_Class" ;
  y.ThresholdCert 	= "Threshold_Golden_Class" ;
  y.DelegateCert 	= "Golden_DelegateCert_Class" ;
  y.cId 			= 1 ;
  y.procTime 		= pt; //uniform(2,3); // processing Request ( registration+ Mem Access+ CPU + signing Attribute Certificate+ other processes)
  cCertiLst.push_back(y);

  y.RootCert 		= "Silver_Class";
  y.ThresholdCert 	= "Threshold_Silver_Class";
  y.DelegateCert 	= "Silver_DelegateCert_Class";
  y.cId 			= 2 ;
  y.procTime 		= pt; //uniform(2,3); // processing Request ( registration+ Mem Access+ CPU + signing Attribute Certificate+ other processes)
  cCertiLst.push_back(y);

  y.RootCert 		= "Bronze_Class" ;
  y.ThresholdCert 	= "Threshold_Bronze_Class" ;
  y.DelegateCert 	= "Bronze_DelegateCert_Class" ;
  y.cId 			= 3 ;
  y.procTime 		= pt; //uniform(2,3); // processing Request ( registration+ Mem Access+ CPU + signing Attribute Certificate+ other processes )
  cCertiLst.push_back(y);

  // Authentication Protocols ----------------------- //

  MsgInfo msgRec1 ;
  MsgProtocolProfileDef MsgProtProfV ;
  struct AuthnType AnRec ;

  // One Pass X509 ----------------------------------//
  msgRec1.indX 						= 1;
  msgRec1.msgProtName 				= "Msg_1";
  msgRec1.fieldNum 					= 2;
  msgRec1.sizeMsg 					= 1100 ;
  msgRec1.generatingProcessDelay 	= uniform(0.8,1); //normal (1, 0.2);
  msgRec1.validateProcessDelay 		= uniform(0.8,1); // normal (1, 0.2);
  MsgProtProfV.push_back(msgRec1);

  AnRec.AuthnName 					= "X509_One_Pass";
  AnRec.authTypeId 					= 1;
  AnRec.numMsg 						= 1;
  AnRec.MsgProtProf 				= MsgProtProfV;
  MsgProtocolProfiles.push_back(AnRec);

  // Two Pass X509 ----------------------------------//
  msgRec1.indX 						= 2;
  msgRec1.msgProtName 				= "Msg_2";
  msgRec1.fieldNum 					= 2 ;
  msgRec1.sizeMsg 					= 1100 ;
  msgRec1.generatingProcessDelay 	= uniform(0.8,1); //normal (1, 0.2);
  msgRec1.validateProcessDelay 		= uniform(0.8,1); //normal (1, 0.2);
  MsgProtProfV.push_back(msgRec1);

  AnRec.AuthnName 					= "X509_Two_Pass";
  AnRec.authTypeId 					= 2 ;
  AnRec.numMsg 						= 2;
  AnRec.MsgProtProf 				= MsgProtProfV;
  MsgProtocolProfiles.push_back(AnRec);

  // Three Pass X509---------------------------------//
  msgRec1.indX 						= 3 ;
  msgRec1.msgProtName 				= "Msg_3";
  msgRec1.fieldNum 					= 2 ;
  msgRec1.sizeMsg 					= 512 ;
  msgRec1.generatingProcessDelay 	= uniform(0.3, 0.5); // normal (0.5, 0.2) ;
  msgRec1.validateProcessDelay 		= uniform(0.3, 0.5); // normal (0.5, 0.2) ;
  MsgProtProfV.push_back(msgRec1);

  AnRec.AuthnName 					= "X509_Three_Pass";
  AnRec.authTypeId 					= 3 ;
  AnRec.numMsg 						= 3;
  AnRec.MsgProtProf 				= MsgProtProfV;
  MsgProtocolProfiles.push_back(AnRec);

}
AuthNManager::~AuthNManager()
{
	delete startServicingTrigger;

}

void AuthNManager::initialize(int stage)
{

		// TODO - Generated method body
		// because of IPAddressResolver, we need to wait until interfaces are registered,
		// address auto-assignment takes place etc.

		if (stage!=3)
			return;

		LocalAuthnManagerPort     = par("localAuthnManPort");
		URprocessTimeDuration     = par("URprocessTimeDuration");
		respMsgLengthAK           = par("respMsgLengthAK");
		respMsgLengthNoAK         = par("respMsgLengthNoAK");
		AuthorityServerType       = par("AuthorityServerType");
		MaxServicesCapacityBuffer = par("ServicesCapacityBuffer");
		MaxThreads                = par("MaxThreads");
		SrvTypeOptions            = par("SrvTypeOptions");
		DasSet 					  = par("DasSet").boolValue();
		DelegatedAttributeCertProcess = par("AttributeCertProcess");

		startServicingTrigger 	  = new cMessage("Req_Releas_Trigger", Req_Release_Timer);

		bat = InetSimpleBatteryAccess().getIfExists(); // Battery
		if (!bat)  hostState = "NO Battery"; //   error("Batter is not registered");
		else  	   hostState = bat->getHostSate();



      // Map variables
      WATCH_MAP(UserList);
      WATCH_MAP(ReqVerfThreads);
      WATCH_MAP(ProtProcessThreads);

      // Vector variables
      WATCH_VECTOR(cNetServices);
      WATCH_VECTOR(cCertiLst);
      WATCH_VECTOR(UserMsgDropLog);

      // Scalar variables
      WATCH (TotalAuthNRequest);
      WATCH (TotalAuthNResponse);
      WATCH (UsersNum);
      WATCH (SucAuth);
      WATCH (UnscAuth);
      WATCH (hostState);
      WATCH (currentReqVerfThreads);
      WATCH (currentAtrrCreaThreads);
      WATCH (numReqsDropped);
      WATCH (numCertiReqsDropped);
      WATCH (startSign);
      WATCH (StartTime);
      WATCH (LastTime);
      WATCH (EndTime);
      WATCH	(TotalReceivedBytes);
      WATCH	(TotalSentBytes);
      WATCH (DelProTemp);

      MU = mainUnitAccess().getIfExists();
      if (!MU) error ("Error in MainUnit Pointer");
      MU->updateManComp(1,true);

      endToEndDelayVec.setName("End-to-End Delay");
      reqBuffer.setName("Service Call Buffer");
      qlenVec.setName("queue length");
      dropVec.setName("drops");
      ThroughputVec.setName("AuthNMAN Throughput InMin");

      if (ev.isGUI())
      {
        char buf[40];
        sprintf(buf, "Authentication\nManager");
        getDisplayString().setTagArg("t",0,buf);


        if (AuthorityServerType==1 )  // Root Authority
        {
        	sprintf(buf, "Central Authority\nServer");
        	getParentModule()->getDisplayString().setTagArg("i",0,"device/server2");
        	getParentModule()->getDisplayString().setTagArg("i2",0, "block/star_vs");
        	getParentModule()->getDisplayString().setTagArg("t",0,buf);
        	//    getParentModule()->getDisplayString().setTagArg("is",0,"n");

        }
        else if (AuthorityServerType==2 )// Threshold Authority
        {
        	sprintf(buf, "Threshold\nAuthority\nServer");
        	getParentModule()->getDisplayString().setTagArg("i",0,"device/wifilaptop");
        	getParentModule()->getDisplayString().setTagArg("i2",0, "block/star_vs");
        	getParentModule()->getDisplayString().setTagArg("t",0,buf);
        	//   getParentModule()->getDisplayString().setTagArg("is",0,"n");
        }
        else if (AuthorityServerType==3 )  // Threshold and Delegated Authority
        {
        	sprintf(buf, "Deleg-Thres\nAuthority\nServer");
        	getParentModule()->getDisplayString().setTagArg("i",0,"device/wifilaptop");
        	getParentModule()->getDisplayString().setTagArg("i2",0, "block/circle_vs");
        	getParentModule()->getDisplayString().setTagArg("t",0,buf);
        }
      }


      Certif = getParentModule()->getName();
      Certif = Certif+"ServerCertficate";
      bindToPort(LocalAuthnManagerPort);
}

void AuthNManager::handleMessage(cMessage *msg)
{
  // TODO - Generated method body

  if(!(hostState =="NO Battery"))  hostState =bat->getHostSate();
  if(hostState =="ACTIVE" || hostState =="NO Battery")
	{
		// using Buffer to handle many Authentication request
		if (msg->arrivedOn("udpIn"))
		{
			if(!startSign) { StartTime = simTime() ; startSign = true;} // start Time for runnig Services


			if(reqBuffer.length()< MaxServicesCapacityBuffer)
			{
				// buffer the authentication coming request

				if(reqBuffer.empty() && currentAtrrCreaThreads <MaxThreads)
				{
					verifyAuthnRequest(PK(msg));
				}
				else
				{
					reqBuffer.insert(msg);
					qlenVec.record(reqBuffer.length());
				}
			}

			else
			{
				delete msg; // drop the request due to full buffer
				numReqsDropped++ ;
				dropVec.record(numReqsDropped);
				getParentModule()->bubble("Request Dropped due to the full Service Buffer");
			}
			simtime_t eed = simTime() - msg->getCreationTime();
			endToEndDelayVec.record(eed);

		}
		else if (msg->isSelfMessage())
		{
		  switch(msg->getKind())
		  {
			case Verification_Timer 		: processUserRequest(msg); break;

			case Protocol_Process_Timer 	: SendRespToUser(msg); break;

			case AttribCert_Proccess_Timer 	:  break ; // Not in Use

			case Req_Release_Timer 			:

				if (reqBuffer.empty())
				{
					ev<< "No Request to serve -------->  " ;
					return;
				}
				else
				{
					ev<< " ****(:)(RELEASE REQUEST FROM REQUEST BUFFER)(:)**** "<<endl ;
					verifyAuthnRequest(PK(reqBuffer.pop()));
					qlenVec.record(reqBuffer.length());
				}
				break;
			}
		}
	}
}

void AuthNManager::verifyAuthnRequest(cPacket *msg)
{
  EndTime = BusySystemTimeSt = simTime();



  UserRecordRef iter = NULL;
  std::string xStr ;

  if(msg->getKind() == UDP_I_ERROR)
    {

	  UDPControlInfo *controlInfoErr = check_and_cast<UDPControlInfo *>(msg->getControlInfo());

	  UserMsgLog MsgLogErr ;

	  MsgLogErr.UserName 			= -1;
	  MsgLogErr.UserAddr 			= controlInfoErr->getSrcAddr();
	  MsgLogErr.UsrPort 			= controlInfoErr->getSrcPort();
	  MsgLogErr.userAuthNType 		= -1;
	  MsgLogErr.MsgType 			= -1;
	  MsgLogErr.arrivalTime 		= msg->getArrivalTime() ;
	  MsgLogErr.processtime 		= simTime();
	  MsgLogErr.userSeq 			= -1;
	  MsgLogErr.TotalByteReceivLog 	= msg->getByteLength() ;
	  MsgLogErr.ErrorType 			= -1; // Error 0 Drop Request due to its request is already in progress

	  UserMsgDropLog.push_back(MsgLogErr) ;

	  scheduleAt(simTime(), startServicingTrigger); // trigger too release msg from the message Buffer
	  delete msg;
      EV<<"UDP ERROR No"<< ErrMsg++;
      return;
    }

  TotalAuthNRequest++;

  AuthenProtocolMsg  *AuthnPacket 	= check_and_cast<AuthenProtocolMsg *>(msg);
  UDPControlInfo *controlInfo 		= check_and_cast<UDPControlInfo *>(AuthnPacket->getControlInfo());

  TotalReceivedBytes +=AuthnPacket->getByteLength();

  std::map<int,const cMessage *>::iterator itr ;
  std::map<int,UserRecord>::iterator it;

  // check if this request is related to any process In progress
  itr = ProtProcessThreads.find((int) AuthnPacket->par("sourceId"));
  it = UserList.find ((int) AuthnPacket->par("sourceId"));

  if(itr !=ProtProcessThreads.end()||
    (it !=UserList.end() && (it->second.userSeq > AuthnPacket->getSeqNum())&& !(AuthnPacket->getMsgType() == AAM_DAS_REQ)))
    {
      getParentModule()->bubble("Drop Request due to its request is already in progress");
      ev << "Drop Request due to its request is in progress"<<endl;

      numCertiReqsDropped++ ;

      UserMsgLog MsgLog ;

      MsgLog.UserName 			= (int) AuthnPacket->par("sourceId") ;
      MsgLog.UserAddr 			= controlInfo->getSrcAddr();
      MsgLog.UsrPort 			= controlInfo->getSrcPort() ;
      MsgLog.userAuthNType 		= AuthnPacket->getAuthNType() ;
      MsgLog.MsgType 			= AuthnPacket->getMsgType();
      MsgLog.arrivalTime 		= AuthnPacket->getArrivalTime() ;
      MsgLog.processtime 		= simTime();
      MsgLog.userSeq 			= AuthnPacket->getSeqNum();
      MsgLog.TotalByteReceivLog = AuthnPacket->getByteLength() ;
      if (it->second.userSeq > AuthnPacket->getSeqNum())
	  MsgLog.ErrorType 			= 2 ; // Error 2 Different Sequence States
      else  MsgLog.ErrorType 	= 0 ; // Error 0 Drop Request due to its request is already in progress

      UserMsgDropLog.push_back(MsgLog) ;

      delete msg;

      scheduleAt(simTime(), startServicingTrigger); // trigger too release msg from the message Buffer

      return ;
    }


	  simtime_t ProcessDelay;

	  /* Registration for New User  or  Update record of existing User */

	  UserRecordRef  d = new  UserRecord;

	  d->UserName 				= (int) AuthnPacket->par("sourceId");
	  d->ServerIndx 			= AuthnPacket->getIndxSrv();
	  d->UserAddr 				= controlInfo->getSrcAddr();
	  d->UsrPort				= controlInfo->getSrcPort();
	  d->userNonceVal 			= AuthnPacket->getNonce();

	  d->userSeq 				=  AuthnPacket->getSeqNum();

	  d->userAuthNType 			=  AuthnPacket->getAuthNType();
	  d->currentMsgType 		=  (AAMMessageType) AuthnPacket->getMsgType();
	  d->TotalByteReceivSrv 	=  AuthnPacket->getByteLength();
	  d->TrustLevel 			=  uniform (0.7,0.9); // Assumption Trust Level
	  d->IdCert 				=  (std::string) AuthnPacket->getIdCertificate() ;


  // Generate random Decision about Identity Membership Certificate Verification

  // The First Phase of Authentication
  if(d->currentMsgType == AAM_AUTHN_PROT_MSG1)
   {

	 // Setup the Timer for Processing
     if (d->IdCert !=  "CorruptedIDCert") d->AuthnState = true ; else  d->AuthnState = false;

     switch (d->userAuthNType)
     {
       case 1 : // Time Delay to process Msg1 Validation X509 OneWay
				verifTimeDuration			= MsgProtocolProfiles[0].MsgProtProf[0].validateProcessDelay ;
                break;

       case 2 : // Time Delay to process Msg1 Validation X509 TwoWay
				verifTimeDuration 			= MsgProtocolProfiles[1].MsgProtProf[0].validateProcessDelay ;
                break;

       case 3 : // Time Delay to process Msg1 Validation X509 ThreeWay
			    verifTimeDuration 			= MsgProtocolProfiles[2].MsgProtProf[0].validateProcessDelay ;
                break;
      }

     // Need to be checked
     // if (it ==UserList.end())  ProcessDelay = URprocessTimeDuration+verifTimeDuration ;
     // else ProcessDelay = URprocessTimeDuration+verifTimeDuration;

     ProcessDelay = verifTimeDuration;
     d->AuthNProtocolStateSrv  = State_Msg1;
     d->AuthnProcessInProgress = true ;
     d->AuthNAtmpt++;
   }
  // The Second Phase of Authentication
  else if(AuthnPacket->getMsgType() == AAM_AUTHN_PROT_MSG3)
   {
     if (AuthnPacket->getNonce() != 0) d->AuthnState = true ;
     else  d->AuthnState = false; // corrupted msg3 from protocol

     d->AuthNProtocolStateSrv = State_Msg2;

     if(it ==UserList.end())
    	 error ("Check Protocol Message Type in %s%, the record is not available",AuthnPacket->getName());

     // setup time for process delay for processing validation
     verifTimeDuration 	= MsgProtocolProfiles[2].MsgProtProf[2].validateProcessDelay;
     ProcessDelay 		= verifTimeDuration;
   }
  else if (AuthnPacket->getMsgType() == AAM_DAS_REQ)
  {
	  TotalAuthNRequest++;

	  if ( AuthorityServerType == 2 && par("SepTASfDAS").boolValue()) // DAS Request
	  {
		  ProcessDelay = URprocessTimeDuration ;
		  d->DASReq = true ;
		  d->DASReqNum++;
		  d->AuthnState = true ;
	  }
	  else error ("Error in Receiving DAS Message");

  }

  // Record User Profile
  if(it ==UserList.end())
  {
	  // New User
	  // create a new record for this user in Users List in Authentication Manager
	  UserList.insert(std::pair<int,UserRecord>(d->UserName,*d));
	  // Increase The Total of the Users in Network
	  UsersNum++;
  }
  else
  {

	  iter = &(it->second);
	  if(!((d->currentMsgType == AAM_AUTHN_PROT_MSG3 && d->userAuthNType ==3)|| d->currentMsgType == AAM_DAS_REQ ))
	  {
		  // iter->AuthNAtmpt ++;
		  iter->IdCert 			= d->IdCert;
		  iter->userNonceVal 	= d->userNonceVal;
		  iter->UserAddr 		= d->UserAddr;
	  }

	  if (d->currentMsgType == AAM_DAS_REQ )
	  {
		  iter->DASReq     =  d->DASReq;
		  iter->DASReqNum +=  d->DASReqNum;
	  }

	  iter->userSeq 				= d->userSeq;
	  iter->currentMsgType 		 	= d->currentMsgType;
	  iter->AuthnProcessInProgress 	= d->AuthnProcessInProgress;
	  iter->userAuthNType          	= d->userAuthNType;

	  iter->AuthnState             	= d->AuthnState;
	  iter->AuthNProtocolStateSrv  	= d->AuthNProtocolStateSrv;
	  iter->TotalByteReceivSrv     += d->TotalByteReceivSrv;
	  iter->AuthNAtmpt 			   += d->AuthNAtmpt;

  }

  char timeName[35];
  sprintf(timeName,"VerifyMsgTimer-U%d-T%d-Msg%d",d->UserName,d->userAuthNType,d->currentMsgType);
  VerificationTimer = new cMessage (timeName,Verification_Timer);

//  ReqVerfThreads.insert (std::pair<int,const cMessage *>(d->UserName,VerificationTimer)); // thread
//  currentReqVerfThreads++;

  ProtProcessThreads.insert (std::pair<int,const cMessage *>(d->UserName,VerificationTimer)); // thread
  currentAtrrCreaThreads++;

  if(currentAtrrCreaThreads==1) BusySystemTimeSt1 =  simTime() ;

  // Setup Timer for Validation and Update User Requests
 int * iX = new int();
     * iX = d->UserName ;

  VerificationTimer->setContextPointer(iX);
  scheduleAt(simTime()+ ProcessDelay, VerificationTimer);

  delete d;
  delete msg;
}

void AuthNManager::processUserRequest(cMessage *msg)
{

  EndTime = simTime();
  int * iU ;
  double 	ProcessGenerateDelay = 0;
  int 		IndxTimer,IUsNa;
  char 		timeName[35];

  iU  = (int *) msg->getContextPointer();
  IUsNa = *iU;

  IndxTimer = Protocol_Process_Timer;

 if(UserList[IUsNa].AuthnState)
    {
      if(UserList[IUsNa].currentMsgType == AAM_AUTHN_PROT_MSG1 &&
        (UserList[IUsNa].userAuthNType ==2||UserList[IUsNa].userAuthNType ==3))
        {
    	  // TwoWay Pass
          ProcessGenerateDelay 	= MsgProtocolProfiles[UserList[IUsNa].userAuthNType-1].MsgProtProf[1].generatingProcessDelay;

          sprintf(timeName,"ProtProcMsgTimer-U%d-T%d-Msg%d",UserList[IUsNa].UserName,UserList[IUsNa].userAuthNType,UserList[IUsNa].currentMsgType);
        }
      else if(UserList[IUsNa].currentMsgType == AAM_AUTHN_PROT_MSG3 ||
    		 (UserList[IUsNa].userAuthNType ==1 && UserList[IUsNa].currentMsgType == AAM_AUTHN_PROT_MSG1 ))
        {
          // Issue Membership Certificate and Send it back to User
          // prepare AC
          processACData(IUsNa, UserList[IUsNa].IdCert);

          // End up with Authentication
          UserList[IUsNa].AuthnProcessInProgress = false;

          // Set Data State
          UserList[IUsNa].AuthNProtocolStateSrv = State_Data;

          // Processing Delay for issuing a relevant certificate

          ProcessGenerateDelay = UserList[IUsNa].AttrProcDelay.dbl();

          // Certificate already  created and not expired
          if (!((UserList[IUsNa].TTL).dbl() ==0 ))
        	  if (!((UserList[IUsNa].TTL - simTime()).dbl()<par("Margin4newCert").doubleValue()))    // Certificate not Expired
        	  DelProTemp =ProcessGenerateDelay /=2 ;
         sprintf(timeName,"DataProcessMsgTimer-U%d-T%d",IUsNa,UserList[IUsNa].userAuthNType);

        }
      else if (UserList[IUsNa].currentMsgType == AAM_DAS_REQ)
    	  {
    	  processACData(IUsNa, UserList[IUsNa].IdCert);
          // Set Data State
          UserList[IUsNa].AuthNProtocolStateSrv = State_DASReq;

          // Processing Delay for Issuing a relevant Certificate
          ProcessGenerateDelay = UserList[IUsNa].AttrProcDelay.dbl();

          // Certificate already  created and not expired
          if ((UserList[IUsNa].DASReqNum)>1)
        	  if (!((UserList[IUsNa].TTL - simTime()).dbl()<par("Margin4newCert").doubleValue()))    // Certificate not Expired
        	  DelProTemp =ProcessGenerateDelay /=2 ;

           sprintf(timeName,"DASReqResProcMsTimer-U%d-N%d",IUsNa,UserList[IUsNa].DASReqNum);
    	  }
    }
  else  // Unsuccessful Validation - for future usage
    {
      // Update The Trust Level Because of Unsuccessful Authentication
      UserList[IUsNa].TrustLevel -=  pow(UserList[IUsNa].TrustLevel,2);

      // Assumption for updating the level of trust for unsuccessful call
      if(UserList[IUsNa].TrustLevel <= 0)  UserList[IUsNa].TrustLevel = 0;

      // Set Data State
      UserList[IUsNa].AuthNProtocolStateSrv = State_Error;

      ProcessGenerateDelay = 0.01 ; // delay for procesing NoAck Msg back to User
      UserList[IUsNa].AuthnProcessInProgress = false ;

      sprintf(timeName,"NOACKDataProcessMsgTimer-U%d-T%d",IUsNa,UserList[IUsNa].userAuthNType);
    }

   int  *xtR = new int();
		*xtR = IUsNa;

    std::map<int,const cMessage *>::iterator xtt;
    xtt = ProtProcessThreads.find (IUsNa);
    if (xtt==ProtProcessThreads.end())
      error("Error in Request Verification Thread for ID %d",(int) UserList[IUsNa].UserName);
    ProtProcessThreads.erase(xtt);

   AttrCertProcessTimer = new cMessage (timeName, IndxTimer);
   ProtProcessThreads.insert (std::pair<int,const cMessage *>(UserList[IUsNa].UserName,AttrCertProcessTimer)); // thread
// currentAtrrCreaThreads++;

   AttrCertProcessTimer->setContextPointer(xtR);
   scheduleAt(simTime()+ProcessGenerateDelay, AttrCertProcessTimer);

   delete iU;
   delete msg;
   VerificationTimer =NULL;
}

void AuthNManager::SendRespToUser(cMessage *msg)
{
  char timeName[35],timeName1[35];

  EndTime = simTime();

  int sizeCounter =0 ; // Size of List

  ThroughputCounter++;

  if((EndTime.dbl()-LastTime.dbl())>= par("THPUTimeScale").doubleValue() )
    {
      ThroughputVec.record(( ((double)ThroughputCounter)/(EndTime -LastTime).dbl())*par("THPUTimeScale").doubleValue());
      ThroughputCounter = 0;
      LastTime = simTime() ;
    }


  int *indxp = (int *) msg->getContextPointer();
  int indxx = *indxp;

  // ev<<"%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% --" <<indxx<<endl;

  std::map<int,const cMessage *>::iterator xt ;
  xt = ProtProcessThreads.find (indxx);

  if (xt==ProtProcessThreads.end())
    error("Error in Request Verification Thread for ID %d",(int) UserList[indxx].UserName);

  ProtProcessThreads.erase(xt);

  if(UserList[indxx].AuthnState)
    {
      if(UserList[indxx].currentMsgType == AAM_AUTHN_PROT_MSG1 &&
         UserList[indxx].AuthNProtocolStateSrv 	!=State_Data   &&
        // UserList[indxx].AuthNProtocolStateSrv 	!=State_DASReq &&
        (UserList[indxx].userAuthNType ==2||UserList[indxx].userAuthNType ==3))
        {
          AuthenProtocolMsg *ARespProtMsg ;

          switch(UserList[indxx].userAuthNType)
          {
          case 2 : 	  // Two way Pass Authentication
				  {
					  sprintf(timeName1,"X509TwoWayPass_MSG2_%d",UserList[indxx].UserName);
					  ARespProtMsg  = new AuthenProtocolMsg(timeName1);
					  ARespProtMsg->setByteLength(MsgProtocolProfiles[UserList[indxx].userAuthNType-1].MsgProtProf[1].sizeMsg);
					  sprintf(timeName,"DataSrvProcessMsg Timer-U%d-T%d",UserList[indxx].UserName,UserList[indxx].userAuthNType);

					  UserList[indxx].AuthnProcessInProgress = false;
					  UserList[indxx].AuthNProtocolStateSrv  = State_Data;

					  // schedual for processing data message
					  int  *xt1 = new int();
					  *xt1 = indxx;
					  double Dt  ;

					  processACData(indxx, UserList[indxx].IdCert.c_str()) ;
					  Dt =SIMTIME_DBL(UserList[indxx].AttrProcDelay) ;

					  UserList[indxx].URProcessTimer = new cMessage (timeName, Protocol_Process_Timer);
					  UserList[indxx].URProcessTimer->setContextPointer(xt1);

					  ProtProcessThreads.insert(std::pair<int,const cMessage *>((int)UserList[indxx].UserName, (cMessage *)UserList[indxx].URProcessTimer));

//					  ProcessTimer = new cMessage (timeName, Protocol_Process_Timer);
//					  ProcessTimer->setContextPointer(xt1);

			          // Certificate already  created and not expired
			          if(!( UserList[indxx].TTL==0))
			          	 if(!((UserList[indxx].TTL - simTime()).dbl()< par("Margin4newCert").doubleValue())) DelProTemp = Dt /=2  ;

					  scheduleAt(simTime()+Dt+(par("DeltaWait").doubleValue()), (cMessage *)UserList[indxx].URProcessTimer); // Schedual for processing Data Msg after Send Msg2
				  }
				  break;

          case 3 :   // Two way Pass Authentication
					  sprintf(timeName1,"X509ThreeWayPass_MSG2_%d",UserList[indxx].UserName);
					  ARespProtMsg  = new AuthenProtocolMsg(timeName1);
					  ARespProtMsg->setByteLength(MsgProtocolProfiles[UserList[indxx].userAuthNType-1].MsgProtProf[1].sizeMsg);
				  break ;

          default :  error("Check Authentication Protocol Type");
          }

          UserList[indxx].ServerNonceVal 		= abs(intuniform(1000, 100000));
          UserList[indxx].ServerSeqVal			= 1;
          UserList[indxx].TotalBytesSendSrv 	+= ARespProtMsg->getByteLength();
          TotalSentBytes						+= ARespProtMsg->getByteLength();

          ARespProtMsg->setMsgType(AAM_AUTHN_PROT_MSG2);
          ARespProtMsg->setIndxSrv(UserList[indxx].ServerIndx);        // Number Server
          ARespProtMsg->setAuthNType(UserList[indxx].userAuthNType);  // Authentication Type
          ARespProtMsg->setSeqNum(UserList[indxx].userSeq);    // Set Seq Server
          ARespProtMsg->setNonce(UserList[indxx].ServerNonceVal) ;  // Set Nonce Server

          ARespProtMsg->setTimestamp(SIMTIME_STR(simTime()));      // time stamp Server
          ARespProtMsg->setIdCertificate(Certif.c_str());         // Certificate is here is String Variable
          ARespProtMsg->setSignature("$$$$$$$$$$$$$$$$$$$$$");

          UserList[indxx].AuthNProtocolStateSrv = State_Data;

          sendToUDP(ARespProtMsg, LocalAuthnManagerPort, UserList[indxx].UserAddr, UserList[indxx].UsrPort);
        }
      else if((UserList[indxx].currentMsgType == AAM_AUTHN_PROT_MSG3 && UserList[indxx].userAuthNType == 3 &&
    		   UserList[indxx].AuthNProtocolStateSrv==State_Data)
    		   ||(UserList[indxx].userAuthNType ==1 && UserList[indxx].AuthNProtocolStateSrv == State_Data) ||
    		   (UserList[indxx].userAuthNType == 2 && UserList[indxx].AuthNProtocolStateSrv==State_Data)
    		 )
        {

            // Update Trust
//            if (UserList[indxx].TTL >  simTime() && !servicesListChanged  && UserList[indxx].TrustLevel > 0.1)
//            	UserList[indxx].TrustLevel -=  uniform (0.0,0.1);
//            else if (UserList[indxx].TrustLevel < 0.9) UserList[indxx].TrustLevel += uniform (0.0,0.1);

            std::stringstream msgNa;
            int lengthTempAK = respMsgLengthAK ;

            msgNa<< "DATA_AUTHN_ACK_"<<UserList[indxx].UserName ;

            DataMsg *DataRespAkAuthnPkt = new  DataMsg (msgNa.str().c_str());
            DataRespAkAuthnPkt->setMsgType(AAM_AUTHN_ACK);
            DataRespAkAuthnPkt->setIndxSrv(UserList[indxx].ServerIndx);
            DataRespAkAuthnPkt->setSeqNum(UserList[indxx].userSeq);

            if(AuthorityServerType==1)
            	DataRespAkAuthnPkt->setAttrbCert(UserList[indxx].RootAttribCertificate.c_str());
            else
            {
            	DataRespAkAuthnPkt->setThreshAttrCert(UserList[indxx].ThresAttribCertificate.c_str());
            	if (SrvTypeOptions == 3 && !par("SepTASfDAS").boolValue())
            	DataRespAkAuthnPkt->setAttrbCert(UserList[indxx].DelegAttribCertificate.c_str());

            }

          // Successful Authentication
          getParentModule()->bubble("Send AK BACK to User");
          EV<< "Send AK BACK to User "<<endl;

          // calculate size of servicesList sent back to user
          for (unsigned int i = 0 ; i < cNetServices.size();i++ )
          if( UserList[indxx].AcID <= cNetServices[i].Clss ) sizeCounter++;

          UserList[indxx].SentSrvListSize = sizeCounter ;

          EV<<"***************************************************************************************"<<endl;
          EV<<" the Size of Services List that is required in order to create it and send it to User is " <<endl;
          EV<<"*************************************************************************************"<<endl;


          struct usrServList lst[sizeCounter];

          // generate and send a AuthenResponsMsg packet

          DataRespAkAuthnPkt->setServicesListArraySize(sizeCounter);

          for(unsigned int i = 0 ; i < cNetServices.size();i++ )
            {
              if(UserList[indxx].AcID <= cNetServices[i].Clss)
                {
                  lst[i].ID  = cNetServices[i].ID ;
                  lst[i].ServiceName  = (opp_string) cNetServices[i].ServiceName ;
                  lst[i].ServiceAddress  = (opp_string) cNetServices[i].ServiceAddress ;
                  lst[i].ServicePort = cNetServices[i].ServicePort ;

                  DataRespAkAuthnPkt->setServicesList(i, (servicesTuple &) lst[i]);

                  EV<<DataRespAkAuthnPkt->getServicesList(i).ID
                  <<" "<<DataRespAkAuthnPkt->getServicesList(i).ServiceName
                  <<" "<<DataRespAkAuthnPkt->getServicesList(i).ServiceAddress
                  <<" "<<DataRespAkAuthnPkt->getServicesList(i).ServicePort<<endl;
                }
            }
          EV<<"*************************************************************************************"<<endl;



          // a user node have no idea about Server Certificate and if we call TAS/DA together
          // it should send it along with both  thresholdCertificate
          //and DelegAtttributeCertificate in order to validation purpose

          if(SrvTypeOptions == 3 && !par("SepTASfDAS").boolValue() && AuthorityServerType ==2)
          {
        	  if(UserList[indxx].userAuthNType ==1) lengthTempAK *=3 ;// ThresholdCertif + DelegCertif+ Server Certif
        	  else lengthTempAK *=2 ; // ThresholdCertif + DelegCertif
          }

          // DAS in Separate Servers
          if(DasSet && UserList[indxx].userAuthNType ==1)  lengthTempAK *=2 ;

          DataRespAkAuthnPkt->setByteLength(lengthTempAK);
          TotalSentBytes += DataRespAkAuthnPkt->getByteLength();
          UserList[indxx].TotalBytesSendSrv += DataRespAkAuthnPkt->getByteLength();

          SucAuth ++;

          if (UserList[indxx].TTL ==0 ||(UserList[indxx].TTL - simTime()).dbl()<par("Margin4newCert").doubleValue())
        	  UserList[indxx].TTL = simTime()+par("TTLACert").doubleValue(); // initialise new TTL to AC

          UserList[indxx].AuthNCompAtmpt ++;
          UserList[indxx].AttrCertCreated = 2 ; // 2 ==> Certificate Created
          UserList[indxx].AuthnCompleted  = true ;
          UserList[indxx].AuthNProtocolStateSrv =State_End; // end protocol

          sendToUDP(DataRespAkAuthnPkt, LocalAuthnManagerPort, UserList[indxx].UserAddr, UserList[indxx].UsrPort);

          if(UserList[indxx].userAuthNType ==2) UserList[indxx].URProcessTimer =NULL ; // Clear Protcol Process timer for AuthnType == 22
          TotalAuthNResponse++;
      }
      else if (UserList[indxx].currentMsgType == AAM_DAS_REQ && UserList[indxx].AuthNProtocolStateSrv == State_DASReq)
      {
          std::stringstream msgDASNa;
          int lengthTemp = respMsgLengthAK ;

          // a user node have no idea about Server Certificate ,
          // it should send along with DelegAtttributeCertificate in order to validation purpose
          if (UserList[indxx].userAuthNType ==1) lengthTemp *=2 ;

          msgDASNa<< "DAS_RESPONSE_U"<<UserList[indxx].UserName ;

          DataMsg *DASRespPkt = new  DataMsg (msgDASNa.str().c_str());
          DASRespPkt->setMsgType(AAM_DAS_RESP);

          DASRespPkt->setServicesListArraySize(0); // No Service List
          DASRespPkt->setIndxSrv(UserList[indxx].ServerIndx);
          DASRespPkt->setSeqNum(UserList[indxx].userSeq);

          DASRespPkt->setByteLength(lengthTemp);
          DASRespPkt->setAttrbCert(UserList[indxx].DelegAttribCertificate.c_str());

          TotalSentBytes += DASRespPkt->getByteLength();
          UserList[indxx].TotalBytesSendSrv += DASRespPkt->getByteLength();

          UserList[indxx].AuthNProtocolStateSrv = State_DAS_END; // end protocol

          UserList[indxx].AttrCertCreated = 3 ; // 3 ==> DAS Certificate Created

          sendToUDP(DASRespPkt, LocalAuthnManagerPort, UserList[indxx].UserAddr, UserList[indxx].UsrPort);

          SucAuth ++;


      } //  END IF For DAS processing DAS Response
    }
  else  // Unsuccessful Validation
    {
      // Unsuccessful Authentication
      std::stringstream msgNaNa ;
      msgNaNa<< "DATA_AUTHN_NoACK_U"<<UserList[indxx].UserName ;
      DataMsg *DataRespNoAkAuthnPkt = new  DataMsg  (msgNaNa.str().c_str());

      DataRespNoAkAuthnPkt->setMsgType(AAM_AUTHN_NOACK);
      DataRespNoAkAuthnPkt->setIndxSrv(UserList[indxx].ServerIndx);
      DataRespNoAkAuthnPkt->setSeqNum(UserList[indxx].userSeq);

      getParentModule()->bubble("Send NOAK BACK to User");

      EV<< "Send NOAK BACK to User "<<endl;

      DataRespNoAkAuthnPkt->setAttrbCert("No Certificate due to Unsuccessful Authentication");
      DataRespNoAkAuthnPkt->setThreshAttrCert("No Certificate due to Unsuccessful Authentication");
      DataRespNoAkAuthnPkt->setByteLength(respMsgLengthNoAK);
      DataRespNoAkAuthnPkt->setServicesListArraySize(0); // No Service List

      UserList[indxx].TotalBytesSendSrv += DataRespNoAkAuthnPkt->getByteLength();
      TotalSentBytes += DataRespNoAkAuthnPkt->getByteLength();

      sendToUDP(DataRespNoAkAuthnPkt, LocalAuthnManagerPort, UserList[indxx].UserAddr, UserList[indxx].UsrPort);

      UnscAuth++;
      UserList[indxx].AttrCertCreated = 0;
      UserList[indxx].DropAuthN 	 += 1;
      UserList[indxx].AuthnCompleted  = false ;
    }





  // remove current Thread to allow other request to get serviced

  if(!(UserList[indxx].URProcessTimer && UserList[indxx].URProcessTimer->isScheduled()))  // this needs to be done only when AuthN is two way passes
  {
    // delete xt->second ; // delete;
	  currentAtrrCreaThreads--;
	  scheduleAt(simTime(), startServicingTrigger); // trigger to release request from  the request Buffer
      TotalAuthNResponse++;
      TotaltimeSytemInWorking += simTime()-BusySystemTimeSt; // calculate Utilisation
      if(currentAtrrCreaThreads==0)TotaltimeSytemInWorking1 +=simTime()-BusySystemTimeSt1;
  }

  delete msg;
  delete indxp;
  AttrCertProcessTimer =NULL;

}

AuthNManager::AttrCertLstRef AuthNManager::getAttribCert(const std::string IdCertificate)
 {

   int CerID = 0 ;
   if (IdCertificate == "GoldenIDCert" )  		CerID = 1 ;
   else if (IdCertificate =="SilverIDCert") 	CerID = 2 ;
   else if (IdCertificate =="BronzeIDCert")   	CerID = 3 ;

   for ( CerLs::iterator it = cCertiLst.begin(); it != cCertiLst.end(); it++)
      {
        if (it->cId == CerID )
          return &(*it);
      }
       return 0 ;
 }

void AuthNManager::processACData(int i, std::string sIC )
{
	// issue AC and Send it back to User
	// prepare AC

	AuthNManager::AttrCertLstRef  Apt = (AuthNManager::AttrCertLstRef)getAttribCert(sIC);
	if (!Apt ) error(" ID Certificate Type: '%s' has no Attribute Certificate", sIC.c_str());

	UserList[i].AttrProcDelay  = Apt->procTime ;

	if (AuthorityServerType==1)
		UserList[i].RootAttribCertificate= Apt->RootCert;
	else
	{
		UserList[i].ThresAttribCertificate= Apt->ThresholdCert;

		if (SrvTypeOptions == 3)
		{
			UserList[i].DelegAttribCertificate= Apt->DelegateCert;

			if (!par("SepTASfDAS").boolValue()) // No Separation in TAS/DAS
			UserList[i].AttrProcDelay *= 2;
		}
	}
	UserList[i].AcID = Apt->cId ;
}

void AuthNManager::finish()
{

  simtime_t t = simTime();
  if (t==0) return;


  std::stringstream  x1 ;
  for ( unsigned int j=0; j < MsgProtocolProfiles.size(); j++ ) // records Generating, Signing and Validating  Protocols Msgs
  {

	  x1<<j+1;
	  recordScalar((const char *)((std::string)"AuthnMAN Gen_Sign Msg"+x1.str()).c_str(), (double) MsgProtocolProfiles [2].MsgProtProf[j].generatingProcessDelay);
	  recordScalar((const char *)((std::string)"AuthnMAN Validate Msg"+x1.str()).c_str(), (double)  MsgProtocolProfiles [2].MsgProtProf[j].validateProcessDelay);
	  x1.str("");
  }

  recordScalar("AuthnMAN Total Functioning Time",(EndTime-StartTime).dbl());
  recordScalar("AuthnMAN Total Simulation Time", simTime().dbl());
  recordScalar("AuthnMAN Utilisation Ratio",TotaltimeSytemInWorking.dbl()/simTime().dbl());
  recordScalar("AuthnMAN Utilisation Ratio_Temp",TotaltimeSytemInWorking1.dbl()/simTime().dbl());

  simtime_t dtt = 0 ;
  simtime_t dtt1 = 0 ;

  if (currentAtrrCreaThreads !=0)
  {
	  dtt = simTime()-BusySystemTimeSt;
	  dtt1 = simTime()-BusySystemTimeSt1;
  }
  recordScalar("AuthnMAN Utilisation Ratio_T1",(TotaltimeSytemInWorking.dbl()+dtt.dbl())/simTime().dbl());
  recordScalar("AuthnMAN Utilisation Ratio_Temp_T1",(TotaltimeSytemInWorking1.dbl()+dtt1.dbl())/simTime().dbl());

  recordScalar("AuthnMAN URprocessTimeDuration", URprocessTimeDuration.dbl());
  recordScalar("AuthnMAN Error UDP Messages Counter", ErrMsg);
  recordScalar("AuthnMAN Number of Users", UsersNum);
  recordScalar("AuthnMAN Successful Authentication", SucAuth);

  recordScalar("AuthnMAN Certificate Freq-Throughput_FT",(SucAuth/(EndTime-StartTime)));
  recordScalar("AuthnMAN Certificate Freq-Throughput_ST",(SucAuth/simTime().dbl()));
  recordScalar("AuthnMAN Unsuccessful Authentication", UnscAuth);
  recordScalar("AuthnMAN Total Dropped Protocol Msgs",numReqsDropped);
  recordScalar("AuthnMAN Total DroppedCertificateProces",numCertiReqsDropped);

  recordScalar("AuthnMAN Total AuthNRequests",TotalAuthNRequest);
  recordScalar("AuthnMAN Total AuthNResponses",TotalAuthNResponse);

  recordScalar("AuthnMAN Total AuthNProto Frequncey_FT",(((double)TotalAuthNResponse) /(EndTime-StartTime)));
  recordScalar("AuthnMAN Total AuthNProto Frequncey_ST",(((double)TotalAuthNResponse) /simTime().dbl()));
  recordScalar("AuthnMAN Total Unprocessed Req", (int) abs(TotalAuthNRequest - TotalAuthNResponse));

  if(!(StartTime == simTime()))
  {
	  recordScalar("AuthnMAN Total AuthNProto Frequncey_STST",(((double)TotalAuthNResponse) /(simTime().dbl()-StartTime)));
	  recordScalar("AuthnMAN Certificate Freq-Throughput_STST",(((double) SucAuth)/(simTime().dbl()-StartTime)));
  }

  recordScalar("AuthnMAN Total ReceivedBytes", TotalReceivedBytes);
  recordScalar("AuthnMAN Total SentBytes", TotalSentBytes);
  recordScalar("AuthnMAN Total Communication Overhead",TotalReceivedBytes+TotalReceivedBytes);

  // consider processing time of different 3 Certificate types is the same
  recordScalar("AuthnMAN MemCert ProcessTime ", (double)cCertiLst[0].procTime);
  recordScalar("AuthnMAN MemCert ProcessTime for CertAlreadyCreated", DelProTemp);


  // Write to the file UserList & Msglog
    std::ofstream myUsersListFile, myMsgLogFile;
  	std::stringstream fileName1,fileName2;

  	fileName1 << "UserList-R" << ev.getConfigEx()->getActiveRunNumber()<<"-"<<getParentModule()->getFullName()<<".txt";
  	fileName2 << "DropMsgLogFile-R" << ev.getConfigEx()->getActiveRunNumber()<<"-"<<getParentModule()->getFullName()<<".txt";

  	if (UserList.size() !=0)
  	{

  		myUsersListFile.open (fileName1.str().c_str());
  		for(std::map<int,UserRecord>::iterator it = UserList.begin(); it != UserList.end();it++)
  		{
  		   myUsersListFile <<"UserName= " 		<<it->second.UserName
  	       <<"\tAuthenProtType= "    		   	<<it->second.userAuthNType
  	       <<"\tUsrNonce= "						<<it->second.userNonceVal
  	       <<"\tUserSeq= "						<<it->second.userSeq
  	       <<"\tServerNonce= "       			<<it->second.ServerNonceVal
  	       <<"\tServerSeq= "					<<it->second.ServerSeqVal
  	       <<"\tUser_Address= "					<<it->second.UserAddr
  	       <<"\tUser_port= "       				<<it->second.UsrPort
  	       <<"\tTrust_Level= " 					<<it->second.TrustLevel
  	       <<"\tProtocolState= "				<<it->second.AuthNProtocolStateSrv
  	       <<"\tID_Cert= "         				<<it->second.IdCert
  	       <<"\tAttributes_Certif= "			<<it->second.RootAttribCertificate
  	       <<"\tThresholdAC= "					<<it->second.ThresAttribCertificate
  	       <<"\tDelegAttribCertif= " 			<<it->second.DelegAttribCertificate
  	       <<"\tACProcDelay= "					<<it->second.AttrProcDelay
  	       <<"\tAuthnProtInProgress= "			<<(it->second.AuthnProcessInProgress? "InProgress":"Completed")
  	       <<"\tAuthenProtocolSt= "				<<(it->second.AuthnState? "Success":"Failure")
  	       <<"\tAuthenCompleted= "				<<(it->second.AuthnCompleted? "Completed" : "Not Completed")
			<<"\tDASRequsted= "					<<(it->second.DASReq? "Completed" : "Not Completed")
  	       <<"\tTime_To_Live= "					<<it->second.TTL.dbl()
  	       <<"\tAUthN Attempt= "                <<it->second.AuthNAtmpt
  	       <<"\tDASReqAtmpt= "					<<it->second.DASReqNum
  	       <<"\tAuthNCompAtmpt= "				<<it->second.AuthNCompAtmpt
  	       <<"\tAuthN_Drop="					<<it->second.DropAuthN
  	       <<"\tSize_ofSentServiceList= " 		<<it->second.SentSrvListSize
  	       <<"\tTotalSendByte= "				<<it->second.TotalBytesSendSrv
  	       <<"\tTotalReceiveByte= "				<<it->second.TotalByteReceivSrv <<"\n";
  		}
  		myUsersListFile.close();

  	}

  	if (UserMsgDropLog.size() !=0)
  	{

  		myMsgLogFile.open (fileName2.str().c_str());
  		for ( unsigned int i =0 ; i < UserMsgDropLog.size() ; i++)
  		{

  		 myMsgLogFile << "ID_User= "		<<UserMsgDropLog[i].UserName
		  <<"\tAddr= "						<<UserMsgDropLog[i].UserAddr
		  <<"\tPort= " 						<<UserMsgDropLog[i].UsrPort
		  <<"\tAuthNType= "					<<UserMsgDropLog[i].userAuthNType
		  <<"\tMsgtype= "					<<UserMsgDropLog[i].MsgType
		  <<"\tArrivalTime= " 				<<UserMsgDropLog[i].arrivalTime
          <<"\tProcesstime= "				<<UserMsgDropLog[i].processtime
          <<"\tMsgSeq= "					<<UserMsgDropLog[i].userSeq
          <<"\tMsgSize= "					<<UserMsgDropLog[i].TotalByteReceivLog
          <<"\tErrType= "					<<UserMsgDropLog[i].ErrorType <<"\n";
  		}
  		myMsgLogFile.close();
  	}



// for (unsigned int i= 0 ; i< UserList.size(); i++)
// {
//   recordScalar("AuthnMAN User TotalAuthnReqs PrevSessions-S"+i, (int)ServSecurVec[i].T_ReqCounter*3);
//   recordScalar("AuthnMAN User  TotalAuthnReqs AllSessions-S"+i,(int)ServSecurVec[i].T_ReqCounter*3+ServSecurVec[i].ReqCounter);
//   recordScalar("AuthnMAN User  Total WaitingTime-S"+i, (double) ServSecurVec[i].T_ReqCounter*7*WTime.dbl()+ x);
//    recordScalar("AuthnMAN User  Authentication Protocol State-S"+i, (int)   ServSecurVec[i].AuthNProtocolStateRec);
//   recordScalar("AuthnMAN User  Authentication ServerConnection State-S"+i, (int) ServSecurVec[i].AuthNUserStateRec);
//    if (AuthNUserState==2) recordScalar("AuthnAgent  TotalRequest2Success-S"+i,ServSecurVec[i].T_ReqCounter*3+ServSecurVec[i].ReqCounter);
//    recordScalar("AuthnAgent TotalBytesSend -S"+i, (int)   ServSecurVec[i].TotalBytesSendRec);
//    recordScalar("AuthnAgent TotalByteReceive -S"+i, (int)   ServSecurVec[i].TotalByteReceivRec);
//  if (ServSecurVec[i].ReciMsgtime !=0)recordScalar("AuthnAgent  RTT -S"+i, (ServSecurVec[i].ReciMsgtime-ServSecurVec[i].sendMsgtime).dbl() ) ;
// }




}

//AuthenResponsMsg *AuthNManager::createAuthnRespons(int i)
//{
//
//}
//
