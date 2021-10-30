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

#ifndef __AUTHNMANAGER_H__
#define __AUTHNMANAGER_H__

#include <omnetpp.h>
#include "UDPAppBase.h"
#include "InetSimpleBattery.h"
#include  "IPvXAddress.h"
#include "CommonAAM_m.h"
#include "mainUnit.h"

#define Verification_Timer  0
#define Protocol_Process_Timer 1
#define Req_Release_Timer 2
#define AttribCert_Proccess_Timer 3
/**
 * TODO - Generated class
 */
class INET_API AuthNManager : public UDPAppBase
{

public:

  enum AuthNProtocolStates
  {
    State_Msg1 =1 ,
    State_Msg2 =2 ,
    State_Msg3 =3,
    State_Data =4,
    State_Error =5,
    State_End =6,
    State_DASReq =7,
    State_DAS_END = 8
  } ;

 struct AttrProcess
  {
    int UsrName;
    IPvXAddress UsrAddr;
    int UPort;
    int cId;
  //  std::string AttrCert;
    bool AuthnSt;
  };

  struct mServicesList
 {
   int ID ; // id module
   opp_string ServiceName;
   opp_string ServiceAddress ;
   int ServicePort;
   int Clss ;
 };

  struct usrServList
 {
   int ID; // id module
   opp_string ServiceName;
   opp_string ServiceAddress;
   int ServicePort;

 };

struct AttrCertLst
  {
    int cId;
    std::string RootCert;
    std::string ThresholdCert ;
    std::string DelegateCert ;
    volatile double procTime ; // processing to create this type of Certificate
  };

struct UserRecord
{
   int UserName;
   IPvXAddress UserAddr;
   int UsrPort;
   int ServerIndx;

   int userAuthNType;
   int userNonceVal ;
   int userSeq;
   int ServerNonceVal ;
   int ServerSeqVal ;

   AuthNProtocolStates AuthNProtocolStateSrv ;
   AAMMessageType currentMsgType ;

   int TotalBytesSendSrv ;
   int TotalByteReceivSrv ;

   std::string IdCert ;
   std::string RootAttribCertificate;
   std::string ThresAttribCertificate;
   std::string DelegAttribCertificate;
   int AcID ;
   simtime_t AttrProcDelay ;
   simtime_t TTL ;

   double TrustLevel; // Percentage
   bool AuthnState; // Identity Certificate is Valid
   bool AuthnProcessInProgress ;
   bool AuthnCompleted;
   bool DASReq ;
   int  AttrCertCreated ; // 0 not created 1 In progress  2 created
   int  AuthNAtmpt;
   int  DropAuthN;
   int	AuthNCompAtmpt;
   int  SentSrvListSize ;
   int  DASReqNum ;


   cMessage * TimerToLiveTimer ;
   cMessage * URProcessTimer;
   UserRecord () { TTL=0 ;SentSrvListSize =0; userNonceVal =0 ; ServerNonceVal=0; ServerSeqVal=0; userSeq =0;
                   AuthNAtmpt=0;AuthNCompAtmpt=0; DropAuthN =0; TotalBytesSendSrv=0; TotalByteReceivSrv =0;
                   TimerToLiveTimer=NULL;URProcessTimer=NULL ;AuthnCompleted=false;DASReq =false; DASReqNum =0;}
};


struct UserMsgLog
{
   int UserName;
   IPvXAddress UserAddr;
   int UsrPort;

   int userAuthNType;
   int MsgType ;
   int userSeq ;
   simtime_t arrivalTime ;
   simtime_t processtime ;

   int TotalByteReceivLog ;
   int ErrorType ;
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

  std::vector<UserMsgLog> UserMsgDropLog ;
  std::vector <AuthnType> MsgProtocolProfiles;

   cMessage *AttrCertProcessTimer;
   cMessage *VerificationTimer;

   // Scalar Variables
   simtime_t verifTimeDuration;
   simtime_t URprocessTimeDuration;
   simtime_t StartTime;
   simtime_t EndTime;
   simtime_t LastTime;
   simtime_t BusySystemTimeSt;
   simtime_t BusySystemTimeSt1;
   simtime_t TotaltimeSytemInWorking ;
   simtime_t TotaltimeSytemInWorking1 ;

   double DelProTemp ;

   bool startSign;
   int LocalAuthnManagerPort;
   int UsersNum,SucAuth, UnscAuth ;
   bool servicesListChanged ;
   int TotalServicesNumber ;
   int respMsgLengthAK ;
   int respMsgLengthNoAK ;
   int MaxThreads ;
   int currentReqVerfThreads;
   int currentAtrrCreaThreads;
   int numCertiReqsDropped ;
   int TotalAuthNRequest;
   int TotalAuthNResponse;
   int  ErrMsg ; // counter for error messages
   int  ThroughputCounter;
   int  TotalReceivedBytes;
   int  TotalSentBytes;
   int AuthorityServerType ;
   double DelegatedAttributeCertProcess;
   int SrvTypeOptions ; // Test Case
   std::string Certif ;

   bool DasSet;


   std::string hostState ;// salah
   InetSimpleBattery *bat ;
   mainUnit *MU;

   // Statistics
   cOutVector endToEndDelayVec;
   cOutVector qlenVec;
   cOutVector dropVec;
   cOutVector ThroughputVec ;

   typedef UserRecord *UserRecordRef;
   typedef AttrCertLst *AttrCertLstRef;
   typedef mServicesList *mServicesListRef;
   typedef AttrProcess *AProcess;
   typedef usrServList *UsrSrvLst;

   cQueue reqBuffer ;
   int MaxServicesCapacityBuffer ;
   int numReqsDropped ;
   cMessage * startServicingTrigger ;
   cMessage * ProcessTimer ;


    // Available Services List in Network maintained by Coordinator

     typedef std::vector<mServicesList> SrvLs;
     SrvLs cNetServices;

       // Attribute Certificates List for network services available for the authorisation phase
      typedef std::vector<AttrCertLst> CerLs;
      CerLs cCertiLst;

      //  Registration to users who request authentication Manager
      typedef std::map<int,UserRecord> UsrLs;
      UsrLs UserList;

      std::map<int, const cMessage *> ReqVerfThreads ;
      std::map<int,const cMessage *> ProtProcessThreads;



 protected:

   virtual void initialize(int stage);
   virtual void handleMessage(cMessage *msg);
   virtual int numInitStages() const {return 4;}


public:

  virtual void verifyAuthnRequest(cPacket *msg);
  virtual void processUserRequest(cMessage *msg);
  virtual AttrCertLstRef getAttribCert (const std::string IdCertificate);
  virtual void SendRespToUser(cMessage *msg);
  virtual void processACData(int i, const std::string);

  //void sendToUDP(cPacket *msg, int srcPort, const IPvXAddress& destAddr, int destPort);
  virtual void finish();
  AuthNManager();
  ~AuthNManager();



};

#endif
