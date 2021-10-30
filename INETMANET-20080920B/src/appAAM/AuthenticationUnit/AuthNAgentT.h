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

#ifndef __AUTHNAGENTT_H__
#define __AUTHNAGENTT_H__

#include <omnetpp.h>
#include "AAMTCPGenericCliAppBase.h"
#include "InetSimpleBattery.h"
#include "IPvXAddress.h"
#include "ChannelControl.h"
#include "BasicMobility.h" // test
#include "ManetManager.h"
#include "mainUnit.h"


/**
 * TODO - Generated class
 *
 */
class INET_API AuthNAgentT : public AAMTCPGenericCliAppBase
{

public:
      enum AuthNUserStates
       {
         AuthenIdle , // not yet request to authentication
         AuthenInProgress , // already requested and waiting a reply
         SucAuthNUser,// successful authentication
         UnscAuthNUser, // Unsccessful authentication
         FailedAuthN, // fail to reach the authenticator after 3 tries
       } ;

      AuthNUserStates AuthNUserState;
      std::vector <std::string> CertiClasses ;
     // std::vector <uint8_t> AuthnBlock;

    struct ServLst
     {
       int ID ; // id module
       opp_string SrvName;
       opp_string SrvAdress ;  //   IPvXAddress SrvAdress ;
       int sPort;
     };

     IPvXAddress AuthnManAddr;
     std::vector<IPvXAddress> AuthnManAddresses;

     cMessage *AuthNExptimer;
     typedef std::vector<ServLst *> SrvLst;
     SrvLst netServices;


     InetSimpleBattery *bat ;
     BasicMobility *BM ;
     ManetManager *MM;
     mainUnit *MP ;

     // Scalar Variables
     std::string hostState ;// salah
     int msgByteLength;
     int ResponMsgByteLength ;
     int AuthnManPort,localAuthnAgentPort;
     simtime_t WTime;
     simtime_t timeToStart;
     simtime_t sendMsgtime;
     simtime_t recMsgtime;
     simtime_t rtt ;
     int RandomGSeed ;
     bool Authenticated;
     bool AuthNReq;
     std::string Certif ;
     opp_string AttribCertif ;
     int Counter;
     int numRequestsDrop;
     int AgentErrMsg;

     cOutVector rttVec;

     cMessage *timeoutMsg;
     bool earlySend;  // if true, don't wait with sendRequest() until established()
     int numRequestsToSend; // requests to send in this session



  protected:

    /** Utility: sends a request to the server */
    virtual void sendRequest();
      /**
      * Initialization. Should be redefined to perform or schedule a connect().
      */
     virtual void initialize(int stage);

     /**
      * For self-messages it invokes handleTimer(); messages arriving from TCP
      * will get dispatched to the socketXXX() functions.
      */
     virtual void handleMessage(cMessage *msg);


     /** Redefined. */
     virtual void handleTimer(cMessage *msg);

     /** Redefined. */
     virtual void socketEstablished(int connId, void *yourPtr);

     /** Redefined. */
     virtual void socketDataArrived(int connId, void *yourPtr, cPacket *msg, bool urgent);

     /** Redefined to start another session after a delay. */
     virtual void socketClosed(int connId, void *yourPtr);

     /** Redefined to reconnect after a delay. */
     virtual void socketFailure(int connId, void *yourPtr, int code);


  public:
    AuthNAgentT() ;
    virtual ~AuthNAgentT();

};

#endif
