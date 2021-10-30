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

#include "AuthNAgentT.h"
#include "CommonAAM_m.h"
#include "IPAddressResolver.h"


#define MSGKIND_CONNECT  0
#define MSGKIND_SEND     1
#define MSGKIND_START_REQ 2

Define_Module(AuthNAgentT);

inline std::ostream& operator<<(std::ostream& out, const AuthNAgentT::ServLst& d) {
    out << "SourceModule=" << d.ID << " Service Name=" << d.SrvName
        << " Srv Address=" << d.SrvAdress<< "  port=" << d.sPort ;
    return out;
}

AuthNAgentT::AuthNAgentT()
{
  AuthNExptimer = NULL;
  AgentErrMsg = 0;
  ResponMsgByteLength =0;
  CertiClasses.push_back("CorruptedIDCert");
  CertiClasses.push_back("GoldenIDCert");
  CertiClasses.push_back("SilverIDCert");
  CertiClasses.push_back("BronzeIDCert");

}

AuthNAgentT::~AuthNAgentT()
{
  MP = NULL ;
  bat= NULL ;
  BM= NULL ;
  MM= NULL;

  for (unsigned int i=0; i<netServices.size(); i++)
      delete netServices[i];
}

void AuthNAgentT::initialize(int stage)
{
    AAMTCPGenericCliAppBase::initialize();

    if (stage!=5)
      return;

    cDisplayString* display_string = &getParentModule()->getDisplayString();

    Counter = 0 ;
    numRequestsDrop =0 ;
    Authenticated = false;
    AuthNUserState = AuthenIdle; // IDLE State to Start Request Authentication


    const char *token = par("AuthNMANAddr") ;
    if ( strstr (token,"Broadcast")!=NULL)
      AuthnManAddr  = IPAddress::ALLONES_ADDRESS;

    else  AuthnManAddr = IPAddressResolver().resolve(token);

   // AuthnManAddr = IPAddressResolver().resolve(par("AuthNMANAddr"));
   AuthnManPort = par("AuthnManPort");
   localAuthnAgentPort=par("localAuthnAgentPort");
   WTime = par("AWaitInterval");
   timeToStart = par("time_begin");
   msgByteLength=par("messageLength");
   RandomGSeed = par("GeneratorSeed");

   bat = InetSimpleBatteryAccess().getIfExists(); // Battery
   if (!bat)  hostState = "NO Battery"; //   error("Batter is not registered");
   else    hostState = bat->getHostSate();

   BM = BasicMobilityAccess().getIfExists(); // access to mobility module
   if (!BM) error("BasicMobility is not registered");

   BM->Registration(false);

   MM = ManetManagerAccess().getIfExists(); // access to mobility module
   if (!MM)    error("ManetManager is not registered");

   MM->SetManetActive(false);

   display_string->setTagArg("i", 1, "#000000");

   Certif="NOT AVAILABLE";

   rtt  = 0 ;

   AuthNReq = false;

   MP = mainUnitAccess().getIfExists() ;

   if (!MP) error ("Error in Main Unit");

   Certif = MP->getCertFromUnit();

   //chooseCertiClasse();

   WATCH_PTRVECTOR (netServices);
   WATCH(hostState);
   WATCH(Certif);
   WATCH(Authenticated);
   WATCH (AuthNUserState);
   WATCH (AuthNReq );
   WATCH(rtt);
   WATCH(Counter);
   WATCH (numRequestsDrop);
   WATCH (AttribCertif);
   WATCH(timeToStart);
   WATCH (AgentErrMsg);
   WATCH(sendMsgtime);
   WATCH(recMsgtime);


   timeoutMsg = new cMessage("AuthNReqStart",MSGKIND_START_REQ);
   if (timeToStart>=0)
           scheduleAt(timeToStart, timeoutMsg);


   rttVec.setName("Round Trip Time");
   rttVec.enable();

   if (ev.isGUI())
   {
       char buf[40];
       sprintf(buf, "Authentication\nAgent");
       getDisplayString().setTagArg("t",0,buf);
   }


    numRequestsToSend = 0;
    earlySend = false;  // TBD make it parameter

    scheduleAt((simtime_t)par("timeToStart"), timeoutMsg);

    WATCH(numRequestsToSend);
    WATCH(earlySend);
}

void AuthNAgentT::handleMessage(cMessage *msg)
{
	// TODO - Generated method body
}

void AuthNAgentT::sendRequest()
{
     EV << "sending request, " << numRequestsToSend-1 << " more to go\n";

     long requestLength = par("requestLength");
     long replyLength = par("replyLength");
     if (requestLength<1) requestLength=1;
     if (replyLength<1) replyLength=1;

     sendPacket(requestLength, replyLength);
}

void AuthNAgentT::handleTimer(cMessage *msg)
{
    switch (msg->getKind())
    {
        case MSGKIND_CONNECT:
            EV << "starting session\n";
            connect(); // active OPEN

            // significance of earlySend: if true, data will be sent already
            // in the ACK of SYN, otherwise only in a separate packet (but still
            // immediately)
            if (earlySend)
                sendRequest();
            break;

        case MSGKIND_SEND:
           sendRequest();
           numRequestsToSend--;
           // no scheduleAt(): next request will be sent when reply to this one
           // arrives (see socketDataArrived())
           break;
    }
}

void AuthNAgentT::socketEstablished(int connId, void *ptr)
{
    AAMTCPGenericCliAppBase::socketEstablished(connId, ptr);

    // determine number of requests in this session
    numRequestsToSend = (long) par("numRequestsPerSession");
    if (numRequestsToSend<1) numRequestsToSend=1;

    // perform first request if not already done (next one will be sent when reply arrives)
    if (!earlySend)
        sendRequest();
    numRequestsToSend--;
}

void AuthNAgentT::socketDataArrived(int connId, void *ptr, cPacket *msg, bool urgent)
{
    AAMTCPGenericCliAppBase::socketDataArrived(connId, ptr, msg, urgent);

    if (numRequestsToSend>0)
    {
        EV << "reply arrived\n";
        timeoutMsg->setKind(MSGKIND_SEND);
        scheduleAt(simTime()+(simtime_t)par("thinkTime"), timeoutMsg);
    }
    else
    {
        EV << "reply to last request arrived, closing session\n";
        close();
    }
}

void AuthNAgentT::socketClosed(int connId, void *ptr)
{
    AAMTCPGenericCliAppBase::socketClosed(connId, ptr);

    // start another session after a delay
    timeoutMsg->setKind(MSGKIND_CONNECT);
    scheduleAt(simTime()+(simtime_t)par("idleInterval"), timeoutMsg);
}

void AuthNAgentT::socketFailure(int connId, void *ptr, int code)
{
    AAMTCPGenericCliAppBase::socketFailure(connId, ptr, code);

    // reconnect after a delay
    timeoutMsg->setKind(MSGKIND_CONNECT);
    scheduleAt(simTime()+(simtime_t)par("reconnectInterval"), timeoutMsg);
}


