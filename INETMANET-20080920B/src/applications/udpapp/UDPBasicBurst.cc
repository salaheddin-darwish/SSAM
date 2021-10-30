//
// Copyright (C) 2000 Institut fuer Telematik, Universitaet Karlsruhe
// Copyright (C) 2007 Universidad de Málaga
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
//


#include <omnetpp.h>
#include "UDPBasicBurst.h"
#include "UDPControlInfo_m.h"
#include "IPAddressResolver.h"



Define_Module(UDPBasicBurst);

int UDPBasicBurst::counter;

static bool selectFunction(cModule *mod, void *name)
{
  return strstr (mod->getName(),(char *)name)!=NULL;
}

void UDPBasicBurst::initialize(int stage)
{
    // because of IPAddressResolver, we need to wait until interfaces are registered,
    // address auto-assignment takes place etc.
    if (stage!=3)
        return;

    counter = 0;
    numSent = 0;
    numReceived = 0;
    numDeleted=0;
    meanDelay = 0;
    limitDelay = par("limitDelay");
    endSend = par("time_end");
    nextPkt = 0;
    timeBurst = 0;

    randGenerator = par("rand_generator");

    batt = InetSimpleBatteryAccess().getIfExists();

         if (!batt) hostState = "NO Battery";
         else hostState = batt->getHostSate();
   //
  //  WATCH (st);  // salah
    WATCH(numSent);
    WATCH(numReceived);
    WATCH(numDeleted);
    ev<<"************************ "<<hostState<<" **************************************"<<endl;
    WATCH(hostState);
    localPort = par("localPort");
    if (localPort!=-1)
        bindToPort(localPort);

    destPort = par("destPort");

    msgByteLength = par("messageLength").longValue();

    const char *destAddrs = par("destAddresses");
    cStringTokenizer tokenizer(destAddrs);
    const char *token;
    const char * random_add;


    double msgFrec = (double)par("messageFreq");
    if (msgFrec==-1)
        isSink=true;
    else
        isSink=false;

    offDisable=false;
    if ((double)par("time_off")==0)
        offDisable=true;

    while ((token = tokenizer.nextToken())!=NULL)
    {
        if ((random_add= strstr (token,"random"))!=NULL)
        {
           const char *leftparenp = strchr(random_add,'(');
           const char *rightparenp = strchr(random_add,')');
           std::string nodetype;
           nodetype.assign(leftparenp+1, rightparenp-leftparenp-1);

           // find module and check protocol
           cTopology topo;
           if ((random_add= strstr (token,"random_name"))!=NULL)
           {
              char name[30];
              strcpy (name,nodetype.c_str());
              topo.extractFromNetwork(selectFunction,name);
              for (int i=0; i<topo.getNumNodes(); i++)
              {
                  cTopology::Node *node = topo.getNode(i);
                  if (strstr (this->getFullPath().c_str(),node->getModule()->getFullPath().c_str())==NULL)
                  {
                     destAddresses.push_back(IPAddressResolver().resolve(node->getModule()->getFullPath().c_str()));
                  }
              }
           }
           else
           {
             // topo.extractByModuleType(nodetype.c_str(), NULL);
              topo.extractByNedTypeName(cStringTokenizer(nodetype.c_str()).asVector());
              for (int i=0; i<topo.getNumNodes(); i++)
              {
                  cTopology::Node *node = topo.getNode(i);
                  if (strstr (this->getFullPath().c_str(),node->getModule()->getFullPath().c_str())==NULL)
                      destAddresses.push_back(IPAddressResolver().resolve(node->getModule()->getFullPath().c_str()));
              }
           }
        }
        else if ( strstr (token,"Broadcast")!=NULL)
           destAddresses.push_back(IPAddress::ALLONES_ADDRESS);
        else
           destAddresses.push_back(IPAddressResolver().resolve(token));
    }

    if (destAddresses.empty())
    {
        isSink=true;
        return;
    }

    activeBurst= par("activeBurst");
    if (!activeBurst) // new burst
    {
    	destAddr = chooseDestAddr();
    }

    if ((double)par("time_begin") ==-1)
        scheduleAt(0, &timerNext);
    else
        scheduleAt(par("time_begin"), &timerNext);
}

IPvXAddress UDPBasicBurst::chooseDestAddr()
{
   // int k = intrand(destAddresses.size());
    int k =genk_intrand(randGenerator,destAddresses.size());
    return destAddresses[k];
}


cPacket *UDPBasicBurst::createPacket()
{
    char msgName[32];
    sprintf(msgName,"UDPBasicAppData-%d", counter++);
    msgByteLength = par("messageLength").longValue() / 8;
    cPacket *payload = new cPacket(msgName);
    payload->setByteLength(msgByteLength);
    payload->addPar("sourceId") = getId();
    payload->addPar("msgId")=numSent;
    return payload;
}

void UDPBasicBurst::sendPacket()
{
    cPacket *payload = createPacket();
    IPvXAddress destAddr = chooseDestAddr();
    sendToUDP(payload, localPort, destAddr, destPort);
    numSent++;
}


void UDPBasicBurst::sendToUDPDelayed(cPacket *msg, int srcPort, const IPvXAddress& destAddr, int destPort,double delay)
{
    // send message to UDP, with the appropriate control info attached
    msg->setKind(UDP_C_DATA);

    UDPControlInfo *ctrl = new UDPControlInfo();
    ctrl->setSrcPort(srcPort);
    ctrl->setDestAddr(destAddr);
    ctrl->setDestPort(destPort);
    msg->setControlInfo(ctrl);
    msg->setTimestamp(delay);

    EV << "Sending packet: ";
    printPacket(msg);

    sendDelayed (msg,delay-simTime(), "udpOut");
}

void UDPBasicBurst::handleMessage(cMessage *msg)
{

    if  (batt) hostState = batt->getHostSate();
    if (hostState =="ACTIVE" || hostState=="NO Battery")
      {

        if (msg->isSelfMessage())
          {
                      if ((endSend==0) || (simTime()< endSend))
                      {
                              // send and reschedule next sending
                              if (!isSink) //if the node is sink it don't generate messages
                                      generateBurst();
                      }
          }
          else
          {
              // process incoming packet
              processPacket(PK(msg));
          }
      }
    else
      {

       // std::string x =msg->getFullPath();

   //     error( "msg is deleted because of deplated battery the msg is '%s' '%s'", x.c_str(), msg->getClassName());


      // cMessage  * c1 = check_and_cast<cMessage *> (msg);
        if (pktDelay) delete pktDelay;
        if (timerNext.isScheduled()) cancelEvent(&timerNext);


     //  error( "msg is deleted because of deplated battery");
       //   endSimulation();


        // cancelAndDelete(msg);

      }

    if (ev.isGUI())
    {
        char buf[40];
        sprintf(buf, "rcvd: %d pks\nsent: %d pks", numReceived, numSent);
        getDisplayString().setTagArg("t",0,buf);
    }
}


void UDPBasicBurst::processPacket(cPacket *msg)
{
    if (msg->hasPar("sourceId"))
    {
    // duplicate control
       int moduleId = (int) msg->par("sourceId");
       int msgId = (int) msg->par("msgId");
       SurceSequence::iterator i;
       i = sourceSequence.find(moduleId);
       if (i!=sourceSequence.end())
       {
           if(i->second >= msgId)
           {
              EV << "Duplicated packet: ";
              printPacket(msg);
              delete msg;
              numDeleted++;
              return;
           }
           else
               i->second = msgId;
       }
       else
          sourceSequence[moduleId] = msgId;

    }
	if (limitDelay>=0)
		if (simTime()-msg->getTimestamp()>limitDelay)
		{
			EV << "Old packet: ";
			printPacket(msg);
			delete msg;
			numDeleted++;
			return;
		}

    EV << "Received packet: ";
    printPacket(msg);
    pktDelay->collect(simTime()-msg->getTimestamp());
//    meanDelay += (msg->getTimestamp()-simTime());
    delete msg;

    numReceived++;
}


void UDPBasicBurst::generateBurst()
{
	simtime_t pkt_time;
	simtime_t now = simTime();
	if (timeBurst<now && activeBurst) // new burst
	{
		timeBurst = now + par("burstDuration");
		destAddr = chooseDestAddr();
	}

	if (nextPkt<now)
	{
		nextPkt = now;
	}

	cPacket *payload = createPacket();
	payload->setTimestamp();
	sendToUDP(payload, localPort, destAddr, destPort);
	numSent++;
	// Next pkt
	nextPkt +=  par("messageFreq");
	if (nextPkt>timeBurst && activeBurst)
	{
		if (!offDisable)
		{
			pkt_time = now+ par("time_off");
			if (pkt_time>nextPkt)
				nextPkt=pkt_time;
		}
	}

	pkt_time = nextPkt+ par("message_freq_jitter");
	if (pkt_time < now)
	{
		opp_error("UDPBasicBurst bad parameters: next pkt time in the past ");
	}
	scheduleAt(pkt_time, &timerNext);

}


void UDPBasicBurst::finish()
{


    simtime_t t = simTime();
    if (t==0) return;

    recordScalar("Total send", numSent);
    recordScalar("Total received", numReceived);
    recordScalar("Total deleted", numDeleted);
//    recordScalar("Mean delay", meanDelay/numReceived);
    recordScalar("Mean delay", pktDelay->getMean());
    recordScalar("Min delay", pktDelay->getMin());
    recordScalar("Max delay", pktDelay->getMax());
    recordScalar("Deviation delay", pktDelay->getStddev());
    delete pktDelay;
	pktDelay = NULL;
}
