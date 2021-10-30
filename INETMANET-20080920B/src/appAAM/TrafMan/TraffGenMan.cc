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

#include "TraffGenMan.h"
#include "IPControlInfo.h"
#include "IPv6ControlInfo.h"
#include "IPAddressResolver.h"


Define_Module(TraffGenMan);

void TraffGenMan::initialize(int stage)
{
	// TODO - Generated method body

	if (!par("selfActivation"))
		return;

	if (stage!=3)
		return;

	TotalBytesRecv=TotalBytesSent=numReceived= numSent= 0;

	//   	    mLowergateIn            = findGate("lowergateIn");
	//		mLowergateOut           = findGate("lowergateOut");

	ev << "initializing TrafGen..." << endl;

	const char *destAddrs = par("trafDest").stringValue();

	cStringTokenizer tokenizer(destAddrs);
	const char *token;
	while ((token = tokenizer.nextToken())!=NULL)
		destAddresses.push_back(IPAddressResolver().resolve(token));

	if (destAddresses.empty())
		return;

	std::stringstream TimerNam1,TimerNam2 ;

	TimerNam1<<"SendTraffMsg-"<<getParentModule()->getName();
	TimerNam2<<"onOffSwitch-"<<getParentModule()->getName();

	mpSendMessage           = new cMessage(TimerNam1.str().c_str());
	mpOnOffSwitch           = new cMessage(TimerNam2.str().c_str());

	if (par("isSink"))
	{
		WATCH(numReceived);
		WATCH(TotalBytesRecv);
		getDisplayString().setTagArg("i",0,"block/sink");
		getParentModule()->getDisplayString().setTagArg("i2",0,"block/sink_vs");

		char buf[40];
		sprintf(buf, "SP-Sink");
		getParentModule()->getDisplayString().setTagArg("t",0,buf);

		// no traffic is to be sent by this node
		return;
	}

	// read all the parameters from the xml file
	if (FirstPacketTime() < 0)
	{
		// no traffic is to be sent by this node
		return;
	}

	// the onOff-traffic timer is scheduled
	// only if the parameters for onOff-traffic are present
	if ((OnIntv() > 0) && (OffIntv() > 0))
	{
		scheduleAt(simTime() + OnIntv(), mpOnOffSwitch);
		mOnOff = TRAFFIC_ON;
	}

	// if the offInterArrivalTime attribute is present: packets are sent during the off interval too
	if ((mOnOff == TRAFFIC_ON) && (OffInterDepartureTime()>0))
	{
		mOffTraffic = true;
	}
	else
	{
		mOffTraffic = false;
	}

	// if the onIdenticalTrafDest attribute is present: packets are
	// sent to the same destination during on intervals
	if (mOnOff == TRAFFIC_ON)
	{
		mOnIdenticalDest = par ("onIdenticalTrafDest");
	}
	else
	{
		mOnIdenticalDest = false;
	}

	mDestination = chooseDestAddr();



	if (mOnIdenticalDest)
	{
		mCurrentOnDest = mDestination;;
	}

	if (FirstPacketTime() < 0)
		error("TrafficGenerator, attribute firstPacketTime: time < 0 is not legal");
	scheduleAt(simTime() + FirstPacketTime(), mpSendMessage);

	WATCH(mOnOff);
	WATCH(numSent);
	WATCH(TotalBytesSent);
	WATCH_VECTOR(destAddresses);

	char buf1[40];
	sprintf(buf1, "SU-Source");
	getParentModule()->getDisplayString().setTagArg("t",0,buf1);
}

void TraffGenMan::handleMessage(cMessage *msg)
{
	// TODO - Generated method body

	if (msg->isSelfMessage())
	    {
			handleSelfMsg(msg);
		}
	    else
	    {
			handleLowerMsg(msg);
	    }

	    if (ev.isGUI())
	    {
		 const char * x;
		 if (!par("isSink"))  x  = (!mOnOff? "ON":"OFF");
		 else x="SinkON";

		 char buf[40];
		 sprintf(buf, "rcvd: %d pks\nsent: %d pks \n State:%s", numReceived, numSent,x);
		 getDisplayString().setTagArg("t",0,buf);
	    }
}

/**
 * Handles self messages (i.e. timer)
 * Two timer types:
 * - mpOnOffSwitch for switching between the on and off state of the generator
 * - mpSendMessage for sending a new message
 * @param pMsg a pointer to the just received message
 */
void TraffGenMan::handleSelfMsg(cMessage* apMsg)
{
	// handle the switching between on and off periods of the generated traffic
	// the values for offIntv, onIntv and interDepartureTime are evaluated each
    // time, in case a distribution function is specified
	if (apMsg == mpOnOffSwitch)
    {
		if (mOnOff == TRAFFIC_ON)
        {
			ev << "switch traffic off" << endl;
			mOnOff = TRAFFIC_OFF;
			scheduleAt(simTime() + OffIntv(), mpOnOffSwitch);
			cancelEvent(mpSendMessage);
			if (mOffTraffic)
			{
				scheduleAt(simTime() + OffInterDepartureTime(), mpSendMessage);
			}
		}
        else if (mOnOff == TRAFFIC_OFF)
        {
			ev << "switch traffic on" << endl;
			mOnOff = TRAFFIC_ON;
			cancelEvent(mpSendMessage);
			scheduleAt(simTime() + OnIntv(), mpOnOffSwitch);
			//scheduleAt(simTime() + InterDepartureTime(), mpSendMessage);

			scheduleAt(simTime()+FirstPacketTime(), mpSendMessage);


			// if identical traffic destinations inside the on interval are
			// required, calculate the destination now!
			if (!mOnIdenticalDest)
			  mCurrentOnDest = chooseDestAddr();

		}


	}
    // handle the sending of a new message
    else if (apMsg == mpSendMessage)
    {
		cPacket* p_traffic_msg = new cPacket("TrafGen Message");

		// calculate the destination and send the message:

		if (mOnOff == TRAFFIC_ON && mOnIdenticalDest)
		{
			ev << "sending message to " << mCurrentOnDest.str() << endl;
			SendTraf(p_traffic_msg, mCurrentOnDest);
		}
		else
		{
			IPvXAddress dest = chooseDestAddr();
			ev << "sending message to " << dest.str() << endl;
			SendTraf(p_traffic_msg, dest);
		}

		// schedule next event
		// interDepartureTime is evaluated each time,
        // in case a distribution function is specified
		if (mOffTraffic && mOnOff == TRAFFIC_OFF)
			scheduleAt(simTime() + OffInterDepartureTime(), mpSendMessage);
		else
			scheduleAt(simTime() + InterDepartureTime(), mpSendMessage);
    }
}

void TraffGenMan::SendTraf(cPacket* cPK, IPvXAddress DistHodt)
{

    cPK->setByteLength(PacketSize());

    if (!DistHodt.isIPv6())
    {
        // send to IPv4
        IPControlInfo *controlInfo = new IPControlInfo();
        controlInfo->setDestAddr(DistHodt.get4());
        controlInfo->setProtocol(par("Protocol"));
        cPK->setControlInfo(controlInfo);

        EV << "Sending packet: ";

        printPacket(cPK);

        TotalBytesSent += cPK->getByteLength();

        send(cPK, "lowergateOut");
    }
    else error("Wrong IP");

  numSent++;
}

IPvXAddress TraffGenMan::chooseDestAddr()
{
    int k = intrand(destAddresses.size());
    return destAddresses[k];
}

void TraffGenMan::finish()
{
	cancelEvent(mpSendMessage);
	delete mpSendMessage;
	cancelEvent(mpOnOffSwitch);
	delete mpOnOffSwitch;

	if (par("isSink"))
	{
		recordScalar("TraffGenMan TrafficRecv", numReceived);
		recordScalar("TraffGenMan TotalBytesReceived", TotalBytesRecv);
	}
	else
	{
		recordScalar("TraffGenMan TrafficSent", numSent);
		recordScalar("TraffGenMan TotalBytesSent", TotalBytesSent);
	}

}

void TraffGenMan::printPacket(cPacket *msg)
{
    IPvXAddress src, dest;
    int protocol = -1;
    if (dynamic_cast<IPControlInfo *>(msg->getControlInfo())!=NULL)
    {
        IPControlInfo *ctrl = (IPControlInfo *)msg->getControlInfo();
        src = ctrl->getSrcAddr();
        dest = ctrl->getDestAddr();
        protocol = ctrl->getProtocol();
    }
    else if (dynamic_cast<IPv6ControlInfo *>(msg->getControlInfo())!=NULL)
    {
        IPv6ControlInfo *ctrl = (IPv6ControlInfo *)msg->getControlInfo();
        src = ctrl->getSrcAddr();
        dest = ctrl->getDestAddr();
        protocol = ctrl->getProtocol();
    }

    ev  << msg << endl;
    ev  << "Payload length: " << msg->getByteLength() << " bytes" << endl;
    if (protocol!=-1)
        ev  << "src: " << src << "  dest: " << dest << "  protocol=" << protocol << "\n";
}

/**
 * @return The time when the first packet should be scheduled
 */
double TraffGenMan::FirstPacketTime()
{
    return par("firstPacketTime").doubleValue();
}

/**
 * @return The time between two subsequent packets
 *
 * WARNING: the return value should not be buffered, as it can change with each
 *    call in case a distribution function is specified as simulation parameter!
 */
double TraffGenMan::InterDepartureTime()
{
    return par("interDepartureTime").doubleValue();
}

/**
 * @return The packet length
 *
 * WARNING: the return value should not be buffered, as it can change with each
 *    call in case a distribution function is specified as simulation parameter!
 */
long TraffGenMan::PacketSize()
{
    return par("packetSize").longValue();
}

double TraffGenMan::OnIntv(){
	return par("onLength").doubleValue();
}

double TraffGenMan::OffIntv()
{
	return par("offLength").doubleValue();
}

double TraffGenMan::OffInterDepartureTime()
{
	return par("offInterDepartureTime").doubleValue();
}

void TraffGenMan::handleLowerMsg(cMessage* apMsg)
{
	// only relevant for the sink

    EV << "Received packet: ";

    cPacket * tPK = check_and_cast<cPacket *>(apMsg);

    printPacket(tPK);

	delete tPK;

	numReceived++;
	TotalBytesRecv += tPK->getByteLength();
}

void TraffGenMan::TriggerTraffic(const char * SinkName, bool act)
{
	Enter_Method ("TriggerTraffic(%s,%s)",SinkName,act? "True":"False");

	if(mpSendMessage->isScheduled() && mpSendMessage)
	{
		cancelEvent(mpSendMessage);
		delete mpSendMessage;
	}

	if(mpOnOffSwitch->isScheduled() && mpOnOffSwitch)
	{
		cancelEvent(mpOnOffSwitch);
		delete mpOnOffSwitch;
	}



   if(act && !par("isSink"))
	{
	   mCurrentOnDest = IPAddressResolver().resolve(SinkName);
	   destAddresses.push_back(mCurrentOnDest);

		std::stringstream TimerNam1,TimerNam2 ;

		TimerNam1<<"SendTraffMsg-"<<getParentModule()->getName();
		TimerNam2<<"onOffSwitch-"<<getParentModule()->getName();

		mpSendMessage           = new cMessage(TimerNam1.str().c_str());
		mpOnOffSwitch           = new cMessage(TimerNam2.str().c_str());

		scheduleAt(simTime() + OnIntv(), mpOnOffSwitch);

		mOnOff = TRAFFIC_ON;

		// if the offInterArrivalTime attribute is present: packets are sent during the off interval too
		if ((mOnOff == TRAFFIC_ON) && (OffInterDepartureTime()>0))
		mOffTraffic = true; else mOffTraffic = false;

		scheduleAt(simTime() + FirstPacketTime(), mpSendMessage);

	}
}
