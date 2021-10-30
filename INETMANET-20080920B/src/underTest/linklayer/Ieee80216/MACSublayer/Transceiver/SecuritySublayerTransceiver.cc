
#include "SecuritySublayerTransceiver.h"
#include "PhyControlInfo_m.h"

Define_Module(SecuritySublayerTransceiver);

SecuritySublayerTransceiver::SecuritySublayerTransceiver()
{

}

SecuritySublayerTransceiver::~SecuritySublayerTransceiver()
{

}

void SecuritySublayerTransceiver::initialize()
{
    commonPartGateIn  = findGate("commonPartGateIn");
    commonPartGateOut = findGate("commonPartGateOut");
    transceiverRadioGateIn  = findGate("transceiverRadioGateIn");
    transceiverRadioGateOut = findGate("transceiverRadioGateOut");
}

void SecuritySublayerTransceiver::handleMessage(cMessage *msg)
{
    if (msg->getArrivalGateId() == commonPartGateIn)
    {
	send(msg,transceiverRadioGateOut);
    }
    else if (msg->getArrivalGateId() == transceiverRadioGateIn)
    {
	send(msg,commonPartGateOut);
    }
    else
    {
    ev << "nothing" << endl;
    }

}




