
#include "ConvergenceSublayerTransceiver.h"
#include "PhyControlInfo_m.h"

Define_Module(ConvergenceSublayerTransceiver);

ConvergenceSublayerTransceiver::ConvergenceSublayerTransceiver()
{
    endTransmissionEvent = NULL;
}

ConvergenceSublayerTransceiver::~ConvergenceSublayerTransceiver()
{
    cancelAndDelete(endTransmissionEvent);
}

void ConvergenceSublayerTransceiver::initialize()
{
	higherLayerGateIn = findGate("higherLayerGateIn");
	commonPartGateOut = findGate("commonPartGateOut");

}

void ConvergenceSublayerTransceiver::handleMessage(cMessage *msg)
{	
    if (msg->arrivedOn(higherLayerGateIn))
    {
    	ev << "\n\nMessage arrived on ConvergenceSublayerTransceiver! ==> " << msg;
    	ev << "Forwarding...";
    	send(msg,"commonPartGateOut");
    }
    
}




