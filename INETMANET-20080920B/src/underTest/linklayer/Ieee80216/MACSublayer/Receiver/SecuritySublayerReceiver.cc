
#include "SecuritySublayerReceiver.h"
#include "PhyControlInfo_m.h"

Define_Module(SecuritySublayerReceiver);

SecuritySublayerReceiver::SecuritySublayerReceiver()
{

}

SecuritySublayerReceiver::~SecuritySublayerReceiver()
{

}

void SecuritySublayerReceiver::initialize()
{
    receiverRadioGateIn  = findGate("receiverRadioGateIn");
    receiverRadioGateOut = findGate("receiverRadioGateOut");
    commonPartGateIn  = findGate("commonPartGateIn");
    commonPartGateOut = findGate("commonPartGateOut");
}

void SecuritySublayerReceiver::handleMessage(cMessage *msg)
{
//	ev << "message eingetroffen an ";

  if (msg->getArrivalGateId() == receiverRadioGateIn )
    {
//	  ev << "receiverRadioGateIn: "<< msg << "\n";
	send(msg, commonPartGateOut);
    }
  else if (msg->getArrivalGateId() == commonPartGateIn )
    {
//	  ev << "commonPartGateIn: "<< msg << "\n";
	send(msg, receiverRadioGateOut);
    }
  else
    {
    ev << "nothing" << endl;
    }

}




