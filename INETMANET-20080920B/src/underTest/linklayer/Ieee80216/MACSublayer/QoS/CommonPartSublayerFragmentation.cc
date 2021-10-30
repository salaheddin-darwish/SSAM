#include "CommonPartSublayerFragmentation.h"
#include "PhyControlInfo_m.h"
#include <stdio.h>
#include <omnetpp.h>

Define_Module(CommonPartSublayerFragmentation);


CommonPartSublayerFragmentation::CommonPartSublayerFragmentation() {

}

CommonPartSublayerFragmentation::~CommonPartSublayerFragmentation() {

}

/**
 * WICHTIG:
 * Nachrichten auf Basic, Broadcast und Initial Ranging Connections dürfen NIE gepackt oder fragmentiert werden!!
 * (siehe Standard --> Management-Messages
 *
 */


void CommonPartSublayerFragmentation::initialize() {
	commonPartGateOut = findGate("commonPartGateOut");
	commonPartGateIn = findGate("commonPartGateIn");
	securityGateIn = findGate("securityGateIn");
	securityGateOut = findGate("securityGateOut");
}

void CommonPartSublayerFragmentation::handleMessage( cMessage *msg ) {
	//ev << "message eingetroffen an ";
	//higher layer message in transceiver
	if ( msg->getArrivalGateId() == commonPartGateIn ) {
		send(msg, securityGateOut);
	}
	//lower layer message in receiver
	else if ( msg->getArrivalGateId() == securityGateIn ) {
		ev << "securityGateIn\n";
		send(msg, commonPartGateOut);
	}
	//higher layer message in receiver
	else if ( msg->getArrivalGateId() == commonPartGateIn ) {
		ev << "commonPartGateIn\n";
		send(msg, securityGateOut);
	}

}
