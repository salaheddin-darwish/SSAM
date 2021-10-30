//
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


#include "AAMTCPGenericCliAppBase.h"
#include "IPAddressResolver.h"
#include "GenericAppMsg_m.h"


void AAMTCPGenericCliAppBase::initialize()
{
    numSessions = numBroken = packetsSent = packetsRcvd = bytesSent = bytesRcvd = 0;

    WATCH(numSessions);
    WATCH(numBroken);
    WATCH(packetsSent);
    WATCH(packetsRcvd);
    WATCH(bytesSent);
    WATCH(bytesRcvd);

    // parameters
    const char *address = par("address");
    int port = par("port");
    socket.bind(*address ? IPvXAddress(address) : IPvXAddress(), port);

    socket.setCallbackObject(this);
    socket.setOutputGate(gate("tcpOut"));

    setStatusString("waiting");
}

void AAMTCPGenericCliAppBase::handleMessage(cMessage *msg)
{
    if (msg->isSelfMessage())
        handleTimer(msg);
    else
        socket.processMessage(msg);
}

void AAMTCPGenericCliAppBase::connect()
{
    // we need a new connId if this is not the first connection
    socket.renewSocket();

    // connect
    const char *connectAddress = par("connectAddress");
    int connectPort = par("connectPort");

    EV << "issuing OPEN command\n";
    setStatusString("connecting");

    socket.connect(IPAddressResolver().resolve(connectAddress), connectPort);

    numSessions++;
}

void AAMTCPGenericCliAppBase::close()
{
    setStatusString("closing");
    EV << "issuing CLOSE command\n";
    socket.close();
}

void AAMTCPGenericCliAppBase::sendPacket(int numBytes, int expectedReplyBytes, bool serverClose)
{
    EV << "sending " << numBytes << " bytes, expecting " << expectedReplyBytes << (serverClose ? ", and server should close afterwards\n" : "\n");

    GenericAppMsg *msg = new GenericAppMsg("data");
    msg->setByteLength(numBytes);
    msg->setExpectedReplyLength(expectedReplyBytes);
    msg->setServerClose(serverClose);

    socket.send(msg);

    packetsSent++;
    bytesSent+=numBytes;
}

void AAMTCPGenericCliAppBase::setStatusString(const char *s)
{
    if (ev.isGUI()) getDisplayString().setTagArg("t", 0, s);
}

void AAMTCPGenericCliAppBase::socketEstablished(int, void *)
{
    // *redefine* to perform or schedule first sending
    EV << "connected\n";
    setStatusString("connected");
}

void AAMTCPGenericCliAppBase::socketDataArrived(int, void *, cPacket *msg, bool)
{
    // *redefine* to perform or schedule next sending
    packetsRcvd++;
    bytesRcvd+=msg->getByteLength();

    delete msg;
}

void AAMTCPGenericCliAppBase::socketPeerClosed(int, void *)
{
    // close the connection (if not already closed)
    if (socket.getState()==TCPSocket::PEER_CLOSED)
    {
        EV << "remote TCP closed, closing here as well\n";
        close();
    }
}

void AAMTCPGenericCliAppBase::socketClosed(int, void *)
{
    // *redefine* to start another session etc.
    EV << "connection closed\n";
    setStatusString("closed");
}

void AAMTCPGenericCliAppBase::socketFailure(int, void *, int code)
{
    // subclasses may override this function, and add code try to reconnect after a delay.
    EV << "connection broken\n";
    setStatusString("broken");

    numBroken++;
}

void AAMTCPGenericCliAppBase::finish()
{
    EV << getFullPath() << ": opened " << numSessions << " sessions\n";
    EV << getFullPath() << ": sent " << bytesSent << " bytes in " << packetsSent << " packets\n";
    EV << getFullPath() << ": received " << bytesRcvd << " bytes in " << packetsRcvd << " packets\n";

    recordScalar("AuthNAgentT number of sessions", numSessions);
    recordScalar("AuthNAgentT packets sent", packetsSent);
    recordScalar("AuthNAgentT packets rcvd", packetsRcvd);
    recordScalar("AuthNAgentT bytes sent", bytesSent);
    recordScalar("AuthNAgentT bytes rcvd", bytesRcvd);
}


AAMTCPGenericCliAppBase::AAMTCPGenericCliAppBase()
{
  // TODO Auto-generated constructor stub

}

AAMTCPGenericCliAppBase::~AAMTCPGenericCliAppBase()
{
  // TODO Auto-generated destructor stub
}
