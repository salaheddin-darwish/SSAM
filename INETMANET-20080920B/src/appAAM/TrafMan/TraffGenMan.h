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

#ifndef __TRAFFGENMAN_H__
#define __TRAFFGENMAN_H__

#include <omnetpp.h>
#include "BasicModule.h"
#include "IPvXAddress.h"

/**
 * TODO - Generated class
 */
class TraffGenMan :  public BasicModule
{
  protected:
	virtual int numInitStages() const {return 4;}
	virtual void initialize(int);
    virtual void finish();
    virtual void handleMessage(cMessage *msg);
    virtual void printPacket(cPacket *msg);

    // OPERATIONS
	virtual void handleSelfMsg(cMessage*);
	virtual void handleLowerMsg(cMessage*);
  	virtual void SendTraf(cPacket*, IPvXAddress);
  	virtual IPvXAddress chooseDestAddr();
  	virtual void TriggerTraffic(const char * SinkName, bool act);

  public:
      double  FirstPacketTime();
      double  InterDepartureTime();
      long    PacketSize();
      double  OnIntv();
      double  OffIntv();
      double  OffInterDepartureTime();
      int 	  TotalBytesSent;
      int	  TotalBytesRecv;

      enum TrafficStateType
      {
    	  TRAFFIC_ON,
    	  TRAFFIC_OFF
      };

      int numReceived;
      int numSent;
  	  std::vector<IPvXAddress> destAddresses;

  private:

  	// MEMBER VARIABLES
  	bool		mOffTraffic;
  	bool		mOnIdenticalDest;
  	bool        mOnOff;
  	bool 		ActFlag;

  	IPvXAddress mDestination;
  	IPvXAddress	mCurrentOnDest;
  	cMessage*   mpSendMessage;
  	cMessage*   mpOnOffSwitch;





};


class INET_API TraffGenManAccess : public ModuleAccess<TraffGenMan>
   {
     public:
    	 TraffGenManAccess() : ModuleAccess<TraffGenMan>("TraffGenMan") {}
   };


#endif
