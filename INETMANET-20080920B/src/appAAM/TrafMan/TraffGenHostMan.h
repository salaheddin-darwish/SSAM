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

#ifndef __TRAFFGENHOSTMAN_H__
#define __TRAFFGENHOSTMAN_H__

#include <omnetpp.h>
#include "BasicModule.h"
#include "IPvXAddress.h"
#include "AuthNAgent.h"

/**
 * TODO - Generated class
 */
class TraffGenHostMan :  public BasicModule
{
  protected:
	virtual int numInitStages() const {return 7;}
	virtual void initialize(int);
    virtual void finish();
    virtual void handleMessage(cMessage *msg);
    virtual void printPacket(cPacket *msg);

    // OPERATIONS
	virtual void handleSelfMsg(cMessage*);
	virtual void handleLowerMsg(cMessage*);

  	virtual void SendTriggerReq (cPacket* cPKReq, IPvXAddress SourceDist);
  	virtual void SourcSelection(bool bV);
  	virtual AuthNAgent *findAuthNAgentOf(cModule *host ) ;

  public:

	  virtual void TriggerTraffic(const char * SinkName, bool act);

	  int 	  TotalBytesSent;
      int	  TotalBytesRecv;
      struct TrafSrc
      {
          opp_string TrafSrvName ;
    	  IPvXAddress TrafSrvIP;
    	  simtime_t StartTime ;
    	  simtime_t SessionLength;
    	  simtime_t lastTimeRecv;


    	  int numReceived ;
      	  int BytesReceived;

      	  int numReqSent ;
      	  int ByteReqSent;
      	  int ReqCounter ;

      	  double probSelection ;
      	  bool SrvReachable ;

      	  cMessage *   WaitTimer;
      	  cMessage * mTriggerSource;

      };

      typedef  TrafSrc  TrafSrcDef ;
      std::vector<TrafSrcDef> TrafSrTable;

      int numReceived;
      int numSent;
      int numReq;
      int Maxcounter ;
      int ACType ;
      int ReqPKSize;
      int ServersInProgress;

      bool ActiveHost ;
      bool ReachableSourceSrvs ;
      IPvXAddress SrAdd;
      int ICMPErrorMsgNum;

  private:
     AuthNAgent *ANM ;
};

class INET_API TraffGenHostManAccess : public ModuleAccess<TraffGenHostMan>
   {
     public:
         TraffGenHostManAccess() : ModuleAccess<TraffGenHostMan>("TraffGenHostMan") {}
   };

#endif
