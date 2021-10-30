// Copyright (C) 2011-2015 Salaheddin Darwish; Department of Computer Science, Brunel University London, UK
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

#ifndef __TRAFFGENSRMAN_H__
#define __TRAFFGENSRMAN_H__

#include <omnetpp.h>
#include "BasicModule.h"
#include "IPvXAddress.h"

/**
 * TODO - Generated class
 */
class TraffGenSrMan : public BasicModule
{
protected:
      virtual int numInitStages() const {return 4;}
      virtual void initialize(int);
  virtual void finish();
  virtual void handleMessage(cMessage *msg);


  // OPERATIONS
      virtual void handleSelfMsg(cMessage*);
      virtual void handleLowerMsg(cMessage*);
      virtual void SendTraf(cPacket*, IPvXAddress,int,double);
      virtual void TriggerTraffic();


public:
    double  FirstPacketTime();
    double  InterDepartureTime();
    long    PacketSize();
    double  OnIntv();
    double  OffIntv();
    double  OffInterDepartureTime();

//    TraffGenSrMan();
//    ~TraffGenSrMan() ;
    virtual void DeactiveNodeRecord(std::string);


    int         TotalBytesSent;
    int         TotalBytesRecv;

    enum TrafficStateType
    {
        TRAFFIC_ON,
        TRAFFIC_OFF
    };

    struct DistAddrProfile
    {
      int UsrId;
      IPvXAddress nIp ;
      simtime_t sessionTime;
      bool Newjoin ;
    };

    typedef DistAddrProfile DistProfVar ;

    int numReceived;
    int numSent;
    int DropReqNum ;
    int DelHost ;
    int MaxFlowNum ;
    bool Start;
    bool sleepMode ;
    bool TrafPatType ;

    int ICMPErrorMsgNum;

    simtime_t startTime ;
    simtime_t lastTime ;
    IPvXAddress SrAdd;
    unsigned int NewNodeJoin ;
    cOutVector * NodesINworking;
    cOutVector * NodeInWaiting;

    std::list<DistProfVar> destAddresses;


    struct NodesRecord
    {
      int id;
      std::string UsrNodeName;
      IPvXAddress UsrNodeIPAddr;
      simtime_t  RecievedReq ;
      simtime_t sendTrafDuration;

      bool WorkFlag;
      int certifType;

      int numReq ;
      int ByteReceived ;

      int numPackSent;
      int ByteSent;
      int DropReq;
    };

    typedef NodesRecord NodesRecordDef ;

    //  Tables for Source and Sink Information
    std::map<int, NodesRecordDef> NodeUsrdeTable;

private:

      // MEMBER VARIABLES
      bool            mOffTraffic;
      bool            mOnIdenticalDest;
      bool            mOnOff;
      bool            ActFlag;

      IPvXAddress mDestination;
      IPvXAddress mCurrentOnDest;
      cMessage*   mpSendMessage;
      cMessage*   mpOnOffSwitch;

};


class INET_API TraffGenSrManAccess : public ModuleAccess<TraffGenSrMan>
   {
     public:
       TraffGenSrManAccess() : ModuleAccess<TraffGenSrMan>("TraffGenSrMan") {}
   };

#endif
