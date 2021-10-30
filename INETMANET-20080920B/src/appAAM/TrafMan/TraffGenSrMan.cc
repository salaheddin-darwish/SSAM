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

#include "TraffGenSrMan.h"
#include "IPControlInfo.h"
#include "IPv6ControlInfo.h"
#include "IPAddressResolver.h"
#include "ICMPMessage_m.h"


Define_Module(TraffGenSrMan);

inline std::ostream& operator<<(std::ostream& out, const TraffGenSrMan::NodesRecord& d)
{
   out 	   <<"UserID= "                 << d.id
           <<"\tUserName= "             << d.UsrNodeName
           <<"\tUserIP= "               << d.UsrNodeIPAddr.str()
           <<"\tRecvTime= "             <<d.RecievedReq.dbl()
           <<"\tDuration= "             <<d.sendTrafDuration.dbl()
           <<"\tActive= "               <<(d.WorkFlag? "Alive": "Dead")
           <<"\tcertifClass= "          <<d.certifType
           <<"\tnumberOfReq= "          <<d.numReq
           <<"\tByteReceived= "         <<d.ByteReceived
           <<"\tnumPackSent= "          <<d.numPackSent
           <<"\tByteSend= "             <<d.ByteSent
           <<"\tDropReq= "              <<d.DropReq ;

  return out;
}


inline std::ostream& operator<<(std::ostream& out, const TraffGenSrMan::DistAddrProfile& d)
{
   out   <<"UserID= "                     << d.UsrId
         <<"\tUserIP= "                   << d.nIp.str()
         <<"\tSessionLength= "            << d.sessionTime.dbl()
         <<"\tNewJoin= "                  << (d.Newjoin? "New":"Old");

   return out;
}

void TraffGenSrMan::initialize(int stage)
{
        // TODO - Generated method body

        if (stage!=3)
                return;

        std::stringstream TimerNam1,TimerNam2;

        TotalBytesRecv=TotalBytesSent=numReceived= numSent= DropReqNum = 0;

        ev << "initializing Traffic Source Generator..." <<getParentModule()->getFullName()<<endl;

        Start = false ;
        sleepMode = true ; // no node calls
        startTime = simTime();
        lastTime  = 0 ;

        NewNodeJoin = 0 ;
        DelHost = 0;
        ICMPErrorMsgNum = 0;

        MaxFlowNum = par("MaxFlowNum");

        if( (int)par("TrafPatType") == 0 )  TrafPatType = true;
        else  TrafPatType = false ;

        NodesINworking =  new cOutVector();
        NodesINworking->setName("NodeInProgress") ;
        NodesINworking->enable() ;


        NodeInWaiting =  new cOutVector();
        NodeInWaiting->setName("NodeInWaiting") ;
        NodeInWaiting->enable() ;

        TimerNam1<<"SendTraffMsg-"<<getParentModule()->getFullName();
        TimerNam2<<"onOffSwitch-"<<getParentModule()->getFullName();

        mpSendMessage           = new cMessage(TimerNam1.str().c_str());
        mpOnOffSwitch           = new cMessage(TimerNam2.str().c_str());

        WATCH(startTime);
        WATCH(mOnOff);
        WATCH(numSent);
        WATCH(TotalBytesSent);
        WATCH(numReceived);
        WATCH_MAP(NodeUsrdeTable);
        WATCH_LIST(destAddresses);
        WATCH(NewNodeJoin) ;
        WATCH(DelHost);
        WATCH(sleepMode);
        WATCH(ICMPErrorMsgNum);

        char buf1[40];
        sprintf(buf1, "SP-Source");
        getParentModule()->getDisplayString().setTagArg("t",0,buf1);
}

void TraffGenSrMan::handleMessage(cMessage *msg)
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
                 const char *  x  = (!mOnOff? "ON":"OFF");
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
void TraffGenSrMan::handleSelfMsg(cMessage* apMsg)
{
  // handle the switching between on and off periods of the generated traffic
  // the values for offIntv, onIntv and interDepartureTime are evaluated each
  // time, in case a distribution function is specified

  if (apMsg == mpOnOffSwitch)
    {
      if (mOnOff == TRAFFIC_ON)
        {
          lastTime = simTime();

          ev << "switch traffic off" << endl;
          mOnOff = TRAFFIC_OFF;
          scheduleAt(simTime() + OffIntv(), mpOnOffSwitch);
          cancelEvent(mpSendMessage);

        }
      else if (mOnOff == TRAFFIC_OFF)
        {

          lastTime = simTime();
          NodesINworking->record((double)destAddresses.size()) ;
          NodeInWaiting->record(NewNodeJoin);

          // change status of New joined node to Old new in order to send traffic to them ;
//          for (std::map< int,DistProfVar>::iterator it = destAddresses.begin();it != destAddresses.end();it++ )
//            if (it->second.Newjoin) it->second.Newjoin = false ;


          ev << "switch traffic on" << endl;
          mOnOff = TRAFFIC_ON;
          cancelEvent(mpSendMessage);

          scheduleAt(simTime() + OnIntv(), mpOnOffSwitch);
          scheduleAt(simTime() + InterDepartureTime(), mpSendMessage);
         // scheduleAt(simTime()+FirstPacketTime(), mpSendMessage);
        }


    }
  // handle the sending of a new message
    else if (apMsg == mpSendMessage)
    {
      lastTime = simTime();

      double iDelay = 0;

      std::list<DistProfVar>::iterator it ;//= destAddresses.begin();

      // calculate the destination and send the message:

      if (mOnOff == TRAFFIC_ON )
        {
    	  int i=0 ;

    	  while( i < (int)par("HandledSrvNum") && !destAddresses.empty() )
    	  {

    	      it = destAddresses.begin();

      	      std::map<int,NodesRecordDef>::iterator ite =  NodeUsrdeTable.find(it->UsrId) ;
              if (ite ==  NodeUsrdeTable.end()) error ("Error in %s Node Record ", it->nIp.str().c_str());

              if(ite->second.WorkFlag)
                {
                  IPvXAddress dest = it->nIp ;
                  cPacket* p_traffic_msg = new cPacket("TrafficMessage");
                  if (par("SendDelayedFlag").boolValue())
                  iDelay = i*par("SendDelayedVal").doubleValue();
                  ev << "Sending message to" << dest.str() << endl;
                  SendTraf(p_traffic_msg, dest, it->UsrId,iDelay);
                   i++ ;
                   if (it->Newjoin)
                	   {
                	    it->Newjoin = false;
                	    NewNodeJoin --;
                	   }
                }

          //  else NewNodeJoin ++ ;

              if((ite->second.numPackSent >= MaxFlowNum && !TrafPatType)
            	||(it->sessionTime < simTime()+InterDepartureTime() && TrafPatType)
            	|| !ite->second.WorkFlag)
              {
            	  destAddresses.pop_front();
              }
              else // session is not expired yet
              {
            	  // Move This Host to the back of destAddresses
            	  DistProfVar tempAdrRec;
            	  tempAdrRec.UsrId 		 = it->UsrId;
            	  tempAdrRec.nIp   		 = it->nIp;
            	  tempAdrRec.sessionTime = it->sessionTime;
            	  tempAdrRec.Newjoin     = it->Newjoin;
            	  destAddresses.pop_front() ;
            	  destAddresses.push_back(tempAdrRec);

              }

            }

    	  NodesINworking->record((double)destAddresses.size()) ;
    	  NodeInWaiting->record(NewNodeJoin);

          // schedule next event
          // interDepartureTime is evaluated each time,
          // in case a distribution function is specified

              if(!destAddresses.empty())
                {
                //  if(NewNodeJoin != destAddresses.size())
                  scheduleAt(simTime() + InterDepartureTime(), mpSendMessage);

                }
              else // destAddresses is empty
                {
                  sleepMode = true ;
                  if (mpOnOffSwitch && mpOnOffSwitch->isScheduled())
                	  cancelEvent(mpOnOffSwitch);
                }
        }
    }
}

void TraffGenSrMan::SendTraf(cPacket* cPK, IPvXAddress DistHodt, int iid,double iD)
{
   std::map<int,NodesRecordDef>::iterator it;

    cPK->setByteLength(PacketSize());

    if(!DistHodt.isIPv6())
    {
        // send to IPv4
        IPControlInfo *controlInfo = new IPControlInfo();
        controlInfo->setDestAddr(DistHodt.get4());
        controlInfo->setProtocol(par("Protocol"));

        SrAdd = IPAddressResolver().resolve(getParentModule()->getFullName());

         if(SrAdd.isIPv6()) error("Wrong Srource Address IP");

        controlInfo->setSrcAddr (SrAdd.get4());
        cPK->setControlInfo(controlInfo);

        EV << "Sending Traffic packet: ";

        ev  <<  cPK << endl;
        ev  << "Payload length: " << cPK->getByteLength() << " bytes" << endl;
        ev  << "src: " <<SrAdd.str() << "  dest: " << DistHodt.str() <<"\n";

        TotalBytesSent += cPK->getByteLength();

      if(par("SendDelayedFlag").boolValue())
      sendDelayed(cPK, iD ,"lowergateOut");
      else send(cPK, "lowergateOut");
    }
    else error("Wrong IP");

    it = NodeUsrdeTable.find(iid);

    if(it == NodeUsrdeTable.end()) error("Erro in %d Record", iid);


    it->second.numPackSent++;
    it->second.ByteSent += PacketSize();

    numSent++;
    TotalBytesSent += PacketSize();
}

void TraffGenSrMan::finish()
{

      for(std::map<int,NodesRecordDef>::iterator it = NodeUsrdeTable.begin(); it != NodeUsrdeTable.end(); it ++)
        {


          std::stringstream sName ;
          sName<<it->second.UsrNodeName;

          recordScalar((const char *)("TraffGenSrMan TrafficRecv-"+sName.str()).c_str(),(int) it->second.numReq);
          recordScalar((const char *)("TraffGenSrMan TrafficByteRecv-"+sName.str()).c_str(),(int) it->second.ByteReceived);
          recordScalar((const char *)("TraffGenSrMan TrafficSent-"+sName.str()).c_str(),(int) it->second.numPackSent);
          recordScalar((const char *)("TraffGenSrMan TrafficByteSent-"+sName.str()).c_str(),(int) it->second.ByteSent);
          recordScalar((const char *)("TraffGenSrMan TrafficDropNum-"+sName.str()).c_str(),(int) it->second.DropReq);
          recordScalar((const char *)("TraffGenSrMan TrafficSessionLength-"+sName.str()).c_str(),(double) it->second.sendTrafDuration.dbl());
          recordScalar((const char *)("TraffGenSrMan TrafficStartTime-"+sName.str()).c_str(),(double) it->second.RecievedReq.dbl());
          sName.str("");
        };

      std::stringstream GNam;
      GNam<<"-"<<getParentModule()->getFullName();

      recordScalar((const char *)("TraffGenSrMan TrafficRecv "+GNam.str()).c_str(), numReceived);
      recordScalar((const char *)("TraffGenSrMan TotalBytesReceived "+GNam.str()).c_str(), TotalBytesRecv);
      recordScalar((const char *)("TraffGenSrMan TrafficSent "+GNam.str()).c_str(), numSent);
      recordScalar((const char *)("TraffGenSrMan TotalBytesSent "+GNam.str()).c_str(), TotalBytesSent);

      recordScalar((const char *)("TraffGenSrMan Start Time Gen "+GNam.str()).c_str(), startTime.dbl());
      recordScalar((const char *)("TraffGenSrMan Last Time Gen "+GNam.str()).c_str(), lastTime.dbl());
      recordScalar((const char *)("TraffGenSrMan NodeInWaiting "+GNam.str()).c_str(), NewNodeJoin);
      recordScalar((const char *)("TraffGenSrMan NodeInSendingBuffer "+GNam.str()).c_str(),destAddresses.size());
      recordScalar((const char *)("TraffGenSrMan TotalReceivingNodes "+GNam.str()).c_str(),NodeUsrdeTable.size());

      recordScalar((const char *)("TraffGenSrMan Throughput "+GNam.str()).c_str(),((double)(numSent+numReceived)*60)/ (lastTime.dbl() - startTime.dbl()));
      recordScalar((const char *)("TraffGenSrMan ICMPErrorMsgNum "+GNam.str()).c_str(),ICMPErrorMsgNum);


      if (mpSendMessage )
        {
         if (mpSendMessage->isScheduled()) cancelEvent(mpSendMessage);
         delete mpSendMessage;

        }

      if (mpOnOffSwitch )
        {
         if (mpOnOffSwitch->isScheduled()) cancelEvent(mpOnOffSwitch);
         delete mpOnOffSwitch;

        }

    delete NodesINworking;
    delete NodeInWaiting ;

    mpOnOffSwitch = NULL;
    mpSendMessage = NULL;
    NodesINworking = NULL;
    NodeInWaiting  =NULL;
}

/**
 * @return The time when the first packet should be scheduled
 */
double TraffGenSrMan::FirstPacketTime()
{
    return par("firstPacketTime").doubleValue();
}

/**
 * @return The time between two subsequent packets
 *
 * WARNING: the return value should not be buffered, as it can change with each
 *    call in case a distribution function is specified as simulation parameter!
 */
double TraffGenSrMan::InterDepartureTime()
{
    return par("interDepartureTime").doubleValue();
}

/**
 * @return The packet length
 *
 * WARNING: the return value should not be buffered, as it can change with each
 *    call in case a distribution function is specified as simulation parameter!
 */
long TraffGenSrMan::PacketSize()
{
    return par("packetSize").longValue();
}

double TraffGenSrMan::OnIntv(){
        return par("onLength").doubleValue();
}

double TraffGenSrMan::OffIntv()
{
        return par("offLength").doubleValue();
}

//double TraffGenSrMan::OffInterDepartureTime()
//{
//        return par("offInterDepartureTime").doubleValue();
//}

void TraffGenSrMan::handleLowerMsg(cMessage* apMsg)
{

  std::map<int,NodesRecordDef>::iterator it;
 // std::list<DistProfVar>::iterator *ite;
  std::list<DistProfVar>::iterator iit;

  NodesRecordDef UserRecord ;
  DistProfVar DistRec ;
  IPvXAddress src, dest;
  int protocol = -1;
  std::string nodeNam ;
  int UserId ;
  double SesLn = par("prsumSessionlength").doubleValue();

  // only relevant for the sink

    EV << "Received New Request : " ;

    if(dynamic_cast<ICMPMessage *>(apMsg))// Error to find node ICMPError
    {
    	ICMPErrorMsgNum++;
    	delete apMsg;
    	return;
    }

    cPacket * tPK = check_and_cast<cPacket *>(apMsg);
    IPControlInfo *ctrl = check_and_cast<IPControlInfo *>(tPK->getControlInfo());

    src = ctrl->getSrcAddr();
    dest = ctrl->getDestAddr();
    protocol = ctrl->getProtocol();


    if (!(((std::string) tPK->par("MsgType") == "TrafficReq") &&(tPK->getKind() == 1) ))
        error ("Error in MsgType Traffic Request: %s", getParentModule()->getFullName()) ;

    nodeNam = (std::string) tPK->par("NodeName");

    ev  <<  tPK << endl;
    ev  << "Payload length: " << tPK->getByteLength() << " bytes" << endl;
    ev<< "src: " << src << "  dest: " << dest << "  protocol=" << protocol << "\n";

    UserId = (int )tPK->par("sourceId");

    it = NodeUsrdeTable.find(UserId) ;

    // Record User Profile
    if(it ==NodeUsrdeTable.end())
      {

        UserRecord.id                   = UserId ;
        UserRecord.UsrNodeIPAddr        = src ;
        UserRecord.UsrNodeName          = nodeNam ;
        UserRecord.RecievedReq          = simTime() ;
        UserRecord.sendTrafDuration     =SesLn;

        UserRecord.numReq               = 1 ;
        UserRecord.ByteReceived         = tPK->getByteLength() ;

        UserRecord.numPackSent          = 0;
        UserRecord.ByteSent             = 0;

        UserRecord.WorkFlag             = true ; // alive
        UserRecord.certifType           = -1;
        UserRecord.DropReq              = 0;
        NodeUsrdeTable.insert(std::pair<int,NodesRecordDef>(UserId,UserRecord));

        DistRec.nIp = src ;
        DistRec.UsrId = UserId;
        DistRec.sessionTime = simTime()+SesLn ;
        DistRec.Newjoin = true;
        NewNodeJoin ++;

        destAddresses.push_back(DistRec);

      }
    else
      {
        if(it->second.WorkFlag)
          {
            it->second.RecievedReq = simTime();
            it->second.numReq++;
            it->second.ByteReceived  += tPK->getByteLength();

        //    ite = destAddresses.find(it->second.id);
				// Find in AddressINProgress
            for (iit = destAddresses.begin(); iit != destAddresses.end(); iit++ )
            	if (it->second.id == iit->UsrId) break;
//            	{
//            		ite = &iit  ;
//            		break;
//            	}


            if(iit == destAddresses.end()) // Not in Sending Buffer
              {
                DistRec.nIp = it->second.UsrNodeIPAddr ;
                DistRec.UsrId = it->second.id ;
                DistRec.sessionTime = simTime()+SesLn ;
                DistRec.Newjoin = true ;
                NewNodeJoin ++ ;

                destAddresses.push_back(DistRec);
              }
            else
            	{

            	iit->sessionTime = iit->sessionTime + SesLn; // Increase Session Duration

            	}

          }
        else // not alive
          {
            ev<<"Drop request since node is alive anymore"<<endl;
            it->second.DropReq ++;
            DropReqNum ++ ;
          }

      }

    TriggerTraffic();

    NodesINworking->record((double)destAddresses.size()) ;

    numReceived++;
    TotalBytesRecv += tPK->getByteLength();
    delete tPK;
}

void TraffGenSrMan::TriggerTraffic()
{

  if(sleepMode)
    {
      // the onOff-traffic timer is scheduled
      // only if the parameters for onOff-traffic are present
      if ((OnIntv() > 0) && (OffIntv() > 0))
        {
          scheduleAt(simTime() + OnIntv(), mpOnOffSwitch);

        }

      // if the offInterArrivalTime attribute is present: packets are sent during the off interval too
//      if ((mOnOff == TRAFFIC_ON) && (OffInterDepartureTime()>0))
//        mOffTraffic = true; else mOffTraffic = false;
         mOnOff = TRAFFIC_ON;
        scheduleAt(simTime() + FirstPacketTime(), mpSendMessage);
        sleepMode = false ;
    }

    if (!Start)
    {
      startTime = simTime();
      Start = true ;
      sleepMode = false ;
    }

}

void TraffGenSrMan::DeactiveNodeRecord(std::string strrVar)
{
  //Enter_Method ("DeactiveNodeRecord(%s)", strrVar.c_str());
  Enter_Method_Silent();

  for(std::map<int,NodesRecordDef>::iterator it = NodeUsrdeTable.begin(); it != NodeUsrdeTable.end(); it ++)
    {
      if (it->second.UsrNodeName == strrVar)
        {
          it->second.WorkFlag = false ;
          DelHost++;
          break;
        }
    }

}


