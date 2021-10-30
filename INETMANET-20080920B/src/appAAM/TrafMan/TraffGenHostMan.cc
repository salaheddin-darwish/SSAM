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

#include "TraffGenHostMan.h"
#include "IPControlInfo.h"
#include "IPv6ControlInfo.h"
#include "IPAddressResolver.h"

#define MSG_KIND_TRA_REQ 0
#define MSG_KIND_TRA_LD	1

Define_Module(TraffGenHostMan);

inline std::ostream& operator<<(std::ostream& out, const TraffGenHostMan::TrafSrc& d)
{
   out     <<"SrSrvName= "		<<d.TrafSrvName
	   <<"\tSrSrvIP= "		<<d.TrafSrvIP.str()
	   <<"\tStartTime= "		<<d.StartTime.dbl()
	   <<"\tLastTimeRecv= "         <<d.lastTimeRecv.dbl()
	    <<"\tnumberRecv= "		<<d.numReceived
	   <<"\tByteReceived= "		<<d.BytesReceived
	   <<"\tnumPackSent= "		<<d.numReqSent
	   <<"\tByteSend= "		<<d.ByteReqSent
	   <<"\tprobSelection= "	<<d.probSelection
	   <<"\tReqCounter= "            <<d.ReqCounter
	   <<"\tReReqTimer= "            <<(d.mTriggerSource? "True": "False")
           <<"\tSenssionLength= "       <<d.SessionLength;

  return out;
}

void TraffGenHostMan::initialize(int stage)
{
	// TODO - Generated method body

	if (stage!=6)
		return;

	TotalBytesRecv=TotalBytesSent=numReceived= numSent= 0;

	Maxcounter = par("MaxReqNum");

	ActiveHost = false ;
	ReachableSourceSrvs = false ;
	ServersInProgress = 0 ;
	ICMPErrorMsgNum = 0 ;

	ev << "initializing TrafHostGen - Sink Node..." << endl;


	WATCH(numReceived);
	WATCH(numReceived);
	WATCH(numSent);
	WATCH(TotalBytesRecv);
	WATCH(TotalBytesSent);
	WATCH_VECTOR(TrafSrTable);
	WATCH(ActiveHost);
	WATCH(ServersInProgress);
	WATCH(ICMPErrorMsgNum);


}

void TraffGenHostMan::handleMessage(cMessage *msg)
{
	// TODO - Generated method body

	if (msg->isSelfMessage())
	    {
	      handleSelfMsg(msg);
	    }
	    else if (msg->arrivedOn("lowergateIn"))
	    {
	     handleLowerMsg(msg);
	    }
	    else delete msg;

	    if (ev.isGUI())
	    {
		 const char * x="HostSinkON";
		 char buf[40];
		 sprintf(buf, "rcvd: %d pks\nsent: %d pks \n State:%s", numReceived, numSent,x);
		 getDisplayString().setTagArg("t",0,buf);
	    }
}

void TraffGenHostMan::handleSelfMsg(cMessage* apMsg)
{

     int * indxP ;
     indxP = (int *) apMsg->getContextPointer();
     int indx = *indxP;
     std::stringstream sName;

     if(apMsg->getKind() == MSG_KIND_TRA_REQ)
     {
         if(par("WaitingEnable").boolValue())
          {
            TrafSrTable[indx].ReqCounter++ ;

            if(TrafSrTable[indx].ReqCounter < Maxcounter-1 && TrafSrTable[indx].numReceived ==0 )
            scheduleAt(simTime() + par("WaitTime").doubleValue(), (cMessage *) TrafSrTable[indx].mTriggerSource );
            else
            {
              delete  TrafSrTable[indx].mTriggerSource;
              TrafSrTable[indx].mTriggerSource =NULL;
              SourcSelection(true);
            }
          }
         else
           {
             delete  TrafSrTable[indx].mTriggerSource ;
             TrafSrTable[indx].mTriggerSource =NULL;
           }



         sName<<"TrafGenReq_"<<getParentModule()->getFullName()<<"_"<<TrafSrTable[indx].TrafSrvName;
         TrafSrTable[indx].StartTime = simTime();
         TrafSrTable[indx].numReqSent++ ;
         TrafSrTable[indx].ByteReqSent += ReqPKSize;


         cPacket* p_traffic_msg = new cPacket(sName.str().c_str(), MSG_KIND_TRA_LD);

         p_traffic_msg->setByteLength(ReqPKSize) ;

         SendTriggerReq(p_traffic_msg, TrafSrTable[indx].TrafSrvIP);
       }
  }

void TraffGenHostMan::finish()
{
 if(ActiveHost)
  {
	  std::stringstream srvName;

	  for (unsigned int i = 0 ; i < TrafSrTable.size(); i++)
	    {

               if (TrafSrTable[i].mTriggerSource)
                 {
                   if ((cMessage *) TrafSrTable[i].mTriggerSource->isScheduled())
                   cancelEvent((cMessage *) TrafSrTable[i].mTriggerSource);
                   delete TrafSrTable[i].mTriggerSource;
                 }

	      TrafSrTable[i].mTriggerSource = NULL ;

	      srvName<<TrafSrTable[i].TrafSrvName;

	      recordScalar(("TraffHostMan StartTime"+srvName.str()).c_str() , TrafSrTable[i].StartTime.dbl());
	      recordScalar(("TraffHostMan lastTimeRecv"+srvName.str()).c_str(), TrafSrTable[i].lastTimeRecv.dbl());
	      recordScalar(("TraffHostMan numReceived"+srvName.str()).c_str(),   TrafSrTable[i].numReceived);
	      recordScalar(("TraffHostMan BytesReceived"+srvName.str()).c_str(), TrafSrTable[i].BytesReceived);
	      recordScalar(("TraffHostMan numReqSent"+srvName.str()).c_str(), TrafSrTable[i].numReqSent);
	      recordScalar(("TraffHostMan ByteReqSent"+srvName.str()).c_str(), TrafSrTable[i].ByteReqSent);
	      recordScalar(("TraffHostMan ReqCounter"+srvName.str()).c_str(),TrafSrTable[i].ReqCounter);

	      srvName.str("");

	    }

	  recordScalar("TraffHostMan TrafficRecv", numReceived);
	  recordScalar("TraffHostMan TotalBytesReceived", TotalBytesRecv);
	  recordScalar("TraffHostMan ReqSent", numSent);
	  recordScalar("TraffHostMan TotalBytesSent", TotalBytesSent);
	  recordScalar("TraffHostMan ICMPErrorMsgNum",ICMPErrorMsgNum);
  }


}

void TraffGenHostMan::printPacket(cPacket *msg)
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
    ev  << "Traffic Request length: " << msg->getByteLength() << " bytes" << endl;
    if (protocol!=-1)
        ev  << "src: " << src << "  dest: " << dest << "  protocol=" << protocol << "\n";
}

void TraffGenHostMan::handleLowerMsg(cMessage* apMsg)
{
	// only relevant for the sink

    EV << "Received packet: ";

    IPControlInfo* ConttPK;

    cPacket * tPK = check_and_cast<cPacket *>(apMsg);

    ConttPK = check_and_cast<IPControlInfo *> (tPK->getControlInfo());

    int indxx = -1 ;

    for (unsigned int j =0 ; j< TrafSrTable.size(); j++)
      {
    	if ( ConttPK->getSrcAddr()== TrafSrTable[j].TrafSrvIP.get4())
    	{
    	  indxx = j ;
    	  break;
    	}

      }

    if(indxx == -1 )
    	{
    	// error("Error in IP check SourceTraffic");
    	ICMPErrorMsgNum ++ ;
    	delete tPK;
    	return ;
    	}

    printPacket(tPK);

    TrafSrTable[indxx].BytesReceived +=tPK->getByteLength();
    TrafSrTable[indxx].numReceived ++;
    TrafSrTable[indxx].lastTimeRecv = simTime();
    TrafSrTable[indxx].SrvReachable = true ;

    if (TrafSrTable[indxx].mTriggerSource && TrafSrTable[indxx].mTriggerSource->isScheduled())
      {
        cancelEvent((cMessage *)TrafSrTable[indxx].mTriggerSource );
        delete TrafSrTable[indxx].mTriggerSource ;
        TrafSrTable[indxx].mTriggerSource  =NULL;
      }

    numReceived++;
    TotalBytesRecv += tPK->getByteLength();
    ReachableSourceSrvs = true ;

    delete tPK;
}

void TraffGenHostMan::TriggerTraffic(const char * SinkName, bool act)
{
          Enter_Method ("TriggerTraffic(%s,%s)",SinkName,act? "True":"False");

          TrafSrcDef TrafSrcTemp ;

           // std::string x = getParentModule()->getFullName();

          SrAdd = IPAddressResolver().addressOf(getParentModule(),2);

          if (SrAdd.isUnspecified()) error ("----------");

	 // ANM =  AuthNAgentAccess().getIfExists();

         ANM = findAuthNAgentOf(getParentModule());

	 if (!ANM)  error ("Error in AutnNAgent Link in %s",getParentModule()->getFullName());

	 if (ANM->netServices.size()==0)
	     error ("Check Node Service List Node s%", getParentModule()->getFullName());

	for (unsigned int i=0 ; i < ANM->netServices.size() ;i++)
	  {
	    TrafSrcTemp.TrafSrvName = ANM->netServices[i]->SrvName;
	    TrafSrcTemp.TrafSrvIP   = IPAddressResolver().resolve(ANM->netServices[i]->SrvAdress.c_str()) ;
	    TrafSrcTemp.StartTime   = 0;
	    TrafSrcTemp.SessionLength  = 0.0 ;
	    TrafSrcTemp.lastTimeRecv   = 0 ;
	    TrafSrcTemp.numReceived    = TrafSrcTemp.BytesReceived = 0;
	    TrafSrcTemp.numReqSent     = TrafSrcTemp.ByteReqSent   = 0 ;
	    TrafSrcTemp.probSelection  = 0.0;
	    TrafSrcTemp.SrvReachable   = false ;
	    TrafSrcTemp.ReqCounter     = 0;

	    TrafSrcTemp.WaitTimer = TrafSrcTemp.mTriggerSource = NULL ;
	    TrafSrTable.push_back(TrafSrcTemp);
	   }

	  ACType = ANM->AttribCertifVec[0].CertifType ;

	  ReqPKSize = par("ReqPacketSize");

	  if(!ANM->AttribCertifVec[0].CertifType == AuthNAgent::DelegThresAc)
	  ReqPKSize *=2;

	  ActiveHost = true ;

	  bool xx = par("SingOrMultiSrv").boolValue() ;

	  SourcSelection(xx);

	  char buf[40];
	  sprintf(buf, "TTH");
	  getParentModule()->getDisplayString().setTagArg("t",0,buf);
}

void TraffGenHostMan::SourcSelection(bool bV)
{

  std::stringstream TimerNam1;
  std::vector<int> SrvIndA ;

  for (unsigned int j=0 ; j<TrafSrTable.size() ;j++)
    {
      if ((TrafSrTable[j].SrvReachable &&
           abs((simTime()-TrafSrTable[j].lastTimeRecv).dbl())< par("WaitingTrafficWindow").doubleValue())
           || TrafSrTable[j].mTriggerSource
           || (!TrafSrTable[j].SrvReachable && TrafSrTable[j].ReqCounter == Maxcounter))continue ;

      SrvIndA.push_back(j);
    }

  if (bV)
    {
      if(SrvIndA.size() == 0 )
        {
          ev<<"No Service free to call  .................................... "<<endl;
          return ;
        }

      int  k = intrand(SrvIndA.size()); // get random Index in of SrvIndA

      TimerNam1<<"TriggerRequest-"<<getParentModule()->getName()<<"Src_N "<<SrvIndA[k]<<endl;

      ev<< TimerNam1.str()<<"To"<<TrafSrTable[SrvIndA[k]].TrafSrvName <<endl;

      int * iV = new int() ;
      * iV = SrvIndA[k] ;

      TrafSrTable[SrvIndA[k]].mTriggerSource  = new cMessage(TimerNam1.str().c_str(),MSG_KIND_TRA_REQ);

      TrafSrTable[SrvIndA[k]].mTriggerSource->setContextPointer(iV);

      ServersInProgress++ ;

      scheduleAt(simTime() + par("TrigTime").doubleValue(), (cMessage *) TrafSrTable[SrvIndA[k]].mTriggerSource);
    }
  else // Multi servers Calls in one Session
    {
      if(SrvIndA.size() == 0 )
        {
          ev<<"No Service free to call  .................................... "<<endl;
          error ("Error in Server Idex") ;
          return ;
        }

      unsigned int SrvNum = par("MultiNumNum") ;

      if (SrvNum >= SrvIndA.size()) // sending for all available serives since
        {
          for(unsigned int i = 0 ; i< SrvIndA.size() ; i++)
            {

              TimerNam1.str("");
              TimerNam1<<"TriggerRequest-"<<getParentModule()->getName()<<"Src_N"<<SrvIndA[i];

              ev<< TimerNam1.str()<<"To"<<TrafSrTable[SrvIndA[i]].TrafSrvName <<endl;

              int * iVx = new int();
              * iVx = SrvIndA[i] ;

              ServersInProgress++;

              TrafSrTable[SrvIndA[i]].mTriggerSource  = new cMessage(TimerNam1.str().c_str(),MSG_KIND_TRA_REQ);
              TrafSrTable[SrvIndA[i]].mTriggerSource->setContextPointer(iVx);
              scheduleAt(simTime() + uniform(0,par("TrigTime").doubleValue()), (cMessage *) TrafSrTable[SrvIndA[i]].mTriggerSource);
            }
        }
      else
        {   // SrvNum  < SrvIndA.size()

          for(unsigned int i=0 ; i < SrvNum ; i++)
            {
              int  xK = intrand(SrvIndA.size());

              TimerNam1.str("");
              TimerNam1<<"TriggerRequest-"<<getParentModule()->getName()<<"Src_N"<<SrvIndA[xK];

              ev<< TimerNam1.str()<<"To"<<TrafSrTable[SrvIndA[xK]].TrafSrvName <<endl;

              int * iVx = new int();
              * iVx = SrvIndA[xK] ;

              ServersInProgress++;

              TrafSrTable[SrvIndA[xK]].mTriggerSource  = new cMessage(TimerNam1.str().c_str(),MSG_KIND_TRA_REQ);
              TrafSrTable[SrvIndA[xK]].mTriggerSource->setContextPointer(iVx);
              scheduleAt(simTime() + uniform(0,par("TrigTime").doubleValue()), (cMessage *) TrafSrTable[SrvIndA[xK]].mTriggerSource);

              SrvIndA.erase(SrvIndA.begin()+xK); // remove from the lit
            }

        }
    }


//  if (bV)
//      {
//        bool Cont  = true ;
//
//        while (Cont)
//        {
//          int  k = intrand(TrafSrTable.size());
//
//          if (TrafSrTable[k].SrvReachable  && TrafSrTable[k].StartTime != 0 )continue ;
//          else
//            {
//              Cont = false ;
//
//
//              TimerNam1<<"TriggerRequest-"<<getParentModule()->getName()<<"Src_N "<<k<<endl;
//              int * iV = new int() ;
//              * iV = k ;
//
//              TrafSrTable[k].mTriggerSource  = new cMessage(TimerNam1.str().c_str(),MSG_KIND_TRA_REQ);
//
//              TrafSrTable[k].mTriggerSource->setContextPointer(iV);
//
//              ServersInProgress++ ;
//
//              scheduleAt(simTime() + par("TrigTime").doubleValue(), (cMessage *) TrafSrTable[k].mTriggerSource);
//            }
//        }
//      }
//    else
//      { // Multi Servers to call
//       int SrvNum = par("MultiNumNum") ;
//       int x = 0 ;
//
//       while (SrvNum !=x)
//       {
//         int  iK = intrand(TrafSrTable.size());
//         TimerNam1.str("");
//         TimerNam1<<"TriggerRequest-"<<getParentModule()->getName()<<"Src_N"<<iK;
//
//         if(!TrafSrTable[iK].mTriggerSource)
//           {
//             x++;
//             int * iVx = new int();
//             * iVx = iK ;
//
//             ServersInProgress++;
//
//             TrafSrTable[iK].mTriggerSource  = new cMessage(TimerNam1.str().c_str(),MSG_KIND_TRA_REQ);
//             TrafSrTable[iK].mTriggerSource->setContextPointer(iVx);
//             scheduleAt(simTime() + uniform(0,par("TrigTime").doubleValue()), (cMessage *) TrafSrTable[iK].mTriggerSource);
//           }
//       }
//       if(x ==0) error("Error in Trigger of Source Srv");
//       }
}

void TraffGenHostMan::SendTriggerReq(cPacket* cPKReq, IPvXAddress SourceDist)
{
  if(!SourceDist.isIPv6())
    {
        // send to IPv4
        IPControlInfo *controlInfo = new IPControlInfo();
        controlInfo->setDestAddr(SourceDist.get4());
        controlInfo->setSrcAddr (SrAdd.get4());

        controlInfo->setProtocol(par("Protocol"));
        cPKReq->setControlInfo(controlInfo);

        cPKReq->addPar("sourceId") = ANM->getId();
        cPKReq->addPar("MsgType") = "TrafficReq";
        cPKReq->addPar("NodeName") = getParentModule()->getFullName();

//        if(CertifType)
//        	cPKReq->addPar("CertifType") = CertifType;
//        else error("Check Certif Variable");

        EV << "Sending packet: ";

        printPacket(cPKReq);

        TotalBytesSent += cPKReq->getByteLength();
        numSent++ ;

        send(cPKReq, "lowergateOut");
    }
    else error("Wrong IP");
}

AuthNAgent *TraffGenHostMan::findAuthNAgentOf(cModule *host )
{
  cModule *mod = host->getSubmodule("udpApp",0);
  return dynamic_cast <AuthNAgent *> (mod);
  //  return (AuthNManager *) mod;

}
