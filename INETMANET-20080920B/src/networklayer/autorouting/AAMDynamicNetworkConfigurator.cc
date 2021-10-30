//**************************************************************************
// Copyright (C) 2011-2015 Salaheddin Darwish; Department of Computer Science, Brunel University London, UK 
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

#include "AAMDynamicNetworkConfigurator.h"
#include <algorithm>
#include "IRoutingTable.h"
#include "IInterfaceTable.h"
#include "IPAddressResolver.h"
#include "InterfaceEntry.h"
#include "IPv4InterfaceData.h"
#include "BonnMotionFileCache.h"
#include <fstream>

#define CREATE_NODE_MSG 0
#define DELETE_NODE_MSG 1
#define MIGRATE_NODE_MSG 2
#define SCHUL_DELETE_NODE_MSG 3
#define END_SIMULATION 4
#define MaxSimulationTime STR_SIMTIME(ev.getConfig()->getConfigValue("sim-time-limit"))
#define CurrentRunNumber ev.getConfigEx()->getActiveRunNumber()

Define_Module(AAMDynamicNetworkConfigurator);

std::ostream& operator<<(std::ostream& os, const AAMDynamicNetworkConfigurator::NodeInfo& h)
{
	os << h.nodeName			<<" "
	   << h.address.str()			<<" "
	   <<h.CertType				<<" "
           <<"x="<<h.initialPos.x		<<" "
           <<"y="<<h.initialPos.y		<<" "
           <<"To be deleted ="                  <<h.scheduleToDeleteNode <<" "
           <<"DelTime="                         <<h.Deltime;

    return os;
}

AAMDynamicNetworkConfigurator *AAMDynamicNetworkConfigurator::getAAMDynNetConfig()
{
	AAMDynamicNetworkConfigurator *cc = dynamic_cast<AAMDynamicNetworkConfigurator *>(simulation.getModuleByPath("AAMDynamicNetworkConfigurator"));
    if (!cc)
        cc = dynamic_cast<AAMDynamicNetworkConfigurator *>(simulation.getModuleByPath("AAMDynamicNetworkConfigurator"));
    if (!cc)
        throw cRuntimeError("Could not find AAMDynamicNetworkConfigurator module");
    return cc;
}


void AAMDynamicNetworkConfigurator::initialize(int stage)
{
	// TODO - Generated method body
	if (stage == 0)
	{

	  index = 0;
	  DelIndex =0 ;
	  ScheduledDelNodes = 0;
	  EndSimulationFlag = false;


     SucNd = FailNd = CRate= CFRate= indxTempSR = FC = SC =  nodeLeavers = TotalSucreq = TotalReq =0 ;
     laTime =llaTime= LastDeleteNodeTime = 0 ;

     SucAuthnCAS = SucAuthnTAS = SucAuthnDAS = 0 ;

     failDeltNode = SucDeltNode = 0 ;

     AVG_SucRate = AVG_SucRatio = AVG_RTT = AVG_SetlTime = AVG_ComOverhead = AVG_FailRate = AVG_FracSucRatio =  0 ;

	  CreationTimeVec .setName("Nodes-CreationTime");
	  CreationTimeVec .enable();

	  DeletionTimeVec.setName("Nodes-DeletionTime") ;
	  DeletionTimeVec.enable();

	  NodesInPlayGround.setName("NodesAlive");
	  NodesInPlayGround.enable();

	  SucessRateVec.setName("SucessRateVec");
      FailRateVec.setName("AccumulativeFailRateVec");
      RTTNodeVec.setName("RTTNodeVec");
      SettlingTimeVec.setName("SettlingTime");
      TotalCommOverheadVec.setName("TotalCommOverhead");
      SucessRatioVec.setName("AccumulativeSucessRatio");
      FractionalSucessRatioVec.setName("FractionalSucessRatio");
      LifeTimeNodeInNet.setName("LifeTimeNodeInNet");
      LifeTimeNodeSetDeltaInNet.setName("SettingLifeTimeNodeInNet");
      SessionLengthNodeInNet.setName("SessionLengthNodeInNet");
      SuccessNodeTypesVec.setName("SuccessNodeTypes");
      LeaveRateVec.setName("LeaveRate");
      SucessReqRatioVec.setName("SucessReqRatio");
      SucessReqRatioSTVec.setName("SucessReqRatioST");

	  ccp = ChannelControl::get();

	  int nH =  par("numHosts");
	  DeleteFlag 		= par("ActivateDeleteNode");
	  DeletionType 		= par("DeletionTypePar");
	  lifetimeMean 		= par("lifetimeMean");
	  lifetimeDistName 	= par("lifetimeDistName").stdstringValue();
	  lifetimeDistPar1 	= par("lifetimeDistPar1");
	  BlockUnit 		= par("BlockUnitPar");




	  for (int i = 0 ; i <nH; i++) iA.push_back (i) ; // Initialisation the index of Nodes in iA List

	  simtime_t x = 0 ;
	 // double e = floor (MaxSimulationTime)/60 ;
	  int jBlock = 0 ;
	  int lamda  = (double)par("JoinRate");
	  int y 	 = 1 ;
	  int indxs  = par("arrivalType");

	  for (int i= 0; i <nH; i++)
	  {
		  int * xp = new int();
		  *xp = i ;

		  std::stringstream msgName ;
		  msgName <<"CreateNode["<<i<<"]";
		  cMessage *msgTimer = new cMessage ((msgName.str()).c_str(),CREATE_NODE_MSG);
		  msgTimer->setContextPointer(xp);

		  // The Type of arrival
		  switch(indxs)
		  {  case 1 : 	  // Uniform Organised Arrival
			  if(lamda >= y)  y++;
			  else
			  {
				  y =2 ;
				  jBlock++;
			  }
			  x = uniform(jBlock*BlockUnit , ((jBlock+1)*BlockUnit)-0.00001) ;
			  break;

		  case 2 :  // Poisson Arrival

			  x = x+ exponential (BlockUnit/(double)par("JoinRate"));
			  break;

		  default:         opp_error("Error in Arrival Type");
		  }
	//	  if ( x >= MaxSimulationTime )  x  = MaxSimulationTime;

		  scheduleAt(x,msgTimer);
	  }

	  LastschedNodeCreation = x ;


	  if (par("EndSimFlag").boolValue())
	  {

		  cMessage * endSimulationTimer =  new cMessage("endSimulationTimer",END_SIMULATION);
	      scheduleAt(x +par("finishDelta").doubleValue(),endSimulationTimer );
	  }




	  CertificateClasses.push_back("CorruptedIDCert");
	  CertificateClasses.push_back("GoldenIDCert");
	  CertificateClasses.push_back("SilverIDCert");
	  CertificateClasses.push_back("BronzeIDCert");

	  setupCertficateCounters (); // initialisation for Certificate types counters

	  moduleType = cModuleType::get("inet.nodes.adhoc.MobileManetRoutingHost_AAM_F");
	  WATCH_LIST(nodesInfo);
	  WATCH_LIST(DeletedNodesInfo) ;
	  WATCH_LIST(TraffGenSrManVec) ;
	  WATCH_LIST(AuthNManVec );
	  WATCH_PTRLIST(killList);
	  //	    WATCH_LIST(iA);
	  WATCH(index);
	  WATCH(DelIndex);
	  WATCH(ScheduledDelNodes);
	  WATCH(SucNd);
	  WATCH(FailNd);
	  WATCH(LastschedNodeCreation);

	}
        else if (stage == 5)
         {
          ManageTrafGenSrHost();
          ManageAuthNMANHost();
         }

}
void AAMDynamicNetworkConfigurator::handleMessage(cMessage *msg)
{
  if ( msg->isSelfMessage())
    {
      if (msg->getKind() == CREATE_NODE_MSG)
        {
    	  int * intValue = (int *)  msg->getContextPointer();
    	  createNode (*intValue); // create node dynamically
    	  delete intValue ;
    	  delete msg;
        }
      if (msg->getKind() == DELETE_NODE_MSG)
        {
          cModule * MSMP = (cModule *)msg->getContextPointer();
          deleteNode (MSMP);
          delete msg;
        }
      if (msg->getKind() == END_SIMULATION)
        {
    	  EndSimulationFlag = true;
    	  endSimulation();
        }
    }
  else delete msg;

}

void AAMDynamicNetworkConfigurator::createNode (int is)
{

        EV<<"Create New Node =============> Host-"<<index<<endl;
        std::stringstream name,displayString;
        name <<"userhost["<<is<< "]";
        // create (possibly compound) module and build its submodules (if  any)
        cModule *module = moduleType->create((name.str()).c_str(),this->getParentModule());
        // set up parameters and gate sizes before we set up its submodules

        // Setup Position
        int iVt = par("positionType");
        Coord c = SetNodesPositions (iVt);

        displayString <<"i=device/pocketpc_s;r=150,,grey71,1;is=n;p="<<c.x<<","<<c.y;
        module->finalizeParameters();
        module->setDisplayString((displayString.str()).c_str());
        module->buildInside();
        // module->setDisplayString("test");

        /* Create Profile for node creation */

        NodeInfo nI ;
        nI.mod_PTR = module;
        nI.nodeName = module->getFullName();
        nI.initialPos.x = c.x;
        nI.initialPos.y = c.y;
        nI.MP = getMainUnit (module); // main Unit pointer
        nI.MMo = getMobility (module);
        nI.ift = IPAddressResolver().interfaceTableOf(module);
        nI.rt = IPAddressResolver().routingTableOf(module);
        nI.CertType = nI.MP->CertificateType =  getRandCertificate();// assignCertificate();
        nI.NodeMan =findAuthNManOf(module)!=NULL;
        nI.scheduleToDeleteNode =false;
        nI.id = nI.MMo->nodeIndx= index;


        int j = 0;
        bool In = true;
        while (module->callInitialize(j))
        {
                if ( j==0 ) { ev<<" Set Node Coordination %%%%%%%%%%%%%%%%%%%%%%%%%%%%"<<endl; nI.MMo->SetPosition(c.x,c.y); }
                if (j == 2 && In )
                {
                        In = false ;
                        uint32 networkAddress = IPAddress(par("dyNetworkAddress").stringValue()).getInt();
              //uint32 netmask = IPAddress(par("netmask").stringValue()).getInt();
                        uint32 addr = networkAddress | uint32(is);
                        nI.address.set(addr);

                //      nodeInfo[index].address.set(addr);
                        EV<<"Address ------------------>>"<<addr<<endl ;

                        // find interface table and assign address to all (non-loopback) interfaces
                        IInterfaceTable *ift = nI.ift;
                //      IInterfaceTable *ift = nodeInfo[index].ift;
                        InterfaceEntry *ie = NULL;
                        for (int k=0; k<ift->getNumInterfaces(); k++)
                        {
                                ie = ift->getInterface(k);
                                if (!ie->isLoopback())
                                {
                                        ie->ipv4Data()->setIPAddress(IPAddress(addr));
                                        ie->ipv4Data()->setNetmask(IPAddress::ALLONES_ADDRESS); // full address must match for local delivery
                                }
                        }
                }

                j++;

        } // while end

  module->scheduleStart(simTime());
  CreationTimeVec.record(index);

  // Detetion Scheduling

  if (DeleteFlag )
  {

	 switch (DeletionType)

	  {

	  case 0 : // Random Deletion
		  if (uniform(0,1)< ((double) par("DeleteRate")))
		  {

			  cModule *KilledNode = nI.mod_PTR ;

			  nI.scheduleToDeleteNode =true;
			  std::stringstream msgNameDN;
			  msgNameDN<<"NodeDel-"<<nI.mod_PTR->getFullName();
			  nI.DeleteTimer =  new cMessage ((msgNameDN.str()).c_str(), DELETE_NODE_MSG);

			  nI.DeleteTimer->setContextPointer(KilledNode);

			 // killList.push_front(KilledNode);

			  ScheduledDelNodes++;

			  scheduleAt(uniform(simTime()+uniform(0,lifetimeMean), MaxSimulationTime) , (cMessage *) nI.DeleteTimer);
		  }

		  break;


	  case 1: // LifeTime Node Distribution
		  {
			  cModule *KilledNode = nI.mod_PTR ;
			  nI.scheduleToDeleteNode =true;

			  std::stringstream msgNameDN;
			  msgNameDN<<"NodeDel-"<<nI.mod_PTR->getFullName();
			  nI.DeleteTimer =  new cMessage ((msgNameDN.str()).c_str(), DELETE_NODE_MSG);

			  nI.DeleteTimer->setContextPointer(KilledNode);

			  //killList.push_front(KilledNode);

			  ScheduledDelNodes++;

			  scheduleAt( simTime()+ distributionFunction() , (cMessage *) nI.DeleteTimer);
		  }
		  break;
	  }

  }

  nodesInfo.push_back(nI);
  index++;
  NodesInPlayGround.record(nodesInfo.size());

}

bool AAMDynamicNetworkConfigurator::scheduleToDelete (cModule *MP,int TypNode,bool AuthUserNode)
{

	Enter_Method_Silent();
	NodeInfoVector::iterator nI_PTR_SchDEL;
	bool nodeExists = false ;
	bool deltFlag = false ;

	switch (TypNode)
	{
	case 0 : // User Node

        for (NodeInfoVector::iterator it = nodesInfo.begin(); it != nodesInfo.end(); it++)
          {
            if (it->mod_PTR == MP)
              {
                nodeExists = true;
                nI_PTR_SchDEL = it ;
              }
          }

          if  (!nodeExists) error ("Node is not in nodeInfo List - check the Node reference - %s", MP->getFullName());

          if (nI_PTR_SchDEL->DeleteTimer &&  nI_PTR_SchDEL->DeleteTimer->isScheduled())
          {
           if(nI_PTR_SchDEL->DeleteTimer->getArrivalTime() > simTime()+par("GraceLeaveDuration").doubleValue())
           {
        	cancelEvent ((cMessage *)nI_PTR_SchDEL->DeleteTimer );
        	 std::stringstream MsNa;
        	 MsNa<<nI_PTR_SchDEL->DeleteTimer->getName()<<"-Forced";
        	 nI_PTR_SchDEL->DeleteTimer->setName(MsNa.str().c_str());
            scheduleAt(simTime()+par("GraceLeaveDuration").doubleValue() , (cMessage *) nI_PTR_SchDEL->DeleteTimer);

            }
           deltFlag = true ;
          }
          else // not Scheduled to be deleted
          {

        	  cModule *KilledNode = nI_PTR_SchDEL->mod_PTR ;
			  std::stringstream msgNameDN;


			  if (!AuthUserNode) // node needs to be deleted because it failed to authenticate
			  {
				  nI_PTR_SchDEL->scheduleToDeleteNode = deltFlag = true;
				  msgNameDN<<"NodeDel-"<<nI_PTR_SchDEL->mod_PTR->getFullName()<<"-Forced";
			      nI_PTR_SchDEL->DeleteTimer =  new cMessage ((msgNameDN.str()).c_str(), DELETE_NODE_MSG);
			      nI_PTR_SchDEL->DeleteTimer->setContextPointer(KilledNode);


				  scheduleAt(simTime()+par("GraceLeaveDuration").doubleValue(), (cMessage *) nI_PTR_SchDEL->DeleteTimer);
				  ScheduledDelNodes++;
				  LifeTimeNodeSetDeltaInNet.record(par("GraceLeaveDuration").doubleValue());

			  }
			  else // node could be deleted because it may a specific lifetime to be in the network
			  {
                  double dt = 0;
	    		 switch (DeletionType)
				  {

					  case 0 : // Random Deletion - Generic  Random Model
						  if (uniform(0,1)< ((double) par("DeleteRate")))
						  {

							  nI_PTR_SchDEL->scheduleToDeleteNode = deltFlag = true;
							  msgNameDN<<"NodeDel-"<<nI_PTR_SchDEL->mod_PTR->getFullName();
						      nI_PTR_SchDEL->DeleteTimer =  new cMessage ((msgNameDN.str()).c_str(), DELETE_NODE_MSG);
						      nI_PTR_SchDEL->DeleteTimer->setContextPointer(KilledNode);

							  ScheduledDelNodes++;
							 // dt = uniform(par("GraceLeaveDuration").doubleValue(),lifetimeMean);
							  dt = truncnormal(lifetimeMean, lifetimeMean/3);
							  scheduleAt(simTime()+dt, (cMessage *) nI_PTR_SchDEL->DeleteTimer);
							  LifeTimeNodeSetDeltaInNet.record(dt);
						  }
						  break;

					  case 1: // LifeTime Node Distribution
						  {
							  nI_PTR_SchDEL->scheduleToDeleteNode = deltFlag = true;
							  msgNameDN<<"NodeDel-"<<nI_PTR_SchDEL->mod_PTR->getFullName();
						      nI_PTR_SchDEL->DeleteTimer =  new cMessage ((msgNameDN.str()).c_str(), DELETE_NODE_MSG);
						      nI_PTR_SchDEL->DeleteTimer->setContextPointer(KilledNode);

						      ScheduledDelNodes++;
						      dt =  distributionFunction() ;
							  scheduleAt( simTime()+dt, (cMessage *) nI_PTR_SchDEL->DeleteTimer);
							  LifeTimeNodeSetDeltaInNet.record(dt);
						  }
						 break;
				 } // Switch End

			  } // Else End

          }
       break;

	case 1 : // AuthenTiion Manager Node

        for (NodeInfoVector::iterator it = AuthNManVec.begin(); it != AuthNManVec.end(); it++)
          {
            if (it->mod_PTR == MP)
              {
                nodeExists = true;
                nI_PTR_SchDEL = it ;
              }
          }
          if  (!nodeExists) error ("Manager Node is not in AuthNManVec List - check the Node reference - %s", MP->getFullName());

          if (nI_PTR_SchDEL->DeleteTimer &&  nI_PTR_SchDEL->DeleteTimer->isScheduled())
          {
           if(nI_PTR_SchDEL->DeleteTimer->getArrivalTime() > simTime()+par("GraceLeaveDuration").doubleValue())
           {
        	cancelEvent ((cMessage *)nI_PTR_SchDEL->DeleteTimer );
            scheduleAt(simTime()+par("GraceLeaveDuration").doubleValue() , (cMessage *) nI_PTR_SchDEL->DeleteTimer);
            }
           deltFlag = true ;
          }
          else // not Scheduled to be deleted
          {
			  cModule *KilledNode = nI_PTR_SchDEL->mod_PTR ;

			  nI_PTR_SchDEL->scheduleToDeleteNode = deltFlag = true;

			  std::stringstream msgNameDN;
			  msgNameDN<<"NodeDel-Forced"<<nI_PTR_SchDEL->mod_PTR->getFullName();
			  nI_PTR_SchDEL->DeleteTimer =  new cMessage ((msgNameDN.str()).c_str(), DELETE_NODE_MSG);
			  nI_PTR_SchDEL->DeleteTimer->setContextPointer(KilledNode);
			  ScheduledDelNodes++;
			  scheduleAt(simTime()+par("GraceLeaveDuration").doubleValue() , (cMessage *) nI_PTR_SchDEL->DeleteTimer);
          }
		break;

	case 2 :

        for (NodeInfoVector::iterator it = TraffGenSrManVec.begin(); it != TraffGenSrManVec.end(); it++)
          {
            if (it->mod_PTR == MP)
              {
                nodeExists = true;
                nI_PTR_SchDEL = it ;
              }
          }
          if  (!nodeExists) error ("TrafGenSr Node is not in TraffGenSrManVec List - check the Node reference - %s", MP->getFullName());

          if (nI_PTR_SchDEL->DeleteTimer &&  nI_PTR_SchDEL->DeleteTimer->isScheduled())
          {
           if(nI_PTR_SchDEL->DeleteTimer->getArrivalTime() > simTime()+par("GraceLeaveDuration").doubleValue())
           {
        	cancelEvent ((cMessage *)nI_PTR_SchDEL->DeleteTimer );
            scheduleAt(simTime()+par("GraceLeaveDuration").doubleValue() , (cMessage *) nI_PTR_SchDEL->DeleteTimer);
            }
           deltFlag = true ;
          }
          else // not Scheduled to be deleted
          {
			  cModule *KilledNode = nI_PTR_SchDEL->mod_PTR ;

			  nI_PTR_SchDEL->scheduleToDeleteNode = deltFlag = true;

			  std::stringstream msgNameDN;
			  msgNameDN<<"NodeDel-Forced"<<nI_PTR_SchDEL->mod_PTR->getFullName();
			  nI_PTR_SchDEL->DeleteTimer =  new cMessage ((msgNameDN.str()).c_str(), DELETE_NODE_MSG);
			  nI_PTR_SchDEL->DeleteTimer->setContextPointer(KilledNode);
			  ScheduledDelNodes++;
			  scheduleAt(simTime()+par("GraceLeaveDuration").doubleValue() , (cMessage *) nI_PTR_SchDEL->DeleteTimer);

          }

		break;


	default : error("Error in Node Type..........");
	}

  return deltFlag;
}

void  AAMDynamicNetworkConfigurator::deleteNode (cModule *MP)
{

//             cModule *module  = (cModule *) msg->getContextPointer() ;
//
//            cModule *module = killList.back();
//            killList.pop_back();

            NodeInfoVector::iterator nI_PTR_DEL;
            bool nodeExists = false ;

            for (NodeInfoVector::iterator it = nodesInfo.begin(); it != nodesInfo.end(); it++)
              {
                if (it->mod_PTR == MP)
                  {
                    nodeExists = true;
                    nI_PTR_DEL = it ;
                  }
              }

            if  (!nodeExists) error ("Node is not in nodeInfo List - check the Node reference - %s", MP->getFullName());


            IInterfaceTable *ift = nI_PTR_DEL->ift;
            InterfaceEntry *ie = NULL;

            for (int k=0; k<ift->getNumInterfaces(); k++)
              {
                ie = ift->getInterface(k);
                if (!ie->isLoopback())
                  {
                    delete ie->ipv4Data();
                  }
              }



            DeletionTimeVec.record(nI_PTR_DEL->id); // record the time of id Node Deletion

            ev<< "|-----Remove Node Record from TrafficGenSrMan Node -----|"<<endl;


            for (std::list<NodeInfo>::iterator iit = TraffGenSrManVec.begin(); iit != TraffGenSrManVec.end(); iit++)
              {
                iit->TraffGenSrMan_PTR->DeactiveNodeRecord(nI_PTR_DEL->nodeName);
                ev<< "Deactivate "<<nI_PTR_DEL->nodeName<< " in Generator:"<<iit->nodeName<<endl;
              }

            ev<< "|-------------Remove Node IP interface -----------------|"<<endl;

            if (ccp->lookupHost(MP)) ccp->unregisterHost(MP);

            ev<< "|-------------Remove Node Control Channel --------------|"<<endl;

            MP->callFinish();
            MP->deleteModule();

            ev<< "|---------Remove Node from the Control Channel ---------|"<<endl;

            NodeInfo DelNI ;
            DelNI.mod_PTR = NULL ;
            DelNI.nodeName = nI_PTR_DEL->nodeName ;
            DelNI.initialPos.x = nI_PTR_DEL->initialPos.x;
            DelNI.initialPos.y = nI_PTR_DEL->initialPos.y;
            DelNI.MP = NULL;
            DelNI.MMo = NULL;
            DelNI.ift = NULL;
            DelNI.rt =  NULL;
            DelNI.CertType = nI_PTR_DEL->CertType ;// assignCertificate();
            DelNI.NodeMan = nI_PTR_DEL->NodeMan ;
            DelNI.scheduleToDeleteNode =true ;
            DelNI.id = nI_PTR_DEL->id ;
            DelNI.deInx = DelIndex ;
            DelNI.Deltime = simTime();

            nodesInfo.erase(nI_PTR_DEL) ;
            DeletedNodesInfo.push_back(DelNI); // log node deletion

            DelIndex++ ;
            // remove node from the node list

            ev<< "|-------------Remove Node From Node List ---------------|"<<endl;
            ScheduledDelNodes--;
            NodesInPlayGround.record(nodesInfo.size());

            nodeLeavers++;
    		if(simTime()- LastDeleteNodeTime >=  par("TimeScale").doubleValue() )
    		    {
    			  LeaveRateVec.record(( nodeLeavers/(simTime()-LastDeleteNodeTime))* par("TimeScale").doubleValue());
    			  LastDeleteNodeTime = simTime() ;
    			  nodeLeavers = 0 ;
    		    }



}

void  AAMDynamicNetworkConfigurator::setupCertficateCounters ()
{
	CorruptedCertPrc = par("CorCertP");
	GlodenCertPrc = par("GoldenCertP");
	SilverCertPrc = par("SilverCertP");
	BronzeCertPrc = par("BronzeCertP");

	CorruptCerCount = floor(CorruptedCertPrc * int(par("numHosts"))) ;

	if ( CorruptCerCount < 1 )
	{
		if (CorruptCerCount < 0.5 )
		{
			CorruptCerCount = 0 ;
		}
		else CorruptCerCount = 1;
	}
	//   error  (" Error in Percentage of Corrupt n= %d of %d",CorruptCerCount,numIPNodes);

	GoldenCerCount  = floor(GlodenCertPrc * int(par("numHosts"))) ;

	if ( GoldenCerCount < 1 )
	{
		if (GoldenCerCount < 0.5 )
		{
			GoldenCerCount = 0 ;
		}
		else GoldenCerCount = 1;
	}


	// if ( GoldenCerCount < 1 ) error  (" Error in Percentage of Golden n= %d of %d",GoldenCerCount,numIPNodes);

	SilverCerCount = floor(SilverCertPrc* int(par("numHosts")))  ;
	if ( SilverCerCount < 1 )
	{
		if (SilverCerCount < 0.5 )
		{
			SilverCerCount = 0 ;
		}
		else SilverCerCount = 1;
	}

	// error  (" Error in Percentage of Silver n= %d of %d",SilverCerCount,numIPNodes);
	BronzeCerCount= floor(BronzeCertPrc* int(par("numHosts")))  ;
	if (BronzeCerCount < 1 )
	{
		if (BronzeCerCount  < 0.5 )
		{
			BronzeCerCount  = 0 ;
		}
		else BronzeCerCount  = 1;
	}

	  int xTotal =CorruptCerCount+GoldenCerCount+SilverCerCount+BronzeCerCount;
	  if (xTotal != (int)par("numHosts") )
	     {
		   	 if ( xTotal < (int)par("numHosts") ) BronzeCerCount += ((int)par("numHosts")-xTotal);
		   	 else  error (" Error in Distribute the Percentage");
	     }
}
std::string AAMDynamicNetworkConfigurator::assignCertificate()
{

  int xRNG = par("SetRNG");


  ev<<"%%%%%%%%%%%%%%%%%%%%%%%%%%%% start to Initialise Random Certificates to the nodes %%%%%%%%%%%%%%%%%%%"<<endl ;

  bool InWhile = true ;
  int rCert;

  if ((CorruptCerCount+GoldenCerCount+SilverCerCount+BronzeCerCount)!=0)
  {
	  do
	  {
		  rCert = genk_intrand(xRNG,CertificateClasses.size());
		  switch (rCert)
		  {
		   case 0 : if (CorruptCerCount>0) { CorruptCerCount--; InWhile = false;}; break;
		   case 1 : if (GoldenCerCount > 0) { GoldenCerCount--; InWhile = false;}; break;
		   case 2 : if (SilverCerCount> 0) {SilverCerCount--; 	InWhile = false;}; break;
		   case 3 : if (BronzeCerCount> 0) {BronzeCerCount--;  	InWhile = false;}; break;
		  }
	  } while (InWhile);

      // Set the Certificate Type
  ev<<"@The Certificate index =>>>>>>>>>>>>>>>>>>>>>>>>>>>"<<CertificateClasses[rCert]<<endl;
  ev<<"%%%%%%%%%%%%%%%%%%%%%%%%%%% Finish from initialising Random Certificates to the nodes count :%%%%%%%%%%%%%%%%%%%%%"<<endl ;

    }
   else
	   {
	   error (" Error No enough Certificate to  assign");
	   }

  return (CertificateClasses[rCert]);
}
std::string AAMDynamicNetworkConfigurator::getRandCertificate()
{

  int xRNG = par("SetRNG");

  ev<<"%%%%%%%%%%%%%%%%%%%%%%%%%%%% start to Initialise Random Certificates to the nodes %%%%%%%%%%%%%%%%%%%"<<endl ;

  double x = uniform(0,1,xRNG);
  double c0,c1,c2,c3,cx ;

  c0 = par("CorCertP") ;
  c1 = par("GoldenCertP");
  c2 = par("SilverCertP");
  c3 = par("BronzeCertP");

  cx = 100-c3+c2+c1+c0 ;

  ev << "Random Value to pick Certificate -->"<< x<<" Total"<<c3+c2+c1+c0 <<endl;

  if (x < c0) return (CertificateClasses[0]) ;
  else if (x < c1+c0) return (CertificateClasses[1]);
  else if (x < c2+c1+c0) return (CertificateClasses[2]);
  else if (x < c3+c2+c1+c0+cx ) return (CertificateClasses[3]);

  error (" No Certificate be assigned, check your percent of Certificate counters ?");

  return (0);
}

mainUnit *AAMDynamicNetworkConfigurator::getMainUnit (cModule *host)
{
  cModule *mod = host->getSubmodule("MainUnit");
  if (!mod)
      opp_error("MainUnit is not found as submodule "
                " `Main Unit' in Node `%s'", host->getFullPath().c_str());
  return check_and_cast<mainUnit *>(mod);
}
BasicMobility *AAMDynamicNetworkConfigurator::getMobility(cModule *host)
{
  cModule *mod = host->getSubmodule("mobility");
  if (!mod)
      opp_error("mobility is not found as submodule "
                " `mobility' in Node `%s'", host->getFullPath().c_str());
  return check_and_cast<BasicMobility *>(mod);
}
AuthNManager *AAMDynamicNetworkConfigurator::findAuthNManOf(cModule *host )
{
  cModule *mod = host->getSubmodule("udpApp",0);
  return dynamic_cast <AuthNManager *> (mod);
  //  return (AuthNManager *) mod;

}
AuthNManager *AAMDynamicNetworkConfigurator::getAuthNManOf(cModule *host)
{
  cModule *mod = host->getSubmodule("udpApp",0);
  if (!mod)
      opp_error("Authentication Manger is not found as submodule "
                " `AuthNManager' in Node `%s'", host->getFullPath().c_str());
  return check_and_cast<AuthNManager *>(mod);
}

TraffGenSrMan *AAMDynamicNetworkConfigurator::getTraffGenSrMan(cModule *host)
{
  cModule *mod = host->getSubmodule("TraffGenSrMan");
  if (!mod)
      opp_error("mobility is not found as submodule "
                " `mobility' in Node `%s'", host->getFullPath().c_str());
  return check_and_cast<TraffGenSrMan *>(mod);
}

TraffGenSrMan *AAMDynamicNetworkConfigurator::findTraffGenSrManOf(cModule *host )
{
  cModule *mod = host->getSubmodule("TraffGenSrMan");
  return dynamic_cast <TraffGenSrMan *> (mod);
  //  return (AuthNManager *) mod;

}

Coord AAMDynamicNetworkConfigurator::SetNodesPositions(int pType)
{
	Coord cC ;
	int marginX = 10;
	int marginY = 10;
	int size,col ;
	double row;
	int indxIA ;
	unsigned int indR ;
	std::list<int>::iterator ite;
	int nT = int( par("numHosts"));

	 switch (pType)
			  {
			   case -1 : // fixed Coordinations
				cC.x = 0;
				cC.y = 0;
				break;

			   case 0 : // get Random Coordinations
						cC.x = uniform(0,ccp->getPgs()->x);
						cC.y = uniform(0,ccp->getPgs()->y);
						break;
			   case 1 : // get Grid coordinations Normal "index" from Create Node function
						size = (int)ceil (sqrt(nT));
						row  = ceil(index / size);
						col  = index % size;
						cC.x = marginX + col * (ccp->getPgs()->x - 2*marginX) / (size-1);
						if(cC.x >= ccp->getPgs()->x) cC.x -=1;
						cC.y = marginY + row * (ccp->getPgs()->y - 2*marginY) / (size-1);
						if(cC.y  >= ccp->getPgs()->y) cC.y -=1;
						break;
			   case 2 :
				       // generate random index for node
						indR = intrand(iA.size()) ;
						ite = iA.begin();
						if (indR ==(iA.size()-1)) indxIA = iA.back(); // index at list end
						else if (indR>0)
						  {
							// index in the middle
							advance(ite,indR);
							indxIA = *ite; // get the randomised ID of the node from xList2
						  }
						else indxIA = *ite ; // index a the begin of the list

						iA.remove(indxIA); // remove the index from node list

						// get Grid coordinations Randomly
						size = (int)ceil (sqrt(nT));
						row  = ceil(indxIA / size);
						col  = indxIA % size;
						cC.x = marginX + col * (ccp->getPgs()->x - 2*marginX) / (size-1);
						if(cC.x >= ccp->getPgs()->x) cC.x -=1;
						cC.y = marginY + row * (ccp->getPgs()->y - 2*marginY) / (size-1);
						if(cC.y  >= ccp->getPgs()->y) cC.y -=1;
						break;
			   case 3 :
			   {
				   std::stringstream xfName;
				   const BonnMotionFile::Line *vecp;

		        xfName<<par("traceFile").stdstringValue()<<CurrentRunNumber<<".movements";

		        const char *fname = xfName.str().c_str();

		        const BonnMotionFile *bmFile = BonnMotionFileCache::getInstance()->getFile(fname);

		        vecp = bmFile->getLine(index);

		        if (!vecp)
		            error("invalid nodeId %d -- no such line in file '%s'", index, fname);

		        // obtain initial position from the file
		        const BonnMotionFile::Line& vec = *vecp;
		        if (vec.size()>=3)
		        {
		        	cC.x = vec[1];
		        	cC.y = vec[2];
			    }
		        else error ("Error in File movements");
			   }
			   break;

			  default :
				  error (" Error in Set Position Type");

			  }

     return cC;

}

double AAMDynamicNetworkConfigurator::distributionFunction()
{
    double par;

    if (lifetimeDistName == "weibull") {
        par = lifetimeMean / tgamma(1 + (1 / lifetimeDistPar1));
        return weibull(par, lifetimeDistPar1);
    } else if (lifetimeDistName == "pareto_shifted") {
        par = lifetimeMean * (lifetimeDistPar1 - 1) / lifetimeDistPar1;
        return pareto_shifted(lifetimeDistPar1, par, 0);
    } else if (lifetimeDistName == "truncnormal") {
        par = lifetimeMean;
        return truncnormal(par, par/3.0);
    } else if (lifetimeDistName == "exponential") {
    	par = lifetimeMean ;
    	return (exponential(par));
    }else {
        opp_error("LifetimeChurn::distribution function: Invalid value "
            "for parameter lifetimeDistName!");
    }

    return lifetimeMean;
}

void AAMDynamicNetworkConfigurator::finish()
{

	// for testing purpose

	recordScalar("AAMDyNetworkConfig LastschedNodeCreation",LastschedNodeCreation.dbl());

	if (simTime()==0)
		return ;


	if (simTime()!=laTime) // record final Vec Values
	{
	  if(CRate !=0)
		  {
		  SucessRateVec.record((CRate/(simTime()-laTime))*par("TimeScale").doubleValue());
		  AVG_SucRate += (CRate/(simTime()-laTime))*par("TimeScale").doubleValue() ;
			FractionalSucessRatioVec.record(((double)CRate)/((double)(SucNd)));
			AVG_FracSucRatio +=((double)CRate)/((double)(SucNd));
			SC++;
		  }
		SucessRatioVec.record(((double)SucNd)/((double)index));
		AVG_SucRatio += ((double)SucNd)/((double)index);

	}

	if (simTime()!=llaTime)
	{
		if(CFRate !=0)
			{
			FailRateVec.record((CFRate/(simTime()-llaTime))* par("TimeScale").doubleValue());
			AVG_FailRate += (CFRate/(simTime()-llaTime))* par("TimeScale").doubleValue();
			FC++;
			}

	}


	recordScalar("AAMDyNetworkConfig CreatedNodeTotal", index) ;
	recordScalar("AAMDyNetworkConfig DeletedNodeTotal", DelIndex);
	recordScalar("AAMDyNetworkConfig ScheduledDelNodes", ScheduledDelNodes);

	recordScalar("AAMDyNetworkConfig TotalSucessNodes",  SucNd) ;
	recordScalar("AAMDyNetworkConfig TotalFailedNodes",  FailNd);
	recordScalar("AAMDyNetworkConfig SucAuthnCAS",SucAuthnCAS);
	recordScalar("AAMDyNetworkConfig SucAuthnTAS",SucAuthnTAS);
	recordScalar("AAMDyNetworkConfig SucAuthnDAS",SucAuthnDAS);
	recordScalar("AAMDyNetworkConfig SucDeltNode", SucDeltNode );
	recordScalar("AAMDyNetworkConfig failDeltNode", failDeltNode);

	recordScalar("AAMDyNetworkConfig SucessReqRatio",(double)SucNd/(double)TotalReq);
	recordScalar("AAMDyNetworkConfig SucessReqRatioST",(double)TotalSucreq/(double)TotalReq);

	recordScalar("AAMDyNetworkConfig TotalReq",TotalReq);
	recordScalar("AAMDyNetworkConfig TotalSucReq",TotalSucreq);

	if(DelIndex !=0)
	{
		recordScalar("AAMDyNetworkConfig SucDeltNode_PRC", SucDeltNode/ (double) DelIndex );
		recordScalar("AAMDyNetworkConfig failDeltNode_PRC", failDeltNode/ (double)DelIndex );
	}


	recordScalar("AAMDyNetworkConfig TotalSucessRate", (SucNd/simTime())*par("TimeScale").doubleValue());
	recordScalar("AAMDyNetworkConfig SuccessRatio", ((double)SucNd)/((double)index)) ;

	if (SucNd != 0)
	{
	 recordScalar("AAMDyNetworkConfig AVG_RTT", AVG_RTT/((double)SucNd));
	 recordScalar("AAMDyNetworkConfig AVG_SetlTime", AVG_SetlTime/((double)SucNd));
	 recordScalar("AAMDyNetworkConfig AVG_ComOverhead", AVG_ComOverhead /((double)SucNd));

	 recordScalar("AAMDyNetworkConfig SucAuthnCAS_PRC",SucAuthnCAS/(double)SucNd);
	 recordScalar("AAMDyNetworkConfig SucAuthnTAS_PRC",SucAuthnTAS/(double)SucNd);
	 recordScalar("AAMDyNetworkConfig SucAuthnDAS_PRC",SucAuthnDAS/(double)SucNd);
	}

    if (SC !=0)
    {
	 recordScalar("AAMDyNetworkConfig AVG_AccumulativeSuccessRatio", AVG_SucRatio/(double)SC);
	 recordScalar("AAMDyNetworkConfig AVG_SuccessRate", AVG_SucRate/(double)SC);
	 recordScalar("AAMDyNetworkConfig AVG_FractionalSuccessRatio", AVG_FracSucRatio/(double)SC);
    }

	if (FC!=0)
	recordScalar("AAMDyNetworkConfig AVG_FailRate",AVG_FailRate/(double)FC);


	std::ofstream myJoinersFile, myLeaversFile;

	std::stringstream fileName1,fileName2;

	fileName1 << "JoinersFile-" << ev.getConfigEx()->getActiveRunNumber()<<".txt";
	fileName2 << "LeaversFile-" << ev.getConfigEx()->getActiveRunNumber()<<".txt";

	if (nodesInfo.size() !=0)
	{

		myJoinersFile.open (fileName1.str().c_str());
		for (NodeInfoVector::iterator ift = nodesInfo.begin(); ift != nodesInfo.end(); ift++)
		{
			myJoinersFile	<< ift->nodeName <<" "
			<< ift->address.str()			 <<" "
			<< ift->CertType				 <<" "
			<<"x="<<ift->initialPos.x		 <<" "
			<<"y="<<ift->initialPos.y		 <<" "
			<<"CreationIndex ="<< ift->id  	 <<" "
			<<"To be deleted ="<< (ift->scheduleToDeleteNode? "Yes":"No") <<"\n";
		}

		myJoinersFile.close();
	}

	if (DeletedNodesInfo.size() !=0)
	{
		myLeaversFile.open (fileName2.str().c_str());
		for (NodeInfoVector::iterator ift = DeletedNodesInfo.begin(); ift != DeletedNodesInfo.end(); ift++)
		{
			myLeaversFile  << ift->nodeName  <<" "
			<< ift->address.str()			 <<" "
			<< ift->CertType				 <<" "
			<<"x="<<ift->initialPos.x		 <<" "
			<<"y="<<ift->initialPos.y		 <<" "
			<<"CreationIndex ="<< ift->id  	 <<" "
			<<"deletionIndex ="<<ift->deInx  <<" "
			<<"Deletion time ="<<ift->Deltime <<" "
			<<"\n";
		}

		myLeaversFile.close();
	}


}
void AAMDynamicNetworkConfigurator::ManageTrafGenSrHost ()
{

  cTopology topo("topo");

  int idx = 0 ;
  // extract topology
   topo.extractByProperty("node");
   EV << "cTopology found " << topo.getNumNodes() << " nodes\n";

  //  TraffGenSrManVec.resize(topo.getNumNodes());

   for (int i=0; i<topo.getNumNodes(); i++)
   {
     cModule *mod = topo.getNode(i)->getModule();

     if (!findTraffGenSrManOf(mod) || !IPAddressResolver().findInterfaceTableOf(mod)) continue;

     NodeInfo nI;
     idx++;

     nI.TraffGenSrMan_PTR = getTraffGenSrMan (mod);

     nI.mod_PTR = mod;
     nI.nodeName = mod->getFullName();

     nI.MP = getMainUnit (mod); // main Unit pointer
     nI.MMo = getMobility (mod);

     nI.initialPos.x = -1;
     nI.initialPos.y = -1;

     nI.ift = IPAddressResolver().interfaceTableOf(mod);
     nI.rt = IPAddressResolver().routingTableOf(mod);
     nI.address = IPAddressResolver().getAddressFrom(nI.ift,2).get4();

     nI.CertType = "NA";
     nI.NodeMan =findAuthNManOf(mod)!=NULL;
     nI.scheduleToDeleteNode =false;
     nI.id = -1 ;

     TraffGenSrManVec.push_back(nI);
   }
   EV << "cTopology TraffGenSrMan found  " << idx << " nodes\n";
}

void AAMDynamicNetworkConfigurator::ManageAuthNMANHost ()
{

  cTopology topo("topo");

  int idx = 0 ;
  // extract topology
   topo.extractByProperty("node");

   EV << "cTopology found " << topo.getNumNodes() << " nodes\n";

  // AuthNManVec.resize(topo.getNumNodes());

   for (int i=0; i<topo.getNumNodes(); i++)
   {
     cModule *mod = topo.getNode(i)->getModule();


     if (!findAuthNManOf(mod) || !IPAddressResolver().findInterfaceTableOf(mod)) continue;

     NodeInfo nI;
     idx++;

     nI.AuthMAN_PTR = getAuthNManOf(mod);

     nI.mod_PTR = mod;
     nI.nodeName = mod->getFullName();
     nI.MP = getMainUnit (mod); // main Unit pointer

     nI.MMo = getMobility (mod);

     nI.initialPos.x = -1;
     nI.initialPos.y = -1;

     nI.ift = IPAddressResolver().interfaceTableOf(mod);
     nI.rt = IPAddressResolver().routingTableOf(mod);
     nI.address = IPAddressResolver().getAddressFrom(nI.ift,2).get4();

     nI.CertType = "NA";
     nI.NodeMan =true;
     nI.scheduleToDeleteNode =false;
     nI.id = -1 ;

     AuthNManVec.push_back(nI);
   }
   EV << "cTopology found AuthNMAN " << idx << " nodes\n";
}

void AAMDynamicNetworkConfigurator::UpdateStatistic(double Val,double St,int Tc, int t,int MemCert, int  ToReq)
{

	Enter_Method_Silent();

	TotalReq += ToReq; // total Request

	switch (t)
	{
	case 0 : // Successful Authentication Node

		SucNd++;
		CRate ++;
		TotalSucreq += ToReq;

		if((simTime()- laTime) >= par("TimeScale").doubleValue())
		    {
			  SucessRateVec.record((CRate/(simTime()-laTime))*par("TimeScale").doubleValue());
			  AVG_SucRate += (CRate/(simTime()-laTime))*par("TimeScale").doubleValue() ;

			  SucessRatioVec.record(((double)SucNd)/((double)index));
			  AVG_SucRatio += ((double)SucNd)/((double)index);

//		      if(indxTempSR != index)
//		    	{
//		    	  FractionalSucessRatioVec.record(((double)CRate)/((double)(index-indxTempSR)));
//		    	  AVG_FracSucRatio +=((double)CRate)/((double)(index-indxTempSR)) ;
//		    	}
//		      else  FractionalSucessRatioVec.record(0);

			  FractionalSucessRatioVec.record(((double)CRate)/((double)(SucNd)));
			  AVG_FracSucRatio +=((double)CRate)/((double)(SucNd));

		      CRate  = 0;
		     // indxTempSR = index;
		      laTime = simTime() ;
		      SC++;

		    }



		RTTNodeVec.record(Val); // record Round Trip Time
		AVG_RTT += Val;
		SettlingTimeVec.record(St+Val); // record Settling Time
		AVG_SetlTime += (St+Val);
		TotalCommOverheadVec.record(Tc); // record Overhead communication
		AVG_ComOverhead +=Tc ;

	   switch(MemCert)
	   {
	   case 0 : SucAuthnCAS++; break;
	   case 1 : SucAuthnTAS++ ; break;
	   case 2 : SucAuthnDAS++ ; break;
	   default: error ("Error in Membership Certificate ");
	   }
	   SuccessNodeTypesVec.record(MemCert);
       break;

	case 1 : // Unsuccessful Authentication Node

		FailNd++;
		CFRate ++;
		if(simTime()- llaTime >=  par("TimeScale").doubleValue() )
		    {
			  FailRateVec.record((CFRate/(simTime()-llaTime))* par("TimeScale").doubleValue());
			  AVG_FailRate += (CFRate/(simTime()-llaTime))* par("TimeScale").doubleValue();
		      CFRate = 0;
		      llaTime = simTime() ;
		      FC++;
		    }

		break;

	case 2 : // update LifeTime Node
		LifeTimeNodeInNet.record(Val);
		SessionLengthNodeInNet.record(Val-St);

		if(Tc==0)
		failDeltNode ++ ;
		else
		SucDeltNode++;


		break;

	default : error("Error in Statistic Type");
	}

    SucessReqRatioVec.record((double)SucNd/(double)TotalReq);
    SucessReqRatioSTVec.record((double)TotalSucreq/(double)TotalReq);

}




