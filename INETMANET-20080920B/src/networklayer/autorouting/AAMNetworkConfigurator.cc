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

#include "AAMNetworkConfigurator.h"
#include <algorithm>
#include "IRoutingTable.h"
#include "IInterfaceTable.h"
#include "IPAddressResolver.h"
#include "InterfaceEntry.h"
#include "IPv4InterfaceData.h"


Define_Module(AAMNetworkConfigurator);


void AAMNetworkConfigurator::initialize(int stage)
{


      ManIn = 0;
      CertificateClasses.push_back("CorruptedIDCert");
      CertificateClasses.push_back("GoldenIDCert");
      CertificateClasses.push_back("SilverIDCert");
      CertificateClasses.push_back("BronzeIDCert");

      ccp = ChannelControl::get();

     cTopology topo("topo");
     NodeInfoVector nodeInfo;
     if (stage==2)
       {
     // will be of size topo.nodes[]

        // extract topology into the cTopology object, then fill in
        // isIPNode, rt and ift members of nodeInfo[]
        extractTopology(topo, nodeInfo);

        // assign addresses to IP nodes, and also store result in nodeInfo[].address
        assignAddresses(topo, nodeInfo);

        // add default routes to hosts (nodes with a single attachment);
        // also remember result in nodeInfo[].usesDefaultRoute
        addDefaultRoutes(topo, nodeInfo);

        // calculate shortest paths, and add corresponding static routes
        fillRoutingTables(topo, nodeInfo);

        // update display string
        setDisplayString(topo, nodeInfo);

        // Assign Certificate to Node of the networks
        assignCertificate (topo, nodeInfo);

        // Assign new position to the node

        SetNodesPositions (topo,nodeInfo);

        WATCH(CorruptCerCount);
        WATCH(GoldenCerCount);
        WATCH (SilverCerCount);
        WATCH(BronzeCerCount);
        WATCH (ManIn);
       }

}

void AAMNetworkConfigurator::extractTopology(cTopology& topo, NodeInfoVector& nodeInfo)
{
    // extract topology
    topo.extractByProperty("node");
    EV << "cTopology found " << topo.getNumNodes() << " nodes\n";

    // fill in isIPNode, ift and rt members in nodeInfo[]
    nodeInfo.resize(topo.getNumNodes());
    for (int i=0; i<topo.getNumNodes(); i++)
    {
       //  cModule *mod = topo.getNode(i)->getModule();
        cModule *mod = nodeInfo [i].mod_PTR = topo.getNode(i)->getModule();

        nodeInfo[i].isIPNode = IPAddressResolver().findInterfaceTableOf(mod)!=NULL;

        nodeInfo[i]. NodeMan= findAuthNManOf(mod)!=NULL; // Salah

        nodeInfo[i].MP = getMainUnit (mod); // main Unit pointer

        nodeInfo[i].MMo = getMobility (mod);

        if (nodeInfo[i].isIPNode)
        {
            nodeInfo[i].ift = IPAddressResolver().interfaceTableOf(mod);
            nodeInfo[i].rt = IPAddressResolver().routingTableOf(mod);
        }

        if (nodeInfo[i].NodeMan) { nodeInfo[i].AuthMAN_PTR = getAuthNManOf (mod); ManIn++;}  ; // Salah

    }
}

void AAMNetworkConfigurator::assignAddresses(cTopology& topo, NodeInfoVector& nodeInfo)
{
    // assign IP addresses
    uint32 networkAddress = IPAddress(par("networkAddress").stringValue()).getInt();
    uint32 netmask = IPAddress(par("netmask").stringValue()).getInt();
    int maxNodes = (~netmask)-1;  // 0 and ffff have special meaning and cannot be used
    if (topo.getNumNodes()>maxNodes)
        error("netmask too large, not enough addresses for all %d nodes", topo.getNumNodes());

    int numIPNodes = 0;
    for (int i=0; i<topo.getNumNodes(); i++)
    {
        // skip bus types
        if (!nodeInfo[i].isIPNode)
            continue;

        uint32 addr = networkAddress | uint32(++numIPNodes);
        nodeInfo[i].address.set(addr);

        // find interface table and assign address to all (non-loopback) interfaces
        IInterfaceTable *ift = nodeInfo[i].ift;
        for (int k=0; k<ift->getNumInterfaces(); k++)
        {
            InterfaceEntry *ie = ift->getInterface(k);
            if (!ie->isLoopback())
            {
                ie->ipv4Data()->setIPAddress(IPAddress(addr));
                ie->ipv4Data()->setNetmask(IPAddress::ALLONES_ADDRESS); // full address must match for local delivery
            }
        }
    }
}

void AAMNetworkConfigurator::addDefaultRoutes(cTopology& topo, NodeInfoVector& nodeInfo)
{
    // add default route to nodes with exactly one (non-loopback) interface
    for (int i=0; i<topo.getNumNodes(); i++)
    {
        cTopology::Node *node = topo.getNode(i);

        // skip bus types
        if (!nodeInfo[i].isIPNode)
            continue;

        IInterfaceTable *ift = nodeInfo[i].ift;
        IRoutingTable *rt = nodeInfo[i].rt;

        // count non-loopback interfaces
        int numIntf = 0;
        InterfaceEntry *ie = NULL;
        for (int k=0; k<ift->getNumInterfaces(); k++)
            if (!ift->getInterface(k)->isLoopback())
                {ie = ift->getInterface(k); numIntf++;}

        nodeInfo[i].usesDefaultRoute = (numIntf==1);
        if (numIntf!=1)
            continue; // only deal with nodes with one interface plus loopback

        EV << "  " << node->getModule()->getFullName() << "=" << nodeInfo[i].address
           << " has only one (non-loopback) interface, adding default route\n";

        // add route
        IPRoute *e = new IPRoute();
        e->setHost(IPAddress());
        e->setNetmask(IPAddress());
        e->setInterface(ie);
        e->setType(IPRoute::REMOTE);
        e->setSource(IPRoute::MANET);
        //e->setSource(IPRoute::MANUAL);
        //e->getMetric() = 1;
        rt->addRoute(e);
    }
}

void AAMNetworkConfigurator::fillRoutingTables(cTopology& topo, NodeInfoVector& nodeInfo)
{
    // fill in routing tables with static routes
    for (int i=0; i<topo.getNumNodes(); i++)
    {
        cTopology::Node *destNode = topo.getNode(i);

        // skip bus types
        if (!nodeInfo[i].isIPNode)
            continue;

        IPAddress destAddr = nodeInfo[i].address;
        std::string destModName = destNode->getModule()->getFullName();

        // calculate shortest paths from everywhere towards destNode
        topo.calculateUnweightedSingleShortestPathsTo(destNode);

        // add route (with host=destNode) to every routing table in the network
        // (excepting nodes with only one interface -- there we'll set up a default route)
        for (int j=0; j<topo.getNumNodes(); j++)
        {
            if (i==j) continue;
            if (!nodeInfo[j].isIPNode)
                continue;

            cTopology::Node *atNode = topo.getNode(j);
            if (atNode->getNumPaths()==0)
                continue; // not connected
            if (nodeInfo[j].usesDefaultRoute)
                continue; // already added default route here

            IPAddress atAddr = nodeInfo[j].address;

            IInterfaceTable *ift = nodeInfo[j].ift;

            int outputGateId = atNode->getPath(0)->getLocalGate()->getId();
            InterfaceEntry *ie = ift->getInterfaceByNodeOutputGateId(outputGateId);
            if (!ie)
                error("%s has no interface for output gate id %d", ift->getFullPath().c_str(), outputGateId);

            EV << "  from " << atNode->getModule()->getFullName() << "=" << IPAddress(atAddr);
            EV << " towards " << destModName << "=" << IPAddress(destAddr) << " interface " << ie->getName() << endl;

            // add route
            IRoutingTable *rt = nodeInfo[j].rt;
            IPRoute *e = new IPRoute();
            e->setHost(destAddr);
            e->setNetmask(IPAddress(255,255,255,255)); // full match needed
            e->setInterface(ie);
            e->setType(IPRoute::DIRECT);
            e->setSource(IPRoute::MANUAL);
           // e->setSource(IPRoute::MANET2);
            //e->getMetric() = 1;
            rt->addRoute(e);
        }
    }
}

void AAMNetworkConfigurator::handleMessage(cMessage *msg)
{
    error("this module doesn't handle messages, it runs only in initialize()");
}

void AAMNetworkConfigurator::setDisplayString(cTopology& topo, NodeInfoVector& nodeInfo)
{
    int numIPNodes = 0;
    for (int i=0; i<topo.getNumNodes(); i++)
        if (nodeInfo[i].isIPNode)
            numIPNodes++;

    // update display string
    char buf[80];
    sprintf(buf, "%d IP nodes\n%d non-IP nodes", numIPNodes, topo.getNumNodes()-numIPNodes);
    getDisplayString().setTagArg("t",0,buf);
}

void AAMNetworkConfigurator::assignCertificate(cTopology& topo, NodeInfoVector& nodeInfo)
{

  int numIPNodes = 0;
  int xRNG = par("SetRNG");
  int rY,iX;
  int cX =0 ;
  int gX =0;
  int sX =0 ;
  int bX =0 ;


  int ic =0 ;
  int iE,iA;
  std::list<int> xList1,xList2, cList1 ;
  std::list<int>::iterator ite, ita ,itl;

  for (int i=0; i<topo.getNumNodes(); i++)
      if (nodeInfo[i].isIPNode and !(nodeInfo[i].NodeMan) )
        {
          numIPNodes++;
          xList1.push_back(i);
        }


  // randomise the List of IDs


  for (int i = 0 ; i < numIPNodes;i++)
    {
      itl = xList1.begin();
      rY= genk_intrand(xRNG,xList1.size());
      if (rY == (xList1.size()-1)) iX = xList1.back();
      else if (rY > 0)
        {
          advance (itl,rY);
          iX = *itl; // get the randomised ID of the node from xList2
        }
      else iX = *itl;

      xList2.push_back(iX);
      xList1.remove(iX);
    }

  ev<< "Temp List Size:"<<xList1.size()<<" IDs List Count: "
  <<xList2.size()<<" First_Element : "<< *(xList2.begin()) <<" Last_Element: "<< xList2.back()<<endl;

//  for (std::list<int>::iterator j = xList2.begin()  ; j != xList2.end();j++)
//    ev<<*j<<endl;

  for (unsigned int i = 0 ; i <4; i++) cList1.push_back (i) ;

  CorruptedCertPrc = par("CorCertP");
  GlodenCertPrc = par("GoldenCertP");
  SilverCertPrc = par("SilverCertP");
  BronzeCertPrc = par("BronzeCertP");

   CorruptCerCount = floor(CorruptedCertPrc * numIPNodes) ;
   if ( CorruptCerCount < 1 ) error  (" Error in Percentage of Corrupt n= %d of %d",CorruptCerCount,numIPNodes);
   GoldenCerCount  = floor(GlodenCertPrc * numIPNodes) ;
   if ( GoldenCerCount < 1 ) error  (" Error in Percentage of Golden n= %d of %d",GoldenCerCount,numIPNodes);
   SilverCerCount = floor(SilverCertPrc* numIPNodes)  ;
   if ( SilverCerCount < 1 ) error  (" Error in Percentage of Silver n= %d of %d",SilverCerCount,numIPNodes);
   BronzeCerCount= floor(BronzeCertPrc* numIPNodes)  ;
   if (BronzeCerCount < 1 ) error  (" Error in Percentage of Bronze n= %d of %d",BronzeCerCount,numIPNodes);

   int xTotal =CorruptCerCount+GoldenCerCount+SilverCerCount+BronzeCerCount;

   if (xTotal != numIPNodes )
     {  if ( xTotal < numIPNodes )
         BronzeCerCount += (numIPNodes-xTotal);
     else  error (" Error in Distribute the Percentage");
     }

  ev<<"%%%%%%%%%%%%%%%%%%%%%%%%%%%% start to Initialise Random Certificates to the nodes %%%%%%%%%%%%%%%%%%%"<<endl ;

  do {
           ite = xList2.begin();
           ita = cList1.begin();

           int rK =genk_intrand(xRNG,cList1.size()); // choose random index of Certifciate Type List;
           int rX =genk_intrand(xRNG,xList2.size()); // random to choose the index of the ID in xList2

          if (rK ==(cList1.size()-1)) iA = cList1.back();
          else if (rK>0)
            {
              advance(ita,rK);
              iA = *ita; // get the randomised ID of the node from xList2
            }
          else iA = *ita ;

           if (rX == (xList2.size()-1)) iE = xList2.back();
           else if (rX > 0)
             {
               advance(ite,rX);
               iE = *ite; // get the randomised ID of the node from xList2
             }
           else iE = *ite;

           switch (iA)
           {
             case 0 : cX++; if (cX >= CorruptCerCount) cList1.remove(0);break;
             case 1 : gX++; if (gX >= GoldenCerCount)  cList1.remove(1);break;
             case 2 : sX++; if (sX >= SilverCerCount)  cList1.remove(2);break;
             case 3 : bX++; if (bX >= BronzeCerCount)  cList1.remove(3);break;
           }

           nodeInfo[iE].MP->CertificateType = CertificateClasses[iA]; // Set the Certificate Type
           ev<<"@The Certificate index ="<<rK<<"="<<iA<<"\t RandIndex of IDs list:"<<rX<<"\t The ID of NodeInfo: "<<iE
                      <<"\tCertificate Type = "<<CertificateClasses[iA]<<" "<<cX<<" "<<gX<<" "<<" "<<sX<<" "<<bX<<endl;
           ic++;
           xList2.remove(iE);

     } while (xList2.size() !=0);

  ev<<"%%%%%%%%%%%%%%%%%%%%%%%%%%%% Finish from initialising Random Certificates to the nodes count :"<<ic<<"%%%%%%%%%%%%%%%%%%%"<<endl ;

}

AuthNManager *AAMNetworkConfigurator::findAuthNManOf(cModule *host )
{
  cModule *mod = host->getSubmodule("udpApp",0);
  return dynamic_cast <AuthNManager *> (mod);
  //  return (AuthNManager *) mod;

}

AuthNManager *AAMNetworkConfigurator::getAuthNManOf(cModule *host)
{
  cModule *mod = host->getSubmodule("udpApp",0);
  if (!mod)
      opp_error("Authentication Manger is not found as submodule "
                " `AuthNManager' in Node `%s'", host->getFullPath().c_str());
  return check_and_cast<AuthNManager *>(mod);
}

mainUnit *AAMNetworkConfigurator::getMainUnit (cModule *host)
{
  cModule *mod = host->getSubmodule("MainUnit");
  if (!mod)
      opp_error("MainUnit is not found as submodule "
                " `Main Unit' in Node `%s'", host->getFullPath().c_str());
  return check_and_cast<mainUnit *>(mod);
}

void AAMNetworkConfigurator::SetNodesPositions (cTopology& topo, NodeInfoVector& nodeInfo)
{

  int numIPNodes = 0 ;

  for (int i=0; i<topo.getNumNodes(); i++)
      if (nodeInfo[i].isIPNode and !(nodeInfo[i].NodeMan) )
        {
          numIPNodes++;
        }

   double size = ceil(sqrt(numIPNodes))  ;
   double dx = ceil(ccp->getPgs()->x / size);
   double dy = ceil(ccp->getPgs()->y / size);

   ev<<"Size"<<size<<" dx:"<<dx<<" dy:"<<dy ;

   NodeInfoVector::iterator itee = nodeInfo.begin();

   double xl = 0 ;
   double yl = 0;

   double xMrg = 40;
   double yMrg = 40;

  for (int i =0 ; i<size ; i++)
     {
       yl = yMrg+(i*dy);


        for (int j = 0 ; j<size ;j++)
         {
           while (itee->NodeMan)
             {
               itee++;
             }

           xl = xMrg+(j*dx);

           ev<<"Node Position>>>>>>("<<xl<<","<<yl<<")"<<endl;

          itee->MMo->SetPosition(xl,yl);

          itee++;

          if (itee == nodeInfo.end()) break;
         }
        if (itee == nodeInfo.end()) break;
     }

}

BasicMobility *AAMNetworkConfigurator::getMobility(cModule *host)
{
  cModule *mod = host->getSubmodule("mobility");
  if (!mod)
      opp_error("mobility is not found as submodule "
                " `mobility' in Node `%s'", host->getFullPath().c_str());
  return check_and_cast<BasicMobility *>(mod);
}
