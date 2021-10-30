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

#ifndef __AAMNETWORKCONFIGURATOR_H__
#define __AAMNETWORKCONFIGURATOR_H__

#include <omnetpp.h>
#include "INETDefs.h"
#include "IPAddress.h"
#include "AuthNManager.h"
#include "mainUnit.h"
#include "BasicMobility.h"

class IInterfaceTable;
class IRoutingTable;
//class mainUnit ;
//class AuthNManager ;
//class AuthNAgent;
/**
 * TODO - Generated class
 */
class AAMNetworkConfigurator : public cSimpleModule
{
protected:
    struct NodeInfo {
        NodeInfo() {isIPNode=false;ift=NULL;rt=NULL;usesDefaultRoute=false; NodeMan =false;}//CertificateType = ""; }
        cModule *mod_PTR;
        bool isIPNode;
        IInterfaceTable *ift;
        IRoutingTable *rt;
        IPAddress address;
        bool usesDefaultRoute;
       // std::string CertType; // Added by Salah
        bool setCer;
        bool NodeMan;
        AuthNManager *AuthMAN_PTR;
        mainUnit *MP;
        BasicMobility *MMo ;


    };
    typedef std::vector<NodeInfo> NodeInfoVector;

   std::vector <std::string> CertificateClasses ;

   double CorruptedCertPrc ;
   double GlodenCertPrc;
   double SilverCertPrc ;
   double BronzeCertPrc ;
   int CorruptCerCount ;
   int GoldenCerCount ;
   int SilverCerCount ;
   int BronzeCerCount;
   int ManIn;

   ChannelControl *ccp;



  protected:
    virtual int numInitStages() const  {return 3;}
    virtual void initialize(int stage);
    virtual void handleMessage(cMessage *msg);

    virtual void extractTopology(cTopology& topo, NodeInfoVector& nodeInfo);
    virtual void assignAddresses(cTopology& topo, NodeInfoVector& nodeInfo);
    virtual void addDefaultRoutes(cTopology& topo, NodeInfoVector& nodeInfo);
    virtual void fillRoutingTables(cTopology& topo, NodeInfoVector& nodeInfo);

    virtual void setDisplayString(cTopology& topo, NodeInfoVector& nodeInfo);


    virtual void assignCertificate(cTopology& topo, NodeInfoVector& nodeInfo);
    virtual AuthNManager *findAuthNManOf(cModule *host);
    virtual AuthNManager *getAuthNManOf(cModule *host);
    virtual mainUnit *getMainUnit (cModule *host) ;

    virtual void SetNodesPositions (cTopology& topo, NodeInfoVector& nodeInfo);
    virtual BasicMobility *getMobility(cModule *host);

//  AuthNAgent *findAuthNAgentOf(cModule *host);
//  AuthNAgent *getAuthNAgentOf(cModule *host);
};

#endif
