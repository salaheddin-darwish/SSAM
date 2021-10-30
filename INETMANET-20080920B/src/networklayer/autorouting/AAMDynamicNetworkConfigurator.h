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

#ifndef __AAMDYNAMICNETWORKCONFIGURATOR_H__
#define __AAMDYNAMICNETWORKCONFIGURATOR_H__

#include <omnetpp.h>
#include "INETDefs.h"
#include "IPAddress.h"
#include "AuthNManager.h"
#include "mainUnit.h"
#include "BasicMobility.h"
#include "TraffGenSrMan.h"
#include "Coord.h"


class IInterfaceTable;
class IRoutingTable;

/**
 * TODO - Generated class
 */
class INET_API AAMDynamicNetworkConfigurator : public cSimpleModule
{
   protected:
      struct NodeInfo
      {
          NodeInfo() {mod_PTR= NULL;ift=NULL;rt=NULL;NodeMan =false; CertType = "NA";
                      deInx = -1 ; Deltime =0;nodeName ="";TraffGenSrMan_PTR =NULL;AuthMAN_PTR=NULL;DeleteTimer=NULL;}

          // pointers
          cModule *mod_PTR;
          //std::string Name
          IInterfaceTable *ift;
          IRoutingTable *rt;
          AuthNManager *AuthMAN_PTR;
          TraffGenSrMan *TraffGenSrMan_PTR;
          mainUnit *MP;
          BasicMobility *MMo ;

          // variable
          IPAddress address;
          std::string CertType; // Added by Salah
          bool NodeMan;
          Coord initialPos;
          bool scheduleToDeleteNode ;// this is scheduled to be delete
          int id;

          int deInx; // Deletion Index
          simtime_t Deltime ; // Deletion Time
          std::string nodeName ;
          cMessage *DeleteTimer;
      };

      typedef std::list<NodeInfo> NodeInfoVector;

      NodeInfoVector nodesInfo; // joiners list

      NodeInfoVector DeletedNodesInfo ; // Killed Nodes or leavers


      std::vector <std::string> CertificateClasses ;

      std::list<cModule *> killList; //!< stores nodes scheduled to be killed

      std::list<NodeInfo> TraffGenSrManVec ;

      std::list<NodeInfo> AuthNManVec ;


      double CorruptedCertPrc ;
      double GlodenCertPrc;
      double SilverCertPrc ;
      double BronzeCertPrc ;
      int CorruptCerCount ;
      int GoldenCerCount ;
      int SilverCerCount ;
      int BronzeCerCount;
      int ManIn;
      unsigned int ScheduledDelNodes ;
      bool DeleteFlag ;
      int DeletionType;
      double BlockUnit ;

      std::string lifetimeDistName; //!< name of the distribution function
      double lifetimeMean; 			//!< mean node lifetime
      double lifetimeDistPar1; 		//!< distribution function parameter


      ChannelControl *ccp;

      int index;
      int DelIndex ;

      int SucNd ;
      int FailNd ;
      int TotalSucreq;
      int TotalReq;

      int CRate ;
      int CFRate;
      int SC;
      int FC;
      int indxTempSR;
      int nodeLeavers;

      int SucAuthnCAS;
      int SucAuthnTAS;
      int SucAuthnDAS ;

      int failDeltNode;
      int SucDeltNode ;


      simtime_t laTime;
      simtime_t llaTime;
      simtime_t LastschedNodeCreation;
      simtime_t LastDeleteNodeTime;

      double AVG_SucRate;
      double AVG_SucRatio;
      double AVG_FracSucRatio;
      double AVG_RTT;
      double AVG_SetlTime;
      double AVG_ComOverhead;
      double AVG_FailRate;


      cModuleType *moduleType ;
      friend std::ostream& operator<<(std::ostream&, const NodeInfo&);
      cOutVector CreationTimeVec ;
      cOutVector DeletionTimeVec ;
      cOutVector NodesInPlayGround;
      cOutVector SuccessNodeTypesVec;

      cOutVector SucessRateVec;
      cOutVector SucessRatioVec;
      cOutVector SucessReqRatioVec;
      cOutVector SucessReqRatioSTVec;
      cOutVector FractionalSucessRatioVec;

      cOutVector FailRateVec;
      cOutVector LeaveRateVec;
      cOutVector RTTNodeVec;
      cOutVector SettlingTimeVec;
      cOutVector TotalCommOverheadVec;
      cOutVector LifeTimeNodeSetDeltaInNet ;
      cOutVector LifeTimeNodeInNet ;
      cOutVector SessionLengthNodeInNet ;
      std::list<int> iA;

public:

  bool EndSimulationFlag;

  virtual int numInitStages() const  {return 6;}
  virtual void initialize(int stage);
  virtual void handleMessage(cMessage *msg);
  virtual void finish();
  virtual bool scheduleToDelete(cModule *MP,int TypNode, bool AuthUserNode);
  static AAMDynamicNetworkConfigurator *getAAMDynNetConfig();
  virtual void UpdateStatistic(double Val,double St,int Tc, int t, int MemCert, int ToReq);

protected:
  virtual void createNode(int is);
  virtual void deleteNode(cModule* MP) ;

  virtual void setupCertficateCounters ();
  virtual std::string assignCertificate();
  virtual std::string getRandCertificate();
  virtual BasicMobility *getMobility(cModule *host);
  virtual mainUnit *getMainUnit (cModule *host) ;
  virtual AuthNManager *findAuthNManOf(cModule *host);
  virtual AuthNManager *getAuthNManOf(cModule *host);
  virtual TraffGenSrMan *getTraffGenSrMan(cModule *host);
  virtual TraffGenSrMan *findTraffGenSrManOf(cModule *host);
  virtual Coord SetNodesPositions (int pType);
  virtual double distributionFunction() ;
  virtual void ManageTrafGenSrHost ();
  virtual void ManageAuthNMANHost ();

};

#endif
