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

#ifndef __MAINUNIT_H__
#define __MAINUNIT_H__

#include <omnetpp.h>
#include "BasicModule.h"
#include  "IPvXAddress.h"
/**
 * TODO - Generated class
 */
class INET_API mainUnit :  public BasicModule
{

public:

  struct typeCat
  {
    int inx;
    std::string tname;
    double value;
  };

 struct nodeServicesRec
 {
   int ID ; // id module
   opp_string ServiceName;
   int ServicePort;
   int ClssIn ; // denote to the class that this service belong to
 };

std::vector <typeCat> ServiceComponents;
std::vector <typeCat> NodeCapacityTypes;
std::vector <typeCat> NodeTrustLevelBasedCategory;
std::vector <typeCat> NodeEnergyLevelCategory;
std::vector <typeCat> NodeMobilityCategory;

std::set<nodeServicesRec> NodeServicesList; // this list is  used only when the node is a service provider.


 struct ManagmentComponents
      {
        bool SecSrvCoSt;     // Security & service Coordinator Module
        bool AuthNManSt ; // Authentication Manager Module
        bool AuthZManSt; // Authorisation Manager
        bool TrustManSt; // Trust Manager
        bool ResManSt; // Resource Manager
        ManagmentComponents ()
        {
          SecSrvCoSt=AuthNManSt=AuthZManSt=TrustManSt=ResManSt= false; // Resource Manager
        }
      } ; // maybe node hosts more than one security role



 typeCat *CurrentNodetype; // current type of node in term of usage
 typeCat *NodeCapacity;
 typeCat *NodeEnergyLevel;
 typeCat *NodeTrustLevel;
 typeCat *NodeMobility;
 ManagmentComponents HostManagmentComponents;
 std::string CertificateType ;

  protected:
    virtual int numInitStages() const {return 6;}
    virtual void initialize(int stage);
    virtual void handleMessage(cMessage *msg);
    virtual void finish();


  public:

      mainUnit();

    void updateCertType(std::string xS)
    {
      Enter_Method("updateCertificateType(%s)",xS.c_str());
      CertificateType = xS ;
    }

    std::string getCertFromUnit()
    {
      Enter_Method("getCertFromUnit()");
      return CertificateType  ;
    }

    void setHostManagmentComponents (bool ssc ,bool an , bool az ,bool tm , bool rm)
    {
      HostManagmentComponents.SecSrvCoSt = ssc;
      HostManagmentComponents.AuthNManSt =an;
      HostManagmentComponents.AuthZManSt =az;
      HostManagmentComponents.TrustManSt =tm;
      HostManagmentComponents.ResManSt = rm ;
    }

    void updatePowerNodeLevel (double eL);
    void updateTrustNodeLevel (double tL);
    void updateMobilityNodeType (double sP);
    void updateManComp (int i , bool bV);

    ManagmentComponents &getHostManagmentComponents () { return HostManagmentComponents;}

    typeCat *getNodeInfo(int indx , int Infotype)
    {

      switch (Infotype)
      {
        case 0 : for (std::vector <typeCat>::iterator i = ServiceComponents.begin(); i != ServiceComponents.end(); i++)
                  {
                    if ( i->inx == indx)
                      {
                        return &(*i);
                      }
                  }
                 break;

        case 1 : for (std::vector <typeCat>::iterator i = NodeCapacityTypes.begin(); i != NodeCapacityTypes.end(); i++)
                 {
                   if ( i->inx == indx)
                     {
                       return &(*i);
                     }
                 }
               break;
      }
       return 0;
    }


};
class INET_API mainUnitAccess : public ModuleAccess<mainUnit>
   {
     public:
       mainUnitAccess() : ModuleAccess<mainUnit>("MainUnit") {}
   };
#endif
