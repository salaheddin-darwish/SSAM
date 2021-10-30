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

#include "mainUnit.h"

Define_Module(mainUnit);

std::ostream& operator<<(std::ostream& out, const mainUnit::typeCat& d) {
    out << "Index= " << d.inx << "\tTypeName= " << d.tname
    << "\tValueType= "<< d.value;
    return out;
}

std::ostream& operator<<(std::ostream& out, const mainUnit::nodeServicesRec& d) {
    out << "ServiceID = " << d.ID << "\tServiceName = " << d.ServiceName
     << "\tServicePort = " << d.ServicePort<< "\tClassLevel = " <<d.ClssIn;
    return out;
}

std::ostream& operator<<(std::ostream& out, const mainUnit::ManagmentComponents& d)
{
    out <<"SSCExists= "<< (d.SecSrvCoSt? "True":"False") << "\tAuthNManExists= "<< (d.AuthNManSt? "True":"False")<< "\tAuthZManExists= "
    << (d.AuthZManSt? "True":"False")<< "\tTrustManExists= "<<(d.TrustManSt? "True":"False")
    <<"\tResManExists= "<<(d.ResManSt? "True":"False");
    return out;
}


mainUnit::mainUnit()
{
	CertificateType ="Cer_NA";

	struct typeCat x ;

  // Using Types
  x.inx = 1 ;
  x.tname = "Service_User";
  ServiceComponents.push_back(x);

  x.inx = 2 ;
  x.tname = "Service_Provider";
  ServiceComponents.push_back(x);


  // Capacity Types
  x.inx = 1 ;
  x.tname = "Light_Duty_Device";
  NodeCapacityTypes.push_back(x);

  x.inx = 2 ;
  x.tname = "Medium_Duty_Device";
  NodeCapacityTypes.push_back(x);

  x.inx = 3 ;
  x.tname = "Heavy_Duty_Device";
  NodeCapacityTypes.push_back(x);

  // Level of trust
  x.inx = 0 ;
  x.tname = "Untrusted";
  x.value = 0.05;
  NodeTrustLevelBasedCategory.push_back(x);


  x.inx = 1 ;
  x.tname = "Low_Trusted";
  x.value = 0.25;
  NodeTrustLevelBasedCategory.push_back(x);


  x.inx = 2 ;
  x.tname = "Partially_Trusted";
  x.value = 0.50;
  NodeTrustLevelBasedCategory.push_back(x);

  x.inx = 3 ;
  x.tname = "Full_Trusted";
  x.value = 0.75;
  NodeTrustLevelBasedCategory.push_back(x);

  // Energy Level
  x.inx = 0 ;
  x.tname = "No_Power";
  x.value = 0;
  NodeEnergyLevelCategory.push_back(x);

  x.inx = 1 ;
  x.tname = "Low_Power";
  x.value = 10;
  NodeEnergyLevelCategory.push_back(x);

  x.inx = 2 ;
  x.tname = "Semi_Low_Power";
  x.value = 25;
  NodeEnergyLevelCategory.push_back(x);

  x.inx = 3 ;
  x.tname = "Half_Power";
  x.value = 50;
  NodeEnergyLevelCategory.push_back(x);

  x.inx = 4 ;
  x.tname = "Semi_Full_Power";
  x.value = 75;
  NodeEnergyLevelCategory.push_back(x);

  x.inx = 4 ;
  x.tname = "Full_Power";
  x.value = 100;
  NodeEnergyLevelCategory.push_back(x);


  // Mobility Types
  x.inx = 0 ;
  x.tname = "Static";
  x.value = 0;
  NodeMobilityCategory.push_back(x);

  x.inx = 1 ;
  x.tname = "Low";
  x.value = 0.01;
  NodeMobilityCategory.push_back(x);

  x.inx = 1 ;
  x.tname = "Medium";
  x.value = 1;
  NodeMobilityCategory.push_back(x);

  x.inx = 1 ;
  x.tname = "High";
  x.value = 5;
  NodeMobilityCategory.push_back(x);

}


void mainUnit::initialize(int stage)
{
	// TODO - Generated method body

  if (stage!=5)
   return;


 WATCH_VECTOR(ServiceComponents);
 WATCH_VECTOR(NodeCapacityTypes);
 WATCH_VECTOR(NodeTrustLevelBasedCategory);
 WATCH_VECTOR(NodeEnergyLevelCategory);
 WATCH_VECTOR(NodeMobilityCategory);
 WATCH_SET(NodeServicesList);
 WATCH(HostManagmentComponents);
 WATCH (CertificateType);


CurrentNodetype = getNodeInfo(par("ServiceNodeTypePar"),0); // Usage node type

if (!CurrentNodetype) error("Null pointer to Node Service Type record");

NodeCapacity = getNodeInfo(par("NodeCapacityPar"),1);// Capacity Types

if (!NodeCapacity) error("Null pointer to Node capacity record");

WATCH (CurrentNodetype->tname);
WATCH (NodeCapacity->tname);



if (ev.isGUI())
    {
        char buf[40];
        const char *  x = (CurrentNodetype->tname+"\n"+NodeCapacity->tname+"\n"+CertificateType).c_str();
        sprintf(buf, "NodeMainUnit\n%s",x);
        getDisplayString().setTagArg("t",0,buf);

//        if (NodeCapacity->inx ==3 )
//           getParentModule()->getDisplayString().setTagArg("i",0,"device/wifilaptop");
//        if (NodeCapacity->inx ==2 && !HostManagmentComponents.AuthNManSt)
//           getParentModule()->getDisplayString().setTagArg("i",0,"device/palm_s");
//
//
//          getParentModule()->getDisplayString().setTagArg("is",0,"n");
        //  getParentModule()->getDisplayString().setTagArg("i2",0, "block/user_vs");
    }
}

void mainUnit::handleMessage(cMessage *msg)
{
	// TODO - Generated method body
  error ("Error-No message should be arrived");
}


void mainUnit::updateManComp (int i , bool bV)
{
  Enter_Method ("updateManComp (%d,%s)",i,bV? "True":"False");

  getParentModule()->getDisplayString().setTagArg("i",0,"device/wifilaptop");
  getParentModule()->getDisplayString().setTagArg("i2",0, "block/star_vs");

  switch (i)
  {
    case 0 :HostManagmentComponents.SecSrvCoSt =bV;break;
    case 1 :HostManagmentComponents.AuthNManSt =bV;break;
    case 2 :HostManagmentComponents.AuthZManSt =bV;break;
    case 3 :HostManagmentComponents.TrustManSt =bV;break;
    case 4 :HostManagmentComponents.ResManSt   =bV;break;
  }
}

void mainUnit::finish()
{
  simtime_t t = simTime();
  if (t==0) return;

  recordScalar("MainUnit Node Service Type", CurrentNodetype->inx );
  recordScalar("MainUnit Node Capacity Type",NodeCapacity->inx );
  recordScalar("MainUnit AuthNManager State", HostManagmentComponents.AuthNManSt? 1:0);
//  recordScalar("Successful Authentication", SucAuth);
//  recordScalar("Unsuccessful Authentication", UnscAuth);
//  recordScalar("Total Dropped Requests",numReqsDropped);


}


