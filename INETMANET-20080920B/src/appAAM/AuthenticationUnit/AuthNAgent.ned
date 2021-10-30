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

package inet.appAAM.AuthenticationUnit;

//package inet.applications.udpapp;

import inet.applications.udpapp.UDPApp;
//
// TODO auto-generated module
//
simple AuthNAgent like UDPApp
{
    parameters:
        int AuthnManPort;
        int localAuthnAgentPort; // if -1, app doesn't bind in UDP

        int messageLength @unit("B"); // length of messages to generate, in bytes NOTE: not in use
        string AuthNMANAddr = default(""); // list of \IP addresses, separated by spaces root Servers
        string AuthNMANThreAddr = default(""); // List of IP Threshold Servers
        int strategyType = default(0); // 0 = Send Reqs for All available Server types , 1 = priority sending Request 

        bool WaitingWindowEnable = default(false); // enable timer for waiting 
        double AWaitInterval @unit("s"); // window for waiting time  to Re-Authenticate incase host doesnt complete Authentication Procedure
        int MaxReAuthNCounter = default(3); // MAX Number of Tries for Authentication 
        int Fix_Exp_WT = default(1);// 0 Fixed or 1 Exponential Time Waiting 

        volatile double time_begin @unit("s");// begin transmission time  should usually be a random value, e.g. exponential(1)
        int GeneratorSeed; // for random generator 

        int AuthenticationType = default(1); // one , two or three way type of authentication protocol for setting up secure channel 
        int TotalNumServers = default(1); // Total Number of  Servers used in Experiement 
        int ThresholdServer = default(2); // number of servers is required to have Attribute Certificate         
        int SrvTypeOptions = default(1); // 1 => Root Servers ; 2 => Threshold Servers ; 3 => root & Threshold Server with DAS; 4=> " without DAS
        
        bool SetTAStoDAS = default(false); // set this flage to activate separation in Delegated authority Services in Threshold Server. 
 		bool StMin = default (false) ; // strategy of choosing false :Radom or true :Min 
        int DASReqLen = default (200);// Length of DAS Request in Byte , 
        volatile double EncryptAndProcessDASReq = default(uniform(1,1.5)); // Processing Time in sending DAS Req
        
        volatile double DecryptValidateDelay = default(uniform(1,1.5)); // process decrypt and validate Attribute Crendential 
        volatile double CombinPocessDelay = default(uniform (1.5,2));

        // Enable or Disable Disconnection when User fails to authenticate 
        // Enable or Disable Disconnection when User fails to authenticate 
        bool DisconnectFlag = default(true); // Enable or Disable Disconnection when User fails to authenticate 
        bool DeleteToFail  = default(false); // forced Delete Node on failure 
        double ProDeletToFail = default(-1); // Probability of Forced to delete ;
        
        bool TriggerTraffic = default (false) ; // enable or disable Traffic generation 
        double ProSeclectionGT = default (0.5) ; // the probility of making this host some Traffic
        
        bool SetNodeLifeTime = default (false); // make Authenticated Node have Lifetime in network
        
        // the time that the node is taking to migrate to different place in the region

        // the time that the node is taking to migrate to different place in the region

        bool EnabledMigr = default(false); // for enabling Migration phase  
        int MigAttempNum = default(1); // Max Migration Attemps
        
        bool SearchForConnection = default(false); // true : find nearby node for access to start authentu
        double updateSearchTimer= default (0.1s) @unit("s"); // timer for looking for neighbouring node
        bool SetMobilModOn = default (false) ; // Activate Channel for discovery 
        
        bool disableCAS = default (false) ; // we need in the case we have only  TAS and DAS together
        
        
        volatile double MigrationTripTime @unit("s") @display("i=block/user") = default(120s);
        @display("i=block/user");
    gates:
        input udpIn;
        output udpOut;

}

