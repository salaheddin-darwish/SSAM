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

import inet.applications.udpapp.UDPApp;
//
// TODO auto-generated module
//


simple AuthNManager like UDPApp
{
    parameters:
		int AuthorityServerType = default(1) ; // Type of Authority Server ( 1: RootAuthority, 2:ThreshodAuthority,)
        int localAuthnManPort; // if -1, app doesn't bind in UDP
        int GeneratorSeed = default(0); // for random generator 
        
        volatile double URprocessTimeDuration = default (uniform(1s,1.5s)) @unit("s"); // DecryptAndValidate process time For DAS Request
        bool SepTASfDAS = default(false); // Separate both Services of TAS and DAS
         
        volatile double AttributeCertProcess = default (normal(1s,0.4s))  @unit("s"); // issuing Attribute Certficate (DAS) 
        int respMsgLengthNoAK = default(512B) @unit("B"); // size of relpy message for unsuccessful authentication
        int respMsgLengthAK = default(1024B)   @unit("B");// size of relpy message for successful authentication
        int ServicesCapacityBuffer = default (10); // Buffer Size 
        int MaxThreads = default (2); // Max Threads can be processed by a device
        int SrvTypeOptions = default(1); // 1 => Root Servers ; 2 => Threshold Servers ; 3 => root & Threshold Server 
        bool DasSet = default(false) ; //  DASs as separate servers
        double DeltaWait = default (0.05); // Delta time span for node send AC back to user in TwoWay Pass AuthN only
        
        double TTLACert  = default(3600); // time to live Attributes Certificate
        double THPUTimeScale = default(60); // Time scale to calculate Throughput of AuthNManger
        double Margin4newCert = default (60) ; // Margin Time for a Certificate to be re-issued in Sec
        
        @display("i=block/star");
        
    gates:
        input udpIn;
        output udpOut;
}