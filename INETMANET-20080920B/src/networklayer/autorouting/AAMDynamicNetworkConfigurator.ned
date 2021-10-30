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

package inet.networklayer.autorouting;

//
// TODO auto-generated module
//
simple AAMDynamicNetworkConfigurator
{
    parameters:

        int numHosts;// number of User host need to be creacted dynamically  
        string dyNetworkAddress = default("192.168.0.0"); // network part of the address (see netmask parameter)
        string netmask = default("255.255.0.0"); // host part of addresses are autoconfigured
        double CorCertP = default(0.05); // percentage of Corrupted Certificate within current Nodes
        // percentage of Golden Certificate within current Nodes
        // percentage of Golden Certificate within current Nodes
        double GoldenCertP = default(0.15); // percentage of Golden Certificate within current Nodes
        double SilverCertP = default(0.30);// percentage of Silver Certificate within current Nodes
        double BronzeCertP = default(0.50);// percentage of Bronze Certificate within current Nodes
        int SetRNG = default(0); // number of Random Generators  
        int positionType = default(2); // 0 = Random position , 1,2 = types of Grid position , 3 = BonneMobility
        int arrivalType = default(1); // type of arrival = > 1: organized , 2: Possion arrival 
        double BlockUnitPar = default(60); // Unit of time for arrival rate in Sec e.g. 60sec = 1min

        bool ActivateDeleteNode = default(false); // 0 : not active 1: active
        int DeletionTypePar = default(1);  // Lifetime of Node : 0-> randdom , 1 -> LifeTime Distribution 
        double DeleteRate = default(0.1);
        double JoinRate = default(1); // Join Rate : 1 Node per mintue 

        double lifetimeMean @unit(s) = default(2000s); // mean node lifetime in seconds 
        // lifetime distribution function  < weibull, pareto_shifted, truncnormal exponential  > 
        // lifetime distribution function  < weibull, pareto_shifted, truncnormal exponential  > 
        string lifetimeDistName = default("weibull"); // lifetime distribution function  < weibull, pareto_shifted, truncnormal exponential  > 
        // parameter for distribution function
        // parameter for distribution function
        double lifetimeDistPar1 = default(1.0); // parameter for distribution function
        int densityLevels = default(1);
        
        double GraceLeaveDuration @unit(s) = default(60s) ; // waiting duration before deleting node 

        string traceFile = default("MySenario"); // Trace File for BonneMobility 
        
        double TimeScale = default (60); // Time scale to count Sucessfull Node
		double finishDelta  @unit(s) = default(220s); // delta time to end simulation in sec 
		  
		bool EndSimFlag = default(false); // Flag for Enabling Ending Simulation 
		  
        @display("i=block/broadcast;is=vs");

}
