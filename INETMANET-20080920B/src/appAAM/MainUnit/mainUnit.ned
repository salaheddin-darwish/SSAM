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

package inet.appAAM.MainUnit;

//
// TODO auto-generated module
//
simple mainUnit
{
    parameters:
        int NodeCapacityPar = default(intuniform (1,3)); //  Node capacity ( Heavy 3 - meduim 2 - Light types 1 )
        int ServiceNodeTypePar = default(1); // Service Node Type ( Service User 1 - Service Provider 2) 
        @display("i=block/segm");
}
