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

//
// TODO generated message class
//
cplusplus {{
#include "INETDefs.h"
#include "IPvXAddress.h"

}}

struct servicesTuple
 {
   int ID ;
   string ServiceName;  
 //  IPvXAddress ServiceAddress ;
   string ServiceAddress ;
   int ServicePort;
   
 }

class noncobject IPvXAddress;

//class AuthBlock
//{
//    BinaryValue signature;
//    BinaryValue pubKey;
//    BinaryValue cert;
//}

enum AAMMessageType
{
    
        //  Authentication Protocol Control Messages type 
        
        AAM_AUTHN_PROT_MSG1 = 1;
        AAM_AUTHN_PROT_MSG2 = 2;
        AAM_AUTHN_PROT_MSG3 = 3; 
        AAM_AUTHN_PROT_MSG4 = 4; 
        
        //  Authentication Protocol Data Messages type 
        
        AAM_AUTHN_ACK = 5; // Successfull Authentication
        AAM_AUTHN_NOACK =6; // unsuccessful Authentication 
        
      
        // Deleagated Authority Messages 
        
        AAM_DAS_REQ = 7;
        AAM_DAS_RESP =8;  
        


};

enum AAuthNProtoType
{
    Unknown_Type	= 0 ;
    X509_One_Pass	= 1;
    X509_Two_Pass 	= 2 ;
    X509_Three_Pass = 3 ;
}



//
// Message class used by AAM Application


packet CommonAAM  
{
    
       int MsgType enum (AAMMessageType);
       //       IPvXAddress AuthenticatorAddress;
//       int AuthenticatorPort; 
  		int indxSrv ;
  		int SeqNum ;  
}


packet AuthenProtocolMsg extends CommonAAM  // control messages 
{
      int Nonce ;
      string Timestamp ;
      string IdCertificate;
      string Signature;
      double length; 
      int AuthNType enum (AAuthNProtoType);    
}

packet DataMsg extends CommonAAM 
{
     
     string AttrbCert; // Services Membership Certificate
     string ThreshAttrCert ;
     servicesTuple ServicesList[];  
}

packet AuthenReqMsg extends CommonAAM 
{
      IPvXAddress AuthenticatorAddress;
      int AuthenticatorPort;
      string AutNhBlock;  // Identity Membership Certificate
}

packet AuthenResponsMsg extends CommonAAM 
{
     string AttrbCert; // Services Membership Certificate
     servicesTuple ServicesList[];     
}


