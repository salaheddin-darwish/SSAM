/*****************************************************************************
 *
 * Copyright (C) 2007 Malaga university
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors: Alfonso Ariza Quintana
 *
 *****************************************************************************/

#ifndef _DYMO_UM_OMNET_H
#define _DYMO_UM_OMNET_H

// This define activate the new queue timer
#define TIMERMAPLIST
// This define activate the new routing table
#define MAPROUTINGTABLE

/* Constants for interface queue packet buffering/dropping */
#define IFQ_BUFFER 0
#define IFQ_DROP 1
#define IFQ_DROP_BY_DEST 2
#define PKT_ENC 0x1       /* Packet is encapsulated */
#define PKT_DEC 0x2 /* Packet arrived at GW and has been decapsulated (and
* should therefore be routed to the Internet */
// #define CONFIG_GATEWAY
// #define DEBUG_HELLO

#ifndef NS_PORT
#define NS_PORT
#endif
#ifndef OMNETPP
#define OMNETPP
#endif

/* This is a C++ port of AODV-UU for ns-2 */
#ifndef NS_PORT
#error "To compile the ported version, NS_PORT must be defined!"
#endif /* NS_PORT */



/* System-dependent datatypes */
/* Needed by some network-related datatypes */
#include "ManetRoutingBase.h"
#include "Ieee80211Frame_m.h"
#include "dymoum/dlist.h"
#include "dymo_msg_struct.h"
#include "IPDatagram.h"
#include "ICMPAccess.h"
#include <map>

/* Forward declaration needed to be able to reference the class */
class DYMOUM;

/* Global definitions and lib functions */

#include "dymoum/defs_dymo.h"

#ifndef IP_BROADCAST
#define IP_BROADCAST ((u_int32_t) 0xffffffff)
#endif /* !IP_BROADCAST */

/* Extract global data types, defines and global declarations */
#undef NS_NO_GLOBALS
#define NS_NO_DECLARATIONS

//#include "dymoum/defs.h"
#include "dymoum/debug_dymo.h"
#include "dymoum/dlist.h"
#include "dymoum/dymo_generic.h"
#include "dymoum/dymo_re.h"
#include "dymoum/dymo_uerr.h"
#include "dymoum/dymo_rerr.h"
#include "dymoum/dymo_socket.h"
#include "dymoum/dymo_timeout.h"
#include "dymoum/rtable.h"
#include "dymoum/pending_rreq.h"
#include "dymoum/timer_queue.h"
#include "dymoum/blacklist.h"
#include "dymoum/icmp_socket.h"
#include "dymoum/dymo_hello.h"
#include "dymoum/dymo_nb.h"

#include "dymo_packet_queue_omnet.h"

#undef NS_NO_DECLARATIONS

/* In omnet we don't care about byte order */
#undef ntohl
#define ntohl(x) x
#undef htonl
#define htonl(x) x
#undef htons
#define htons(x) x
#undef ntohs
#define ntohs(x) x



/* The AODV-UU routing agent class */
class DYMOUM : public ManetRoutingBase
{
  private:

    struct mac_address
    {

        char address[6];
        bool equals(mac_address addr) const
        {
            for (int i=0; i<6; i++)
                if (address[i]!=addr.address[i])
                    return false;
            return true;
        }
        bool operator==(const mac_address& addr1) const {return equals(addr1);}
        bool operator!=(const mac_address& addr1) const {return !equals(addr1);}

        bool operator<(const mac_address& addr1) const
        {
            for (int i=0; i<6; i++)
                if (address[i] < addr1.address[i])
                    return true;
            return false;
        }

    };

    // cMessage messageEvent;

    typedef std::map<mac_address, unsigned int> MacToIpAddress;
    typedef std::multimap<simtime_t, struct timer*> DymoTimerMap;
    typedef std::map<Uint128, rtable_entry_t *> DymoRoutingTable;

    // this static map simulate the exchange of seq num by the proactive protocol.
    static std::map<Uint128,u_int32_t *> mapSeqNum;

    MacToIpAddress macToIpAdress;
    DymoTimerMap dymoTimerList;
    DymoRoutingTable dymoRoutingTable;


    char nodeName[50];
    ICMPAccess icmpAccess;


    IPAddress *ipNodeId;
    DYMO_element * send_buf;
    struct host_info this_host;
    u_int32_t dev_indices[DYMO_MAX_NR_INTERFACES];
    int ifindex2devindex(u_int32_t ifindex)
    {
        int i;
        for (i = 0; i < this_host.nif; i++)
            if (dev_indices[i] == ifindex)
                return i;
        return -1;
    }

    void promiscuous_rrep(RE *,struct in_addr);
    int numInterfacesActive;
    // Configuration parameters
    int norouteBehaviour;
    bool PromiscOperation;
    int debug;
    // from dymo_socket.h
    int DYMO_RATELIMIT;
    //from dymo_generic.h
    int NET_DIAMETER;
    // from rtable.h
    long ROUTE_TIMEOUT;     //3000
    long ROUTE_DELETE_TIMEOUT;  //(5 * ROUTE_TIMEOUT)
    // from dymo_re.h
    long RREQ_WAIT_TIME;//  1000
    int  RREQ_TRIES;//  3

    // from main.c
    int no_path_acc;
    int reissue_rreq;
    int s_bit;
    int hello_ival;
    long int timer_elem;
    bool intermediateRREP;
    bool attachPacket;
    bool useIndex;


    virtual void processLinkBreak(const cPolymorphic *details);
    virtual void processPromiscuous (const cPolymorphic *details);
    virtual void processFullPromiscuous(const cPolymorphic *details);

  public:
    static int  log_file_fd;
    static bool log_file_fd_init;
    DYMOUM() {attachPacket=false; is_init =false; log_file_fd_init=false; ipNodeId=NULL; gateWayAddress=NULL; numInterfacesActive=0; timer_elem=0; sendMessageEvent = new cMessage();/*&messageEvent;*/mapSeqNum.clear();}
    ~DYMOUM();
    void packetFailed(IPDatagram *);
    void packetFailedMac(Ieee80211DataFrame *);
    virtual std::string detailedInfo() const;

    // Routing information access
    virtual uint32_t getRoute(const Uint128 &,Uint128 add[]);
    virtual bool getNextHop(const Uint128 &,Uint128 &add,int &iface);
    virtual bool isProactive();
    virtual void setRefreshRoute(const Uint128 &,const Uint128 &,const Uint128 &,const Uint128&);
    virtual bool isOurType(cPacket *);
    virtual bool getDestAddress(cPacket *,Uint128 &);

  protected:
    void drop (cPacket *p,int cause = 0)
    {
        delete p;
        // icmpAccess.get()->sendErrorMessage(p, ICMP_DESTINATION_UNREACHABLE, cause);
    }
    int startDYMOUMAgent();
    void scheduleNextEvent();
    const char *if_indextoname(int, char *);
    IPDatagram *pkt_encapsulate(IPDatagram *, IPAddress);
    IPDatagram *pkt_decapsulate(IPDatagram *);
    virtual void handleMessage(cMessage *msg);
    virtual void finish();
    int numInitStages() const  {return 5;}
    void initialize(int stage);
    void recvDYMOUMPacket(cMessage * p);
    void processPacket(IPDatagram *,unsigned int);
    void processMacPacket(cPacket * p,const Uint128 &,const Uint128 &,int);
    void getMacAddress(IPDatagram *);

    cPacket * get_packet_queue(struct in_addr dest_addr);

    bool is_init;
    cMessage * sendMessageEvent;

    int initialized;
    int  node_id;
    IPAddress *gateWayAddress;
    int NS_DEV_NR;
    uint32_t NS_IFINDEX;
    // cModule *ipmod;

// Variables from main.c
    char    *progname;

    // Variables from pending_rreq.c
    dlist_head_t    pendingRREQ;
#define PENDING_RREQ this->pendingRREQ
    // Variables from timer_queue.c
    dlist_head_t    timeList;
#define TQ this->timeList
    /*
          list_t timeList;
    #define TQ this->timeList
    */
    // Variables from blacklist.c
    dlist_head_t    blackList;
#define BLACKLIST this->blackList


    // Variables from icmp_socket.c

    // Variables from dymo_hello.c
    struct timer hello_timer;

    // Variables from dymo_nb.c
    dlist_head_t nbList;
#define NBLIST this->nbList
    /*
      Extract method declarations (and occasionally, variables)
      from header files
    */
#define NS_NO_GLOBALS
#undef NS_NO_DECLARATIONS

#define NS_NO_GLOBALS
#undef  NS_NO_DECLARATIONS

#undef __DEFS_H__
#include "dymoum/defs_dymo.h"

#undef __DEBUG_H__
#include "dymoum/debug_dymo.h"

#undef __DYMO_GENERIC_H__
#include "dymoum/dymo_generic.h"

#undef __DYMO_RE_H__
#include "dymoum/dymo_re.h"

#undef __DYMO_UERR_H__
#include "dymoum/dymo_uerr.h"

#undef __DYMO_RERR_H__
#include "dymoum/dymo_rerr.h"

#undef __DYMO_SOCKET_H__
#include "dymoum/dymo_socket.h"

#undef __DYMO_TIMEOUT_H__
#include "dymoum/dymo_timeout.h"

#undef __RTABLE_H__
#include "dymoum/rtable.h"

#undef __PENDING_RREQ_H__
#include "dymoum/pending_rreq.h"

#undef __TIMER_QUEUE_H__
#include "dymoum/timer_queue.h"

#undef __BLACKLIST_H__
#include "dymoum/blacklist.h"

#undef __ICMP_SOCKET_H__
#include "dymoum/icmp_socket.h"

#undef __DYMO_HELLO_H__
#include "dymoum/dymo_hello.h"

#undef __DYMO_NB_H__
#include "dymoum/dymo_nb.h"

#undef _DYMO_PACKET_QUEUE_H
#include "dymo_packet_queue_omnet.h"

#undef NS_NO_GLOBALS

    static bool iswrite;
    static int totalSend;
    static int totalRreqSend;
    static int totalRreqRec;
    static int totalRrepSend;
    static int totalRrepRec;
    static int totalRrepAckSend;
    static int totalRrepAckRec;
    static int totalRerrSend;
    static int totalRerrRec;
};

#endif /* _DYMO_UM_OMNET_H */
