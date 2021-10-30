/***************************************************************************
 * Simple battery model for inetmanet framework
 * Author:  Alfonso Ariza
 * Based in the mixim code Author:  Laura Marie Feeney
 *
 * Copyright 2009 Malaga University.
 * Copyright 2009 Swedish Institute of Computer Science.
 *
 * This software is provided `as isst
 * ' and without any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose.
 *
 ***************************************************************************/

/*
 * A simple linear model of battery consumption.  Simple Battery
 * receives DrawMsg's from one or more devices, updates residual
 * capacity (total current * voltage * time), publishes HostState
 * notification on battery depletion, and provides time series and
 * summary information to Battery Stats module.
 */

#include <omnetpp.h>
#include "InetSimpleBattery.h"

Define_Module(InetSimpleBattery);


//InetSimpleBattery *InetSimpleBattery::get()
//{
//  cModule *mod;
//  InetSimpleBattery *ba = dynamic_cast<InetSimpleBattery *>(mod->getParentModule()->getSubmodule("battery"));
//    if (!ba)
//        ba = dynamic_cast<InetSimpleBattery *>(mod->getParentModule()->getSubmodule("battery"));
//    if (!ba)
//        throw cRuntimeError("Could not find InetSimpleBattery module");
//
//    return ba;
//}


inline std::ostream& operator<<(std::ostream& out, const DeviceEntry& d)
{
    out <<"Device Name= "<< d.name << " Current Name =" << d.currentActivity <<" Current draw= "<< d.draw <<
         " Activities Number =" << d.numAccts << *d.radioUsageCurrent;
    return out;
}


void InetSimpleBattery::initialize(int stage)
{

    BasicBattery::initialize(stage); //DO NOT DELETE!!
    if (stage == 0)
    {
        cc = ChannelControl::get();

        voltage = par("voltage");

        nominalCapmAh = par("nominal");

        if (nominalCapmAh <= 0)
        {
            error("invalid nominal capacity value");
        }

        capmAh = par("capacity");

        // Publish capacity to BatteryStats every publishTime (if > 0) and
        // whenever capacity has changed by publishDelta (if < 100%).

        publishTime = 0;

        publishDelta = 1;

        publishDelta = par("publishDelta");

        if (publishDelta < 0 || publishDelta > 1)
        {
            error("invalid publishDelta value");
        }

        resolution = par("resolution");
        EV<< "capacity = " << capmAh << "mA-h (nominal = " << nominalCapmAh <<
        ") at " << voltage << "V" << endl;
        EV << "publishDelta = " << publishDelta * 100 << "%, publishTime = "
        << publishTime << "s, resolution = " << resolution << "sec"
        << endl;

        capacity = capmAh * 60 * 60 * voltage; // use mW-sec internally
        nominalCapacity = nominalCapmAh * 60 * 60 * voltage;

        residualCapacity = lastPublishCapacity = capacity;
        lifetime = -1; // -1 means not dead

        publishTime = par("publishTime");

        if (publishTime > 0)
        {
            lastUpdateTime = simTime();
            publish = new cMessage("publish", PUBLISH);
            publish->setSchedulingPriority(2000);
            scheduleAt(simTime() + publishTime, publish);
        }

        mCurrEnergy=NULL;

       // hostState=new HostState();

        if (par("ConsumedVector")) //&&  hostState->info()=="ACTIVE") // salah
          {
            mCurrEnergy = new cOutVector("Consumed");
            residualVec = new cOutVector("PR_ResiCapcity");

          }

          // DISable by default (use BatteryStats for data collection)
         // residualVec.enable();
        //residualVec.disable();

         double prp = (residualCapacity/capacity)*100;

       // residualVec->setName(" Current Percentage of residualCapacity");

        residualVec->record(prp);
        timeout = new cMessage("auto-update", AUTO_UPDATE);
        timeout->setSchedulingPriority(500);
        scheduleAt(simTime() + resolution, timeout);

        lastUpdateTime = simTime();

        WATCH_PTRMAP(deviceEntryMap);

        x=1;
        WATCH (x1);
        WATCH(x2);
        WATCH (y);
        WATCH (x);
        x +=1;
        WATCH(residualCapacity);
        WATCH(lastPublishCapacity);


    }
    else  if(stage==2)
      {

       //        st=hostState->info();
       //        WATCH_PTR(hostState);
        WATCH(hostState);
        ev<< "HostSate stage"<<stage << endl;
        WATCH_PTRMAP(deviceEntryMap);
      }
}


void InetSimpleBattery::registerWirelessDevice(int id,double mUsageRadioIdle,double mUsageRadioRecv,double mUsageRadioSend,double mUsageRadioSleep)
{
    Enter_Method_Silent();
    if (deviceEntryMap.find(id)!=deviceEntryMap.end())
    {
        EV << "This device is register \n";
        return;
    }

    EV << "registering new device \n";

    DeviceEntry *device = new DeviceEntry();

    hostState="ACTIVE";

    device->numAccts = 4;
    device->accts = new double[4];
    device->times = new simtime_t[4];
    device->name = getParentModule()->getFullName();

    if (RadioState::IDLE>=4)
        error("Battery and RadioState problem");
    if (RadioState::RECV>=4)
        error("Battery and RadioState problem");
    if (RadioState::TRANSMIT>=4)
        error("Battery and RadioState problem");
    if (RadioState::SLEEP>=4)
        error("Battery and RadioState problem");

    device->radioUsageCurrent[RadioState::IDLE]=mUsageRadioIdle;
    device->radioUsageCurrent[RadioState::RECV]=mUsageRadioRecv;
    device->radioUsageCurrent[RadioState::TRANSMIT]=mUsageRadioSend;
    device->radioUsageCurrent[RadioState::SLEEP]=mUsageRadioSleep;

    for (int i = 0; i < 4; i++)
    {
        device->accts[i] = 0.0;
    }
    for (int i = 0; i < 4; i++)
    {
        device->times[i] = 0.0;
    }

    deviceEntryMap.insert(std::pair<int,DeviceEntry*>(id,device));

    if (mustSubscribe)
    {
        mpNb->subscribe(this, NF_RADIOSTATE_CHANGED);
        //mpNb->subscribe()
        mustSubscribe=false;
    }
}

void InetSimpleBattery::handleMessage(cMessage *msg)
{
    if (msg->isSelfMessage() && residualCapacity>0 )
    {

        switch (msg->getKind())
        {
        case AUTO_UPDATE:
            // update the residual capacity (ongoing current draw)
            scheduleAt(simTime() + resolution, timeout);
            x +=1;
            deductAndCheck() ;
            break;



        case PUBLISH:
            // publish the state to the BatteryStats module
            lastPublishCapacity = residualCapacity;
            scheduleAt(simTime() + publishTime, publish);
            x +=1;
            break;

        default:
            error("battery receives mysterious timeout");
            break;
        }
    }
    else if (residualCapacity<=0)
      cancelAndDelete (msg);

    else
    {
        error("unexpected message");
        delete msg;
    }
}


void InetSimpleBattery::finish()
{
    // do a final update of battery capacity
    deductAndCheck();
    deviceEntryMap.clear();

}

void InetSimpleBattery::receiveChangeNotification (int aCategory, const cPolymorphic* aDetails)
{
    Enter_Method_Silent();
//  Enter_Method("receiveChangeNotification(%s, %s)", notificationCategoryName(aCategory),
//                  aDetails?aDetails->info().c_str() : "n/a");
    EV << "[Battery]: receiveChangeNotification" << endl;
    if (aCategory == NF_RADIOSTATE_CHANGED)
    {
        RadioState *rs = check_and_cast <RadioState *>(aDetails);

        DeviceEntryMap::iterator it = deviceEntryMap.find(rs->getRadioId());

        if (it==deviceEntryMap.end())
            return;

        if (rs->getState()>=it->second->numAccts)
            opp_error("Error in battery states");

        double current = it->second->radioUsageCurrent[rs->getState()];

        EV << simTime() << " wireless device " << rs->getRadioId() << " draw current " << current <<
        "mA, new state = " << rs->getState() << "\n";

        // update the residual capacity (finish previous current draw)
        deductAndCheck();

        // set the new current draw in the device vector

        it->second->draw = y=current; // salah
        it->second->currentActivity =x2= rs->getState(); //salah
    }
}

/**
 *  Function to update the display string with the remaining energy
 */

InetSimpleBattery::~InetSimpleBattery()
{
    while (!deviceEntryMap.empty())
    {
        delete deviceEntryMap.begin()->second;
        deviceEntryMap.erase(deviceEntryMap.begin());
    }

    delete   mCurrEnergy;
    delete residualVec;



}


void InetSimpleBattery::deductAndCheck()
{


     // already depleted, devices should have stopped sending drawMsg,
    // but we catch any leftover messages in queue
    if (residualCapacity <= 0)
    {
        return;
    }

    simtime_t now = simTime();

    // If device[i] has never drawn current (e.g. because the device
    // hasn't been used yet or only uses ENERGY) the currentActivity is
    // still -1.  If the device is not drawing current at the moment,
    // draw has been reset to 0, so energy is also 0.  (It might perhaps
    // be wise to guard more carefully against fp issues later.)


    ev<<"DeviceEntryMap loop"<<endl;
    for (DeviceEntryMap::iterator it = deviceEntryMap.begin(); it!=deviceEntryMap.end(); it++)
    {
        int currentActivity = it->second->currentActivity;

        ev<<"DeviceEntryMap"<<currentActivity <<endl;

        x2=currentActivity ; // salah

        if (currentActivity > -1)
        {
            double energy = it->second->draw * voltage * (now - lastUpdateTime).dbl();
            if (energy > 0)
            {
                it->second->accts[currentActivity] += energy;
                it->second->times[currentActivity] += (now - lastUpdateTime);
                residualCapacity -= energy;
            }
        }
    }


    lastUpdateTime = now;

    EV << "residual capacity = " << residualCapacity << "\n";

    cDisplayString* display_string = &getParentModule()->getDisplayString();

    // battery is depleted
    if (residualCapacity <= 0.0 )
    {

        EV << "[BATTERY]: " << getParentModule()->getFullName() <<" 's battery exhausted, stop simulation" << "\n";
        display_string->setTagArg("i", 1, "#000000");
    //    display_string->setTagArg("i", 1, "#ff0000");

           lifetime= now;

            cModule *mod;
            for (mod = getParentModule(); mod != 0; mod = mod->getParentModule())
                if (mod->getSubmodule("notificationBoard"))
                    break;
            if (!mod)
                error("findHost(): host module not found (it should have a submodule named notificationBoard)");

           // hostState->set(HostState::OFF);

          // st=hostState->info();

            hostState ="OFF";

         // get a pointer to the host

         EV << "UnRegister Host";
         ev<<"delete success in Battery Module !\n";

         cancelAndDelete(timeout);
         cancelAndDelete(publish);
         cc->unregisterHost(mod);
       }

    // battery is not depleted, continue
     else
     {
        // publish the battery capacity if it changed by more than delta
        if ((lastPublishCapacity - residualCapacity)/capacity >= publishDelta)
        {
            lastPublishCapacity = residualCapacity;
        }
     }

    double prp = (residualCapacity/capacity)*100;

    if (mCurrEnergy)
      {
      mCurrEnergy->record(capacity-residualCapacity);
      residualVec->record(prp);
      }

}
