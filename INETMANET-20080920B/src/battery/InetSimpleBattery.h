/***************************************************************************
 * Simple battery model for inetmanet framework
 * Author:  Alfonso Ariza
 * Based in the mixim code Author:  Laura Marie Feeney
 *
 * Copyright 2009 Malaga University.
 * Copyright 2009 Swedish Institute of Computer Science.
 *
 * This software is provided `as is' and without any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose.
 *
 ***************************************************************************/

#ifndef INET_SIMPLE_BATTERY_H
#define INET_SIMPLE_BATTERY_H

#include <omnetpp.h>
#include <vector>
#include <map>
#include "BasicBattery.h"
#include "ChannelControl.h"
//#include "HostState.h"
#include "RadioState.h"
#include "DeviceEntry.h"

/**
 * @brief Base class for any power source.
 *
 * See "SimpleBattery" for an example implementation.
 *
 * @ingroup baseModules
 * @ingroup power
 * @see SimpleBattery
 */


class INET_API InetSimpleBattery : public BasicBattery
{
  protected:
    typedef std::map<int,DeviceEntry*>  DeviceEntryMap;
    DeviceEntryMap deviceEntryMap;

  public:

//  static InetSimpleBattery *get() ;
    virtual void    initialize(int);
    virtual int numInitStages   () const {return 3;}
    virtual void    finish();
    virtual void handleMessage(cMessage *msg);

    ChannelControl    *cc;
   // HostState  *hostState;// salah

    /**
     * @brief Registers a power draining device with this battery.
     *
     * Takes the name of the device as well as a number of accounts
     * the devices draws power for (like rx, tx, idle for a radio device).
     *
     * Returns an ID by which the device can identify itself to the
     * battery.
     *
     * Has to be implemented by actual battery implementations.
     */
   // virtual int registerDevice(cObject *id,int numAccts);
    virtual void registerWirelessDevice(int id,double mUsageRadioIdle,double mUsageRadioRecv,double mUsageRadioSend,double mUsageRadioSleep);

    /**
     * @brief Draws power from the battery.
     *
     * The actual amount and type of power drawn is defined by the passed
     * DrawAmount parameter. Can be an fixed single amount or an amount
     * drawn over time.
     * The drainID identifies the device which drains the power.
     * "Account" identifies the account the power is drawn from.
     */
 //   virtual void draw(int drainID, DrawAmount& amount, int account);
    ~InetSimpleBattery();
    InetSimpleBattery() {mustSubscribe = true; hostState ="ACTIVE";}
    double getVoltage();
    /** @brief current state of charge of the battery, relative to its
     * rated nominal capacity [0..1]
     */
    double estimateResidualRelative();
    /** @brief current state of charge of the battery (mW-s) */
    double estimateResidualAbs();
    /** @brief handlr state of Host  */

    //std::string getHostSate() {return hostState->info();}
    std::string getHostSate() {return hostState;}

  protected:
    std::string  hostState;// salah

    int x1,x2; // salah

    double y ; // salah
    cOutVector* residualVec;
    cOutVector* mCurrEnergy;

    int x ; // salah
    enum msgType
    {
        AUTO_UPDATE, PUBLISH,
    };

    cMessage *publish;
    simtime_t lastUpdateTime;

    virtual void deductAndCheck();
    void receiveChangeNotification (int aCategory, const cPolymorphic* aDetails);

};

class INET_API InetSimpleBatteryAccess : public ModuleAccess<InetSimpleBattery>
{
  public:
	  InetSimpleBatteryAccess() : ModuleAccess<InetSimpleBattery>("battery") {}
};
#endif

