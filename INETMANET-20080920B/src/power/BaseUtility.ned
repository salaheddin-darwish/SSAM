package inet.power;

import inet.base.NotificationBoard;
// Basic utility module for a host.
// Mainly provides black board like information
// exchange between the other modules of a host.
simple BaseUtility extends NotificationBoard
{
    parameters:
        @class(BaseUtility);
        @display("i=block/blackboard");
}

