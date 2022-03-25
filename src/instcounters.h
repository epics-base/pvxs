/* Names of internal object instance counters.
 * Included in three places in utilpvt.h and util.cpp
 */
#ifndef CASE
// for IDEs
#  define CASE(NAME)
#  error Must define CASE
#endif
CASE(StructTop);

CASE(UDPListener);
CASE(evbase);
CASE(evbaseRunning);
CASE(Timer);

CASE(GPROp);
CASE(Connection);
CASE(Channel);
CASE(ClientPvt);
CASE(ClientContextImpl);
CASE(InfoOp);
CASE(SubScriptionImpl);

CASE(ServerChannelControl);
CASE(ServerChan);
CASE(ServerConn);
CASE(ServerSource);
CASE(ServerPvt);
CASE(ServerIntrospect);
CASE(ServerIntrospectControl);
CASE(ServerGPR);
CASE(ServerGPRConnect);
CASE(ServerGPRExec);
CASE(MonitorOp);
CASE(ServerMonitorControl);
CASE(ServerMonitorSetup);
CASE(SharedPVImpl);
CASE(SubscriptionImpl);
