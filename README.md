# eID-sim
Simulation and test environment for eID cards and passports

The eIDSim profile contains a full simulation of a id card providing an ePassport, eID and eSign application
as defined in TR-03110 2.1 implementing BAC, SAC, PACE and EAC (1.11+2.1). It is functionally equivalent to
the German eID card and contains the required test data generators as well as a CVC PKI for the IS,AT and ST
branch.

## Installation

You need to install the Smart Card Shell available at [OpenSCDP](https://www.openscdp.org/scsh3/index.html). You need at
least version 3.14.330.

Clone or unpack this project in a directory of your choice, start the Smart Card Shell and select
the eID-sim directory as workspace.

## Starting the simulation

Start the simulator using **File/Run Script (CTRL-R)** with the **eIDsim.js** script.

The simulator runs as a background task, which can be seen in the **Tasks** tab. It opens port 8050 to receive
messages in the JCOP Simulation procotol. Select the **JCOPSimulation** card reader from **Options/Reader Configuration**
and enter "r" in the shell. You should see the ATR from the simulator.

## Loading the test suite

Start the script **testing/loadtests.js** to load the test suite. It shows the test outline in the explorer panel.
Right-click on **eID Test Suite** to open the context menu and select **expand**. You should now see the test cases.
Select **run** from the context menu to start all tests.
