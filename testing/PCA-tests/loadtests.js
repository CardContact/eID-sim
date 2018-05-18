/**
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|
 * |#       #|  Copyright (c) 1999-2008 CardContact Software & System Consulting
 * |'##> <##'|  Andreas Schwier, 32429 Minden, Germany (www.cardcontact.de)
 *  ---------
 *
 *  This file is part of OpenSCDP.
 *
 *  OpenSCDP is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  OpenSCDP is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with OpenSCDP; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * @fileoverview Script to load all tests for the eID test suite into the GUI test runner
 */

load("tools/TestRunner.js");
load("tools/TestGroup.js");
load("tools/TestProcedure.js");

load("tools/eccutils.js");

// load("../../icao/eac20.js");
EAC20				= require('scsh/eac/EAC20').EAC20;
CVCertificateStore	= require('scsh/eac/CVCertificateStore').CVCertificateStore;


var param = new Array();

param["crypto"] = new Crypto();

param["MRZ"] =	"TPD<<T220001293<<<<<<<<<<<<<<<" +
		"6408125<1010318D<<<<<<<<<<<<<6" +
		"MUSTERMANN<<ERIKA<<<<<<<<<<<<<";

param["PIN"] = "55555";

var certstorepath = GPSystem.mapFilename("../../cvc", GPSystem.CWD);
param["certstore"] = new CVCertificateStore(certstorepath);
param["isrootpath"] = "/UTISCVCA";
param["atrootpath"] = "/UTATCVCA";
param["strootpath"] = "/UTSTCVCA";
param["isodcertpath"] = param["isrootpath"] + "/UTISDVCAOD/UTTERM";		// Official Domestic Inspection System
param["isofcertpath"] = param["isrootpath"] + "/UTISDVCAOF/UTTERM";		// Foreign Inspection System
param["atodcertpath"] = param["atrootpath"] + "/UTATDVCAOD/UTTERM";		// Official Domestic Authentication Terminal
param["atnocertpath"] = param["atrootpath"] + "/UTATDVCANO/UTTERM";		// Non-official Domestic Authentication Terminal

param["pcapipcertpath"] = param["atrootpath"] + "/UTATDVCANO/UTTERMPCAPIP";		// Non-official Domestic Authentication Terminal with PIP authorization
param["pcappcertpath"] = param["atrootpath"] + "/UTATDVCANO/UTTERMPCAPP";		// Non-official Domestic Authentication Terminal with PP authorization
param["pcapicertpath"] = param["atrootpath"] + "/UTATDVCANO/UTTERMPCAPI";		// Non-official Domestic Authentication Terminal with PI authorization

param["stabcertpath"] = param["strootpath"] + "/UTSTDVCAAB/UTTERM";		// Accreditation Body Signature Terminal
param["stcpcertpath"] = param["strootpath"] + "/UTSTDVCACP/UTTERM";		// Certificate Service Provider Signature Terminal

param["PCAAID"] = new ByteString("A0 00 00 07 73 50 43 41", HEX);


/**
 * Create a new instance of the EAC20 class
 *
 * <p>This method allows to tailor the EAC instance before running the test.</p>
 *
 * @param {Crypto} crypto the crypto provider to use
 * @param {Card} card the card under test
 * @type EAC20
 * @return a new instance of the EAC20 protocol stack
 */
function newEAC20(crypto, card) {
	var eac = new EAC20(crypto, card);
	eac.verbose = true;
	return eac;
}



function printEncodedPoint(encPoint) {
	var encoding = encPoint.byteAt(0);
	var point = encPoint.bytes(1);

	if (encoding == 4) {
		var x = point.bytes(0, point.length / 2);
		print("X: " + x.toString(HEX));
		var y = point.bytes(point.length / 2);
		print("Y: " + y.toString(HEX));
	} else if (encoding == 2) {
		print("X: " + point.toString(HEX));
	}
}



var testRunner = new TestRunner("PCA Test Suite");
testRunner.addTestProcedureFromXML("tp_randomization.xml");
testRunner.addTestGroupFromXML("tg_PCA.xml", param);

print("Test-Suite loaded...");
print("Right-click on the tests on the left.");
