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



// Point 0
var b = new Key();
b.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP320r1", OID));
b.setComponent(Key.ECC_QX, new ByteString("26e848758cd601a62c3c96f29001259e4560763f9e79bf9e35e3b69103e4d442b4e9d4a8de208c45", HEX));
b.setComponent(Key.ECC_QY, new ByteString("99caee26203cec3ff6ecdedd2d71bc6871d3a41da4d4d11885bb0b4c4bb05866eac2d9a6553fdf49", HEX));
param["blinding"] = b;

// Point 1
var cipherPI = new Key();
cipherPI.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP320r1", OID));
cipherPI.setComponent(Key.ECC_QX, new ByteString("474fb982ab20899d3633ae479b6983c309350f55aaeb3cf7d22eaf81d89488859da4bd3b03f3b0e2", HEX));
cipherPI.setComponent(Key.ECC_QY, new ByteString("a5954fc8036359c530c87c05f5699b194a95b98d5a22e1cbf0e576e2d449ebf828a07456903b556a", HEX));
param["cipherPI"] = cipherPI;

// Point 2
var cipherPP = new Key();
cipherPP.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP320r1", OID));
cipherPP.setComponent(Key.ECC_QX, new ByteString("18877740186ea40e51932bccecd38d971caaf07a9f26c4d50a8f32bce3b6a667962307fe8d66e3a5", HEX));
cipherPP.setComponent(Key.ECC_QY, new ByteString("601b614fe272546c41e2efef64353b6f40729df4d7321fffdd026a58d2c473c185b5150870e7a319", HEX));
param["cipherPP"] = cipherPP;

// Private Key PI
var privPI = new Key();
privPI.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP320r1", OID));
privPI.setComponent(Key.ECC_D, new ByteString("ea2dcb06e52c6111550de1590c2b6449591f91ad9c6a59a4baae2e3d4e44cb70ff1017a0c6463c21", HEX));
param["privPI"] = privPI;

// Private Key PP
var privPP = new Key();
privPP.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP320r1", OID));
privPP.setComponent(Key.ECC_D, new ByteString("79a1524da2058c6e5d4c1af1a5f4ecb5aef1eb24241b5874ce6261b17ac30d8b6a5e15422030f959", HEX));
param["privPP"] = privPP;



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
	} else {
		print("X: " + point.toString(HEX));
	}
}



function verifyPI(randBlinding, randCipher) {
	return verifyRandomizedPoint(param.privPI, param.cipherPI, randBlinding, randCipher);
}



function verifyPP(randBlinding, randCipher) {
	return verifyRandomizedPoint(param.privPP, param.cipherPP, randBlinding, randCipher);
}



function verifyRandomizedPoint(privKey, refCipherPoint, randBlinding, randCipher) {
	var refBlinding = new ByteString("04", HEX);
	refBlinding = refBlinding.concat(param.blinding.getComponent(Key.ECC_QX));
	refBlinding = refBlinding.concat(param.blinding.getComponent(Key.ECC_QY));

	refCipher = new ByteString("04", HEX);
	refCipher = refCipher.concat(refCipherPoint.getComponent(Key.ECC_QX));
	refCipher = refCipher.concat(refCipherPoint.getComponent(Key.ECC_QY));
	
	var refPlain = decrypt(privKey, refBlinding, refCipher);
	var randPlain = decrypt(privKey, randBlinding, randCipher);

	return refPlain.equals(randPlain);
}



function decrypt(privKey, blinding, cipher) {
	var seq = new ASN1(ASN1.SEQUENCE);
	
	var pubSeq = new ASN1(0x7F49);
	pubSeq.add(new ASN1(0x06, new ByteString("brainpoolP320r1", OID)));
	pubSeq.add(new ASN1(0x86, blinding)); 
	seq.add(pubSeq);

	var pubSeq = new ASN1(0x7F49);
	pubSeq.add(new ASN1(0x06, new ByteString("brainpoolP320r1", OID)));
	pubSeq.add(new ASN1(0x86, cipher)); 
	seq.add(pubSeq);

	var c = new Crypto();
	var resp = c.decrypt(privKey, Crypto.ECELGAMAL, seq.getBytes());
	
	GPSystem.trace("Plain");
	GPSystem.trace(new ASN1(resp));
	
	return resp;
}



var testRunner = new TestRunner("PCA Test Suite");
testRunner.addTestProcedureFromXML("tp_randomization.xml");
testRunner.addTestGroupFromXML("tg_PCA.xml", param);

print("Test-Suite loaded...");
print("Right-click on the tests on the left.");
