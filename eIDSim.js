/**
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|
 * |#       #|  Copyright (c) 1999-2018 CardContact Software & System Consulting
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
 * @fileoverview An eID card simulation
 */


eIDCommandInterpreter                       = require('eID/eIDCommandInterpreter').eIDCommandInterpreter;

MFAccessController                          = require('eID/MFAccessController').MFAccessController;
ePassAccessController                       = require('eID/ePassAccessController').ePassAccessController;
eIDAccessController                         = require('eID/eIDAccessController').eIDAccessController;
eSignAccessController                       = require('eID/eSignAccessController').eSignAccessController;

APDU                                        = require('cardsim/APDU').APDU;
AuthenticationObject                        = require('cardsim/AuthenticationObject').AuthenticationObject;
TrustAnchor                                 = require('cardsim/TrustAnchor').TrustAnchor;
SignatureKey                                = require('cardsim/SignatureKey').SignatureKey;
FileSelector                                = require('cardsim/FileSelector').FileSelector;
FCP                                         = require('cardsim/FCP').FCP;
TransparentEF                               = require('cardsim/TransparentEF').TransparentEF;
FSNode                                      = require('cardsim/FSNode').FSNode;
DF                                          = require('cardsim/DF').DF;
SecureChannel                               = require('cardsim/SecureChannel').SecureChannel;

File                                        = require('scsh/file/File').File;
EAC20                                       = require('scsh/eac/EAC20').EAC20;
CVC                                         = require('scsh/eac/CVC').CVC;
PACEInfo                                    = require('scsh/eac/PACE').PACEInfo;
PACE                                        = require('scsh/eac/PACE').PACE;
ChipAuthenticationInfo                      = require('scsh/eac/ChipAuthentication').ChipAuthenticationInfo;
ChipAuthenticationDomainParameterInfo       = require('scsh/eac/ChipAuthentication').ChipAuthenticationDomainParameterInfo;
ChipAuthenticationPublicKeyInfo             = require('scsh/eac/ChipAuthentication').ChipAuthenticationPublicKeyInfo;
ChipAuthentication                          = require('scsh/eac/ChipAuthentication').ChipAuthentication;
RestrictedIdentificationDomainParameterInfo = require('scsh/eac/RestrictedIdentification').RestrictedIdentificationDomainParameterInfo;
RestrictedIdentificationInfo                = require('scsh/eac/RestrictedIdentification').RestrictedIdentificationInfo;
RestrictedIdentification                    = require('scsh/eac/RestrictedIdentification').RestrictedIdentification;

var mrz =	"TPD<<T220001293<<<<<<<<<<<<<<<" +
		"6408125<1010318D<<<<<<<<<<<<<6" +
		"MUSTERMANN<<ERIKA<<<<<<<<<<<<<";

var paceInfo = new PACEInfo();
paceInfo.protocol = new ByteString("id-PACE-ECDH-GM-AES-CBC-CMAC-128", OID);
paceInfo.version = 2;
paceInfo.parameterId = 13;

var chipAuthenticationInfo = new ChipAuthenticationInfo();
chipAuthenticationInfo.protocol = new ByteString("id-CA-ECDH-AES-CBC-CMAC-128", OID);
chipAuthenticationInfo.version = 2;
chipAuthenticationInfo.keyId = 16;

var privChipAuthenticationInfo = new ChipAuthenticationInfo();
privChipAuthenticationInfo.protocol = new ByteString("id-CA-ECDH-AES-CBC-CMAC-128", OID);
privChipAuthenticationInfo.version = 2;
privChipAuthenticationInfo.keyId = 17;

var chipAuthenticationInfoDG14 = new ChipAuthenticationInfo();
chipAuthenticationInfoDG14.protocol = new ByteString("id-CA-ECDH-3DES-CBC-CBC", OID);
// chipAuthenticationInfoDG14.protocol = new ByteString("id-CA-ECDH-AES-CBC-CMAC-128", OID);
chipAuthenticationInfoDG14.version = 1;

var chipAuthenticationDomainParameterInfo = new ChipAuthenticationDomainParameterInfo();
chipAuthenticationDomainParameterInfo.protocol = new ByteString("id-CA-ECDH", OID);
chipAuthenticationDomainParameterInfo.standardizedDomainParameter = 13;
chipAuthenticationDomainParameterInfo.keyId = 16;

var privChipAuthenticationDomainParameterInfo = new ChipAuthenticationDomainParameterInfo();
privChipAuthenticationDomainParameterInfo.protocol = new ByteString("id-CA-ECDH", OID);
privChipAuthenticationDomainParameterInfo.standardizedDomainParameter = 13;
privChipAuthenticationDomainParameterInfo.keyId = 17;

var groupCAPrk = new Key("kp_prk_GroupCAKey.xml");
var groupCAPuk = new Key("kp_puk_GroupCAKey.xml");
groupCAPrk.setComponent(Key.ECC_CURVE_OID, groupCAPrk.getComponent(Key.ECC_CURVE_OID));

var chipAuthenticationPublicKeyInfo = new ChipAuthenticationPublicKeyInfo();
chipAuthenticationPublicKeyInfo.protocol = new ByteString("id-PK-ECDH", OID);
chipAuthenticationPublicKeyInfo.algorithm = new ByteString("standardizedDomainParameter", OID);
chipAuthenticationPublicKeyInfo.standardizedDomainParameter = 13;
chipAuthenticationPublicKeyInfo.publicKey = groupCAPuk;
chipAuthenticationPublicKeyInfo.keyId = 16;

var chipAuthenticationPublicKeyInfoDG14 = new ChipAuthenticationPublicKeyInfo();
chipAuthenticationPublicKeyInfoDG14.protocol = new ByteString("id-PK-ECDH", OID);
chipAuthenticationPublicKeyInfoDG14.algorithm = new ByteString("id-ecPublicKey", OID);
chipAuthenticationPublicKeyInfoDG14.publicKey = groupCAPuk;

var chipCAPrk = new Key("kp_prk_UniqueCAKey.xml");
var chipCAPuk = new Key("kp_puk_UniqueCAKey.xml");
chipCAPrk.setComponent(Key.ECC_CURVE_OID, chipCAPrk.getComponent(Key.ECC_CURVE_OID));

var privChipAuthenticationPublicKeyInfo = new ChipAuthenticationPublicKeyInfo();
privChipAuthenticationPublicKeyInfo.protocol = new ByteString("id-PK-ECDH", OID);
privChipAuthenticationPublicKeyInfo.algorithm = new ByteString("standardizedDomainParameter", OID);
privChipAuthenticationPublicKeyInfo.standardizedDomainParameter = 13;
privChipAuthenticationPublicKeyInfo.publicKey = chipCAPuk;
privChipAuthenticationPublicKeyInfo.keyId = 17;

var terminalAuthenticationInfo = new ASN1("terminalAuthenticationInfo", ASN1.SEQUENCE,
										new ASN1("protocol", ASN1.OBJECT_IDENTIFIER, new ByteString("id-TA", OID)),
										new ASN1("version", ASN1.INTEGER, ByteString.valueOf(2))
									);

var terminalAuthenticationInfoDG14 = new ASN1("terminalAuthenticationInfo", ASN1.SEQUENCE,
										new ASN1("protocol", ASN1.OBJECT_IDENTIFIER, new ByteString("id-TA", OID)),
										new ASN1("version", ASN1.INTEGER, ByteString.valueOf(1))
									);

var restrictedIdentificationDomainParameterInfo = new RestrictedIdentificationDomainParameterInfo();
restrictedIdentificationDomainParameterInfo.protocol = new ByteString("id-RI-ECDH", OID);
restrictedIdentificationDomainParameterInfo.standardizedDomainParameter = 13;

var rIKeys = [];

var restrictedIdentificationRecovation = new RestrictedIdentificationInfo();
restrictedIdentificationRecovation.protocol = new ByteString("id-RI-ECDH-SHA-256", OID);
restrictedIdentificationRecovation.version = 1;
restrictedIdentificationRecovation.keyId = 0x8;
restrictedIdentificationRecovation.authorizedOnly = false;

var riKey = new Key("kp_prk_RevocationKey.xml");
rIKeys[restrictedIdentificationRecovation.keyId] = {
	prk: riKey,
	authorizedOnly: false
};


var restrictedIdentificationSector = new RestrictedIdentificationInfo();
restrictedIdentificationSector.protocol = new ByteString("id-RI-ECDH-SHA-256", OID);
restrictedIdentificationSector.version = 1;
restrictedIdentificationSector.keyId = 0x9;
restrictedIdentificationSector.authorizedOnly = true;

var riKey = new Key("kp_prk_IDKey.xml");
rIKeys[restrictedIdentificationSector.keyId] = {
	prk: riKey,
	authorizedOnly: true
};

var ciInfo = 	new ASN1(ASN1.SEQUENCE,
					new ASN1(ASN1.OBJECT_IDENTIFIER, new ByteString("id-CI", OID)),
					new ASN1(ASN1.IA5String, new ByteString("http://www.openscdp.org/eID/eID.xml", ASCII))
				);


var cardAccess = new ASN1(ASN1.SET,
							terminalAuthenticationInfo,
							chipAuthenticationInfo.toTLV(),
							paceInfo.toTLV(),
							chipAuthenticationDomainParameterInfo.toTLV(),
							ciInfo,
							new ASN1(ASN1.SEQUENCE,
								new ASN1(ASN1.OBJECT_IDENTIFIER, new ByteString("id-PT", OID)),
								new ASN1(ASN1.SET,
									privChipAuthenticationInfo.toTLV(),
									privChipAuthenticationDomainParameterInfo.toTLV()
								)
							)
						);
print("CardAccess:");
print(cardAccess);

var cardSecurity = new ASN1(ASN1.SET,
							terminalAuthenticationInfo,
							chipAuthenticationInfo.toTLV(),
							paceInfo.toTLV(),
							restrictedIdentificationRecovation.toTLV(),
							restrictedIdentificationSector.toTLV(),
							restrictedIdentificationDomainParameterInfo.toTLV(),
							chipAuthenticationDomainParameterInfo.toTLV(),
							ciInfo,
							chipAuthenticationPublicKeyInfo.toTLV()
						);
print("CardSecurity:");
print(cardSecurity);

var chipSecurity = new ASN1(ASN1.SET,
							terminalAuthenticationInfo,
							privChipAuthenticationInfo.toTLV(),
							paceInfo.toTLV(),
							restrictedIdentificationRecovation.toTLV(),
							restrictedIdentificationSector.toTLV(),
							restrictedIdentificationDomainParameterInfo.toTLV(),
							privChipAuthenticationDomainParameterInfo.toTLV(),
							ciInfo,
							privChipAuthenticationPublicKeyInfo.toTLV()
						);
print("ChipSecurity:");
print(chipSecurity);

var dg14 = new ASN1(0x6E,
					new ASN1(ASN1.SET,
							terminalAuthenticationInfoDG14,
							chipAuthenticationInfoDG14.toTLV(),
							chipAuthenticationPublicKeyInfoDG14.toTLV()
						)
				);


var dskey = new Key("kp_prk_DocSigner.xml");
var dscert = new X509("C_DocSigner.cer");

var gen = new CMSGenerator(CMSGenerator.TYPE_SIGNED_DATA);
gen.setDataContent(cardSecurity.getBytes());
gen.addSigner(dskey, dscert, new ByteString("id-sha256", OID), true);
var signedCardSecurity = gen.generate(new ByteString("id-SecurityObject", OID));
//print(new ASN1(signedCardSecurity));

var gen = new CMSGenerator(CMSGenerator.TYPE_SIGNED_DATA);
gen.setDataContent(chipSecurity.getBytes());
gen.addSigner(dskey, dscert, new ByteString("id-sha256", OID), true);
var signedChipSecurity = gen.generate(new ByteString("id-SecurityObject", OID));
//print(new ASN1(signedChipSecurity));


// Load root certificates
var f = new File(GPSystem.mapFilename("cvc/UTISCVCA/UTISCVCA00001.selfsigned.cvcert", GPSystem.CWD));
var c = new CVC(f.readAllAsBinary());
print(c);
var currentDate = c.getCED();
var cvcis = new TrustAnchor(c);

var f = new File(GPSystem.mapFilename("cvc/UTATCVCA/UTATCVCA00001.selfsigned.cvcert", GPSystem.CWD));
var c = new CVC(f.readAllAsBinary());
print(c);
var cvcat = new TrustAnchor(c);

var f = new File(GPSystem.mapFilename("cvc/UTSTCVCA/UTSTCVCA00001.selfsigned.cvcert", GPSystem.CWD));
var c = new CVC(f.readAllAsBinary());
print(c);
var cvcst = new TrustAnchor(c);



/**
 * Create a card simulation object
 *
 * @class Class implementing a simple ISO 7816-4 card simulation
 * @constructor
 */
function eIDSimulation() {
	this.createFileSystem();
	this.initialize();
}



/**
 * Handle actions from context menu
 */
eIDSimulation.prototype.actionListener = function(source, action) {
	switch(action) {
		case "Stop":
			source.dispose();
			break;
	}
}



/**
 * Initialize card runtime
 */
eIDSimulation.prototype.createFileSystem = function() {
	var eac = new EAC20(new Crypto());

	this.mf = new DF(FCP.newDF("3F00", null),
						new TransparentEF(FCP.newTransparentEF("011C", 0x1C, 100), cardAccess.getBytes()),
						new TransparentEF(FCP.newTransparentEF("011D", 0x1D, 100), signedCardSecurity),
						new TransparentEF(FCP.newTransparentEF("011B", 0x1B, 100), signedChipSecurity)
					);

	this.mf.addMeta("accessController", new MFAccessController());
	this.mf.addMeta("groupChipAuthenticationPrivateKey", groupCAPrk);
	this.mf.addMeta("groupChipAuthenticationPublicKey", groupCAPuk);
	this.mf.addMeta("groupChipAuthenticationInfo", chipAuthenticationInfo);
	this.mf.addMeta("uniqueChipAuthenticationPrivateKey", chipCAPrk);
	this.mf.addMeta("uniqueChipAuthenticationPublicKey", chipCAPuk);
	this.mf.addMeta("uniqueChipAuthenticationInfo", privChipAuthenticationInfo);

	this.mf.addMeta("paceInfo", paceInfo);
	this.mf.addMeta("idPICC", new ByteString(EAC20.decodeDocumentNumber(mrz), ASCII));
	this.mf.addObject(cvcis);
	this.mf.addObject(cvcat);
	this.mf.addObject(cvcst);
	this.mf.addMeta("currentDate", { currentDate: currentDate} );

	var pacemrz = new AuthenticationObject("PACE_MRZ", AuthenticationObject.TYPE_PACE, 1,
									eac.hashMRZ(mrz));
	pacemrz.initialretrycounter = 0;
	this.mf.addObject(pacemrz);

	var pacecan = new AuthenticationObject("PACE_CAN", AuthenticationObject.TYPE_PACE, 2,
									new ByteString("500540", ASCII));
	pacecan.initialretrycounter = 0;
	pacecan.allowResetRetryCounter = true;
	pacecan.allowResetValue = true;
	this.mf.addObject(pacecan);

	var pacepin = new AuthenticationObject("PACE_PIN", AuthenticationObject.TYPE_PACE, 3,
									new ByteString("55555", ASCII));
	pacepin.isTransport = true;
	pacepin.allowActivate = true;
	pacepin.allowDeactivate = true;
	pacepin.allowResetRetryCounter = true;
	pacepin.allowResetValue = true;
	pacepin.minLength = 6;
	pacepin.unsuspendAuthenticationObject = pacecan;
	this.mf.addObject(pacepin);

	var pacepuk = new AuthenticationObject("PACE_PUK", AuthenticationObject.TYPE_PACE, 4,
									new ByteString("87654321", ASCII));
	pacecan.initialretrycounter = 0;
	this.mf.addObject(pacepuk);

	pacepin.unblockAuthenticationObject = pacepuk;

	var binCVCA = (new ASN1(0x42, new ByteString("UTISCVCA00001", ASCII))).getBytes();
	var binCVCA = binCVCA.concat((new ByteString("000000000000000000000000000000000000000000000000000000000000000000000000", HEX)).bytes(binCVCA.length));
	var efCVCA = new TransparentEF(FCP.newTransparentEF("011C", 0x1C, 36), binCVCA);			// EF.CVCA

	this.mf.addMeta("efCVCA", efCVCA);

	var com = (new ASN1(0x60,
					new ASN1(0x5F01, new ByteString("0107", ASCII)),
					new ASN1(0x5F36, new ByteString("040000", ASCII)),
					new ASN1(0x5C, new ByteString("6175637664", HEX))
				)).getBytes();
	var dg1 = (new ASN1(0x61, new ASN1(0x5F1F, new ByteString(mrz, ASCII)))).getBytes();
	print(dg1);

	var dFePass = 		new DF(FCP.newDF(null, new ByteString("A0000002471001", HEX)),
							new TransparentEF(FCP.newTransparentEF("011E", 0x1E, 100),		// EF.COM
								com),
							new TransparentEF(FCP.newTransparentEF("011D", 0x1D, 100),		// EF.SOD
								new ByteString("77050123456789", HEX)),
							new TransparentEF(FCP.newTransparentEF("0101", 0x01, 100),		// EF.DG1
								dg1),
							new TransparentEF(FCP.newTransparentEF("0102", 0x02, 100),		// EF.DG2
								new ByteString("75037F6101AA", HEX)),
							new TransparentEF(FCP.newTransparentEF("0103", 0x03, 100),		// EF.DG3
								new ByteString("63037F6101AA", HEX)),
							new TransparentEF(FCP.newTransparentEF("0104", 0x04, 100),		// EF.DG4
								new ByteString("76037F6101AA", HEX)),
							new TransparentEF(FCP.newTransparentEF("010E", 0x0E, 100),		// EF.DG14
								dg14.getBytes()),
							efCVCA
						);

	dFePass.addMeta("accessController", new ePassAccessController());

	dFePass.addMeta("KENC", eac.calculateBACKey(mrz, 1));
	dFePass.addMeta("KMAC", eac.calculateBACKey(mrz, 2));

	dFePass.addMeta("chipAuthenticationPrivateKey", groupCAPrk);
	dFePass.addMeta("chipAuthenticationPublicKey", groupCAPuk);
	dFePass.addMeta("chipAuthenticationInfo", chipAuthenticationInfoDG14);


	var dFeID = 		new DF(FCP.newDF(null, new ByteString("E80704007F00070302", HEX)),
							new TransparentEF(FCP.newTransparentEF("0101", 0x01, 100), 		// EF.DG1
								new ByteString("6100", HEX)),
							new TransparentEF(FCP.newTransparentEF("0102", 0x02, 100), 		// EF.DG2
								new ByteString("6200", HEX)),
							new TransparentEF(FCP.newTransparentEF("0103", 0x03, 100), 		// EF.DG3
								new ByteString("6300", HEX)),
							new TransparentEF(FCP.newTransparentEF("0104", 0x04, 100), 		// EF.DG4
								new ByteString("6400", HEX)),
							new TransparentEF(FCP.newTransparentEF("0105", 0x05, 100), 		// EF.DG5
								new ByteString("6500", HEX)),
							new TransparentEF(FCP.newTransparentEF("0106", 0x06, 100), 		// EF.DG6
								new ByteString("6600", HEX)),
							new TransparentEF(FCP.newTransparentEF("0107", 0x07, 100), 		// EF.DG7
								new ByteString("6700", HEX)),
							new TransparentEF(FCP.newTransparentEF("0108", 0x08, 100), 		// EF.DG8
								new ByteString("6800", HEX)),
							new TransparentEF(FCP.newTransparentEF("0109", 0x09, 100), 		// EF.DG9
								new ByteString("6900", HEX)),
							new TransparentEF(FCP.newTransparentEF("010A", 0x0A, 100), 		// EF.DG10
								new ByteString("6A00", HEX)),
							new TransparentEF(FCP.newTransparentEF("010B", 0x0B, 100), 		// EF.DG11
								new ByteString("6B00", HEX)),
							new TransparentEF(FCP.newTransparentEF("010C", 0x0C, 100), 		// EF.DG12
								new ByteString("6C00", HEX)),
							new TransparentEF(FCP.newTransparentEF("010D", 0x0D, 100), 		// EF.DG13
								new ByteString("6D00", HEX)),
							new TransparentEF(FCP.newTransparentEF("010E", 0x0E, 100), 		// EF.DG14
								new ByteString("6E00", HEX)),
							new TransparentEF(FCP.newTransparentEF("010F", 0x0F, 100), 		// EF.DG15
								new ByteString("6F00", HEX)),
							new TransparentEF(FCP.newTransparentEF("0110", 0x10, 100), 		// EF.DG16
								new ByteString("7000", HEX)),
							new TransparentEF(FCP.newTransparentEF("0111", 0x11, 200), 		// EF.DG17
								new ByteString("7100", HEX)),
							new TransparentEF(FCP.newTransparentEF("0112", 0x12, 100), 		// EF.DG18
								new ByteString("7200", HEX)),
							new TransparentEF(FCP.newTransparentEF("0113", 0x13, 100), 		// EF.DG19
								new ByteString("7300", HEX)),
							new TransparentEF(FCP.newTransparentEF("0114", 0x14, 100), 		// EF.DG20
								new ByteString("7400", HEX)),
							new TransparentEF(FCP.newTransparentEF("0115", 0x15, 100), 		// EF.DG21
								new ByteString("7500", HEX))
						);

	dFeID.addMeta("accessController", new eIDAccessController());
	dFeID.addMeta("DateOfExpiry", "20161231");
	dFeID.addMeta("DateOfBirth", "19661109");
	dFeID.addMeta("CommunityID", "1234");
	dFeID.addMeta("RIKeys", rIKeys);


	var dFeSign =		new DF(FCP.newDF(null, new ByteString("A000000167455349474E", HEX)),
							new TransparentEF(FCP.newTransparentEF("C000", 1, 2048)), 		// EF.C.ZDA.QES
							new TransparentEF(FCP.newTransparentEF("C001", 2, 2048)) 		// EF.C.ICC.QES
						);

	dFeSign.addMeta("accessController", new eSignAccessController());

	var signpin = new AuthenticationObject("PIN.QES", AuthenticationObject.TYPE_PIN, 1);
	signpin.isTerminated = true;
	signpin.allowTerminate = true;
	signpin.allowResetRetryCounter = true;
	signpin.allowResetValue = true;
	signpin.allowChangeReferenceData = true;
	signpin.unblockAuthenticationObject = pacepuk;
	dFeSign.addObject(signpin);

	var signaturekey = new SignatureKey("PrK.QES", 1);
	signaturekey.useAuthenticationObject = signpin;
	signpin.associatedKey = signaturekey;
	dFeSign.addObject(signaturekey);

	this.mf.add(dFePass);
	this.mf.add(dFeID);
	this.mf.add(dFeSign);

	print(this.mf.dump(""));
}



/**
 * Initialize card runtime
 */
eIDSimulation.prototype.initialize = function() {
	this.fileSelector = new FileSelector(this.mf);
	this.commandInterpreter = new eIDCommandInterpreter(this.fileSelector);

}



/**
 * Process an inbound APDU
 *
 * @param {ByteString} capdu the command APDU
 * @type ByteString
 * @return the response APDU
 */
eIDSimulation.prototype.processAPDU = function(capdu) {
//	print("Command APDU : " + capdu);

	var apdu;

	try	{
		apdu = new APDU(capdu);
	}
	catch(e) {
		GPSystem.trace(e);
		var sw = APDU.SW_GENERALERROR;
		if (e instanceof GPError) {
			sw = e.reason;
		}
		var bb = new ByteBuffer();
		bb.append(sw >> 8);
		bb.append(sw & 0xFF);
		return bb.toByteString();
	}

	this.commandInterpreter.processAPDU(apdu);

	var rapdu = apdu.getResponseAPDU();
//	print("Response APDU: " + rapdu);
	return rapdu;
}



/**
 * Respond to reset request
 *
 * @param {Number} type reset type (One of Card.RESET_COLD or Card.RESET.WARM)
 * @type ByteString
 * @return answer to reset
 */
eIDSimulation.prototype.reset = function(type) {
//	print("Reset type: " + type);

	this.initialize();

	var atr = new ByteString("3B600000", HEX);
	return atr;
}



/*
 * Create new simulation and register with existing or newly created adapter singleton.
 *
 */
var sim = new eIDSimulation();

var tasks = Task.getTaskList();
if (tasks.length == 0) {
	var adapter = new CardSimulationAdapter("JCOPSimulation", "8050");
	adapter.setSimulationObject(sim);
	var task = new Task(adapter);
	task.setContextMenu( [ "Stop" ] );
	task.start();
	print("Simulation running...");
} else {
	tasks[0].userObject.setSimulationObject(sim);
	print("Simulation replaced...");
}
