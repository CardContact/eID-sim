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



eIDCommandInterpreter						= require('eID/eIDCommandInterpreter').eIDCommandInterpreter;

MFAccessController							= require('eID/MFAccessController').MFAccessController;
ePassAccessController						= require('eID/ePassAccessController').ePassAccessController;
eIDAccessController							= require('eID/eIDAccessController').eIDAccessController;
eSignAccessController						= require('eID/eSignAccessController').eSignAccessController;

PolymorphicObject							= require('pca/PolymorphicObject').PolymorphicObject;
PolymorphicInfo								= require('pca/PolymorphicInfo').PolymorphicInfo;
PCAAccessController							= require('pca/PCAAccessController').PCAAccessController;
PCACommandInterpreter						= require('pca/PCACommandInterpreter').PCACommandInterpreter;

APDU										= require('cardsim/APDU').APDU;
AuthenticationObject						= require('cardsim/AuthenticationObject').AuthenticationObject;
TrustAnchor									= require('cardsim/TrustAnchor').TrustAnchor;
SignatureKey								= require('cardsim/SignatureKey').SignatureKey;
FileSelector								= require('cardsim/FileSelector').FileSelector;
FCP											= require('cardsim/FCP').FCP;
TransparentEF								= require('cardsim/TransparentEF').TransparentEF;
FSNode										= require('cardsim/FSNode').FSNode;
DF											= require('cardsim/DF').DF;
SecureChannel								= require('cardsim/SecureChannel').SecureChannel;

File										= require('scsh/file/File').File;
EAC20										= require('scsh/eac/EAC20').EAC20;
CVC											= require('scsh/eac/CVC').CVC;
PACEInfo									= require('scsh/eac/PACE').PACEInfo;
PACE										= require('scsh/eac/PACE').PACE;
ChipAuthenticationInfo						= require('scsh/eac/ChipAuthentication').ChipAuthenticationInfo;
ChipAuthenticationDomainParameterInfo		= require('scsh/eac/ChipAuthentication').ChipAuthenticationDomainParameterInfo;
ChipAuthenticationPublicKeyInfo				= require('scsh/eac/ChipAuthentication').ChipAuthenticationPublicKeyInfo;
ChipAuthentication							= require('scsh/eac/ChipAuthentication').ChipAuthentication;
RestrictedIdentificationDomainParameterInfo	= require('scsh/eac/RestrictedIdentification').RestrictedIdentificationDomainParameterInfo;
RestrictedIdentificationInfo				= require('scsh/eac/RestrictedIdentification').RestrictedIdentificationInfo;
RestrictedIdentification					= require('scsh/eac/RestrictedIdentification').RestrictedIdentification;

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

var chipAuthenticationDomainParameterInfo = new ChipAuthenticationDomainParameterInfo();
chipAuthenticationDomainParameterInfo.protocol = new ByteString("id-CA-ECDH", OID);
chipAuthenticationDomainParameterInfo.standardizedDomainParameter = 13;
chipAuthenticationDomainParameterInfo.keyId = 16;

var groupCAPrk = new Key("kp_prk_GroupCAKey.xml");
var groupCAPuk = new Key("kp_puk_GroupCAKey.xml");
groupCAPrk.setComponent(Key.ECC_CURVE_OID, groupCAPrk.getComponent(Key.ECC_CURVE_OID));

var chipAuthenticationPublicKeyInfo = new ChipAuthenticationPublicKeyInfo();
chipAuthenticationPublicKeyInfo.protocol = new ByteString("id-PK-ECDH", OID);
chipAuthenticationPublicKeyInfo.algorithm = new ByteString("standardizedDomainParameter", OID);
chipAuthenticationPublicKeyInfo.standardizedDomainParameter = 13;
chipAuthenticationPublicKeyInfo.publicKey = groupCAPuk;
chipAuthenticationPublicKeyInfo.keyId = 16;

var terminalAuthenticationInfo = new ASN1("terminalAuthenticationInfo", ASN1.SEQUENCE,
										new ASN1("protocol", ASN1.OBJECT_IDENTIFIER, new ByteString("id-TA", OID)),
										new ASN1("version", ASN1.INTEGER, ByteString.valueOf(2))
									);

var ciInfo = 	new ASN1(ASN1.SEQUENCE,
					new ASN1(ASN1.OBJECT_IDENTIFIER, new ByteString("id-CI", OID)),
					new ASN1(ASN1.IA5String, new ByteString("http://www.openscdp.org/eID/eID.xml", ASCII))
				);


var polymorphicInfo = new PolymorphicInfo();

var cardAccess = new ASN1(ASN1.SET,
							terminalAuthenticationInfo,
							chipAuthenticationInfo.toTLV(),
							paceInfo.toTLV(),
							chipAuthenticationDomainParameterInfo.toTLV(),
							ciInfo,
							polymorphicInfo.toTLV()
						);
print("CardAccess:");
print(cardAccess);

var cardSecurity = new ASN1(ASN1.SET,
							terminalAuthenticationInfo,
							chipAuthenticationInfo.toTLV(),
							paceInfo.toTLV(),
							chipAuthenticationDomainParameterInfo.toTLV(),
							ciInfo,
							chipAuthenticationPublicKeyInfo.toTLV(),
							polymorphicInfo.toTLV()
						);
print("CardSecurity:");
print(cardSecurity);

var dskey = new Key("kp_prk_DocSigner.xml");
var dscert = new X509("C_DocSigner.cer");

var gen = new CMSGenerator(CMSGenerator.TYPE_SIGNED_DATA);
gen.setDataContent(cardSecurity.getBytes());
gen.addSigner(dskey, dscert, new ByteString("id-sha256", OID), true);
var signedCardSecurity = gen.generate(new ByteString("id-SecurityObject", OID));

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
function PCASimulation() {
	this.createFileSystem();
	this.initialize();
}



/**
 * Handle actions from context menu
 */
PCASimulation.prototype.actionListener = function(source, action) {
	switch(action) {
		case "Stop":
			source.dispose();
			break;
	}
}



/**
 * Initialize card runtime
 */
PCASimulation.prototype.createFileSystem = function() {
	var eac = new EAC20(new Crypto());

	this.mf = new DF(FCP.newDF("3F00", null),
						new TransparentEF(FCP.newTransparentEF("011C", 0x1C, 100), cardAccess.getBytes()),
						new TransparentEF(FCP.newTransparentEF("011D", 0x1D, 100), signedCardSecurity)
					);

	this.mf.addMeta("accessController", new MFAccessController());
	this.mf.addMeta("groupChipAuthenticationPrivateKey", groupCAPrk);
	this.mf.addMeta("groupChipAuthenticationPublicKey", groupCAPuk);
	this.mf.addMeta("groupChipAuthenticationInfo", chipAuthenticationInfo);

	this.mf.addMeta("paceInfo", paceInfo);
	this.mf.addMeta("idPICC", new ByteString(EAC20.decodeDocumentNumber(mrz), ASCII));
	this.mf.addObject(cvcis);
	this.mf.addObject(cvcat);
	this.mf.addObject(cvcst);
	this.mf.addMeta("currentDate", { currentDate: currentDate} );
	this.mf.addMeta("polymorphicInfo", polymorphicInfo);

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

	// Point 0
	var b = new Key();
	b.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP320r1", OID));
	b.setComponent(Key.ECC_QX, new ByteString("26e848758cd601a62c3c96f29001259e4560763f9e79bf9e35e3b69103e4d442b4e9d4a8de208c45", HEX));
	b.setComponent(Key.ECC_QY, new ByteString("99caee26203cec3ff6ecdedd2d71bc6871d3a41da4d4d11885bb0b4c4bb05866eac2d9a6553fdf49", HEX));

	// Point 1
	var cipherPI = new Key();
	cipherPI.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP320r1", OID));
	cipherPI.setComponent(Key.ECC_QX, new ByteString("474fb982ab20899d3633ae479b6983c309350f55aaeb3cf7d22eaf81d89488859da4bd3b03f3b0e2", HEX));
	cipherPI.setComponent(Key.ECC_QY, new ByteString("a5954fc8036359c530c87c05f5699b194a95b98d5a22e1cbf0e576e2d449ebf828a07456903b556a", HEX));

	// Point 2
	var cipherPP = new Key();
	cipherPP.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP320r1", OID));
	cipherPP.setComponent(Key.ECC_QX, new ByteString("18877740186ea40e51932bccecd38d971caaf07a9f26c4d50a8f32bce3b6a667962307fe8d66e3a5", HEX));
	cipherPP.setComponent(Key.ECC_QY, new ByteString("601b614fe272546c41e2efef64353b6f40729df4d7321fffdd026a58d2c473c185b5150870e7a319", HEX));

	// Point 3
	var pubKeyPI = new Key();
	pubKeyPI.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP320r1", OID));
	pubKeyPI.setComponent(Key.ECC_QX, new ByteString("9426cebf206de90b56c083f032b8f82b02501c4f7cddd72956525c539fc34a6766642998acd2ab2d", HEX));
	pubKeyPI.setComponent(Key.ECC_QY, new ByteString("cd490dc6200a2346de929996a457cb336ce179686fc71c4fff04ff29618d639bff8da7b052de86b5", HEX));

	// Point 4
	var pubKeyPP = new Key();
	pubKeyPP.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP320r1", OID));
	pubKeyPP.setComponent(Key.ECC_QX, new ByteString("4c89ed2eb8fe5753b6832aeee93224fac1e6cdd854b6d98c2fb176915d0581ac1d9f1c0fc9ce9ca4", HEX));
	pubKeyPP.setComponent(Key.ECC_QY, new ByteString("9d7e437bfafc10cd6bd5f6afd2e5f58bb4c8456caf65efb62336a3d75ce3f02d22da178032fab50b", HEX));


    var pip = new PolymorphicObject(b, cipherPI, cipherPP, pubKeyPI, pubKeyPP);

    var dFPCA = new DF(FCP.newDF(null, new ByteString("A0 00 00 07 73 50 43 41", HEX)));
    dFPCA.addObject(pip);

	dFPCA.addMeta("accessController", new PCAAccessController());

    this.mf.add(dFPCA);

	print(this.mf.dump(""));
}



/**
 * Initialize card runtime
 */
PCASimulation.prototype.initialize = function() {
	this.fileSelector = new FileSelector(this.mf);
	this.commandInterpreter = new PCACommandInterpreter(this.fileSelector);

}



/**
 * Process an inbound APDU
 *
 * @param {ByteString} capdu the command APDU
 * @type ByteString
 * @return the response APDU
 */
PCASimulation.prototype.processAPDU = function(capdu) {
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
PCASimulation.prototype.reset = function(type) {
//	print("Reset type: " + type);

	this.initialize();

	var atr = new ByteString("3B600000", HEX);
	return atr;
}



/*
 * Create new simulation and register with existing or newly created adapter singleton.
 *
 */
var sim = new PCASimulation();

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
