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
 * @fileoverview Implementation of a ISO 7816-4 file system simulation
 */


APDU                = require('cardsim/APDU').APDU;
FCP                 = require('cardsim/FCP').FCP;
DF                  = require('cardsim/DF').DF
TransparentEF       = require('cardsim/TransparentEF').TransparentEF;
SecurityEnvironment = require('cardsim/SecurityEnvironment').SecurityEnvironment;



/**
 * Create a file selector object
 *
 * @class Class implementing a file selector used to store information about the currently selected
 *        file system object and to process the SELECT APDU
 * @constructor
 * @param {DF} mf the master file
 */
function FileSelector(mf) {
	if ((typeof(mf) != "object") && !(mf instanceof DF)) {
		throw new GPError("FileSelector", GPError.INVALID_TYPE, APDU.SW_GENERALERROR, "Argument 1 must be of type DF");
	}
	
	this.mf = mf;
	this.selectMF();
	
	this.se = { VEXK: new SecurityEnvironment(), CDIK: new SecurityEnvironment(), SMRES: new SecurityEnvironment(), SMCOM: new SecurityEnvironment()};
	this.globalAuthenticationState = [];
}

exports.FileSelector = FileSelector;



/**
 * Returns the current EF, if any
 *
 * @type EF
 * @return the current EF or null
 */
FileSelector.prototype.getCurrentEF = function() {
	return this.currentEF;
}



/**
 * Return the current security environment
 *
 * @type Object
 * @returns Object with properties VEXK, CDIK, SMRES and SMCOM containing SecurityEnvironment objects
 */
FileSelector.prototype.getSecurityEnvironment = function() {
	return this.se;
}



/**
 * Return meta data associated with the current DF or MF
 *
 * @param {String} name the meta data name
 * @type Object
 * @returns The meta data
 */
FileSelector.prototype.getMeta = function(name) {
	var meta;

	if (this.currentDF) {
//		print("DF selected: " + this.currentDF);
		var meta = this.currentDF.meta[name];
//		print("Found: " + meta);
	}

	if (!meta) {
		meta = this.mf.meta[name];
	}
	return meta;
}



/**
 * Return object of given type identified by id
 *
 * <p>If bit b8 in the id is 1, then the search will start in the current DF. If the object
 *    is not found, the search is continued in the MF. If the bit is not set, then the search
 *    will only look into the MF.</p>
 *
 * @param {String} type the type of the object
 * @param {Number} id the id, bit b8 indicating local DF or global MF search
 * @type {Object}
 * @returns the object of the requested type or null if not found
 */
FileSelector.prototype.getObject = function(type, id) {
	var olist;

	if (id & 0x80) {
		olist = this.currentDF.meta[type];
		if (olist) {
			var o = olist[id & 0x7F];
			
			if (o) {
				return o;
			}
		}
	}

	olist = this.mf.meta[type];
	if (olist) {
		var o = olist[id & 0x7F];

		if (o) {
			return o;
		}
	}
	return null;
}



/**
 * Enumerate objects of a defined type
 *
 * @param {String} type the type of the object
 * @type {Number[]}
 * @returns the list of objects found
 */
FileSelector.prototype.enumerateObjects = function(type) {
	var idlist = [];

	if (this.mf != this.currentDF) {
		for each (var o in this.currentDF.meta[type]) {
			idlist.push(o.getId());
		}
	}

	for each (var o in this.mf.meta[type]) {
		idlist.push(o.getId());
	}

	return idlist;
}



/**
 * Add authenticated object to the list of authentication states for the local DF or global MF
 *
 * @param{boolean} global true if global state else local DF state
 * @param{AuthenticationObject} ao the authentication object for which authentication was successfull
 */
FileSelector.prototype.addAuthenticationState = function(global, ao) {
	if (global) {
		this.globalAuthenticationState.push(ao);
	} else {
		this.localAuthenticationState.push(ao);
	}
}



/**
 * Add authenticated object to the list of authentication states for the local DF or global MF
 *
 * @param{boolean} global true if global state else local DF state
 * @param{AuthenticationObject} ao the authentication object for which authentication was successfull
 */
FileSelector.prototype.isAuthenticated = function(global, ao) {
	if (global) {
		var list = this.globalAuthenticationState;
	} else {
		var list = this.localAuthenticationState;
	}
	for each (var aao in list) {
		if (aao === ao) {
			return true;
		}
	}
	return false;
}



/**
 * Select the MF
 */
FileSelector.prototype.selectMF = function() {
	this.currentDF = this.mf;
	this.currentEF = null;
	this.localAuthenticationState = [];

	return this.mf;
}



/**
 * Select a DF entry by FID
 *
 * @param {ByteString} fid the file identifier
 * @param {boolean} check if file matches expected type EF or DF
 * @param {boolean} df true if the check must check for a DF type, else a EF type
 * @type FSNode
 * @return the selected file system node
 */
FileSelector.prototype.selectFID = function(fid, check, df) {
	var node = this.currentDF.selectByFID(fid);
	
	if (!node) {
		throw new GPError("FileSelector", GPError.INVALID_DATA, APDU.SW_FILENOTFOUND, "File " + fid + " not found");
	}

	if (check) {
		if ((df && !node.isDF()) || (!df && node.isDF())) {
			throw new GPError("FileSelector", GPError.INVALID_DATA, APDU.SW_FILENOTFOUND, "File " + fid + " not found or not of matching type");
		}
	}
	
	if (node.isDF()) {
		this.currentDF = node;
		this.localAuthenticationState = [];
		this.currentEF = null;
	} else {
		this.currentEF = node;
	}
	return node;
}



/**
 * Select a DF entry by SFI
 *
 * @param {Number} sfi the short file identifier
 * @type FSNode
 * @return the selected file system node
 */
FileSelector.prototype.selectSFI = function(sfi) {
	var node = this.currentDF.selectBySFI(sfi);
	
	if (!node) {
		throw new GPError("FileSelector", GPError.INVALID_DATA, APDU.SW_FILENOTFOUND, "File with SFI " + sfi + " not found");
	}

	this.currentEF = node;
	return node;
}



/**
 * Processes the SELECT APDU
 *
 * <p>Supports in P1</p>
 * <ul>
 *  <li>'00' with empty data to select the MF</li>
 *  <li>'00' with "3F00" to select the MF</li>
 *  <li>'00' with fid to select an entry in the current DF</li>
 *  <li>'01' with fid to select a DF in the current DF</li>
 *  <li>'02' with fid to select an EF in the current DF</li>
 *  <li>'03' with empty data to select the parent</li>
 * </ul>
 * <p>Supports in P2</p>
 * <ul>
 *  <li>'00' with P1=='00' return no data</li>
 *  <li>'04' return FCP</li>
 *  <li>'0C' return no data</li>
 * </ul>
 * @param {APDU} apdu the select APDU
 */
FileSelector.prototype.processSelectAPDU = function(apdu) {
	var node;

	var p2 = apdu.getP2();
	if ((p2 != 0x00) && (p2 != 0x04) && (p2 != 0x0C)) {
		throw new GPError("FileSelector", GPError.INVALID_DATA, APDU.SW_INCP1P2, "Incorrect parameter P2 (" + p2.toString(16) + ")");
	}

	var data = apdu.getCData();
	var p1 = apdu.getP1();
	switch(p1) {
	case 0x00:
		if ((typeof(data) == "undefined") || (data.toString(HEX) == "3F00")) {
			node = this.selectMF();
		} else {
			node = this.selectFID(data, false, false);
		}
		break;
	case 0x01:
		node = this.selectFID(data, true, true);
		break;
	case 0x02:
		node = this.selectFID(data, true, false);
		break;
	case 0x03:
		// ToDo data must be missing APDU.SW_INVLC
		if (this.currentEF) {
			this.currentEF = null;
			node = this.currentDF;
		} else {
			node = this.currentDF.getParent();
			if (node) {
				this.currentDF = node;
				this.localAuthenticationState = [];
			} else {
				node = this.currentDF;
			}
		}
		break;
	case 0x04:
		node = this.mf.selectByAID(data);
		if (typeof(node) == "undefined") {
			throw new GPError("FileSelector", GPError.INVALID_DATA, APDU.SW_FILENOTFOUND, "Application " + data + " not found");
		}
		this.currentDF = node;
		this.currentEF = null;
		this.localAuthenticationState = [];
		break;
	default:
		throw new GPError("FileSelector", GPError.INVALID_DATA, APDU.SW_INCP1P2, "Incorrect parameter P1 (" + p1.toString(16) + ")");
	}
	
	switch(p2) {
	case 0x00:
		apdu.setRData(node.getFCP().getFCI().getBytes());
		break;
	case 0x04:
		apdu.setRData(node.getFCP().getBytes());
		break;
	}

	apdu.setSW(APDU.SW_OK);
}



/**
 * Return a human readable string for this object
 */
FileSelector.prototype.toString = function() {
	var str = "FileSelector: Current DF=" + this.currentDF + " / Current EF=" + this.currentEF;
	if (this.globalAuthenticationState.length > 0) {
		str += "\nGlobally authenticated objects:";
		for each (var aao in this.globalAuthenticationState) {
			str += "\n" + aao.toString();
		}
	}
	if (this.localAuthenticationState.length > 0) {
		str += "\nLocally authenticated objects:";
		for each (var aao in this.localAuthenticationState) {
			str += "\n" + aao.toString();
		}
	}
	return str;
}



FileSelector.test = function() {

	var aid = new ByteString("A0000000010101", HEX);

	var mf = new DF(FCP.newDF("3F00", null),
						new TransparentEF(FCP.newTransparentEF("2F00", -1, 100)),
						new TransparentEF(FCP.newTransparentEF("2F01", 0x17, 100)),
						new DF(FCP.newDF("DF01", aid),
							new TransparentEF(FCP.newTransparentEF("2F01", -1, 100))
						)
					);

	print(mf.dump(""));

	assert(mf.isDF());
	
	var ef = mf.selectByFID(new ByteString("2F00", HEX));
	assert(!ef.isDF());
	assert(ef.getFCP().getFID().toString(HEX) == "2F00");

	var ef = mf.selectBySFI(0x17);
	assert(ef.getFCP().getFID().toString(HEX) == "2F01");
	
	var df = mf.selectByAID(aid);
	assert(df.getFCP().getFID().toString(HEX) == "DF01");

	var fs = new FileSelector(mf);
	
	var a = new APDU(0x00, 0xA4, 0x00, 0x0C, new ByteString("3F00", HEX));
	fs.processSelectAPDU(a);
	print(fs);
	print(a);

	var a = new APDU(0x00, 0xA4, 0x00, 0x0C, new ByteString("2F00", HEX));
	fs.processSelectAPDU(a);
	print(fs);
	print(a);
	
	var a = new APDU(0x00, 0xA4, 0x01, 0x0C, new ByteString("DF01", HEX));
	fs.processSelectAPDU(a);
	print(fs);
	print(a);

	var a = new APDU(0x00, 0xA4, 0x02, 0x0C, new ByteString("2F01", HEX));
	fs.processSelectAPDU(a);
	print(fs);
	print(a);
}


// test();

