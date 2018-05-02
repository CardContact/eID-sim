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
 * @fileoverview AuthenticationObject - Password, PIN or key container for external authentication
 */


APDU                = require('cardsim/APDU').APDU;



/**
 * Create an adapter to decode a APDU for data unit handling
 *
 * @class Adapter class to decode APDUs for data unit handling
 * @constructor
 * @param {APDU} apdu the APDU to decode
 */ 
function DataUnitAPDU(apdu) {
	this.apdu = apdu;

	var p1 = apdu.getP1();
	
	if ((this.apdu.getINS() & 1) == 0) {		// Even instruction
		if ((p1 & 0x80) == 0x80) {				// SFI in P1
			this.offset = this.apdu.getP2();
			this.sfi = p1 & 0x1F;
		} else {
			this.offset = (p1 << 8) + this.apdu.getP2();
		}
		this.data = apdu.getCData();
	} else {									// Odd instruction
		var p2 = apdu.getP2();
		var fid = (p1 << 8) + p2;				// FID in P1 P2
		// If bits b16 - b6 are all 0 and b5 - b1 are not all equal, then we have an SFI 
		if (((fid & 0xFFE0) == 0) && ((fid & 0x1F) >= 1) && ((fid & 0x1F) <= 30)) {
			this.sfi = fid & 0x1F;
		} else if (fid != 0) {					// FID = 0000 means current file
			var bb = new ByteBuffer();
			bb.append(p1);
			bb.append(p2);
			this.fid = bb.toByteString();
		}

		var a = this.apdu.getCDataAsTLVList();

		if ((a.length < 1) || (a.length > 2)) {
			throw new GPError("DataUnitAPDU", GPError.INVALID_DATA, APDU.SW_INVDATA, "Invalid data for odd instruction data handling command, less than one or more than two elements in TLV");
		}

		var o = a.index(0);
		if (o.getTag() != 0x54) {
			throw new GPError("DataUnitAPDU", GPError.INVALID_DATA, APDU.SW_INVDATA, "Invalid data for odd instruction data handling command, first tag must be '54' offset");
		}
		
		this.offset = o.getValue().toUnsigned();
		
		if (a.length == 2) {
			var o = a.index(1);
			var t = o.getTag();
			if ((t != 0x53) && (t != 0x73)) {
				throw new GPError("DataUnitAPDU", GPError.INVALID_DATA, APDU.SW_INVDATA, "Invalid data for odd instruction data handling command, second tag must be '53' or '73'");
			}
		
			this.data = o.getValue();
		}
	}
}

exports.DataUnitAPDU = DataUnitAPDU;



/**
 * Gets the short file identifier, if one defined
 * 
 * @type Number
 * @return the short file identifier in the range 1 to 30 or -1 if not defined
 */
DataUnitAPDU.prototype.getSFI = function() {
	if (typeof(this.sfi) == "undefined") {
		return -1;
	}
	return this.sfi;
}



/**
 * Gets the file identifier, if one defined
 * 
 * @type ByteString
 * @return the file identifier or null if not defined
 */
DataUnitAPDU.prototype.getFID = function() {
	if (typeof(this.fid) == "undefined") {
		return null;
	}
	return this.fid;
}



/**
 * Gets the offset
 * 
 * @type Number
 * @return the offset to read from or write to
 */
DataUnitAPDU.prototype.getOffset = function() {
	return this.offset;
}



/**
 * Get the command data
 *
 * @type ByteString
 * @return the command data
 */
DataUnitAPDU.prototype.getCData = function() {
	if (!this.hasCData()) {
		throw new GPError("APDU", GPError.INVALID_DATA, APDU.SW_INVDATA, "No data in command APDU");
	}
	return this.data;
}



/**
 * Returns true if command data in contained in the APDU
 *
 * @type boolean
 * @returns true if command data contained
 */
DataUnitAPDU.prototype.hasCData = function() {
	return ((typeof(this.data) != "undefined") && (this.data != null));
}



/**
 * Simple Unit Test
 */
DataUnitAPDU.test = function() {
	var apdu = new APDU(0x00, 0xB0, 0, 0, 0);
	var dh = new DataUnitAPDU(apdu);
	assert(dh.getOffset() == 0);
	assert(!dh.hasCData());
	
	var apdu = new APDU(0x00, 0xB0, 0x7F, 0xFF, 0);
	var dh = new DataUnitAPDU(apdu);
	assert(dh.getOffset() == 0x7FFF);
	assert(!dh.hasCData());

	var apdu = new APDU(0x00, 0xB0, 0x80, 0, 0);
	var dh = new DataUnitAPDU(apdu);
	assert(dh.getOffset() == 0);
	assert(!dh.hasCData());

	var apdu = new APDU(0x00, 0xB0, 0x80, 0xFF, 0);
	var dh = new DataUnitAPDU(apdu);
	assert(dh.getOffset() == 0xFF);
	assert(!dh.hasCData());

	var apdu = new APDU(0x00, 0xB1, 0, 0, new ByteString("540100", HEX), 0);
	var dh = new DataUnitAPDU(apdu);
	assert(dh.getOffset() == 0);
	assert(!dh.hasCData());

	var apdu = new APDU(0x00, 0xB1, 0, 0, new ByteString("5401FF", HEX), 0);
	var dh = new DataUnitAPDU(apdu);
	assert(dh.getOffset() == 0xFF);
	assert(!dh.hasCData());

	var apdu = new APDU(0x00, 0xB1, 0, 0, new ByteString("540401000000", HEX), 0);
	var dh = new DataUnitAPDU(apdu);
	assert(dh.getOffset() == 0x01000000);
	assert(!dh.hasCData());

	var data = new ByteString("1234", ASCII);
	
	var apdu = new APDU(0x00, 0xD6, 0, 0, data);
	var dh = new DataUnitAPDU(apdu);
	assert(dh.getOffset() == 0);
	assert(dh.hasCData());
	assert(dh.getCData().equals(data));
	
	var apdu = new APDU(0x00, 0xD6, 0x7F, 0xFF, data);
	var dh = new DataUnitAPDU(apdu);
	assert(dh.getOffset() == 0x7FFF);
	assert(dh.hasCData());
	assert(dh.getCData().equals(data));

	var apdu = new APDU(0x00, 0xD6, 0x80, 0, data);
	var dh = new DataUnitAPDU(apdu);
	assert(dh.getOffset() == 0);
	assert(dh.hasCData());
	assert(dh.getCData().equals(data));

	var apdu = new APDU(0x00, 0xD6, 0x80, 0xFF, data);
	var dh = new DataUnitAPDU(apdu);
	assert(dh.getOffset() == 0xFF);
	assert(dh.hasCData());
	assert(dh.getCData().equals(data));

	var apdu = new APDU(0x00, 0xD7, 0, 0, (new ByteString("5401005304", HEX)).concat(data), 0);
	var dh = new DataUnitAPDU(apdu);
	assert(dh.getOffset() == 0);
	assert(dh.hasCData());
	assert(dh.getCData().equals(data));

	var apdu = new APDU(0x00, 0xD7, 0, 0, (new ByteString("5401FF5304", HEX)).concat(data), 0);
	var dh = new DataUnitAPDU(apdu);
	assert(dh.getOffset() == 0xFF);
	assert(dh.hasCData());
	assert(dh.getCData().equals(data));

	var apdu = new APDU(0x00, 0xD7, 0, 0, (new ByteString("5404010000005304", HEX)).concat(data), 0);
	var dh = new DataUnitAPDU(apdu);
	assert(dh.getOffset() == 0x01000000);
	assert(dh.hasCData());
	assert(dh.getCData().equals(data));
}
