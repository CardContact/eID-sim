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



/**
 * Create a File Control Parameter containing information about a file system node
 *
 * @class Class storing File Control Parameter for a file system node
 * @constructor
 */
function FCP() {
}

exports.FCP = FCP;


/** File type for DF */
FCP.DEDICATEDFILE = 0x38;

/** File type for transparent EF */
FCP.TRANSPARENT   = 0x01;

/** File type for record oriented EF with fixed record size */
FCP.LINEARFIXED   = 0x02;

/** File type for record oriented EF with variable record size */
FCP.LINEARVARIABLE   = 0x04;


/**
 * Convert an integer value into an two byte ByteString
 *
 * @param {Number} val the value
 * @type ByteString
 * @return the 2 byte encoded value MSB||LSB
 */
FCP.short2bytestring = function(val) {
	var bb = new ByteBuffer();
	bb.append(val >> 8);
	bb.append(val & 0xFF);
	return(bb.toByteString());
}



/**
 * Construct a new FCP object from parameters.
 *
 * <p>This function should never be called directly. Use newTransparentDF(), newDF() or newLinearEF() instead.</p>
 *
 * @param {String|ByteString} fid the file identifier (2 Bytes)
 * @param {Number} sfi the short file identifier or -1 or 0 if not defined
 * @param {Number} type the file type, one of FCP.DEDICATEDFILE, FCP.TRANSPARENT or FCP.LINEAR*
 * @param {Boolean} shareable true, if file may be shared between logical channels
 * @param {Boolean} internal true, if file is internal only and not externally selectable
 * @param {ByteString} supl supplemental information
 * @type FCP
 * @return the newly constructed FCP object
 */
FCP.newFCP = function(fid, sfi, type, shareable, internal, supl) {
	var fcp = new FCP();
	
	if (fid != null) {
		if (typeof(fid) == "string") {
			if (fid.length != 4) {
				throw new GPError("FCP", GPError.INVALID_DATA, 0, "File Identifier must be 2 bytes");
			}
			fcp.fid = new ByteString(fid, HEX);
		} else if (fid instanceof ByteString) {
			if (fid.length != 2) {
				throw new GPError("FCP", GPError.INVALID_DATA, 0, "File Identifier must be 2 bytes");
			}
			fcp.fid = fid;
		} else {
			throw new GPError("FCP", GPError.INVALID_TYPE, 0, "Argument must be of type String or ByteString");
		}
	}
	
	if (typeof(sfi) != "number") {
		throw new GPError("FCP", GPError.INVALID_TYPE, 1, "Argument must be of type Number");
	}
	if ((sfi >= -1) && (sfi <= 30)) {
		if (sfi > 0) {
			fcp.sfi = sfi;
		}
	} else {
		throw new GPError("FCP", GPError.INVALID_DATA, 1, "SFI must be in the range 1 to 30 or 0 if not defined");
	}

	if (typeof(type) != "number") {
		throw new GPError("FCP", GPError.INVALID_TYPE, 2, "Argument must be of type Number");
	}
	fcp.type = type;

	if (typeof(shareable) != "boolean") {
		throw new GPError("FCP", GPError.INVALID_TYPE, 3, "Argument must be of type Boolean");
	}
	fcp.shareable = shareable;

	if (typeof(internal) != "boolean") {
		throw new GPError("FCP", GPError.INVALID_TYPE, 4, "Argument must be of type Boolean");
	}
	fcp.internal = internal;

	fcp.supl = supl;
	return fcp;
}



/**
 * Construct a new FCP object for an EF of type transparent.
 *
 * @param {String|ByteString} fid the file identifier (2 Bytes)
 * @param {Number} sfi the short file identifier or -1 or 0 if not defined
 * @param {Number} size the file size
 * @param {ByteString} supl supplemental information
 * @type FCP
 * @return the newly constructed FCP object
 */
FCP.newTransparentEF = function(fid, sfi, size, supl) {
	if (typeof(size) != "number") {
		throw new GPError("FCP", GPError.INVALID_TYPE, 2, "Argument size must be of type Number");
	}

	var fcp = FCP.newFCP(fid, sfi, FCP.TRANSPARENT, false, false, supl);

	fcp.size = size;
	return fcp;
}



/**
 * Construct a new FCP object for a DF.
 *
 * @param {String|ByteString} fid the file identifier (2 Bytes)
 * @param {ByteString} aid the DF's application identifier (DFName)
 * @param {ByteString} supl supplemental information
 * @type FCP
 * @return the newly constructed FCP object
 */
FCP.newDF = function(fid, aid, supl) {
	var fcp = FCP.newFCP(fid, -1, FCP.DEDICATEDFILE, false, false, supl);

	if (aid != null) {
		if ((typeof(aid) != "object") && !(aid instanceof(ByteString))) {
			throw new GPError("FCP", GPError.INVALID_TYPE, 2, "Argument size must be of type Number");
		}
		fcp.aid = aid;
	}

	return fcp;
}



/**
 * Construct a new FCP object for an EF of type linear.
 *
 * @param {String|ByteString} fid the file identifier (2 Bytes)
 * @param {Number} sfi the short file identifier or -1 or 0 if not defined
 * @param {Number} type the file type, one of FCP.LINEARFIXED or FCP.LINEARVARIABLE
 * @param {Number} recno the maximum number of records
 * @param {Number} recsize the maximum or fixed record size
 * @param {ByteString} supl supplemental information
 * @type FCP
 * @return the newly constructed FCP object
 */
FCP.newLinearEF = function(fid, sfi, type, recno, recsize, supl) {
	if (typeof(recsize) != "number") {
		throw new GPError("FCP", GPError.INVALID_TYPE, 3, "Argument recsize must be of type Number");
	}
	if (typeof(recno) != "number") {
		throw new GPError("FCP", GPError.INVALID_TYPE, 4, "Argument recno must be of type Number");
	}

	var fcp = FCP.newFCP(fid, sfi, type, false, false, supl);
	return fcp;
}



/**
 * Returns the File Identifier (FID)
 *
 * @type ByteString
 * @return the FID
 */
FCP.prototype.getFID = function() {
	return this.fid;
}



/**
 * Returns the Application Identifier (AID)
 *
 * @type ByteString
 * @return the AID
 */
FCP.prototype.getAID = function() {
	return this.aid;
}



/**
 * Returns the Short File Identifier (SFI)
 *
 * @type Number
 * @return the SFI
 */
FCP.prototype.getSFI = function() {
	return this.sfi;
}



/**
 * Returns the encoded FCP
 *
 * @type ByteString
 * @return the encoded FCP
 */
FCP.prototype.getBytes = function() {
	var fcp = new ASN1("fcp", 0x62);

	if (typeof(this.size) != "undefined") {
		fcp.add(new ASN1("fileSizeTransparent", 0x80, FCP.short2bytestring(this.size)));
	}

	var bb = new ByteBuffer();
	bb.append(this.type);
	
	// ToDo: extra type bytes
	
	fcp.add(new ASN1("fileDescriptor", 0x82, bb.toByteString()));
	
	if (typeof(this.fid) != "undefined") {
		fcp.add(new ASN1("fileIdentifier", 0x83, this.fid));
	}
	
	if (typeof(this.aid) != "undefined") {
		fcp.add(new ASN1("dFName", 0x84, this.aid));
	}
	
	if (typeof(this.sfi) != "undefined") {
		var bb = new ByteBuffer();
		bb.append(this.sfi << 3);
		fcp.add(new ASN1("shortFileIdentifier", 0x88, bb.toByteString()));
	}
	
	return(fcp.getBytes());
}



/**
 * Returns the FCI
 *
 * @type ASN1
 * @return the FCI
 */
FCP.prototype.getFCI = function() {
	var fci = new ASN1("fci", 0x6F);

	if (typeof(this.aid) != "undefined") {
		fci.add(new ASN1("dFName", 0x84, this.aid));
	}

	if (this.supl) {
		fci.add(new ASN1(this.supl));
	}

	return(fci);
}



/**
 * Return a human readible string for this object
 *
 * @type String
 * @return the string
 */
FCP.prototype.toString = function() {
	var str = "FCP(";
	
	for (var i in this) {
		if (typeof(this[i]) != "function") {
			str += i + "=" + this[i] + ",";
		}
	}
	str += ")";
	return str;
}
