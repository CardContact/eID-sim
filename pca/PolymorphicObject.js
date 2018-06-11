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
 * @fileoverview Model for polymorphic objects
 */


FileSystemIdObject  = require('cardsim/FileSystemIdObject').FileSystemIdObject;



PolymorphicObject.RANDOMIZED_PP_RETRIEVAL = 1;
PolymorphicObject.RANDOMIZED_PI_RETRIEVAL = 2;
PolymorphicObject.RANDOMIZED_PIP_RETRIEVAL = 3;

PolymorphicObject.TYPE = "PolymorphicObject";



function PolymorphicObject(b, cipherPI, cipherPP, pubKeyPI, pubKeyPP) {
	FileSystemIdObject.call(this, "Polymorphic Object", 1);

	var curve = new Key();
	curve.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP320r1", OID));
	this.generator = new Key();
	this.generator.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP320r1", OID));
	this.generator.setComponent(Key.ECC_QX, curve.getComponent(Key.ECC_GX));
	this.generator.setComponent(Key.ECC_QY, curve.getComponent(Key.ECC_GY));

	this.b = b;
	this.cipherPI = cipherPI;
	this.cipherPP = cipherPP;
	this.pubKeyPI = pubKeyPI;
	this.pubKeyPP = pubKeyPP;

	this.schemeVersion = new ByteString("01", HEX);
	this.schemeKeyVersion = new ByteString("01", HEX);
	this.creator = new ByteString("00 00 00 04 00 32 14 34 50 01", HEX); // BCD encoded OIN
	this.recipient = new ByteString("00 00 00 01 80 47 70 69 40 00", HEX); // BCD encoded OIN
	this.recipientKeySetVersion = new ByteString("01", HEX);
	this.type = new ByteString("42", HEX);
	/*
	 * Octet	Description
	 * 7		Century if year >= 2050
	 * 6		Year
	 * 5		Month
	 * 4		Day
	 * 3		Hour
	 * 2		Minute
	 * 1		Second
	 * 0		Sequence number
	 */
	this.sequenceNo = new ByteString("28 02 05 15 34 52 02", HEX);
}

PolymorphicObject.prototype = new FileSystemIdObject();
PolymorphicObject.constructor = PolymorphicObject;

exports.PolymorphicObject = PolymorphicObject;



/**
 * Override from base class
 */
PolymorphicObject.prototype.getType = function() {
	return PolymorphicObject.TYPE;
}



/**
 * Get the Dynamic Authentication Data object containing
 * a randomized Polymorphic Object.
 * 
 * @param {ByteString} oid the Cryptographic mechanism reference
 * @type ByteString
 */
PolymorphicObject.prototype.getData = function(oid) {
	var retrievalType = PolymorphicObject.getRetrievalType(oid);
	var isCompressed = PolymorphicObject.isCompressed(oid);
	var isReduced = PolymorphicObject.isReduced(oid);

	GPSystem.trace("getData (oid=" + oid.toString(OID) + ", retrievalType=" + retrievalType + ", isCompressed=" + isCompressed + ", isReduced=" + isReduced + ")");

	this.randomise(retrievalType);

	var a = new ASN1(0x7C);
	a.add(new ASN1(ASN1.OBJECT_IDENTIFIER, oid));

	var seq = new ASN1(0xA0);

	seq.add(new ASN1(0x80, this.getEncodedECPoint(isCompressed, this.b)));
	if (retrievalType == PolymorphicObject.RANDOMIZED_PIP_RETRIEVAL || retrievalType == PolymorphicObject.RANDOMIZED_PI_RETRIEVAL) {
		seq.add(new ASN1(0x81, this.getEncodedECPoint(isCompressed, this.cipherPI)));
	}
	if (retrievalType == PolymorphicObject.RANDOMIZED_PIP_RETRIEVAL || retrievalType == PolymorphicObject.RANDOMIZED_PP_RETRIEVAL) {
		seq.add(new ASN1(0x82, this.getEncodedECPoint(isCompressed, this.cipherPP)));
	}
	if (!isReduced) {
		if (retrievalType == PolymorphicObject.RANDOMIZED_PIP_RETRIEVAL || retrievalType == PolymorphicObject.RANDOMIZED_PI_RETRIEVAL) {
			seq.add(new ASN1(0x83, this.getEncodedECPoint(isCompressed, this.pubKeyPI)));
		}
		if (retrievalType == PolymorphicObject.RANDOMIZED_PIP_RETRIEVAL || retrievalType == PolymorphicObject.RANDOMIZED_PP_RETRIEVAL) {
			seq.add(new ASN1(0x84, this.getEncodedECPoint(isCompressed, this.pubKeyPP)));
		}
	}

	seq.add(new ASN1(0x85, this.schemeVersion));
	seq.add(new ASN1(0x86, this.schemeKeyVersion));
	seq.add(new ASN1(0x87, this.creator));
	seq.add(new ASN1(0x88, this.recipient));
	seq.add(new ASN1(0x89, this.recipientKeySetVersion));
	if (retrievalType != PolymorphicObject.RANDOMIZED_PI_RETRIEVAL) {
		seq.add(new ASN1(0x8A, this.type));
	}
	seq.add(new ASN1(0x8B, this.sequenceNo));

	a.add(seq);

	return a.getBytes();
}



/**
 * Get a ByteString containing the encoded EC Point
 * 
 * @param{Boolean} compress true if compressed encoding (only x coordinates of the EC Point) false otherwise
 * @param{Key} ecPoint the EC Point
 * @type ByteString
 */
PolymorphicObject.prototype.getEncodedECPoint = function(compress, ecPoint) {
	if (compress) {
		var qy = ecPoint.getComponent(Key.ECC_QY);
		if ((qy.byteAt(qy.length -1) & 0x1) == 0x1) {
			var enc = new ByteString("03", HEX);
		} else {
			var enc = new ByteString("02", HEX);
		}
		enc = enc.concat(ecPoint.getComponent(Key.ECC_QX));
	} else {
		var enc = new ByteString("04", HEX);
		enc = enc.concat(ecPoint.getComponent(Key.ECC_QX));
		enc = enc.concat(ecPoint.getComponent(Key.ECC_QY));
	}

	return enc;
}



/**
 * Perform randomisation
 * 
 * @param{Number} type the type specifing which EC Points will be randomised. Must be one of  PolymorphicObject.RANDOMIZED_PIP_RETRIEVAL, PolymorphicObject.RANDOMIZED_PP_RETRIEVAL or PolymorphicObject.RANDOMIZED_PI_RETRIEVAL
 */
PolymorphicObject.prototype.randomise = function(type) {
	if (type != PolymorphicObject.RANDOMIZED_PIP_RETRIEVAL && type != PolymorphicObject.RANDOMIZED_PI_RETRIEVAL && type != PolymorphicObject.RANDOMIZED_PP_RETRIEVAL) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "Randomisation Type must be either PIP, PI or PP");
	}
	var crypto = new Crypto();
	var random = crypto.generateRandom(40);

	// Randomise Blinding
	// g * random + b
	crypto.deriveKey(this.generator, Crypto.EC_MULTIPLY_ADD, random, this.b)

	// Randomise PI Cipher
	// pubKeyPi * random + cipherPI
	crypto.deriveKey(this.pubKeyPI, Crypto.EC_MULTIPLY_ADD, random, this.cipherPI)

	// Randomise PP Cipher
	// pubKeyPP * random + cipherPP
	crypto.deriveKey(this.pubKeyPP, Crypto.EC_MULTIPLY_ADD, random, this.cipherPP)
}



PolymorphicObject.getRetrievalType = function(oid) {
	if (oid.equals(new ByteString("id-PCA-PIP", OID)) ||
		oid.equals(new ByteString("id-PCA-PIP-compressed", OID)) ||
		oid.equals(new ByteString("id-PCA-PIP-reduced-compressed", OID)) ||
		oid.equals(new ByteString("id-PCA-PIP-reduced-uncompressed", OID))
	) {
		return PolymorphicObject.RANDOMIZED_PIP_RETRIEVAL;
	}

	if (oid.equals(new ByteString("id-PCA-PP", OID)) ||
		oid.equals(new ByteString("id-PCA-PP-compressed", OID)) ||
		oid.equals(new ByteString("id-PCA-PP-reduced-compressed", OID)) ||
		oid.equals(new ByteString("id-PCA-PP-reduced-uncompressed", OID))
	) {
		return PolymorphicObject.RANDOMIZED_PP_RETRIEVAL;
	}

	if (oid.equals(new ByteString("id-PCA-PI", OID)) ||
		oid.equals(new ByteString("id-PCA-PI-compressed", OID)) ||
		oid.equals(new ByteString("id-PCA-PI-reduced-compressed", OID)) ||
		oid.equals(new ByteString("id-PCA-PI-reduced-uncompressed", OID))
	) {
		return PolymorphicObject.RANDOMIZED_PI_RETRIEVAL;
	}

	return -1;
}



PolymorphicObject.isCompressed = function(oid) {
	if (oid.equals(new ByteString("id-PCA-PIP-compressed", OID)) ||
		oid.equals(new ByteString("id-PCA-PP-compressed", OID)) ||
		oid.equals(new ByteString("id-PCA-PI-compressed", OID)) ||
		
		oid.equals(new ByteString("id-PCA-PIP-reduced-compressed", OID)) ||
		oid.equals(new ByteString("id-PCA-PP-reduced-compressed", OID)) ||
		oid.equals(new ByteString("id-PCA-PI-reduced-compressed", OID))
	) {
		return true;
	}

	return false;
}



PolymorphicObject.isReduced = function(oid) {
	if (oid.equals(new ByteString("id-PCA-PIP-reduced-uncompressed", OID)) ||
		oid.equals(new ByteString("id-PCA-PP-reduced-uncompressed", OID)) ||
		oid.equals(new ByteString("id-PCA-PI-reduced-uncompressed", OID)) ||
		
		oid.equals(new ByteString("id-PCA-PIP-reduced-compressed", OID)) ||
		oid.equals(new ByteString("id-PCA-PP-reduced-compressed", OID)) ||
		oid.equals(new ByteString("id-PCA-PI-reduced-compressed", OID))
	) {
		return true;
	}

	return false;
}
