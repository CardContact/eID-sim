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
 * @fileoverview Generator for PolymorphicInfo ASN1 object
 */



function PolymorphicInfo(flag) {
	if (!flag) {
		flag = true;
	}
	this.setDefaultValues(flag);
}

exports.PolymorphicInfo = PolymorphicInfo;



PolymorphicInfo.prototype.setDefaultValues = function(flagValue) {
	this.pcaVersion = new ByteString("01", HEX);
	this.schemeVersion = new ByteString("01", HEX);
	this.schemeKeyVersion = new ByteString("01", HEX);
	
	// ImplementationInfo
	this.version = new ByteString("01", HEX);
	/* D for Driving License Card,
	 * I for Polymorphic Identity card or
	 * P for Polymorphic eMRTD passport
	 */
	this.type = new ByteString("D", ASCII);

	// PolymorphicFlags
	this.randomizedPI = flagValue;
	this.randomizedPP = flagValue;
	this.randomizedPIP = flagValue;
	this.uncompressedEncoding = flagValue;
	this.compressedEncoding = flagValue;
	this.reducedEncoding = flagValue;
	this.regularEncoding = flagValue;
}



PolymorphicInfo.prototype.toTLV = function() {
	var implementationInfo = new ASN1(ASN1.SEQUENCE);
	implementationInfo.add(new ASN1(ASN1.UTF8String, this.type));
	implementationInfo.add(new ASN1(ASN1.INTEGER, this.version));

	var bitString = new ByteString("00", HEX);
	if (this.randomizedPI) {
		bitString = bitString.add(1);
	}
	if (this.randomizedPP) {
		bitString = bitString.add(1 << 1);
	}
	if (this.randomizedPIP) {
		bitString = bitString.add(1 << 2);
	}
	if (this.uncompressedEncoding) {
		bitString = bitString.add(1 << 3);
	}
	if (this.compressedEncoding) {
		bitString = bitString.add(1 << 4);
	}
	if (this.reducedEncoding) {
		bitString = bitString.add(1 << 5);
	}
	if (this.regularEncoding) {
		bitString = bitString.add(1 << 6);
	}
	var polymorphicFlags = new ASN1(ASN1.BIT_STRING, bitString);

	var requiredPolymorphicData = new ASN1(ASN1.SEQUENCE);
	requiredPolymorphicData.add(new ASN1(ASN1.INTEGER, this.pcaVersion));
	requiredPolymorphicData.add(implementationInfo);
	requiredPolymorphicData.add(new ASN1(ASN1.INTEGER, this.schemeVersion));
	requiredPolymorphicData.add(new ASN1(ASN1.INTEGER, this.schemeKeyVersion));
	requiredPolymorphicData.add(polymorphicFlags);

	var polymorphicInfo = new ASN1(ASN1.SEQUENCE);
	polymorphicInfo.add(new ASN1(ASN1.OBJECT_IDENTIFIER, new ByteString("id-PCA-info", OID)));
	polymorphicInfo.add(requiredPolymorphicData);

	return polymorphicInfo;
}
