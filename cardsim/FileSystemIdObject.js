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
 * @fileoverview Implementation of ISO 7816-4 APDU processing
 */



/**
 * Create a file system object identifiable by an id
 *
 * @class Abstract class for file system objects identified by an identifier
 *
 * @param {String} name the human readable name of the object
 * @param {Number} id the id
 */
function FileSystemIdObject(name, id) {
	this.name = name;
	this.id = id;
}

exports.FileSystemIdObject = FileSystemIdObject;


/**
 * Return id of object
 */
FileSystemIdObject.prototype.getId = function() {
	return this.id;
}



/**
 * Return type of object
 * @type string
 * @return type of object
 */
FileSystemIdObject.prototype.getType = function() {
	throw new GPError("FileSystemIdObject", GPError.NOT_IMPLEMENTED, 0, "Derived class must override getType()");
}



/**
 * Return human readable string
 */
FileSystemIdObject.prototype.toString = function() {
	return this.name + "(" + this.id + ")";
}
