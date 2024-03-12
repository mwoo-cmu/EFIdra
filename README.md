# EFIdra


## ROM Format JSON Specification

ROM Formats should be specified using a JSON object, with the following keys, all of which are optional. These JSON files should be placed within the plugin zip file under `efidra/data/rom_formats/`.

### structures
This should be a list of structure definitions, in load order. If one structure contains another, the internal structure should be defined first, so it may be used in the Ghidra structure definition.

Each structure should be a JSON object with the following keys (example from [data/rom_formats/PiFirmware.json](https://github.com/LGSDET/efidra/tree/main/data/rom_formats/PiFirmware.json)):

```json
{
	// this should be the name of the structure
	"name": "EFI_FIRMWARE_VOLUME_HEADER",
	
	// this should be the members of the structure, in order
	"members": [
		// each member should be a JSON object, and requires
		// a name and type, with an optional size and comment.
		// If the type is an array type, the size is required
		// and should be placed between the brackets.
		// Strings should use the size key, however.
		
		// Example of byte array type
		{
			"type": "byte[16]",
			"name": "ZeroVector",
			"comment": "The first 16 bytes are reserved to allow for the reset vector of\nprocessors whose reset vector is at address 0."
		},
		
		// Example of nested structure type (EFI_GUID) is 
		// defined earlier in the file.
		{
			"type": "EFI_GUID",
			"name": "FileSystemGuid",
			"comment": "Declares the file system with which the firmware volume is formatted."
		},
		
		// Example of simple built-in type
		{
			"type": "qword",
			"name": "FvLength",
			"comment": "Length in bytes of the complete firmware volume, including the header."
		},
		
		// Example of string (char array) type
		{
			"type": "string",
			"size": 4,
			"name": "Signature",
			"comment": "Set to EFI_FVH_SIGNATURE"
		},
		
		// more members are defined in the original file,
		// but these show the primary ways to define members.
		...
	]
}
```

Note that in practice, comments cannot be included in the JSON file, but these are here for explanation purposes.

All structures defined in these are added to the Data Type Manager and are visible in the Code Browser.


### parser
The parser should be a JSON object with two members: `name` and `layout`. `name` should be a string identifying the name of this ROM layout.

`layout` should be a JSON array of objects which defines the layout of the ROM [with respect to] the structures defined.

Each JSON object must include the following keys:

```json
{
	// this should be the string name of the type of the structure 
	// to apply. This can be a struct defined in the "structures"
	// member, or a Ghidra built-in type.
	// It may also be a list of possible types with their
	// necessary conditions, or the string "efidra_layout",
	// both of which are further described after the optional keys.
	"type": "uint"
	
}
```

They may also include any number of the following optional keys:

```json
{
	// This key should be used if this structure occurs
	// a known number of times in the layout. For example,
	// if some type of volume always contains 5 files, this 
	// value should be set to 5 in the JSON object that describes
	// where the file structure occurs within the layout.
	// If the count is not known, this key should be omitted.
	"count": 1,
	
	// This key should be used if this structure has a 
	// specified value or members with specified values.
	// If this is a structure type, the members with known
	// values should be included. Note that unknown members
	// may be omitted. If no values are known, this key 
	// should be omitted.
	"value": 0,
	// or 
	"value": {
		"ZeroVector": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
		"Signature": "_FVH",
		"Reserved": 0,
		"Revision": 2
	},
	
	// This should be a string expression for the 
	// condition that must be satisfied for this structure
	// to be used in this location. If omitted, the 
	// structure is always used.
	"condition": "this.Attributes & 1 == 1",
	
	// This key identifies how this structure can
	// be referenced by the parser in this layout for
	// conditions or offsets.
	"name": "FVHeader",
	
	// This should be the offset from the current parser address
	// in the ROM to the start of this structure
	// This may be an integer number of bytes or
	// an expression related to other structures. 
	// If the offset is 0, this key may be omitted.
	"offset": 8,
	// or 
	"offset": "FVHeader.ExtHeaderOffset",
	// or
	"offset": "FVHeader.ExtHeaderOffset - FVHeader.HeaderLength",
	
	// This key is used to move the pointer for the parser's
	// current location, and may be used in place of an 
	// offset. This can also be an integer number of bytes
	// or an expression.
	"movePtr": -16,
	
	// This key is used to set the pointer for the parser's
	// current location to a specific address
	// or expression.
	"setPtr": "this.base + this.HeaderLength",
	
	// This key specifies the byte alignment at which to
	// search for this structure. If it is omitted, no
	// byte alignment is used.
	"alignment": 8
}
```

<!-- The parser uses specific unique values, which can be used in `type`s, field values, `condition` strings, etc. These should be prefixed with the `;` character, and are as follows: 
`unknown`: This value is not known or may be different between instances of this structure. This is particularly relevant for  `count` -->

The `type` key may be specified as a list of possible types and their conditions. In this case, the list will be iterated from top to bottom, with conditions checked, and the first successful condition will be applied. The last element should be a default type with `condition` set to `true`, or omitted. In this case, the `type` key should take the following form:

```json
[
	{
		"type": "EFI_FFS_FILE_HEADER2",
		"condition": "this.Attributes & 1 == 1"
	},
	{
		"type": "EFI_FFS_FILE_HEADER"
	}
]
```

The `type` key also may be set to `"efidra_layout"` to string multiple different structures together as one layout item. This is useful for identifying structures like firmware volumes, which consist of a firmware header and an unknown number of firmware files. If the `type` is set to `"efidra_layout"`, the `value` key should be specified as a JSON array, and takes the same format as the overall parser `layout` array.

### Examples
Examples of ROM Format specifications for PiFirmware (defined for [volumes](https://github.com/tianocore/edk2/blob/master/BaseTools/Source/C/Include/Common/PiFirmwareVolume.h) and [files](https://github.com/tianocore/edk2/blob/master/BaseTools/Source/C/Include/Common/PiFirmwareFile.h) in edk2) and BPDT () can be found in [data/rom_formats](https://github.com/LGSDET/efidra/tree/main/data/rom_formats) in this repository, or in `efidra/data/rom_formats/` in plugin distribution zip files.

