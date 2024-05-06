# EFIdra
An extensible Ghidra plugin designed to lower the barrier-of-entry to UEFI firmware static reverse engineering.

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
			"type": "ulonglong",
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

A enumeration maybe be defined in the `structures` array by using the "enum" tag instead of the "members" tag.

```json
{
	// The name of the enum type
	"name": "EFI_SECTION_TYPE",
	// all of the enum names and their values
	"enum": {
		"EFI_SECTION_ALL": 0,
		"EFI_SECTION_COMPRESSION": 1,
		"EFI_SECTION_GUID_DEFINED": 2,
		"EFI_SECTION_PE32": 16,
		"EFI_SECTION_PIC": 17,
		...
	}
}

```

Note that in practice, comments cannot be included in the JSON file, but these are here for explanation purposes.

All structures defined in these are added to the Data Type Manager and are visible in the Code Browser.

### Examples
Examples of ROM Format specifications for PiFirmware (defined for [volumes](https://github.com/tianocore/edk2/blob/master/BaseTools/Source/C/Include/Common/PiFirmwareVolume.h) and [files](https://github.com/tianocore/edk2/blob/master/BaseTools/Source/C/Include/Common/PiFirmwareFile.h) in edk2) can be found in [data/rom_formats](https://github.com/LGSDET/efidra/tree/main/data/rom_formats) in this repository, or in `efidra/data/rom_formats/` in plugin distribution zip files.

