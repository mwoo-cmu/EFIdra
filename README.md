# EFIdra


## ROM Format JSON Specification

ROM Formats should be specified using a JSON object, with the following keys, all of which are optional. These JSON files should be placed within the plugin zip file under `efidra/data/rom_formats/`.

### parser

### structures
This should be a list of structure definitions, in load order. If one structure contains another, the internal structure should be defined first, so it may be used in the Ghidra structure definition.

Each structure should be a JSON object with the following keys (example from [data/rom_formats/PiFirmware.json]()):

```json
{
	// this should be the name of the structure
	"name": "EFI_FIRMWARE_VOLUME_HEADER",
	// this should be the members of the structure, in order
	"members": [
	]
}
```

Examples of ROM Format specifications for PiFirmware (defined for [volumes](https://github.com/tianocore/edk2/blob/master/BaseTools/Source/C/Include/Common/PiFirmwareVolume.h) and [files](https://github.com/tianocore/edk2/blob/master/BaseTools/Source/C/Include/Common/PiFirmwareFile.h) in edk2) and BPDT () can be found in [data/rom_formats](https://github.com/LGSDET/efidra/tree/main/data/rom_formats) in this repository, or in `efidra/data/rom_formats/` in plugin distribution zip files.