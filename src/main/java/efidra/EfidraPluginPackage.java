package efidra;

import ghidra.framework.plugintool.util.PluginPackage;

public class EfidraPluginPackage extends PluginPackage {

	public static final String NAME = "EFIdra";
	
	protected EfidraPluginPackage() {
		super(NAME, null, "EFIdra plugin package for analyzing UEFI ROMs");
	}

}
