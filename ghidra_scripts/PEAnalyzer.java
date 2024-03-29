import java.awt.BorderLayout;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.swing.JPanel;

import efidra.EFIdraExecutableAnalyzerScript;
import efidra.EFIdraExecutableData;
import efidra.EFIdraROMFormatLoader;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.mz.DOSHeader;
import ghidra.app.util.bin.format.pe.DataDirectory;
import ghidra.app.util.bin.format.pe.FileHeader;
import ghidra.app.util.bin.format.pe.NTHeader;
import ghidra.app.util.bin.format.pe.OptionalHeader;
import ghidra.app.util.bin.format.pe.PeUtils;
import ghidra.app.util.bin.format.pe.PortableExecutable;
import ghidra.app.util.bin.format.pe.SectionHeader;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import ghidra.app.util.bin.format.pe.debug.DebugCOFFSymbol;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Group;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighGlobal;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

public class PEAnalyzer extends EFIdraExecutableAnalyzerScript {
	// private methods createDataTypes, processSymbols, processDOSHeadeer,
	// processNTHeader, processSections, processDataDirectories, processStringTable 
	// copied from https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/src/main/java/ghidra/app/cmd/formats/PortableExecutableBinaryAnalysisCommand.java
	
	private final String TEXT_FRAG_NAME = ".text_DATA_";
	
	private final String BOOT_SERVICES_TYPE_NAME = "EFI_BOOT_SERVICES *";
	private final String BOOT_SERVICES_VAR_NAME = "gBS";
	private final String EFI_HANDLE_TYPE_NAME = "EFI_HANDLE";
	private final String EFI_HANDLE_VAR_NAME = "gImageHandle";
	private final String RUNTIME_SERVICES_TYPE_NAME = "EFI_RUNTIME_SERVICES *";
	private final String RUNTIME_SERVICES_VAR_NAME = "gRT";
	private final String SYSTEM_TABLE_TYPE_NAME = "EFI_SYSTEM_TABLE *";
	private final String SYSTEM_TABLE_VAR_NAME = "gST";
	
	private final String LOCATE_PROTOCOL = "EFI_LOCATE_PROTOCOL";
	private final String INSTALL_PROTOCOL = "EFI_INSTALL_PROTOCOL_INTERFACE";
	
	private Address baseAddr;
	private Listing listing;
	private ProgramModule progRoot;
	private MessageLog messages;
	private String progName;
	private PortableExecutable pe = null;
	
	private boolean createDataTypes() throws Exception {
		DOSHeader dos = pe.getDOSHeader();
		NTHeader nt = pe.getNTHeader();
		if (nt == null) {
			return false;
		}
		
		// maybe we can get the machine data and figure out 32/64-bit and then
		// use that for disassembly?
		// nt.getFileHeader().getMachine();

		processDOSHeader(dos);
		processNTHeader(dos, nt);
		processSections(nt);
		processDataDirectories(nt);
		processSymbols(nt.getFileHeader());

		return true;
	}

	private void processSymbols(FileHeader fileHeader) throws Exception {
		if (fileHeader.getPointerToSymbolTable() == 0) {
			return;
		}
		Address address = baseAddr.add(fileHeader.getPointerToSymbolTable());
		List<DebugCOFFSymbol> symbols = fileHeader.getSymbols();
		for (DebugCOFFSymbol symbol : symbols) {
			if (symbol == null) {
				continue;
			}
			String comment = "Name: " + symbol.getName() + '\n' + "Storage Class: " +
				symbol.getStorageClassAsString() + '\n' + "Type: " + symbol.getTypeAsString();
			listing.setComment(address, CodeUnit.PLATE_COMMENT, comment);
			DataType symbolDT = symbol.toDataType();
			Data data = listing.createData(address, symbolDT);
			createOrAddToFragment("COFF_Symbols", data.getMinAddress(), data.getLength());
			address = address.add(data.getLength());
		}
		processStringTable(address);
	}

	private void processStringTable(Address address) throws Exception {
		// Data dwordData = createDWord(address);
		Data dwordData = listing.createData(address, DWordDataType.dataType);

		createOrAddToFragment("StringTable", dwordData.getMinAddress(), dwordData.getLength());

		int usedBytes = dwordData.getLength();
		int totalBytes = currentProgram.getMemory().getInt(address);

		Address stringAddress = address.add(4);

		while (usedBytes < totalBytes) {
			if (monitor.isCancelled()) {
				break;
			}

			// Data stringData = createAsciiString(stringAddress);
			Data stringData = listing.createData(stringAddress, TerminatedStringDataType.dataType);
			listing.setComment(stringAddress, CodeUnit.EOL_COMMENT, "");
			createOrAddToFragment("StringTable", stringData.getMinAddress(), stringData.getLength());

			usedBytes += stringData.getLength();

			stringAddress = stringAddress.add(stringData.getLength());
		}
	}

	private void processDOSHeader(DOSHeader dos) throws DuplicateNameException, Exception {
		DataType dosDT = dos.toDataType();
		Address dosStartAddr = baseAddr.add(0);
		listing.createData(dosStartAddr, dosDT);
		createOrAddToFragment(dosDT.getName(), dosStartAddr, dosDT.getLength());
	}

	private void processNTHeader(DOSHeader dos, NTHeader nt)
			throws DuplicateNameException, IOException, Exception {
		DataType ntDT = nt.toDataType();
		Address ntStartAddr = baseAddr.add(dos.e_lfanew());
		Address ntEndAddr = ntStartAddr.add(ntDT.getLength());
		clearListing(ntStartAddr, ntEndAddr);//sometimes overlaps DOS header to packing
		listing.createData(ntStartAddr, ntDT);
		createOrAddToFragment(ntDT.getName(), ntStartAddr, ntDT.getLength());
	}

	private void processDataDirectories(NTHeader nt) throws Exception {
		MessageLog log = new MessageLog();
		OptionalHeader oh = nt.getOptionalHeader();
		DataDirectory[] datadirs = oh.getDataDirectories();
		for (DataDirectory datadir : datadirs) {
			if (datadir == null || datadir.getSize() == 0) {
				continue;
			}

			if (datadir.hasParsedCorrectly()) {
				datadir.markup(currentProgram, true, monitor, log, nt);

				// TODO: look at this! This needs to be moved to match 
				// the real address!
//				Address startAddr = PeUtils.getMarkupAddress(currentProgram, true, nt,
//						datadir.getVirtualAddress());
				int offset = datadir.getVirtualAddress();
				int ptr = nt.rvaToPointer(offset);
				Address startAddr;
				if (ptr < 0 && offset > 0) {//directory does not appear inside a loadable section
					Msg.error(PeUtils.class, "Invalid RVA " + Integer.toHexString(offset));
					startAddr = baseAddr.add(offset);
				} else {
					startAddr = baseAddr.add(ptr);
				}
				createOrAddToFragment(datadir.getDirectoryName(), startAddr, datadir.getSize());
			}
		}
		messages.appendMsg(log.toString());
	}

	private void processSections(NTHeader nt)
			throws Exception, DuplicateNameException, InvalidInputException {
		FileHeader fh = nt.getFileHeader();
		SectionHeader[] sections = fh.getSectionHeaders();
		int index = fh.getPointerToSections();
		for (SectionHeader section : sections) {
			DataType sectionDT = section.toDataType();
			Address sectionStartAddr = baseAddr.add(index);
			listing.createData(sectionStartAddr, sectionDT);
			createOrAddToFragment(sectionDT.getName(), sectionStartAddr, sectionDT.getLength());

			// setPlateComment(sectionStartAddr, section.toString());
			listing.setComment(sectionStartAddr, CodeUnit.PLATE_COMMENT, section.toString());

			index += SectionHeader.IMAGE_SIZEOF_SECTION_HEADER;

			if (section.getPointerToRawData() == 0 || section.getSizeOfRawData() == 0) {
				continue;
			}

			Address dataStartAddr = baseAddr.add(section.getPointerToRawData());
			currentProgram.getSymbolTable().createLabel(dataStartAddr, section.getName(),
				SourceType.IMPORTED);
			createOrAddToFragment(section.getName() + "_DATA", dataStartAddr,
				section.getSizeOfRawData());
		}
	}
	
	private ProgramFragment getFragment(String name) {
		for (Group progItem : progRoot.getChildren()) {
			if (name.equals(progItem.getName()))
				return (ProgramFragment) progItem;
		}
		return null;
	}
	
	private ProgramFragment createOrAddToFragment(String name, Address start, long length) 
			throws NotFoundException, AddressOutOfBoundsException, DuplicateNameException {
		String pName = name + "_" + progName;
		ProgramFragment frag = getFragment(pName);
		if (frag == null)
			frag = progRoot.createFragment(pName);
		frag.move(start, start.add(length));
		return frag;
	}
	
	@Override
	public boolean canAnalyze(ByteProvider provider) {
		try {
			pe = new PortableExecutable(provider, SectionLayout.MEMORY);
			DOSHeader dos = pe.getDOSHeader();
			if (dos == null || dos.e_magic() != DOSHeader.IMAGE_DOS_SIGNATURE) {
				return false;
			}

			NTHeader nt = pe.getNTHeader();
			if (nt == null) {
				return false;
			}
			return true;
		} catch (IOException e) {
			return false;
		}
	}

	private void findUEFIGlobals(PcodeOpAST op, SymbolTable symbolTable, Namespace namespace) 
			throws CodeUnitInsertionException, InvalidInputException {
		Varnode outVar = op.getOutput();
		HighVariable output = outVar.getHigh();
		DataType assignType = op.getInput(0).getHigh().getDataType();
		String asgTypeName = assignType.getName();
		if (output instanceof HighGlobal) {
			// assign UEFI globals
			Address globalAddr = outVar.getAddress();
			String globalName;
			if (BOOT_SERVICES_TYPE_NAME.equals(asgTypeName)) {
				globalName = BOOT_SERVICES_VAR_NAME;
			} else if (EFI_HANDLE_TYPE_NAME.equals(asgTypeName)) {
				globalName = EFI_HANDLE_VAR_NAME;
			} else if (RUNTIME_SERVICES_TYPE_NAME.equals(asgTypeName)) {
				globalName = RUNTIME_SERVICES_VAR_NAME;
			} else if (SYSTEM_TABLE_TYPE_NAME.equals(asgTypeName)) {
				globalName = SYSTEM_TABLE_VAR_NAME;
			} else {
				return;
			}
			// set type and label for relevant globals
			listing.createData(globalAddr, assignType);
			symbolTable.createLabel(globalAddr, globalName, namespace, SourceType.ANALYSIS);
		}
	}
	
	private void findUEFIFuncs(PcodeOpAST op) {
		// likely calls through system table
		Varnode funcVarnode = op.getInput(0);
		HighVariable funcVar = funcVarnode.getHigh();
		DataType funcType = funcVar.getDataType();
		String funcTypeName = funcType.getName();
		if (INSTALL_PROTOCOL.equals(funcTypeName)) {
			if (funcType instanceof FunctionDefinition) {
				FunctionDefinition funcDef = (FunctionDefinition) funcType;
				ParameterDefinition[] args = new ParameterDefinition[] {
					new ParameterDefinitionImpl("Handle", 
							new PointerDataType(EFIdraROMFormatLoader.getType(
									"/UefiBaseType.h/EFI_HANDLE")), 
							"A pointer to the EFI_HANDLE on which the interface is to be installed."),
					new ParameterDefinitionImpl("Protocol", 
							new PointerDataType(EFIdraROMFormatLoader.getType("EFI_GUID")),
							"The numeric ID of the protocol interface."),
					new ParameterDefinitionImpl("InterfaceType",
							EFIdraROMFormatLoader.getType("/UefiSpec.h/EFI_INTERFACE_TYPE"),
							"Indicates whether Interface is supplied in native form."),
					new ParameterDefinitionImpl("Interface",
							new PointerDataType(VoidDataType.dataType),
							"A pointer to the protocol interface.")
				};
				funcDef.setArguments(args);
			}
		} else if (LOCATE_PROTOCOL.equals(funcTypeName)) {
			if (funcType instanceof FunctionDefinition) {
				FunctionDefinition funcDef = (FunctionDefinition) funcType;
				ParameterDefinition[] args = new ParameterDefinition[] {
					new ParameterDefinitionImpl("Protocol", 
							new PointerDataType(EFIdraROMFormatLoader.getType("EFI_GUID")),
							"The numeric ID of the protocol interface."),
					new ParameterDefinitionImpl("Registration",
							new PointerDataType(VoidDataType.dataType),
							"Indicates whether Interface is supplied in native form."),
					new ParameterDefinitionImpl("Interface",
							new PointerDataType(new PointerDataType(VoidDataType.dataType)),
							"A pointer to the protocol interface.")
				};
				funcDef.setArguments(args);
			}
		}
	}
	
	private void propagateFunctionParameters(PcodeOpAST op, Namespace namespace) 
			throws InvalidInputException, DuplicateNameException {
		Varnode funcVarnode = op.getInput(0);
//		HighVariable funcVar = funcVarnode.getHigh();
//		DataType fType = funcVar.getDataType();
//		if (!(fType instanceof FunctionDefinition))
//			return;
		Address fAddr = funcVarnode.getAddress();
		if (listing.getFunctionAt(fAddr) != null)
			return;
		try {
			Function func = listing.createFunction("FUN_" + fAddr.toString(), namespace, fAddr, 
					CreateFunctionCmd.getFunctionBody(currentProgram, fAddr, monitor), 
					SourceType.ANALYSIS);
			List<ParameterImpl> parameters = new ArrayList<>();
			for (int i = 1; i < op.getNumInputs(); i++) {
				Varnode node = op.getInput(i);
				HighVariable hVar = node.getHigh();
				String pName = hVar.getName();
				if (pName == null || "UNNAMED".equals(pName))
					pName = "param" + i;;
				parameters.add(new ParameterImpl(pName, hVar.getDataType(), 
						currentProgram));
			}
			func.replaceParameters(parameters, 
					Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, 
					true, SourceType.ANALYSIS);
			
			// propagate down to calls made by this function
			decompileAndAnalyze(func, namespace);
		} catch (OverlappingFunctionException e) {
			e.printStackTrace();
		} catch (CodeUnitInsertionException e) {
			e.printStackTrace();
		}
	}
	
	private void decompileAndAnalyze(Function function, Namespace namespace) 
			throws CodeUnitInsertionException, InvalidInputException, DuplicateNameException {
		DecompileResults res = decompileFunction(function, 0, monitor);
		
		if (!res.decompileCompleted()) {
			JPanel panel = new JPanel(new BorderLayout());
			Msg.showError(this, panel, "Error Decompiling Executable", 
					"Encountered an error while decompiling " + progName);
			Msg.error(this, res.getErrorMessage());
			return;
		}
		
		HighFunction hFunc = res.getHighFunction();
		Iterator<PcodeOpAST> pCodeOps = hFunc.getPcodeOps();
		SymbolTable symbolTable = currentProgram.getSymbolTable();
		while (pCodeOps.hasNext()) {
			PcodeOpAST sOp = pCodeOps.next();
			int opCode = sOp.getOpcode();
			if (opCode == PcodeOp.COPY) {
				findUEFIGlobals(sOp, symbolTable, namespace);
			} else if (opCode == PcodeOp.CALLIND) {
				findUEFIFuncs(sOp);
			} else if (opCode == PcodeOp.CALL) {
				propagateFunctionParameters(sOp, namespace);
			}
		}
	}
	
	@Override
	public void analyzeExecutable(EFIdraExecutableData exe, MessageLog log, TaskMonitor tMonitor) {
		if (pe == null) {
			try {
				pe = new PortableExecutable(exe.provider, SectionLayout.MEMORY);
				DOSHeader dos = pe.getDOSHeader();
				if (dos == null || dos.e_magic() != DOSHeader.IMAGE_DOS_SIGNATURE) {
					log.appendMsg("Not a binary PE program: DOS header not found.");
				}
				
				NTHeader nt = pe.getNTHeader();
				if (nt == null) {
					log.appendMsg("Not a binary PE program: NT header not found.");
				}
			} catch (IOException e) {
				log.appendException(e);
				return;
			}
		}
		baseAddr = exe.baseAddr;
		listing = exe.parentROM.getListing();
		messages = log;
		progRoot = exe.programTree;
		progName = exe.name;
		
		try {
			createDataTypes();
			ProgramFragment textFrag = getFragment(TEXT_FRAG_NAME + exe.name);
			if (textFrag != null) {
				Address funcBase = textFrag.getMinAddress();
				Disassembler disassembler = getDisassembler(exe.parentROM);
				disassembler.disassemble(funcBase, textFrag);
				Function uefiMain = listing.createFunction("UefiMain", exe.namespace, funcBase, 
						CreateFunctionCmd.getFunctionBody(currentProgram, funcBase, tMonitor), 
						SourceType.ANALYSIS);
//				Apply UefiMain function signature
				Variable efiHandle = new ParameterImpl("ImageHandle", 
						EFIdraROMFormatLoader.getType("/UefiBaseType.h/EFI_HANDLE"), 
						currentProgram);
				Variable systemTable = new ParameterImpl("SystemTable",
						new PointerDataType(EFIdraROMFormatLoader.getType(
								"/UefiSpec.h/EFI_SYSTEM_TABLE")), currentProgram);
				uefiMain.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, 
						true, SourceType.ANALYSIS, efiHandle, systemTable);
				uefiMain.setReturnType(EFIdraROMFormatLoader.getType(
						"/UefiBaseType.h/EFI_STATUS"), SourceType.ANALYSIS);
				
				
				decompileAndAnalyze(uefiMain, exe.namespace);
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

}
