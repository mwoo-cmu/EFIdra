package efidra;

import java.io.IOException;
import java.util.List;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.mz.DOSHeader;
import ghidra.app.util.bin.format.pe.DataDirectory;
import ghidra.app.util.bin.format.pe.FileHeader;
import ghidra.app.util.bin.format.pe.NTHeader;
import ghidra.app.util.bin.format.pe.OptionalHeader;
import ghidra.app.util.bin.format.pe.PeUtils;
import ghidra.app.util.bin.format.pe.PortableExecutable;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import ghidra.app.util.bin.format.pe.SectionHeader;
import ghidra.app.util.bin.format.pe.debug.DebugCOFFSymbol;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Group;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

public class ExecutableSectionAnalyzers {
	// private methods createDataTypes, processSymbols, processDOSHeadeer,
	// processNTHeader, processSections, processDataDirectories, processStringTable 
	// copied from https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/src/main/java/ghidra/app/cmd/formats/PortableExecutableBinaryAnalysisCommand.java
	
	private static final String TEXT_FRAG_NAME = ".text_DATA_";
	
	private static Address baseAddr;
	private static Listing listing;
	private static ProgramModule progRoot;
	private static MessageLog messages;
	private static TaskMonitor monitor;
	private static Program currentProgram;
	private static String progName;
	
	private static boolean createDataTypes(PortableExecutable pe) throws Exception {
		DOSHeader dos = pe.getDOSHeader();
		NTHeader nt = pe.getNTHeader();
		if (nt == null) {
			return false;
		}

		processDOSHeader(dos);
		processNTHeader(dos, nt);
		processSections(nt);
		processDataDirectories(nt);
		processSymbols(nt.getFileHeader());

		return true;
	}

	private static void processSymbols(FileHeader fileHeader) throws Exception {
		if (fileHeader.getPointerToSymbolTable() == 0) {
			return;
		}
		Address address = toAddr(fileHeader.getPointerToSymbolTable());
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

	private static void processStringTable(Address address) throws Exception {
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

	private static void processDOSHeader(DOSHeader dos) throws DuplicateNameException, Exception {
		DataType dosDT = dos.toDataType();
		Address dosStartAddr = toAddr(0);
		listing.createData(dosStartAddr, dosDT);
		createOrAddToFragment(dosDT.getName(), dosStartAddr, dosDT.getLength());
	}

	private static void processNTHeader(DOSHeader dos, NTHeader nt)
			throws DuplicateNameException, IOException, Exception {
		DataType ntDT = nt.toDataType();
		Address ntStartAddr = toAddr(dos.e_lfanew());
		Address ntEndAddr = ntStartAddr.add(ntDT.getLength());
		clearListing(ntStartAddr, ntEndAddr);//sometimes overlaps DOS header to packing
		listing.createData(ntStartAddr, ntDT);
		createOrAddToFragment(ntDT.getName(), ntStartAddr, ntDT.getLength());
	}

	private static void processDataDirectories(NTHeader nt) throws Exception {
		MessageLog log = new MessageLog();
		OptionalHeader oh = nt.getOptionalHeader();
		DataDirectory[] datadirs = oh.getDataDirectories();
		for (DataDirectory datadir : datadirs) {
			if (datadir == null || datadir.getSize() == 0) {
				continue;
			}

			if (datadir.hasParsedCorrectly()) {
				datadir.markup(currentProgram, true, monitor, log, nt);

				Address startAddr = PeUtils.getMarkupAddress(currentProgram, true, nt,
						datadir.getVirtualAddress());
				createOrAddToFragment(datadir.getDirectoryName(), startAddr, datadir.getSize());
			}
		}
		messages.appendMsg(log.toString());
	}

	private static void processSections(NTHeader nt)
			throws Exception, DuplicateNameException, InvalidInputException {
		FileHeader fh = nt.getFileHeader();
		SectionHeader[] sections = fh.getSectionHeaders();
		int index = fh.getPointerToSections();
		for (SectionHeader section : sections) {
			DataType sectionDT = section.toDataType();
			Address sectionStartAddr = toAddr(index);
			listing.createData(sectionStartAddr, sectionDT);
			createOrAddToFragment(sectionDT.getName(), sectionStartAddr, sectionDT.getLength());

			// setPlateComment(sectionStartAddr, section.toString());
			listing.setComment(sectionStartAddr, CodeUnit.PLATE_COMMENT, section.toString());

			index += SectionHeader.IMAGE_SIZEOF_SECTION_HEADER;

			if (section.getPointerToRawData() == 0 || section.getSizeOfRawData() == 0) {
				continue;
			}

			Address dataStartAddr = toAddr(section.getPointerToRawData());
			currentProgram.getSymbolTable().createLabel(dataStartAddr, section.getName(),
				SourceType.IMPORTED);
			createOrAddToFragment(section.getName() + "_DATA", dataStartAddr,
				section.getSizeOfRawData());
		}
	}
	
	private static Address toAddr(long offset) {
		return baseAddr.add(offset);
	}
	
	private static ProgramFragment getFragment(String name) {
		for (Group progItem : progRoot.getChildren()) {
			if (name.equals(progItem.getName()))
				return (ProgramFragment) progItem;
		}
		return null;
	}
	
	private static ProgramFragment createOrAddToFragment(String name, Address start, long length) 
			throws NotFoundException, AddressOutOfBoundsException, DuplicateNameException {
		String pName = name + "_" + progName;
		ProgramFragment frag = getFragment(pName);
		if (frag == null)
			frag = progRoot.createFragment(pName);
		frag.move(start, start.add(length));
		return frag;
	}
	
	private static void clearListing(Address start, Address end) throws CancelledException {
		listing.clearCodeUnits(start, end, false, monitor);
	}
	
	public static void runPEAnalyzer(Program program, ProgramModule root, 
			Disassembler disassembler, ByteProvider provider, String exeName, 
			Address exeBase, MessageLog log, TaskMonitor tMonitor) {
		// similar to what is done in PortableExecutableAnalyzer (PortableExecutableBinaryAnalysisCommand)
		baseAddr = exeBase;
		currentProgram = program;
		listing = program.getListing();
		messages = log;
		monitor = tMonitor;
		progRoot = root;
		progName = exeName;
		try {
			PortableExecutable pe = new PortableExecutable(provider, SectionLayout.MEMORY);
			DOSHeader dos = pe.getDOSHeader();
			if (dos == null || dos.e_magic() != DOSHeader.IMAGE_DOS_SIGNATURE) {
				log.appendMsg("Not a binary PE program: DOS header not found.");
			}

			NTHeader nt = pe.getNTHeader();
			if (nt == null) {
				log.appendMsg("Not a binary PE program: NT header not found.");
			}
			
			createDataTypes(pe);
			ProgramFragment textFrag = getFragment(TEXT_FRAG_NAME + exeName);
			if (textFrag != null) {
				disassembler.disassemble(textFrag.getMinAddress(), textFrag);
			}
		} catch (IOException e) {
			log.appendException(e);
		} catch (Exception e) {
			log.appendException(e);
		}
	}
}
