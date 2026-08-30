// Recover and normalize MSVC RTTI vtables on x64 Windows PE binaries.
//
// A working replacement for FixUpRttiAnalysisScript, whose 64-bit path was never finished
// (getReferencedAddress() returns null without a pre-existing reference -- the
// "// TODO: get ibo bytes" case). Here every image-base-relative offset (RVA) is resolved
// directly as imageBase + (int32)rva, so no prior analysis is required, and Complete
// Object Locators are found by their self-reference (COL.pSelf RVA -> its own address).
//
// Names every vtable RTTI describes with the *readable* C++ class name from Ghidra's
// Microsoft demangler -- VTABLE_ConcreteFormFactory<AlchemyItem,46>, VTABLE_bnet::UserQueue,
// VTABLE_NiTMap<char_const*,Setting*> -- i.e. angle brackets / :: / * kept intact (Ghidra
// allows them in labels). This is the convergence convention: the symbol table reads like
// the source, and the ugly-but-required _/__-mangle is confined to the CommonLib C++
// headers (where VTABLE_* must be valid identifiers). The CommonLib import/export does the
// deterministic mangle <-> demangle at that boundary; Ghidra itself stays readable.
//
// RTTI is ground truth, so this is also the canonical namer: it renames any existing
// VTABLE_ label (e.g. a half-mangled CommonLib import) to the authoritative readable form.
// Multiple-inheritance subobject vtables are disambiguated VTABLE_<class>, _2, _3 ... by
// the COL subobject offset. Only VTABLE_* labels and FUN_ destructors are touched; fp_dtor
// pointers, hand-named functions and all other symbols are left alone.
//
// Surfaces RTTI ground truth the PDB missed -- e.g. on SkyrimVR the VR-exclusive
// BSVRInterface / BSOpenVRControllerDevice / BSTrackedControllerDevice and the VR shaders
// that an SE-based PDB never had.
//
//@author Alan Tse
//@category C++
//@menupath Tools.Recover RTTI Vtables
//@license GPL-3.0

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.microsoft.MicrosoftDemangler;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SourceType;

public class RecoverRttiVtablesScript extends GhidraScript {

	private static final class Blk {
		final long start;
		final byte[] data;
		final boolean exec;

		Blk(long start, byte[] data, boolean exec) {
			this.start = start;
			this.data = data;
			this.exec = exec;
		}

		boolean has(long a) {
			return a >= start && a < start + data.length;
		}
	}

	// one vtable: its address, the subobject offset (from the COL) and the type-info name
	private static final class Vtbl {
		final long addr;
		final long subOffset;
		final String typeName;

		Vtbl(long addr, long subOffset, String typeName) {
			this.addr = addr;
			this.subOffset = subOffset;
			this.typeName = typeName;
		}
	}

	private static final Pattern RTTI_SUFFIX = Pattern.compile("_`RTTI_Type_Descriptor'$");
	private static final Pattern QUALIFIER = Pattern.compile("(^|[<,(])(class|struct|enum|union)_");
	private static final Pattern PTR_NOISE = Pattern.compile("_*__ptr(32|64)");
	private static final Pattern PRE_BRACKET = Pattern.compile("_+(?=[>,])");

	private long imageBase;
	private List<Blk> blocks;
	private final MicrosoftDemangler demangler = new MicrosoftDemangler();

	@Override
	public void run() throws Exception {
		String id = currentProgram.getLanguageID().getIdAsString().toLowerCase();
		if (!id.contains("x86") || currentProgram.getDefaultPointerSize() != 8) {
			println("This script targets x64 Windows PE binaries only.");
			return;
		}
		imageBase = currentProgram.getImageBase().getOffset();
		cacheBlocks();

		// COL address -> {subObject offset, typeDescriptor address, type-info name}
		Map<Long, long[]> colMeta = new HashMap<>();   // col -> {subOffset, tdAddr}
		Map<Long, String> colName = new HashMap<>();    // col -> type-info name
		collectCompleteObjectLocators(colMeta, colName);
		println("Complete Object Locators (self-ref): " + colName.size());

		// group every vtable by its class (type descriptor address)
		Map<Long, List<Vtbl>> byClass = new HashMap<>();
		mapVtables(colMeta, colName, byClass);
		int total = 0;
		for (List<Vtbl> v : byClass.values()) {
			total += v.size();
		}
		println("Vtables mapped from COLs: " + total + " across " + byClass.size() + " classes");

		int renamed = 0, created = 0, unchanged = 0, dtors = 0, undemangled = 0;
		for (List<Vtbl> group : byClass.values()) {
			monitor.checkCancelled();
			group.sort(Comparator.comparingLong(v -> v.subOffset));
			String readable = readableName(group.get(0).typeName);
			if (readable == null) {
				undemangled += group.size();
				continue;
			}
			for (int i = 0; i < group.size(); i++) {
				Vtbl v = group.get(i);
				String label = "VTABLE_" + readable + (i == 0 ? "" : "_" + (i + 1));
				Address a = toAddrFast(v.addr);
				if (a == null) {
					continue;
				}
				Symbol existing = existingVtableSymbol(a, label);
				if (existing != null && existing.getName().equals(label)) {
					unchanged++;
				}
				else if (existing != null) {
					try {
						existing.setName(label, SourceType.USER_DEFINED);
						renamed++;
					}
					catch (Exception ex) {
						// leave it
					}
				}
				else {
					try {
						currentProgram.getSymbolTable().createLabel(a, label, SourceType.USER_DEFINED);
						created++;
					}
					catch (Exception ex) {
						// duplicate/invalid
					}
				}
				if (nameDestructor(v.addr, readable)) {
					dtors++;
				}
			}
		}
		println(String.format(
			"VTABLE labels: %d renamed, %d created, %d already correct, %d destructors, %d undemanglable.",
			renamed, created, unchanged, dtors, undemangled));
	}

	// Demangle the RTTI type-descriptor name (.?AV...@@) to a readable C++ class name,
	// keeping <> :: * intact. Returns null if it cannot be demangled.
	private String readableName(String typeName) {
		if (typeName == null || typeName.length() < 4) {
			return null;
		}
		String wrapped = "??_R0" + typeName.substring(1) + "@8"; // type-descriptor decorated symbol
		String cpp;
		try {
			DemangledObject d = demangler.demangle(wrapped);
			if (d == null) {
				return null;
			}
			cpp = d.getName();
		}
		catch (Exception ex) {
			return null;
		}
		if (cpp == null || cpp.isEmpty()) {
			return null;
		}
		cpp = RTTI_SUFFIX.matcher(cpp).replaceAll("");
		cpp = QUALIFIER.matcher(cpp).replaceAll("$1");
		cpp = PTR_NOISE.matcher(cpp).replaceAll("");
		cpp = cpp.replace(" ", "");
		cpp = PRE_BRACKET.matcher(cpp).replaceAll(""); // drop stray '_' before '>' or ','
		return cpp;
	}

	// Return the (single) VTABLE_ symbol at the address, preferring an exact match to label.
	private Symbol existingVtableSymbol(Address a, String label) {
		Symbol any = null;
		for (Symbol s : currentProgram.getSymbolTable().getSymbols(a)) {
			if (s.getName().startsWith("VTABLE_")) {
				if (s.getName().equals(label)) {
					return s;
				}
				any = s;
			}
		}
		return any;
	}

	private void cacheBlocks() throws Exception {
		blocks = new ArrayList<>();
		for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
			monitor.checkCancelled();
			if (!b.isInitialized() || b.getSize() <= 0x800 || b.getSize() >= 0x4000000) {
				continue;
			}
			byte[] data = new byte[(int) b.getSize()];
			b.getBytes(b.getStart(), data);
			blocks.add(new Blk(b.getStart().getOffset(), data, b.isExecute()));
		}
	}

	private Blk blockOf(long a) {
		for (Blk blk : blocks) {
			if (blk.has(a)) {
				return blk;
			}
		}
		return null;
	}

	private int u32(byte[] d, int off) {
		return ByteBuffer.wrap(d, off, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
	}

	private long u64(byte[] d, int off) {
		return ByteBuffer.wrap(d, off, 8).order(ByteOrder.LITTLE_ENDIAN).getLong();
	}

	private String cString(long a) {
		Blk blk = blockOf(a);
		if (blk == null) {
			return null;
		}
		int off = (int) (a - blk.start);
		int end = off;
		while (end < blk.data.length && blk.data[end] != 0 && end - off < 400) {
			end++;
		}
		if (end >= blk.data.length || blk.data[end] != 0) {
			return null;
		}
		return new String(blk.data, off, end - off, java.nio.charset.StandardCharsets.US_ASCII);
	}

	// RTTICompleteObjectLocator (x64): +0 signature, +4 offset(subobject), +0x0C pTypeDescriptor(RVA),
	// +0x14 pSelf(RVA). Identified by pSelf resolving back to its own address.
	private void collectCompleteObjectLocators(Map<Long, long[]> meta, Map<Long, String> name)
			throws Exception {
		for (Blk blk : blocks) {
			monitor.checkCancelled();
			if (blk.exec) {
				continue;
			}
			byte[] d = blk.data;
			for (int o = 0; o + 0x18 <= d.length; o += 4) {
				if ((u32(d, o) & 0xFFFFFFFFL) > 1) {
					continue;
				}
				if (imageBase + u32(d, o + 0x14) != blk.start + o) {
					continue;
				}
				long tdAddr = imageBase + u32(d, o + 0x0C);
				String tn = cString(tdAddr + 0x10);
				if (tn != null && tn.startsWith(".?A")) {
					long col = blk.start + o;
					meta.put(col, new long[] { u32(d, o + 4) & 0xFFFFFFFFL, tdAddr });
					name.put(col, tn);
				}
			}
		}
	}

	// A vtable's meta pointer (vtable-8) holds the COL address; vtable = that slot + 8.
	private void mapVtables(Map<Long, long[]> meta, Map<Long, String> name,
			Map<Long, List<Vtbl>> byClass) throws Exception {
		for (Blk blk : blocks) {
			monitor.checkCancelled();
			if (blk.exec) {
				continue;
			}
			byte[] d = blk.data;
			for (int o = 0; o + 8 <= d.length; o += 8) {
				long col = u64(d, o);
				long[] m = meta.get(col);
				if (m != null) {
					byClass.computeIfAbsent(m[1], k -> new ArrayList<>())
							.add(new Vtbl(blk.start + o + 8, m[0], name.get(col)));
				}
			}
		}
	}

	private boolean nameDestructor(long vt, String readable) throws Exception {
		Blk blk = blockOf(vt);
		if (blk == null) {
			return false;
		}
		long h = u64(blk.data, (int) (vt - blk.start));
		Blk hb = blockOf(h);
		if (hb == null || !hb.exec) {
			return false;
		}
		Address a = toAddrFast(h);
		Function f = getFunctionAt(a);
		if (f == null) {
			new CreateFunctionCmd(a).applyTo(currentProgram);
			f = getFunctionAt(a);
		}
		if (f == null) {
			return false;
		}
		String n = f.getName();
		if (!(n.startsWith("FUN_") || n.startsWith("sub_") || n.startsWith("thunk_"))) {
			return false;
		}
		try {
			f.setName(readable.replaceAll("[^A-Za-z0-9]", "_") + "__dtor", SourceType.USER_DEFINED);
			return true;
		}
		catch (Exception ex) {
			return false;
		}
	}

	private Address toAddrFast(long a) {
		try {
			return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(a);
		}
		catch (Exception ex) {
			return null;
		}
	}
}
