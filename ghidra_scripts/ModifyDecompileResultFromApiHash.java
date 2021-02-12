// @author Ko Nakagawa
// @category PCode
// @keybinding
// @menupath
// @toolbar

import com.google.gson.Gson;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import java.io.File;
import java.nio.file.Files;
import java.util.HashMap;

public class ModifyDecompileResultFromApiHash extends GhidraScript {
  private static class HashToName {
    public long hash;
    public String name;

    private static HashMap<Long, String> ConvertToHashMap(HashToName[] hashToApiNames) {
      HashMap<Long, String> hashMap = new HashMap<Long, String>();
      for (HashToName hashToApiName : hashToApiNames) {
        hashMap.put(hashToApiName.hash, hashToApiName.name);
      }
      return hashMap;
    }
  }

  private String getFunctionNameFromPcode(PcodeOpAST pcodeAst) {
    final var varNode = pcodeAst.getInput(0);

    if (!varNode.isAddress()) return null;

    final var addr = varNode.getAddress();
    if (addr == null) {
      System.err.println("Cannot get function name address");
      return null;
    }

    final var sym = getSymbolAt(addr); // for API externally defined
    if (sym != null) {
      return sym.toString();
    }

    final var func = getFunctionAt(addr);
    if (func != null) {
      return func.toString();
    }

    return null;
  }

  private DecompileResults decompileCurrentFunction() {
    final Function curFunction = getFunctionContaining(currentAddress);
    final var options = new DecompileOptions();
    final var ifc = new DecompInterface();
    ifc.setOptions(options);
    ifc.openProgram(currentProgram);
    ifc.setSimplificationStyle("decompile");
    return ifc.decompileFunction(curFunction, 30, monitor);
  }

  public void run() throws Exception {
    final File hashDbFile = askFile("DB for API hash values", "import");
    if (!hashDbFile.exists()) {
      System.err.println("Hash DB file does not exists");
      return;
    }

    final String targetFunction =
        askString("Type the function name", "Function resolving API address dynamically");

    final String hashToNameRaw = Files.readString(hashDbFile.toPath());
    final HashToName[] hashToName = new Gson().fromJson(hashToNameRaw, HashToName[].class);
    if (hashToName == null) {
      System.err.println("Cannot load hash db");
      return;
    }
    final var hashToNameMap = HashToName.ConvertToHashMap(hashToName);

    var curFuncDecompileResults = decompileCurrentFunction();

    final HighFunction highFunction = curFuncDecompileResults.getHighFunction();
    if (highFunction == null) {
      System.err.println("Cannot get high function");
      return;
    }

    // iterate for all pcode operations in current function
    final var iterPcodeOps = highFunction.getPcodeOps();
    while (iterPcodeOps.hasNext()) {
      final var pcode = iterPcodeOps.next();
      final var opcode = pcode.getOpcode();

      if (opcode != PcodeOp.CALL) continue;

      final var apiResolveFncName = getFunctionNameFromPcode(pcode);
      if (apiResolveFncName == null) {
        System.err.println("Cannot get function name");
        continue;
      }

      if (!apiResolveFncName.contains(targetFunction)) {
        System.err.println(apiResolveFncName + " is not a target function. Skipping");
        continue;
      }

      final var dllHash = Long.valueOf(pcode.getInput(1).getOffset());
      final var fncHash = Long.valueOf(pcode.getInput(2).getOffset());
      final var dllName = hashToNameMap.get(dllHash);
      final var fncName = hashToNameMap.get(fncHash);

      if (dllName != null && fncName != null) {
        final var apiName = dllName.replace('.', '_') + "_" + fncName;

        final VarnodeAST outVarnode = (VarnodeAST) pcode.getOutput();
        final HighVariable outHighVariable = outVarnode.getHigh();
        if (outHighVariable == null) {
          System.err.println("Cannot get HighVariable");
          continue;
        }

        final HighSymbol outHighSymbol = outHighVariable.getSymbol();
        if (outHighSymbol == null) {
          System.err.println("Cannot get HighSymbol");
          continue;
        }

        HighFunctionDBUtil.updateDBVariable(outHighSymbol, apiName, null, SourceType.USER_DEFINED);
        println("Update variable...");
      } else {
        if (dllName == null) {
          System.err.println(
              "Cannot find name corresponding to the hash value ("
                  + Long.toHexString(dllHash)
                  + ")");
        }
        if (fncName == null) {
          System.err.println(
              "Cannot find name corresponding to the hash value ("
                  + Long.toHexString(fncHash)
                  + ")");
        }
      }
    }
  }
}
