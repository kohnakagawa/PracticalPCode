// @author Ko Nakagawa
// @category PCode
// @keybinding
// @menupath
// @toolbar

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;

public class ModifyDecompileResultFromFunctionName extends GhidraScript {

  private boolean isTargetFunction(VarnodeAST vn, String fncName) {
    if (!vn.isAddress()) return false;

    final var addr = vn.getAddress();
    final var fnc = getSymbolAt(addr);
    if (fnc == null) return false;

    return fnc.toString().contains(fncName);
  }

  private String findProcName(PcodeOpAST pcGetProcAddress) {
    // NOTE: get the varnode of the second argument
    VarnodeAST vn = (VarnodeAST) pcGetProcAddress.getInput(2);

    // get varnode of copy source
    PcodeOp copyPcode = vn.getDef();
    if (copyPcode == null) {
      return null;
    }

    VarnodeAST vnIn = (VarnodeAST) copyPcode.getInput(0);
    if (!vnIn.isConstant() && !vnIn.isAddress()) {
      return null;
    }

    final var nameDataAtConst = vnIn.getAddress();
    if (nameDataAtConst == null) {
      return null;
    }

    // NOTE: Cannot get string data at const address space, thus convert it to ram address space
    final var nameDataAtRamSpace = toAddr(nameDataAtConst.getUnsignedOffset());
    final var nameString = getDataAt(nameDataAtRamSpace);
    if (nameString == null) {
      return null;
    }

    final var procName = nameString.getDefaultValueRepresentation();
    if (procName == null) {
      return null;
    }

    // NOTE: remove ""
    return procName.substring(1, procName.length() - 1);
  }

  public void run() throws Exception {
    final var options = new DecompileOptions();
    final var ifc = new DecompInterface();

    ifc.setOptions(options);
    ifc.openProgram(currentProgram);
    ifc.setSimplificationStyle("decompile");

    final var curFunction = getFunctionContaining(currentAddress);
    final var res = ifc.decompileFunction(curFunction, 30, monitor);

    final var highFunction = res.getHighFunction();
    if (highFunction == null) {
      throw new Exception("Cannot get high function");
    }

    final var pcodeOps = highFunction.getPcodeOps();
    while (pcodeOps.hasNext()) {
      final var pcodeElem = pcodeOps.next();
      final var opcode = pcodeElem.getOpcode();
      if ((opcode != PcodeOp.CALL) && (opcode != PcodeOp.CALLIND)) {
        continue;
      }

      VarnodeAST vn = (VarnodeAST) pcodeElem.getInput(0);
      if (isTargetFunction(vn, "GetProcAddress")) {
        println("GetProcAddress is found");
        final var procName = findProcName(pcodeElem);
        printf("Second argument is %s\n", procName);

        Varnode outVarnode = pcodeElem.getOutput();
        final var outVarnodeHighVariable = outVarnode.getHigh();
        if (outVarnodeHighVariable == null) {
          println("Cannot find high variable");
          break;
        }

        final var highVariable = outVarnodeHighVariable.getSymbol();
        if (highVariable != null) {
          HighFunctionDBUtil.updateDBVariable(
              highVariable, "pfn" + procName, null, SourceType.USER_DEFINED);
        } else {
          println("Cannot get high symbol");
        }
      }
    }
  }
}
