#for GoAhead
#@author OneShell
#@category Httpds
#@keybinding
#@menupath
#@toolbar

#TODO: Add script code here

from ghidra.program.util import DefinedDataIterator
from ghidra.app.util import XReferenceUtils
from ghidra.app.decompiler import DecompInterface, DecompileOptions, DecompileResults
from ghidra.program.model.pcode import PcodeOp, PcodeOpAST
from ghidra.program.model.listing import FunctionManager

from ghidra.program.model.data import DataType
from ghidra.program.model.data import IntegerDataType, PointerDataType, CharDataType
from ghidra.program.model.listing import ParameterImpl
from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SourceType

import re
from collections import Counter

class GoAhead():
    def __init__(self):
        self.program = getCurrentProgram()
        self.function_manager = self.program.getFunctionManager()
        self.address_factory = self.program.getAddressFactory()
        
        self.function_websUrlHandlerDefine = None
        self.function_initWebs = None 
        self.function_handlers = []

    def get_version(self):
        # check whether current program is GoAhead and get version
        flag_is_goahead = False
        version_ref_functions = []
        version_pattern = r'\b\d+\.\d+\.\d+\b'
        version = None
        for tmp_str in DefinedDataIterator.definedStrings(self.program):
            string = tmp_str.getValue()
            if str(string) == "GoAhead-Webs":
                flag_is_goahead = True
            if str(string) == "SERVER_SOFTWARE" :
                for ref in XReferenceUtils.getXReferences(tmp_str, -1):
                    ref_func = getFunctionContaining(ref.getFromAddress()).getName()
        
            # find version pattern
            match = re.search(version_pattern, string)
            if match:
                for ref in XReferenceUtils.getXReferences(tmp_str, -1):
                    tmp_func = getFunctionContaining(ref.getFromAddress()).getName()
                    tmp_dic = {
                        "version" : string,
                        "func" : tmp_func
                    }
                    version_ref_functions.append(tmp_dic)
        for each in version_ref_functions:
            if ref_func == each["func"]:
                version = each["version"]
                
        if flag_is_goahead and version:
            print(f"version: {version}")
            return True
        return False
        
    def decompile_function(self, function):
        # decompile the fucntion and get PCode
        decomplib = DecompInterface()
        decomplib.openProgram(self.program)
        timeout = 30
        decompiled_res = decomplib.decompileFunction(function, timeout, getMonitor())
        high_function = decompiled_res.getHighFunction()
        ops = high_function.getPcodeOps()
        return ops
    
    def locate_initWebs(self):
        # locate function initWebs by api strings, such as /cgi-bin/, /login, etc
        possible_initWebs = []
        api_pattern = r"^/[A-Za-z0-9-]+$"
        for tmp_str in DefinedDataIterator.definedStrings(currentProgram()):
            string = tmp_str.getValue()
            match = re.search(api_pattern, string)
            if match:
                tmp_func_list = []
                for ref in XReferenceUtils.getXReferences(tmp_str, -1):
                    tmp_func = getFunctionContaining(ref.getFromAddress())
                    tmp_func_list.append(tmp_func)
                tmp_dic = {
                    "api" : string,
                    "func" : tmp_func_list,
                }
                possible_initWebs.append(tmp_dic)
        common_func_set = set(possible_initWebs[0]["func"])
        for each in possible_initWebs[1:]:
            common_func_set.intersection_update(each["func"])
        common_func_set = list(common_func_set)
        if len(common_func_set) != 0 :
            self.function_initWebs = common_func_set[0]
            print(f"locate: {self.function_initWebs} at {self.function_initWebs.getEntryPoint()}")
            return True
        print("initWebs not found")
        return False
            
    def locate_websUrlHandlerDefine(self):
        # locate function UrlHandlerDefine, which called in function initWebs and whose fourth param is a function
        ops = self.decompile_function(self.function_initWebs)
        possible_websUrlHandlerDefine = []
        while ops.hasNext():
            pcode_OP_AST = ops.next()
            opcode = pcode_OP_AST.getOpcode()
            if opcode == PcodeOp.CALL:
                call_addr = pcode_OP_AST.getInput(0).getAddress()
                inputs = pcode_OP_AST.getInputs()
                inputs_num = pcode_OP_AST.getNumInputs()
                # parse params for GoAhead 2.1.8
                if inputs_num == 6 and inputs[5].isConstant :
                    try:
                        handler_op = inputs[4].getDef().getInputs() 
                        for each in handler_op:
                            if each.isAddress() or each.isConstant():
                                possible_address = each.getAddress().toString().split(":")[-1]
                                # check whether address is a function
                                address = self.address_factory.getAddress(possible_address)
                                handler = self.function_manager.getFunctionContaining(address)
                                if handler:
                                    possible_websUrlHandlerDefine.append(call_addr)
                    except Exception as e:
                        # print(e)
                        pass
        counter = Counter(possible_websUrlHandlerDefine)
        addr_websUrlHandlerDefine, _, = counter.most_common(1)[0]
        self.function_websUrlHandlerDefine = self.function_manager.getFunctionAt(addr_websUrlHandlerDefine)
        
        print("locate: websUrlHandlerDefine at %s" % (self.function_websUrlHandlerDefine.getEntryPoint()))
              
    def locate_all_handlers(self):
        # locate all handlers defined in websUrlHandlerDefine
        for ref in getReferencesTo(self.function_websUrlHandlerDefine.getEntryPoint()):
            print(ref.getFromAddress())
            function_cur = self.function_manager.getFunctionContaining(ref.getFromAddress())
            ops = self.decompile_function(function_cur)
            while ops.hasNext():
                pcode_OP_AST = ops.next()
                opcode = pcode_OP_AST.getOpcode()
                if opcode == PcodeOp.CALL:
                    call_addr = pcode_OP_AST.getInput(0).getAddress()
                    # for GoAhead 2.1.8
                    inputs = pcode_OP_AST.getInputs()
                    # locate websUrlHandlerDefine
                    inputs_num = pcode_OP_AST.getNumInputs()
                    # parse params
                    if inputs_num == 6 and inputs[5].isConstant :
                        try:
                            handler_op = inputs[4].getDef().getInputs() # PcodeOpAST
                            for each in handler_op:
                                if each.isAddress() or each.isConstant():
                                    possible_address = each.getAddress().toString().split(":")[-1]
                                    # check whether address is a function
                                    address = self.address_factory.getAddress(possible_address)
                                    handler = self.function_manager.getFunctionAt(address)
                                    if handler:
                                        if handler not in self.function_handlers:
                                            self.function_handlers.append(handler)
                                            # print("handler %s, defined at %s" % (handler, ref.getFromAddress()))
                        except Exception as e:
                            pass 
    
    def redefine_handlers_params(self):
        # redefine all handlers and set params
        handler_params = [
            ParameterImpl("wp", PointerDataType(IntegerDataType.dataType), self.program, SourceType.USER_DEFINED),
            ParameterImpl("urlPrefix", PointerDataType(CharDataType.dataType), self.program, SourceType.USER_DEFINED),
            ParameterImpl("webdir", PointerDataType(CharDataType.dataType), self.program, SourceType.USER_DEFINED),
            ParameterImpl("arg", PointerDataType(IntegerDataType.dataType), self.program, SourceType.USER_DEFINED),
            ParameterImpl("url", PointerDataType(CharDataType.dataType), self.program, SourceType.USER_DEFINED),
            ParameterImpl("path", PointerDataType(CharDataType.dataType), self.program, SourceType.USER_DEFINED),
            ParameterImpl("query", PointerDataType(CharDataType.dataType), self.program, SourceType.USER_DEFINED)
        ]

        for handler in self.function_handlers:
            # print(type(handler))
            handler.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, True, SourceType.USER_DEFINED, handler_params)

goAhead = GoAhead()
goAhead.get_version()
goAhead.locate_initWebs()
goAhead.locate_websUrlHandlerDefine()
goAhead.locate_all_handlers()
goAhead.redefine_handlers_params()