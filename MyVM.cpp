//===- StringObfuscation.cpp - Obfuscates the usage of static string constants  ---------------===//

#include <string>
#include <vector>
#include <map>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Function.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/IR/GlobalValue.h"

using namespace llvm;

#define DEBUG_TYPE "MyVM"

namespace {

  struct MyVMObfuscation : public FunctionPass {
    static char ID;
    MyVMObfuscation() : FunctionPass(ID) {}

    std::string readAnnotate(Function *f) 
    {
        std::string annotation = "";
        // Get annotation variable
        GlobalVariable *glob = f->getParent()->getGlobalVariable("llvm.global.annotations");
        if (glob != NULL) {
            // Get the array
            if (ConstantArray *ca = dyn_cast<ConstantArray>(glob->getInitializer())) 
            {
                for (unsigned i = 0; i < ca->getNumOperands(); ++i) 
                {
                    // Get the struct
                    if (ConstantStruct *structAn = dyn_cast<ConstantStruct>(ca->getOperand(i))) 
                    {
                        if (ConstantExpr *expr = dyn_cast<ConstantExpr>(structAn->getOperand(0)))
                        {
                            // If it's a bitcast we can check if the annotation is concerning
                            // the current function
                            if (expr->getOpcode() == Instruction::BitCast && expr->getOperand(0) == f) 
                            {
                                ConstantExpr *note = cast<ConstantExpr>(structAn->getOperand(1));
                                // If it's a GetElementPtr, that means we found the variable
                                // containing the annotations
                                if (note->getOpcode() == Instruction::GetElementPtr) 
                                {
                                    if (GlobalVariable *annoteStr = dyn_cast<GlobalVariable>(note->getOperand(0))) 
                                    {
                                        if (ConstantDataSequential *data = dyn_cast<ConstantDataSequential>(annoteStr->getInitializer())) 
                                        {
                                            if (data->isString()) 
                                            {
                                                annotation += data->getAsString().str() + " ";
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return annotation;
    }
    
    bool runOnFunction(Function &F) override
    {
        // Check if declaration
        if (F.isDeclaration()) {
            return false;
        }

        // Check external linkage
        if(F.hasAvailableExternallyLinkage() != 0) {
            return false;
        }

        // If fla annotations
        #define LIGHT_VM "LightVM"
        const std::string & annotation = readAnnotate(&F);
        if (annotation.find(LIGHT_VM) == std::string::npos) {
            return false;
        }
        
        std::vector<BasicBlock *> originBBs;
        for(BasicBlock &originBB : F) 
        {
            if(!originBB.empty())
            {
                //PHI NODE肯定位于block的第一条件指令
                Instruction & insn = *(originBB.begin());
                if(isa<PHINode>(insn))
                {
                    errs() << "Processing bb has PHINODE\n";
                    continue;
                }

                if(originBB.size() <=2 )
                {
                    errs() << "BB size less than 2\n";
                    continue;
                }
            }

            //exception handler block不处理
            if(originBB.isEHPad())
                continue;

            LLVMContext & context = originBB.getContext();
            IRBuilder<> builder(context);

            errs() << "Origin BB: " << originBB << "\n";

            //VMInterpreterBody
            BasicBlock * VMInterpreterbody_bb = BasicBlock::Create(context, "VMInterpreterBody", &F, &originBB);
            //VMInterpreter
            BasicBlock * VMInterpreter_bb = BasicBlock::Create(context, "VMInterpreter", &F, VMInterpreterbody_bb);
            //先创建初始化向量表的block
            BasicBlock * entry_bb = BasicBlock::Create(context, "entry", &F, VMInterpreter_bb);
            originBB.replaceAllUsesWith(entry_bb);
            
            std::vector<BasicBlock *> handlerbb_list;
            srand(time(0));
            //PC向量表
            std::vector<ConstantInt*> switch_elems;
            std::vector<Constant*> const_array_elems;
            //为解决变量生命周期问题，为每一条指令都申请一个变量
            std::vector<Value *> var_declare;
            size_t insn_count = 0;

            while(!originBB.empty())
            {
                BasicBlock::iterator first_insn = originBB.begin();
                unsigned int insn_opcode = first_insn->getOpcode();
                if(insn_opcode == Instruction::Alloca) //变量声明不混淆，放在entry
                {
                    entry_bb->getInstList().splice(entry_bb->end(), originBB.getInstList(), first_insn);
                    continue;
                }

                ++ insn_count;
                BasicBlock * new_bb = BasicBlock::Create(context, "VMInterpreterHandler", &F, &originBB);
                new_bb->getInstList().splice(new_bb->end(), originBB.getInstList(), first_insn);
                
                if(!new_bb->begin()->isTerminator())
                {
                    builder.SetInsertPoint(new_bb, new_bb->end());
                    builder.CreateBr(VMInterpreterbody_bb);
                }
                else
                {
                    new_bb->replaceSuccessorsPhiUsesWith(&originBB, new_bb);
                }

                int code = rand();
                switch_elems.push_back(ConstantInt::get(Type::getInt32Ty(context), code));
                const_array_elems.push_back(ConstantInt::get(Type::getInt32Ty(context), code));
                handlerbb_list.push_back(new_bb);
            }

            for(BasicBlock * bb : handlerbb_list)
            {
                for(Instruction & insn : *bb)
                {
                    llvm::Value * returnval = llvm::cast<llvm::Value>(&insn);
                    //指令返回值下面有引用
                    if(returnval->hasNUsesOrMore(1))
                    {
                        std::vector<BasicBlock *> returnval_users;
                        for(auto user : returnval->users())
                        {
                            //找到引用此变量的bb
                            Instruction * insn = llvm::cast<Instruction>(user);
                            BasicBlock * that_bb = insn->getParent();
                            //找出不在当前bb的引用
                            if(that_bb != bb)
                            {
                                returnval_users.push_back(that_bb);
                            }
                        }

                        if(!returnval_users.empty())
                        {
                            //在entry新声明一个变量
                            builder.SetInsertPoint(entry_bb, entry_bb->end());
                            Value * tmpPtr = builder.CreateAlloca(returnval->getType(), nullptr, "replace");
                            errs() << "replace VALUE type :" << *tmpPtr->getType() << "\n";
                            //在new_bb中对此变量赋值, 并将该指令返回值的所有使用处替换为该变量
                            BasicBlock::iterator p = bb->end();
                            --p;
                            builder.SetInsertPoint(bb, p);
                            builder.CreateStore(returnval, tmpPtr);

                            for(BasicBlock * ele_bb : returnval_users)
                            {
                                builder.SetInsertPoint(ele_bb, ele_bb->begin());
                                Value * replace = builder.CreateLoad(tmpPtr);
                                returnval->replaceUsesOutsideBlock(replace, bb);
                            }
                        }
                    }
                }
            }

            originBBs.push_back(&originBB);

            ArrayType * array_type = ArrayType::get(Type::getInt32Ty(context), insn_count);
            GlobalVariable* opcodes = new llvm::GlobalVariable(*F.getParent(),
                /*Type=*/array_type,
                /*isConstant=*/true,
                /*Linkage=*/llvm::GlobalValue::PrivateLinkage,
                /*Initializer=*/0, // has initializer, specified below
                /*Name=*/"opcodes");
            opcodes->setAlignment(MaybeAlign(4));
            opcodes->setInitializer(ConstantArray::get(array_type, const_array_elems));
            errs() << *opcodes << "\n";
            
            //entry
            builder.SetInsertPoint(entry_bb, entry_bb->end());
            Value * opcodesPtr = builder.CreateAlloca(Type::getInt32PtrTy(context), nullptr, "opcodesPtr");
            Value * opcodesGVCast = builder.CreateBitCast(opcodes, Type::getInt32PtrTy(context), "opcodesGVCast");
            builder.CreateStore(opcodesGVCast, opcodesPtr);
            builder.CreateBr(VMInterpreter_bb);

            //errs() << "Processing VMInterpreter\n";
            //VMInterpreter
            builder.SetInsertPoint(VMInterpreter_bb);
            //创建变量i并创始化为0
            Value * i_alloc = builder.CreateAlloca(Type::getInt32Ty(context), nullptr, "i_alloc");
            Value * con0 = ConstantInt::get(Type::getInt32Ty(context), 0);
            builder.CreateStore(con0, i_alloc);
            Value * loadedOpcodePtr = builder.CreateLoad(opcodesPtr, "loadedOpcodePtr");
            builder.CreateBr(VMInterpreterbody_bb);

            //errs() << "Processing VMInterperterBody\n";
            //VMInterperterBody
            builder.SetInsertPoint(VMInterpreterbody_bb);
            Value * loaded_i = builder.CreateLoad(i_alloc, "load_i");
            Value * con1 = ConstantInt::get(Type::getInt32Ty(context), 1);
            Value * increased_i = builder.CreateAdd(loaded_i, con1, "increased_i");
            builder.CreateStore(increased_i, i_alloc);
            Value * opcodesIdx = builder.CreateGEP(Type::getInt32Ty(context), loadedOpcodePtr, loaded_i, "opcodesIdx");
            Value * loadedOpcode = builder.CreateLoad(opcodesIdx, "loadedOpcode");
            //创建switch语句
            SwitchInst * switch_inst = builder.CreateSwitch(loadedOpcode, VMInterpreterbody_bb, insn_count);
            for(int i = 0; i < insn_count; ++i)
            {
                switch_inst->addCase(switch_elems[i], handlerbb_list[i]);
            }

            //errs() << *entry_bb << "\n";
            //errs() << *VMInterpreter_bb << "\n";
            //errs() << *VMInterpreterbody_bb << "\n";
        }

        for(auto & bb : originBBs)
        {
            bb->eraseFromParent();
        }

        errs() << "======================= After =======================\n" << F << "\n";

        return false;
    }
  };
}

char MyVMObfuscation::ID = 0;
static RegisterPass<MyVMObfuscation> Y("vmobfs", "Light VM Obfuscate");
