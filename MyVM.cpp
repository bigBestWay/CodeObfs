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

    bool isPHINodeBranchInst(Instruction & insn)
    {
        if(isa<BranchInst>(insn))
        {
            BranchInst * bran_inst = cast<BranchInst>(&insn);
            for(auto * succ : bran_inst->successors())
            {
                auto first_insn = succ->begin();
                if(isa<PHINode>(*first_insn))
                    return true;
            }
        }
        return false;
    }
    
    bool runOnFunction(Function &F) override
    {
        errs() << F.getName() << " =================== start =======================\n";
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

        //在函数的entrybb前插入一个bb用来存放临时变量
        BasicBlock * fn_new_entry_bb = BasicBlock::Create(F.getContext(), "fn_entry", &F, &F.getEntryBlock());
        
        std::vector<BasicBlock *> toearse_bbs;
        int count = 0;
        for(BasicBlock &originBB : F) 
        {
            std::string name = "OriginBB" + std::to_string(count++);
            originBB.setName(name);
            errs() << originBB << "\n";
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
            if(originBB.empty() || originBB.isEHPad())
                continue;

            LLVMContext & context = originBB.getContext();
            IRBuilder<> builder(context);

            //VMInterpreterBody
            BasicBlock * VMInterpreterbody_bb = BasicBlock::Create(context, "VMInterpreterBody", &F, &originBB);
            //VMInterpreter
            BasicBlock * VMInterpreter_bb = BasicBlock::Create(context, "VMInterpreter", &F, VMInterpreterbody_bb);
            //先创建初始化向量表的block
            BasicBlock * entry_bb = BasicBlock::Create(context, "entry", &F, VMInterpreter_bb);
                        
            std::vector<BasicBlock *> handlerbb_list;
            srand(time(0));
            //PC向量表
            std::vector<ConstantInt*> switch_elems;
            std::vector<Constant*> const_array_elems;
            //为解决变量生命周期问题，为每一条指令都申请一个变量
            std::vector<Value *> var_declare;
            size_t split_bb_num = 0;

            while(!originBB.empty())
            {
                BasicBlock::iterator first_insn = originBB.begin();
                unsigned int insn_opcode = first_insn->getOpcode();
                if(insn_opcode == Instruction::Alloca) //变量声明不混淆，放在entry
                {
                    entry_bb->getInstList().splice(entry_bb->end(), originBB.getInstList(), first_insn);
                    continue;
                }

                //对于跳转到PHINODE的指令，不切割成一个单独的bb，放到前一个指令的bb
                if(isPHINodeBranchInst(*first_insn))
                {
                    BasicBlock * bb = *handlerbb_list.rbegin();
                    //移除上一次添加的br
                    bb->getTerminator()->eraseFromParent();
                    bb->getInstList().splice(bb->end(), originBB.getInstList(), first_insn);
                    bb->replaceSuccessorsPhiUsesWith(&originBB, bb);
                }
                else
                {
                    ++ split_bb_num;
                    BasicBlock * new_bb = BasicBlock::Create(context, "VMInterpreterHandler", &F, &originBB);
                    new_bb->getInstList().splice(new_bb->end(), originBB.getInstList(), first_insn);
                    
                    if(!new_bb->begin()->isTerminator())
                    {
                        builder.SetInsertPoint(new_bb, new_bb->end());
                        builder.CreateBr(VMInterpreterbody_bb);
                    }
                    //else
                    //{
                    //    new_bb->replaceSuccessorsPhiUsesWith(&originBB, new_bb);
                    //}
                    int code = rand();
                    switch_elems.push_back(ConstantInt::get(Type::getInt32Ty(context), code));
                    const_array_elems.push_back(ConstantInt::get(Type::getInt32Ty(context), code));
                    handlerbb_list.push_back(new_bb);
                }
            }

            for(size_t i = 0; i < handlerbb_list.size(); ++i)
            {
                BasicBlock * bb = handlerbb_list[i];
                for(Instruction & insn : *bb)
                {
                    llvm::Value * returnval = llvm::cast<llvm::Value>(&insn);
                    //指令返回值下面有引用
                    if(returnval->hasNUsesOrMore(1))
                    {
                        std::vector<BasicBlock *> returnval_users;
                        for(auto user : returnval->users())
                        {
                            //找到引用此变量的指令
                            Instruction * insn = llvm::cast<Instruction>(user);
                            //如果该指令不是PHINODE
                            if(!isa<PHINode>(*insn))
                            {
                                BasicBlock * that_bb = insn->getParent();
                                //找出不在当前bb的引用
                                if(that_bb != bb)
                                {
                                    returnval_users.push_back(that_bb);
                                }
                            }
                        }

                        if(!returnval_users.empty())
                        {
                            //在entry新声明一个变量
                            builder.SetInsertPoint(fn_new_entry_bb, fn_new_entry_bb->end());
                            Value * tmpPtr = builder.CreateAlloca(returnval->getType(), nullptr, "replace");
                            //在new_bb中对此变量赋值, 并将该指令返回值的所有使用处替换为该变量
                            BasicBlock::iterator p = bb->end();
                            --p;
                            builder.SetInsertPoint(bb, p);
                            builder.CreateStore(returnval, tmpPtr);

                            for(BasicBlock * ele_bb : returnval_users)
                            {
                                builder.SetInsertPoint(ele_bb, ele_bb->begin());
                                Value * replace = builder.CreateLoad(tmpPtr);

                                //获取ele_bb的位置
                                int ele_bb_id = -1;
                                for(size_t j = 0; j < handlerbb_list.size(); ++j)
                                {
                                    if(handlerbb_list[j] == ele_bb)
                                    {
                                        ele_bb_id = j;
                                        break;
                                    }
                                }

                                returnval->replaceUsesWithIf(replace, [handlerbb_list, ele_bb_id](Use &U) {
                                    auto *I = dyn_cast<Instruction>(U.getUser());
                                    if(I == nullptr)
                                        return true;
                                    //仅替换当前bb后面bb引用的变量，否则产生BUG!!
                                    for(size_t j = ele_bb_id; ele_bb_id > 0 && j < handlerbb_list.size(); ++j)
                                    {
                                        if(handlerbb_list[j] == I->getParent())
                                        {
                                            return true;
                                        }
                                    }
                                    return false;
                                });
                            }
                        }
                    }

                    //每次循环都把所有的block打印一遍
                    /*
                    errs() << "=======================================\n";
                    for(size_t j = 0; j < handlerbb_list.size(); ++j)
                    {
                        errs() << * handlerbb_list[j] << "\n";
                    }
                    errs() << "+++++++++++++++++++++++++++++++++++++++\n";
                    */
                }
            }

            toearse_bbs.push_back(&originBB);

            ArrayType * array_type = ArrayType::get(Type::getInt32Ty(context), split_bb_num);
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
            //替换originBB前驱后继为entry_bb
            originBB.replaceAllUsesWith(entry_bb);
            
            //VMInterpreter
            builder.SetInsertPoint(VMInterpreter_bb);
            //创建变量i并创始化为0
            Value * i_alloc = builder.CreateAlloca(Type::getInt32Ty(context), nullptr, "i_alloc");
            Value * con0 = ConstantInt::get(Type::getInt32Ty(context), 0);
            builder.CreateStore(con0, i_alloc);
            Value * loadedOpcodePtr = builder.CreateLoad(opcodesPtr, "loadedOpcodePtr");
            builder.CreateBr(VMInterpreterbody_bb);

            //VMInterperterBody
            builder.SetInsertPoint(VMInterpreterbody_bb);
            Value * loaded_i = builder.CreateLoad(i_alloc, "load_i");
            Value * con1 = ConstantInt::get(Type::getInt32Ty(context), 1);
            Value * increased_i = builder.CreateAdd(loaded_i, con1, "increased_i");
            builder.CreateStore(increased_i, i_alloc);
            Value * opcodesIdx = builder.CreateGEP(Type::getInt32Ty(context), loadedOpcodePtr, loaded_i, "opcodesIdx");
            Value * loadedOpcode = builder.CreateLoad(opcodesIdx, "loadedOpcode");
            //创建switch语句
            SwitchInst * switch_inst = builder.CreateSwitch(loadedOpcode, VMInterpreterbody_bb, split_bb_num);
            for(int i = 0; i < split_bb_num; ++i)
            {
                switch_inst->addCase(switch_elems[i], handlerbb_list[i]);
            }

            //errs() << *entry_bb << "\n";
            //errs() << *VMInterpreter_bb << "\n";
            //errs() << *VMInterpreterbody_bb << "\n";
        }

        for(auto & bb : toearse_bbs)
        {
            bb->eraseFromParent();
        }

        //将新entry串进去
        {
            IRBuilder<> builder(F.getContext());
            builder.SetInsertPoint(fn_new_entry_bb, fn_new_entry_bb->end());
            builder.CreateBr(fn_new_entry_bb->getNextNode());
        }

        errs() << F.getName() << " =================== After =======================\n" << F << "\n";

        return false;
    }
  };
}

char MyVMObfuscation::ID = 0;
static RegisterPass<MyVMObfuscation> Y("vmobfs", "Light VM Obfuscate");
