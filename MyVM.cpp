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
#include "llvm/Transforms/Utils/ValueMapper.h"
#include <unistd.h>
#include <fcntl.h>

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

    void getRandom(void *p, int len)
    {
        int fd = open("/dev/urandom", 0);
        (void)read(fd, p, len);
        close(fd);
    }

    int getRandInt32()
    {
        int i;
        getRandom(&i, sizeof(i));
        return i;
    }

    int getRandInt16()
    {
        short i;
        getRandom(&i, sizeof(i));
        return i;
    }

    /* createAlteredBasicBlock
     *
     * This function return a basic block similar to a given one.
     * It's inserted just after the given basic block.
     * The instructions are similar but junk instructions are added between
     * the cloned one. The cloned instructions' phi nodes, metadatas, uses and
     * debug locations are adjusted to fit in the cloned basic block and
     * behave nicely.
     */
    BasicBlock* createAlteredBasicBlock(BasicBlock * basicBlock, const Twine &  Name = "gen")
    {
      // Useful to remap the informations concerning instructions.
      ValueToValueMapTy VMap;
      BasicBlock * alteredBB = BasicBlock::Create(basicBlock->getContext(), "junkbb", basicBlock->getParent(), basicBlock);
      alteredBB->moveAfter(basicBlock);

      for(auto & insn: *basicBlock)
      {
          Instruction * clone_insn = insn.clone();
          alteredBB->getInstList().push_back(clone_insn);
          VMap[&insn] = clone_insn;
      }

      // Remap operands.
      BasicBlock::iterator ji = basicBlock->begin();
      for (BasicBlock::iterator i = alteredBB->begin(), e = alteredBB->end() ; i != e; ++i){
        // Loop over the operands of the instruction
        for(User::op_iterator opi = i->op_begin (), ope = i->op_end(); opi != ope; ++opi){
          // get the value for the operand
          Value *v = MapValue(*opi, VMap,  RF_None, 0);
          if (v != 0){
            *opi = v;
          }
        }
        // Remap phi nodes' incoming blocks.
        if (PHINode *pn = dyn_cast<PHINode>(i)) {
          for (unsigned j = 0, e = pn->getNumIncomingValues(); j != e; ++j) {
            Value *v = MapValue(pn->getIncomingBlock(j), VMap, RF_None, 0);
            if (v != 0){
              pn->setIncomingBlock(j, cast<BasicBlock>(v));
            }
          }
        }
        // Remap attached metadata.
        SmallVector<std::pair<unsigned, MDNode *>, 4> MDs;
        i->getAllMetadata(MDs);
        // important for compiling with DWARF, using option -g.
        i->setDebugLoc(ji->getDebugLoc());
        ji++;
      } // The instructions' informations are now all correct

      // add random instruction in the middle of the bloc. This part can be improve
      for (BasicBlock::iterator i = alteredBB->begin(), e = alteredBB->end() ; i != e; ++i){
        // in the case we find binary operator, we modify slightly this part by randomly
        // insert some instructions
        if(i->isBinaryOp()){ // binary instructions
          unsigned opcode = i->getOpcode();
          BinaryOperator *op, *op1 = NULL;
          Twine *var = new Twine("_");
          // treat differently float or int
          // Binary int
          if(opcode == Instruction::Add || opcode == Instruction::Sub ||
              opcode == Instruction::Mul || opcode == Instruction::UDiv ||
              opcode == Instruction::SDiv || opcode == Instruction::URem ||
              opcode == Instruction::SRem || opcode == Instruction::Shl ||
              opcode == Instruction::LShr || opcode == Instruction::AShr ||
              opcode == Instruction::And || opcode == Instruction::Or ||
              opcode == Instruction::Xor){
            for(int random = getRandInt32() % 10; random < 10; ++random){
              switch(getRandInt32() % 4){ // to improve
                case 0: //do nothing
                  break;
                case 1: op = BinaryOperator::CreateNeg(i->getOperand(0),*var,&*i);
                        op1 = BinaryOperator::Create(Instruction::Add,op,
                            i->getOperand(1),"gen",&*i);
                        break;
                case 2: op1 = BinaryOperator::Create(Instruction::Sub,
                            i->getOperand(0),
                            i->getOperand(1),*var,&*i);
                        op = BinaryOperator::Create(Instruction::Mul,op1,
                            i->getOperand(1),"gen",&*i);
                        break;
                case 3: op = BinaryOperator::Create(Instruction::Shl,
                            i->getOperand(0),
                            i->getOperand(1),*var,&*i);
                        break;
              }
            }
          }
          // Binary float
          if(opcode == Instruction::FAdd || opcode == Instruction::FSub ||
              opcode == Instruction::FMul || opcode == Instruction::FDiv ||
              opcode == Instruction::FRem){
            for(int random = getRandInt32() % 10; random < 10; ++random){
              switch(getRandInt32() % 3){ // can be improved
                case 0: //do nothing
                  break;
                case 1: op = BinaryOperator::CreateFDiv(i->getOperand(0),
                            i->getOperand(1),*var,&*i);
                        op1 = BinaryOperator::Create(Instruction::FAdd,op,
                            i->getOperand(1),"gen",&*i);
                        break;
                case 2: op = BinaryOperator::Create(Instruction::FSub,
                            i->getOperand(0),
                            i->getOperand(1),*var,&*i);
                        op1 = BinaryOperator::Create(Instruction::FMul,op,
                            i->getOperand(1),"gen",&*i);
                        break;
              }
            }
          }
          if(opcode == Instruction::ICmp){ // Condition (with int)
            ICmpInst *currentI = (ICmpInst*)(&i);
            switch(getRandInt32() % 3){ // must be improved
              case 0: //do nothing
                break;
              case 1: currentI->swapOperands();
                      break;
              case 2: // randomly change the predicate
                      switch(getRandInt32() % 10){
                        case 0: currentI->setPredicate(ICmpInst::ICMP_EQ);
                                break; // equal
                        case 1: currentI->setPredicate(ICmpInst::ICMP_NE);
                                break; // not equal
                        case 2: currentI->setPredicate(ICmpInst::ICMP_UGT);
                                break; // unsigned greater than
                        case 3: currentI->setPredicate(ICmpInst::ICMP_UGE);
                                break; // unsigned greater or equal
                        case 4: currentI->setPredicate(ICmpInst::ICMP_ULT);
                                break; // unsigned less than
                        case 5: currentI->setPredicate(ICmpInst::ICMP_ULE);
                                break; // unsigned less or equal
                        case 6: currentI->setPredicate(ICmpInst::ICMP_SGT);
                                break; // signed greater than
                        case 7: currentI->setPredicate(ICmpInst::ICMP_SGE);
                                break; // signed greater or equal
                        case 8: currentI->setPredicate(ICmpInst::ICMP_SLT);
                                break; // signed less than
                        case 9: currentI->setPredicate(ICmpInst::ICMP_SLE);
                                break; // signed less or equal
                      }
                      break;
            }

          }
          if(opcode == Instruction::FCmp){ // Conditions (with float)
            FCmpInst *currentI = (FCmpInst*)(&i);
            switch(getRandInt32() % 3){ // must be improved
              case 0: //do nothing
                break;
              case 1: currentI->swapOperands();
                      break;
              case 2: // randomly change the predicate
                      switch(getRandInt32() % 10){
                        case 0: currentI->setPredicate(FCmpInst::FCMP_OEQ);
                                break; // ordered and equal
                        case 1: currentI->setPredicate(FCmpInst::FCMP_ONE);
                                break; // ordered and operands are unequal
                        case 2: currentI->setPredicate(FCmpInst::FCMP_UGT);
                                break; // unordered or greater than
                        case 3: currentI->setPredicate(FCmpInst::FCMP_UGE);
                                break; // unordered, or greater than, or equal
                        case 4: currentI->setPredicate(FCmpInst::FCMP_ULT);
                                break; // unordered or less than
                        case 5: currentI->setPredicate(FCmpInst::FCMP_ULE);
                                break; // unordered, or less than, or equal
                        case 6: currentI->setPredicate(FCmpInst::FCMP_OGT);
                                break; // ordered and greater than
                        case 7: currentI->setPredicate(FCmpInst::FCMP_OGE);
                                break; // ordered and greater than or equal
                        case 8: currentI->setPredicate(FCmpInst::FCMP_OLT);
                                break; // ordered and less than
                        case 9: currentI->setPredicate(FCmpInst::FCMP_OLE);
                                break; // ordered or less than, or equal
                      }
                      break;
            }
          }
        }
      }
      return alteredBB;
    } 

    //一元二次方程 ax^2 + bx + c = 0有解的前提是b^2 - 4ac > 0
    //生成不满足该条件的a,b,c
    void get_a_b_c(int & a, int & b, int & c)
    {
        b = getRandInt16();
        long bb = b*b;
        long ac4;
        do
        {
            a = getRandInt16();
            c = getRandInt16();
            ac4 = 4*a*c;
        } while (bb >= ac4);
    }

    //构建不透明谓词
    //7y^2 - x^2 != 1
    //dst原本是src的后继
    bool insert_opaque_predicate(BasicBlock * src, BasicBlock * dst)
    {
        if(src == nullptr || dst == nullptr || dst->empty())
            return false;
        
        auto * terminator = src->getTerminator();
        if(isa<BranchInst>(terminator))
        {
            BranchInst * inst = cast<BranchInst>(terminator);
            if(inst->isConditional())
            {
                return false;
            }
        }

        LLVMContext & context = src->getContext();
        IRBuilder<> builder(context);

        //清除结尾br
        terminator->eraseFromParent();
        //创建junk bb
        BasicBlock * junk_bb = this->createAlteredBasicBlock(dst);
        
        //构造不透明谓词
        builder.SetInsertPoint(src, src->end());
        int a,b,c;
        get_a_b_c(a, b, c);
        Value * con_a = ConstantInt::get(Type::getInt32Ty(context), a);
        Value * con_b = ConstantInt::get(Type::getInt32Ty(context), b);
        Value * con_c = ConstantInt::get(Type::getInt32Ty(context), c);
        Value * con_0 = ConstantInt::get(Type::getInt32Ty(context), 0);
        //a*x^2+b*x+c==0
        Value * x = builder.CreateAlloca(Type::getInt32Ty(context), nullptr, "x");
        builder.CreateLifetimeStart(x);
        Value * x_load = builder.CreateLoad(x, "x_load");
        Value * xx = builder.CreateMul(x_load, x_load);
        Value * axx = builder.CreateMul(xx, con_a);
        Value * bx = builder.CreateMul(x_load, con_b);
        Value * add1 = builder.CreateAdd(axx, bx);
        Value * add2 = builder.CreateAdd(add1, con_c);
        
        Value * cmp = builder.CreateCmp(CmpInst::Predicate::ICMP_NE, add2, con_0);
        builder.CreateLifetimeEnd(x);
        builder.CreateCondBr(cmp, dst, junk_bb);
        return true;        
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
                    fn_new_entry_bb->getInstList().splice(fn_new_entry_bb->end(), originBB.getInstList(), first_insn);
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

            //alloca集中放在入口
            builder.SetInsertPoint(fn_new_entry_bb, fn_new_entry_bb->end());
            Value * opcodesPtr = builder.CreateAlloca(Type::getInt32PtrTy(context), nullptr, "opcodesPtr");
            Value * i_alloc = builder.CreateAlloca(Type::getInt32Ty(context), nullptr, "i_alloc");
            
            //entry
            builder.SetInsertPoint(entry_bb, entry_bb->end());
            Value * opcodesGVCast = builder.CreateBitCast(opcodes, Type::getInt32PtrTy(context), "opcodesGVCast");
            builder.CreateStore(opcodesGVCast, opcodesPtr);
            builder.CreateBr(VMInterpreter_bb);
            //替换originBB前驱后继为entry_bb
            originBB.replaceAllUsesWith(entry_bb);
            
            //VMInterpreter
            builder.SetInsertPoint(VMInterpreter_bb);
            //创建变量i并创始化为0
            Value * con0 = ConstantInt::get(Type::getInt32Ty(context), 0);
            builder.CreateStore(con0, i_alloc);
            builder.CreateBr(VMInterpreterbody_bb);

            //VMInterperterBody
            builder.SetInsertPoint(VMInterpreterbody_bb);
            Value * loaded_i = builder.CreateLoad(i_alloc, "load_i");
            Value * con1 = ConstantInt::get(Type::getInt32Ty(context), 1);
            Value * increased_i = builder.CreateAdd(loaded_i, con1, "increased_i");
            builder.CreateStore(increased_i, i_alloc);
            Value * loadedOpcodePtr = builder.CreateLoad(opcodesPtr, "loadedOpcodePtr");
            Value * opcodesIdx = builder.CreateGEP(Type::getInt32Ty(context), loadedOpcodePtr, loaded_i, "opcodesIdx");
            Value * loadedOpcode = builder.CreateLoad(opcodesIdx, "loadedOpcode");
            //创建switch语句
            SwitchInst * switch_inst = builder.CreateSwitch(loadedOpcode, VMInterpreterbody_bb, split_bb_num);
            for(size_t i = 0; i < split_bb_num; ++i)
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

        std::vector<BasicBlock *> all_bbs;
        for(BasicBlock & bb : F)
        {
            all_bbs.push_back(&bb);
        }

        for(auto * bb : all_bbs)
        {
            if(rand() % 2 == 0)
            {
                if(bb->getTerminator()->getNumSuccessors() == 1)
                {
                    insert_opaque_predicate(bb, bb->getSingleSuccessor());
                }
            }
        }

        errs() << F.getName() << " =================== After =======================\n" << F << "\n";

        return false;
    }
  };
}

char MyVMObfuscation::ID = 0;
static RegisterPass<MyVMObfuscation> Y("vmobfs", "Light VM Obfuscate");
