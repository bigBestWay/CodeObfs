//g++ obf_re.cpp -o obf_re -lLIEF -lcapstone -lkeystone -lunicorn -lpthread
#include <keystone/keystone.h>
#include <capstone/platform.h>
#include <capstone/capstone.h>
#include <unicorn/unicorn.h>
#include <LIEF/ELF.hpp>
#include <string>
#include <vector>
#include <map>

using namespace LIEF::ELF;

struct PatchUnit
{
    uint64_t address;
    std::vector<uint8_t> newcode;
};

static std::unique_ptr<Binary> _binary;
static csh _handle;
static ks_engine * _ks;
static uc_engine * _uc = nullptr;

static std::vector<PatchUnit> _patch_list;

size_t disasm(const std::vector<uint8_t> & code, uint64_t address, cs_insn **insn)
{
	return cs_disasm(_handle, code.data(), code.size(), address, 0, insn);
}

void assemble(const std::string & assembly, uint64_t address, std::vector<uint8_t> & code)
{
	unsigned char * encode = nullptr;
	size_t count = 0;
	size_t size = 0;

	if (ks_asm(_ks, assembly.c_str(), address, &encode, &size, &count))
	{
		printf("%s ", assembly.c_str());
		printf("ERROR: failed on ks_asm() with count = %lu, error code = %u\n", count, ks_errno(_ks));
	}
	else 
	{
		code.insert(code.end(), encode, encode + size);
		ks_free(encode);
	}
}

void disasmShow(const cs_insn & insn, bool showdetail = true)
{
	printf("0x%" PRIx64 ": ", insn.address);	
	printf("\t%s\t%s\n", insn.mnemonic, insn.op_str);
    printf("\tINSNID=%d\n", insn.id);
	if (showdetail)
	{
		cs_x86 * x86 = &(insn.detail->x86);
		if (x86->op_count)
			printf("\top_count: %u\n", x86->op_count);

		// Print out all operands
		for (int j = 0; j < x86->op_count; j++) {
			cs_x86_op *op = &(x86->operands[j]);

			switch ((int)op->type) {
			case X86_OP_REG:
				printf("\t\toperands[%u].type: REG = %s\n", j, cs_reg_name(_handle, op->reg));
				break;
			case X86_OP_IMM:
				printf("\t\toperands[%u].type: IMM = 0x%" PRIx64 "\n", j, op->imm);
				break;
			case X86_OP_MEM:
				printf("\t\toperands[%u].type: MEM\n", j);
				if (op->mem.segment != X86_REG_INVALID)
					printf("\t\t\toperands[%u].mem.segment: REG = %s\n", j, cs_reg_name(_handle, op->mem.segment));
				if (op->mem.base != X86_REG_INVALID)
					printf("\t\t\toperands[%u].mem.base: REG = %s\n", j, cs_reg_name(_handle, op->mem.base));
				if (op->mem.index != X86_REG_INVALID)
					printf("\t\t\toperands[%u].mem.index: REG = %s\n", j, cs_reg_name(_handle, op->mem.index));
				if (op->mem.scale != 1)
					printf("\t\t\toperands[%u].mem.scale: %u\n", j, op->mem.scale);
				if (op->mem.disp != 0)
					printf("\t\t\toperands[%u].mem.disp: 0x%" PRIx64 "\n", j, op->mem.disp);
				break;
			default:
				break;
			}
		}
	}
}

//阶段一，消减分支
void iter1()
{
    const Section & text = _binary->text_section();
    const std::vector<uint8_t> & code = _binary->get_content_from_virtual_address(text.virtual_address(), text.size());

    //反编译
    //匹配如下模式：
    /*
    imul    ecx, ecx
    imul    ecx, 3E8Ch
    imul    eax, 0FFFFFC55h
    add     ecx, eax
    add     ecx, 3632h
    cmp     ecx, 0
    jnz     short loc_405F25
    */
    enum STATE
    {
        STATE0,
        STATE1,
        STATE2,
        STATE3,
        STATE4,
        STATE5,
        STATE6,
        UNKOWN = 0xff
    };
    
    cs_insn *insns = nullptr;
    size_t count = disasm(code, text.virtual_address(), &insns);
    STATE state = UNKOWN;
    for(size_t i = 0; i < count; ++i)
    {
        const cs_insn & insn = insns[i];

        //jmp $+2
        if(insn.size == 2 && insn.bytes[0] == 0xeb && insn.bytes[1] == 0)
        {
            PatchUnit unit;
            unit.address = insn.address;
            unit.newcode.resize(2, 0x90);
            _patch_list.push_back(unit);
            continue;
        }

        switch (state)
        {
        case UNKOWN:
            {
                if(insn.size == 3 && insn.bytes[0] == 0xf && insn.bytes[1] == 0xaf && insn.bytes[2] == 0xc9)//imul ecx,ecx = [ 0f af c9 ]
                {
                    state = STATE0;
                }
            }
            break;
        case STATE0:
            {
                if(insn.id == X86_INS_IMUL)
                {
                    cs_x86 * x86 = &(insn.detail->x86);
		            if (x86->op_count)
                    {
                        cs_x86_op *op = &(x86->operands[0]);
                        if(op->type == X86_OP_REG && std::string("ecx") == cs_reg_name(_handle, op->reg))
                        {
                            state = STATE1;
                        }
                    }
                }
            }
            break;
        case STATE1:
            {
                if(insn.id == X86_INS_IMUL)
                {
                    cs_x86 * x86 = &(insn.detail->x86);
		            if (x86->op_count)
                    {
                        cs_x86_op *op = &(x86->operands[0]);
                        if(op->type == X86_OP_REG && std::string("eax") == cs_reg_name(_handle, op->reg))
                        {
                            state = STATE2;
                        }
                    }
                }
            }
            break;
        case STATE2:
            {
                if(insn.id == X86_INS_ADD)
                {
                    cs_x86 * x86 = &(insn.detail->x86);
		            if (x86->op_count == 2)
                    {
                        cs_x86_op *op1 = &(x86->operands[0]);
                        cs_x86_op *op2 = &(x86->operands[1]);
                        if(op1->type == X86_OP_REG && std::string("ecx") == cs_reg_name(_handle, op1->reg)
                        && op2->type == X86_OP_REG && std::string("eax") == cs_reg_name(_handle, op2->reg))
                        {
                            state = STATE3;
                        }
                    }
                }
            }
            break;
        case STATE3:
            {
                if(insn.id == X86_INS_ADD)
                {
                    cs_x86 * x86 = &(insn.detail->x86);
		            if (x86->op_count == 2)
                    {
                        cs_x86_op *op1 = &(x86->operands[0]);
                        cs_x86_op *op2 = &(x86->operands[1]);
                        if(op1->type == X86_OP_REG && std::string("ecx") == cs_reg_name(_handle, op1->reg)
                        && op2->type == X86_OP_IMM)
                        {
                            state = STATE4;
                        }
                    }
                }
            }
            break;
        case STATE4:
            {
                //83 f9 00
                if(insn.size == 3 && insn.bytes[0] == 0x83 && insn.bytes[1] == 0xf9 && insn.bytes[2] == 0)
                {
                    state = STATE5;
                }
            }
            break;
        case STATE5:
            {
                //jnz xxxx
                if(insn.id == X86_INS_JNE)
                {
                    cs_x86 * x86 = &(insn.detail->x86);
                    if (x86->op_count)
                    {
                        cs_x86_op *op = &(x86->operands[0]);
                        if(op->type == X86_OP_IMM)
                        {
                            int64_t imm = op->imm;
                            PatchUnit unit;
                            unit.address = insns[i - 6].address;

                            std::string newjmp = "jmp ";
                            newjmp += std::to_string(imm);
                            
                            int total = 0;
                            for(int j = i - 6; j < i; ++j)
                            {
                                total += insns[j].size;
                            }
                            unit.newcode.resize(total, 0x90);
                            std::vector<uint8_t> tmp;
                            assemble(newjmp, insn.address, tmp);

                            while(tmp.size() < insn.size)
                            {
                                tmp.push_back(0x90);
                            }
                            unit.newcode.insert(unit.newcode.end(), tmp.begin(), tmp.end());
                            printf("push unit at %lx\n", unit.address);
                            _patch_list.push_back(unit);
                        }
                    }
                }
                else if (insn.id == X86_INS_JE)
                {
                    PatchUnit unit;
                    unit.address = insns[i - 6].address;
                    int total = 0;
                    for(int j = i - 6; j <= i; ++j)
                    {
                        total += insns[j].size;
                    }
                    unit.newcode.resize(total, 0x90);
                    _patch_list.push_back(unit);
                }
                state = UNKOWN;
            }
            break;
        default:
            state = UNKOWN;
            break;
        }
    }

    for (size_t i = 0; i < _patch_list.size(); i++)
    {
        const PatchUnit & unit = _patch_list[i];
        _binary->patch_address(unit.address, unit.newcode);
    }
}

bool is_jmp_grp_type(const cs_insn & insn)
{
	for (uint8_t i = 0; i < insn.detail->groups_count; ++i)
	{
		if (insn.detail->groups[i] == CS_GRP_JUMP)
			return true;
	}
	return false;
}

typedef std::map<uint64_t, uint64_t> Cmd2HandlerMap;

struct DispatcherData
{
    uint64_t begin;
    uint64_t end;
    Cmd2HandlerMap cmd2handler;
};
typedef std::map<uint64_t, DispatcherData> DispatcherMap;

static DispatcherMap _dispatcher_data;
static std::vector<std::string> _block_plain_texts;
static std::string _insn_str;

static uint64_t _free_address = 0;

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	//int eflags;
    static uint64_t dispatcher_range_begin =0, dispatcher_range_end = 0, dispatcher_exit_insn = 0;
    const std::vector<uint8_t> & code = _binary->get_content_from_virtual_address(address, size);
	cs_insn *insns = nullptr;
    size_t count = disasm(code, address, &insns);
    if(count > 0)
    {
        const cs_insn & insn = insns[0];
        bool is_in_dispatcher = false;
        for (auto & it : _dispatcher_data)
        {
            if(insn.address >= it.second.begin && insn.address <= it.second.end)
            {
                is_in_dispatcher = true;
                break;
            }
        }

        if(!is_in_dispatcher)
        {
            if (insn.id != X86_INS_JMP && insn.id != X86_INS_NOP)
            {
                printf("[%lx]%s\t%s\n", insn.address, insn.mnemonic, insn.op_str);
                if(is_jmp_grp_type(insn) || insn.id == X86_INS_RET)//条件跳转之类的指令，换个行，提示block结束
                {
                    if(insn.id == X86_INS_RET)
                        _insn_str += "ret";
                    if(_block_plain_texts.empty() || *_block_plain_texts.rbegin() != _insn_str)
                        _block_plain_texts.push_back(_insn_str);
                    _insn_str.clear();
                    printf("\n");
                }
                else
                {
                    //跳转语句的后半部分不加，因为要换新位置
                    _insn_str += insn.mnemonic;
                    _insn_str += " ";
                    _insn_str += insn.op_str;
                    _insn_str += ";";
                }
            }
        }

        if (insn.id == X86_INS_RET)
	        uc_emu_stop(_uc);
        
        /*
        if(dispatcher_range_begin == 0)
        {
            //dispatcher的第2条指令
            DispatcherMap::iterator it = _dispatcher_data.find(insn.address);
            if(it != _dispatcher_data.end())//到达一处dispatcher
            {
                //在mov     eax, [rcx+rax*4]指令处才能取出rcx，设置bp到该指令处
                dispatcher_range_begin = insn.address;
            }
        }

        //执行到bp，此时dispatcher_range_begin不为0
        if(dispatcher_range_begin != 0 && dispatcher_range_end == 0)
        {
            if (insn.size == 3 && insn.bytes[0] == 0x8b && insn.bytes[1] == 0x4 && insn.bytes[2] == 0x81)//到达mov     eax, [rcx+rax*4]
            {
                DispatcherMap::iterator it = _dispatcher_data.find(dispatcher_range_begin);
                if(it != _dispatcher_data.end())//到达一处dispatcher
                {
                    const DispatcherData & handler_data = it->second;
                    const Cmd2HandlerMap & cmd2handler = handler_data.cmd2handler;

                    for(auto iit : cmd2handler)
                    {
                        printf("handler %lx->%lx\n", iit.first, iit.second);
                    }
                    
                    int64_t rcx;
                    uc_reg_read(_uc, UC_X86_REG_RCX, &rcx);
                    uint32_t array[100] = {0};
                    if(uc_mem_read(_uc, rcx, array, 4*cmd2handler.size()))//读出命令码
                    {
                        printf("Failed to read %lx cmd array!\n", rcx);
                    }
                    
                    //出口命令码为最后一个
                    uint32_t last_code = array[cmd2handler.size()-1];
                    auto itt = cmd2handler.find(last_code);
                    if(itt != cmd2handler.end())
                    {
                        printf("find %lx->%lx exit handler in dispatcher %lx\n", last_code, itt->second, it->first);
                        const std::vector<uint8_t> & exit_code = _binary->get_content_from_virtual_address(itt->second, 1000);
                        cs_insn *insns_handler = nullptr;
                        size_t count1 = disasm(exit_code, itt->second, &insns_handler);
                        if(count1 > 0)
                        {
                            for (size_t i = 0; i < count1; i++)
                            {
                                //disasmShow(insns_handler[i]);
                                if(insns_handler[i].id == X86_INS_JMP)
                                {
                                    dispatcher_exit_insn = insns_handler[i].address;
                                    dispatcher_range_end = handler_data.end;
                                    printf("run in dispatcher [%lx,%lx], exit insn %lx\n", dispatcher_range_begin, dispatcher_range_end, dispatcher_exit_insn);
                                    break;
                                }
                            }
                            cs_free(insns_handler, count1);
                        }
                    }
                    else
                    {
                        printf("not find %lx handler in dispatcher %lx\n", last_code, it->first);
                    }

                    //到达bp之后还没有找到dispatcher出口，清空状态
                    if(dispatcher_range_end == 0)
                    {
                        dispatcher_range_begin = 0;
                    }
                }
            }
        }
        
        if((insn.address < dispatcher_range_begin || insn.address >= dispatcher_range_end) && dispatcher_range_begin != 0 && dispatcher_range_end != 0
            || (dispatcher_range_end == 0 && dispatcher_range_begin == 0))
        {
            if (insn.id != X86_INS_JMP && insn.id != X86_INS_NOP)
                printf("[%lx]%s\t%s\n", insn.address, insn.mnemonic, insn.op_str);
        }

        if(insn.address == dispatcher_exit_insn)
        {
            printf("dispatcher %lx exit\n", dispatcher_range_begin);
            dispatcher_range_begin = 0;
            dispatcher_exit_insn = 0;
            dispatcher_range_end = 0;
        }*/

        cs_free(insns, count);
    }
}

#define ADDRESS 0x400000
#define STACK_ADDR 0x8000000
#define STACK_SIZE 16* 1024 * 1024 /* 16M */

void simulate_sub_405EA0(uint64_t address, int size)
{
    //unicorn init
    uc_err err2;
	if (ELF_CLASS::ELFCLASS32 == _binary->type())
	{
		err2 = uc_open(UC_ARCH_X86, UC_MODE_32, &_uc);
	}
	else
	{
		err2 = uc_open(UC_ARCH_X86, UC_MODE_64, &_uc);
	}

    if (err2) {
		printf("Failed on uc_open() with error returned: %u\n", err2);
		return;
	}

    //模拟执行
    // map 200MB memory for this emulation
    uc_mem_map(_uc, ADDRESS, 200 * 1024 * 1024, UC_PROT_ALL);
    uc_mem_map(_uc, STACK_ADDR, STACK_SIZE, UC_PROT_ALL);

    const std::vector<uint8_t> & whole_elf = _binary->get_content_from_virtual_address(ADDRESS, _binary->original_size());;
    if (uc_mem_write(_uc, ADDRESS, whole_elf.data(), whole_elf.size())) 
    {
        printf("Failed to write emulation code to memory, quit!\n");
        return;
    }

    uc_hook trace1;
    uc_hook_add(_uc, &trace1, UC_HOOK_CODE, (void *)hook_code, NULL, address, address + size);

    uint64_t rsp_value = STACK_ADDR + STACK_SIZE / 2;
    uc_reg_write(_uc, UC_X86_REG_RSP, &rsp_value);

    //设置2个参数 char *, int
    int64_t rsi_value = 16;
    uc_reg_write(_uc, UC_X86_REG_RSI, &rsi_value);

    int64_t rdi_value = STACK_ADDR;
    uc_reg_write(_uc, UC_X86_REG_RDI, &rdi_value);

    uc_err err = uc_emu_start(_uc, address, address + size, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",	err, uc_strerror(err));
        return;
    }

    uc_close(_uc);
    _uc = nullptr;
}

//4个BLOCK
void rewrite_405EA0()
{
    if(_block_plain_texts.size() != 4)
    {
        printf("rewrite_405EA0 block size err %d\n", _block_plain_texts.size());
        return ;
    }

    std::string & block1 = _block_plain_texts[0];
    std::string & block2 = _block_plain_texts[1];
    std::string & block3 = _block_plain_texts[2];
    std::string & block4 = _block_plain_texts[3];

    std::vector<uint8_t> block1code, block2code, block3code, block4code;
    assemble(block1, _free_address, block1code);
    _binary->patch_address(_free_address, block1code);
    _free_address += block1code.size();
    //为末尾的跳转指令预留10字节
    uint64_t block1_terminator = _free_address;
    _free_address += 10;

    uint64_t block2_start = _free_address;
    assemble(block2, block2_start, block2code);
     _binary->patch_address(block2_start, block2code);
    _free_address += block2code.size();
    //为末尾的跳转指令预留10字节
    uint64_t block2_terminator = _free_address;
    _free_address += 10;

    uint64_t block3_start = _free_address;
    assemble(block3, block3_start, block3code);
     _binary->patch_address(block3_start, block3code);
    _free_address += block3code.size();
    //为末尾的跳转指令预留10字节
    uint64_t block3_terminator = _free_address;
    _free_address += 10;

    uint64_t block4_start = _free_address;
    assemble(block4, block4_start, block4code);
     _binary->patch_address(block4_start, block4code);
    _free_address += block4code.size();

    //连接各block
    //bb1 -> bb2
    std::vector<uint8_t> tmpCode;
    std::string jmpstr = "jmp " + std::to_string(block2_start);
    assemble(jmpstr, block1_terminator, tmpCode);
    _binary->patch_address(block1_terminator, tmpCode);
    //bb2 -> bb4
    jmpstr = "jne " + std::to_string(block4_start);
    tmpCode.clear();
    assemble(jmpstr, block2_terminator, tmpCode);
    _binary->patch_address(block2_terminator, tmpCode);
    //bb3->bb3
    jmpstr = "jne " + std::to_string(block3_start);
    tmpCode.clear();
    assemble(jmpstr, block3_terminator, tmpCode);
    _binary->patch_address(block3_terminator, tmpCode);
}

//控制流还原
void iter2(const std::vector<uint64_t> & funcs)
{
    //添加一个段用于写还原后的函数
    Section new_section{ ".gnu.text" };
	new_section.add(ELF_SECTION_FLAGS::SHF_EXECINSTR);
	new_section.add(ELF_SECTION_FLAGS::SHF_ALLOC);
	std::vector<uint8_t> data(0x4000, 0x90);
	new_section.content(data);
	new_section = _binary->add(new_section);
    _free_address = new_section.virtual_address();
    //end

    std::map<uint64_t, uint64_t> func2Size;

    enum STATE_ITER2
    {
        STATE0,
        STATE1,
        STATE2,
        STATE3,
        STATE4,
        STATE5,
        STATE6,
        UNKOWN = 0xff
    };

    for (const LIEF::Function & func : _binary->functions())
	{
        if(std::find(funcs.begin(), funcs.end(), func.address()) == funcs.end())
            continue;

        func2Size[func.address()] = func.size();

        printf("Function range %lx to %lx\n", func.address(), func.address() + func.size());
        const std::vector<uint8_t> & code = _binary->get_content_from_virtual_address(func.address(), func.size());
        /*匹配如下模式
        movsxd  rax, [rbp+var_18]
        mov     ecx, eax
        add     ecx, 1
        mov     [rbp+var_18], ecx
        mov     rcx, [rbp+var_78]
        mov     eax, [rcx+rax*4]
        mov     ecx, eax
        */
        cs_insn *insns = nullptr;
        size_t count = disasm(code, func.address(), &insns);
        STATE_ITER2 state = UNKOWN;

        DispatcherData handler_data;
        //disasmShow(insns[count-1]);
        for(size_t i = 0; i < count; ++i)
        {
            const cs_insn & insn = insns[i];
            switch (state)
            {
            case UNKOWN:
                {
                    if(insn.id == X86_INS_MOVSXD)
                    {
                        cs_x86 * x86 = &(insn.detail->x86);
                        if (x86->op_count == 2)
                        {
                            cs_x86_op *op1 = &(x86->operands[0]);
                            cs_x86_op *op2 = &(x86->operands[1]);
                            if(op1->type == X86_OP_REG && std::string("rax") == cs_reg_name(_handle, op1->reg)
                            && op2->type == X86_OP_MEM)
                            {
                                state = STATE0;
                                //printf("iter2 state0 at %lx\n", insn.address);
                            }
                        }
                    }
                }
                break;
            case STATE0:
                {
                    if(insn.size == 2 && insn.bytes[0] == 0x89 && insn.bytes[1] == 0xc1)
                    {
                        state = STATE1;
                        //printf("iter2 state1 at %lx", insn.address);
                    }
                }
                break;
            case STATE1:
                {
                    if(insn.size == 3 && insn.bytes[0] == 0x83 && insn.bytes[1] == 0xc1 && insn.bytes[2] == 0x1)
                    {
                        state = STATE2;
                        //printf("iter2 state2 at %lx", insn.address);
                    }
                }
                break;
            case STATE2:
                {
                    if(insn.id == X86_INS_MOV)
                    {
                        cs_x86 * x86 = &(insn.detail->x86);
                        if (x86->op_count == 2)
                        {
                            cs_x86_op *op1 = &(x86->operands[0]);
                            cs_x86_op *op2 = &(x86->operands[1]);
                            if(op2->type == X86_OP_REG && std::string("ecx") == cs_reg_name(_handle, op2->reg)
                            && op1->type == X86_OP_MEM)
                            {
                                state = STATE3;
                                //printf("iter2 state3 at %lx", insn.address);
                            }
                        }
                    }
                }
                break;
            case STATE3: //mov     rcx, [rbp+var_78]
                {
                    if(insn.id == X86_INS_MOV)
                    {
                        cs_x86 * x86 = &(insn.detail->x86);
                        if (x86->op_count == 2)
                        {
                            cs_x86_op *op1 = &(x86->operands[0]);
                            cs_x86_op *op2 = &(x86->operands[1]);
                            if(op1->type == X86_OP_REG && std::string("rcx") == cs_reg_name(_handle, op1->reg)
                            && op2->type == X86_OP_MEM)
                            {
                                state = STATE4;
                                //printf("iter2 state4 at %lx", insn.address);
                            }
                        }
                    }
                }
                break;
            case STATE4://mov     eax, [rcx+rax*4] 8B 04 81
                {
                    if (insn.size == 3 && insn.bytes[0] == 0x8b && insn.bytes[1] == 0x4 && insn.bytes[2] == 0x81)
                    {
                        state = STATE5;
                        //printf("iter2 state5 at %lx", insn.address);
                    }
                }
                break;
            case STATE5:
                {
                    if(insn.size == 2 && insn.bytes[0] == 0x89 && insn.bytes[1] == 0xc1)
                    {
                        state = STATE6;
                        //printf("iter2 state6 at %lx\n", insn.address);
                        handler_data.begin = insns[i - 6].address;
                        handler_data.cmd2handler.clear();
                    }
                }
                break;
            case STATE6:
                {
                    //收集handler
                    if(insn.id == X86_INS_SUB)
                    {
                        cs_x86 * x86 = &(insn.detail->x86);
                        if (x86->op_count == 2)
                        {
                            cs_x86_op *op1 = &(x86->operands[0]);
                            cs_x86_op *op2 = &(x86->operands[1]);
                            if(op1->type == X86_OP_REG && op2->type == X86_OP_IMM)
                            {
                                if(insns[i + 1].id == X86_INS_JE)
                                {
                                    cs_x86 * x86_next = &(insns[i + 1].detail->x86);
                                    if (x86_next->op_count)
                                    {
                                        cs_x86_op *op_next = &(x86_next->operands[0]);
                                        if(op_next->type == X86_OP_IMM)
                                        {
                                            i += 1;
                                            handler_data.cmd2handler[op2->imm] = op_next->imm;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    else if(insn.id == X86_INS_JMP)
                    {                       
                        cs_x86 * x86 = &(insn.detail->x86);
                        if (x86->op_count)
                        {
                            cs_x86_op *op = &(x86->operands[0]);
                            if(op->type == X86_OP_IMM)
                            {
                                //printf("at %lx JMP %lx\n", insn.address, op->imm);
                                if(op->imm <= handler_data.begin)
                                {
                                     const std::vector<uint8_t> & code1 = _binary->get_content_from_virtual_address(op->imm, handler_data.begin - op->imm);
                                     bool isAllNop = true;
                                     for (size_t i = 0; i < code1.size(); i++)
                                     {
                                         if(code1[i] != 0x90)
                                         {
                                             isAllNop = false;
                                             break;
                                         }
                                     }
                                     
                                     if(isAllNop)
                                     {
                                         handler_data.end = insn.address;
                                         _dispatcher_data[handler_data.begin] = handler_data;
                                         
                                         for(auto it : handler_data.cmd2handler)
                                         {
                                             printf("[handler begin at %lx] find cmd %lx handler %lx\n", handler_data.begin, it.first, it.second);
                                         }
                                         printf("=============================================\n");
                                     }
                                }                    
                            }
                        }
                        state = UNKOWN;
                    }
                }
                break;
            default:
                state = UNKOWN;
                break;
            }
        }        
	}

    //收集dispatcher范围后，模拟执行，将除了dispatcher范围内的指令都打印出来
    simulate_sub_405EA0(0x405ea0, func2Size[0x405ea0]);
    rewrite_405EA0();
}

int main(int argc, char * argv[])
{
    if(argc != 2)
    {
        printf("%s elfpath\n", argv[0]);
        return 1;
    }

    std::string path = argv[1];
    try {
		_binary = Parser::parse(path);
	}
	catch (const LIEF::exception& e) {
		std::cerr << e.what() << std::endl;
		return 1;
	}

    //capstone初始化
    cs_err err = CS_ERR_OK;
	if (ELF_CLASS::ELFCLASS32 == _binary->type())
	{
		err = cs_open(CS_ARCH_X86, CS_MODE_32, &_handle);
	}
	else
	{
		err = cs_open(CS_ARCH_X86, CS_MODE_64, &_handle);
	}

	if (err) 
	{
		std::cerr<<"Failed on cs_open() with error returned: "<< err <<std::endl;
        return 1;
	}

	cs_option(_handle, CS_OPT_DETAIL, CS_OPT_ON);
    //keystone初始化
    ks_err err1;
	if (ELF_CLASS::ELFCLASS32 == _binary->type())
	{
		err1 = ks_open(KS_ARCH_X86, KS_MODE_32, &_ks);
	}
	else
	{
		err1 = ks_open(KS_ARCH_X86, KS_MODE_64, &_ks);
	}

	if (err1 != KS_ERR_OK) {
		std::cerr << "Failed on ks_open() with error returned: " << err1 << std::endl;
        return 1;
	}
    
    std::string outfile = path + "_patched";

    iter1();
    std::vector<uint64_t> addrs = {0x407B20, 0x405ea0};
    iter2(addrs);

    _binary->write(outfile);
    
    return 0;
}
