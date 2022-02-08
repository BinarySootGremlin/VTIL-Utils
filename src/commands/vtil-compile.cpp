// Copyright © 2021 Keegan Saunders
//
// Permission to use, copy, modify, and/or distribute this software for
// any purpose with or without fee is hereby granted.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
// AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
// OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//

#include <asmjit/x86.h>
#include <asmjit/x86/x86operand.h>
#include <set>
#include <vector>
#include <unordered_map>
#include <vtil/arch>
#include <vtil/vtil>
#include <vtil-utils.hpp>

using namespace asmjit;
namespace ins
{
using namespace vtil::ins;
};

static void compile(vtil::basic_block* basic_block, struct routine_state* state);

struct routine_state
{
	std::unordered_map<vtil::vip_t, Label> label_map;
	std::set<vtil::vip_t> is_compiled;
	std::unordered_map<vtil::operand::register_t, x86::Gp> reg_map;
	//x86::Gp flags_reg;
	x86::Compiler& cc;
	Imm base_address;

	routine_state(x86::Compiler& cc, uint64_t base)
		: cc(cc)
		, base_address(base)
	{
		//stack = cc.newStack(8, 8, "temp_stack");
	}

	Label get_label(vtil::vip_t address)
	{
		if (label_map.count(address))
		{
			return label_map.at(address);
		}
		else
		{
			// TODO: Create a namedLabel
			//
			Label label = cc.newLabel();
			label_map.insert({ address, label });
			return label;
		}
	}

	x86::Gp reg_for_size(vtil::operand const& operand)
	{
		switch (operand.bit_count())
		{
		// TODO: Handle sized register access
		//
		case 1:
		case 8:
			//return cc.newGpb();
		case 16:
			//return cc.newGpw();
		case 32:
			//return cc.newGpd();
		case 64:
			return cc.newGpq();
		default:
			unreachable();
		}
	}

	x86::Gp tmp_imm(vtil::operand const& reg)
	{
		x86::Gp tmp = reg_for_size(reg);
		cc.mov(tmp, reg.imm().ival);
		return tmp;
	}

	x86::Gp get_reg(vtil::operand::register_t const& operand)
	{
		using vtil::logger::log;

		// TODO: Handle bit selectors on registers

		log("get_reg: %s\n", operand.to_string());
		if (operand.is_physical())
		{
			log("\tis_physical\n");
			// Transform the VTIL register into an AsmJit one.
			//
			// TODO: This shouldnt be a separate condition, but just
			// in the same switch
			//
			if (operand.is_stack_pointer())
			{
				log("\t\tis_stack_pointer\n");
				// TODO: this might cause problems, the stack
				// of the program and of VTIL are shared
				//
				return x86::rsp;
			}
			else if (operand.is_flags())
			{
				log("\t\tis_flags\n");/*, flags_reg.isValid());
				if (!flags_reg.isValid())
				{
					flags_reg = cc.newGpq();
				}

				return flags_reg;*/
								
				fassert(operand.bit_count > 8);

				// If this is hit, we need to modify VTIL or create a VTIL pre-compile pass that removes partial offset shifted access to the flags register
				//
				fassert(operand.bit_offset == 0);

				// Preserve full size ax
				//
				cc.push(x86::rax);

				switch (operand.bit_count)
				{
				case 16:					
					cc.pushf();
					cc.pop(x86::ax);
					return x86::ax;
				case 32:
					cc.pushfd();
					cc.pop(x86::eax);
					return x86::eax;
				case 64:
					cc.pushfq();
					cc.pop(x86::rax);
					return x86::rax;				
				}

				fassert(false);
				return x86::rax;
			}
			else
			{
				log("\t\tmachine_register: %s\n", vtil::amd64::name(operand.combined_id));
				switch (operand.combined_id)
				{
				case X86_REG_AL:
					return x86::al;
				case X86_REG_BL:
					return x86::bl;
				case X86_REG_CL:
					return x86::cl;
				case X86_REG_DL:
					return x86::dl;
				case X86_REG_SIL:
					return x86::sil;
				case X86_REG_DIL:
					return x86::dil;
				case X86_REG_BPL:
					return x86::bpl;
				case X86_REG_R8B:
					return x86::r8b;
				case X86_REG_R9B:
					return x86::r9b;
				case X86_REG_R10B:
					return x86::r10b;
				case X86_REG_R11B:
					return x86::r11b;
				case X86_REG_R12B:
					return x86::r12b;
				case X86_REG_R13B:
					return x86::r13b;
				case X86_REG_R14B:
					return x86::r14b;
				case X86_REG_R15B:
					return x86::r15b;
				case X86_REG_AX:
					return x86::ax;
				case X86_REG_BX:
					return x86::bx;
				case X86_REG_CX:
					return x86::cx;
				case X86_REG_DX:
					return x86::dx;
				case X86_REG_SI:
					return x86::si;
				case X86_REG_DI:
					return x86::di;
				case X86_REG_BP:
					return x86::bp;
				case X86_REG_R8W:
					return x86::r8w;
				case X86_REG_R9W:
					return x86::r9w;
				case X86_REG_R10W:
					return x86::r10w;
				case X86_REG_R11W: 
					return x86::r11w;
				case X86_REG_R12W: 
					return x86::r12w;
				case X86_REG_R13W: 
					return x86::r13w;
				case X86_REG_R14W: 
					return x86::r14w;
				case X86_REG_R15W:
					return x86::r15w;
				case X86_REG_EAX:
					return x86::eax;
				case X86_REG_EBX:
					return x86::ebx;
				case X86_REG_ECX:
					return x86::ecx;
				case X86_REG_EDX:
					return x86::edx;
				case X86_REG_ESI:
					return x86::esi;
				case X86_REG_EDI:
					return x86::edi;
				case X86_REG_EBP:
					return x86::ebp;
				case X86_REG_R8D:
					return x86::r8d;
				case X86_REG_R9D:
					return x86::r9d;
				case X86_REG_R10D:
					return x86::r10d;
				case X86_REG_R11D:
					return x86::r11d;
				case X86_REG_R12D:
					return x86::r12d;
				case X86_REG_R13D:
					return x86::r13d;
				case X86_REG_R14D:
					return x86::r14d;
				case X86_REG_R15D:
					return x86::r15d;
				case X86_REG_RAX:
					return x86::rax;
				case X86_REG_RBX:
					return x86::rbx;
				case X86_REG_RCX:
					return x86::rcx;
				case X86_REG_RDX:
					return x86::rdx;
				case X86_REG_RSI:
					return x86::rsi;
				case X86_REG_RDI:
					return x86::rdi;
				case X86_REG_RBP:
					return x86::rbp;
				case X86_REG_R8:
					return x86::r8;
				case X86_REG_R9:
					return x86::r9;
				case X86_REG_R10:
					return x86::r10;
				case X86_REG_R11:
					return x86::r11;
				case X86_REG_R12:
					return x86::r12;
				case X86_REG_R13:
					return x86::r13;
				case X86_REG_R14:
					return x86::r14;
				case X86_REG_R15:
					return x86::r15;
				default:
					abort();
				}
			}
		}
		else
		{
			log("\tis_virtual\n");

			if (operand.is_image_base())
			{
				log("\t\tis_image_base\n");
				// TODO: This obviously won't work for different
				// base addresses
				//
				x86::Gp base_reg = reg_for_size(operand);
				cc.mov(base_reg, base_address);				
				return base_reg;
			}
			else if (operand.is_flags())
			{
				log("\t\tis_flags\n");
				abort();
			}
			// Grab the register from the map, or create and insert otherwise.
			//
			else if (reg_map.count(operand))
			{
				return reg_map[operand];
			}
			else
			{
				x86::Gp reg = reg_for_size(operand);
				reg_map[operand] = reg;
				return reg;
			}
		}
	}

	x86::Gp get_register_from_id(uint64_t combined_id)
	{
		switch (combined_id)
		{
		case X86_REG_AL:
			return x86::al;
		case X86_REG_BL:
			return x86::bl;
		case X86_REG_CL:
			return x86::cl;
		case X86_REG_DL:
			return x86::dl;
		case X86_REG_SIL:
			return x86::sil;
		case X86_REG_DIL:
			return x86::dil;
		case X86_REG_BPL:
			return x86::bpl;
		case X86_REG_R8B:
			return x86::r8b;
		case X86_REG_R9B:
			return x86::r9b;
		case X86_REG_R10B:
			return x86::r10b;
		case X86_REG_R11B:
			return x86::r11b;
		case X86_REG_R12B:
			return x86::r12b;
		case X86_REG_R13B:
			return x86::r13b;
		case X86_REG_R14B:
			return x86::r14b;
		case X86_REG_R15B:
			return x86::r15b;
		case X86_REG_AX:
			return x86::ax;
		case X86_REG_BX:
			return x86::bx;
		case X86_REG_CX:
			return x86::cx;
		case X86_REG_DX:
			return x86::dx;
		case X86_REG_SI:
			return x86::si;
		case X86_REG_DI:
			return x86::di;
		case X86_REG_BP:
			return x86::bp;
		case X86_REG_R8W:
			return x86::r8w;
		case X86_REG_R9W:
			return x86::r9w;
		case X86_REG_R10W:
			return x86::r10w;
		case X86_REG_R11W:
			return x86::r11w;
		case X86_REG_R12W:
			return x86::r12w;
		case X86_REG_R13W:
			return x86::r13w;
		case X86_REG_R14W:
			return x86::r14w;
		case X86_REG_R15W:
			return x86::r15w;
		case X86_REG_EAX:
			return x86::eax;
		case X86_REG_EBX:
			return x86::ebx;
		case X86_REG_ECX:
			return x86::ecx;
		case X86_REG_EDX:
			return x86::edx;
		case X86_REG_ESI:
			return x86::esi;
		case X86_REG_EDI:
			return x86::edi;
		case X86_REG_EBP:
			return x86::ebp;
		case X86_REG_R8D:
			return x86::r8d;
		case X86_REG_R9D:
			return x86::r9d;
		case X86_REG_R10D:
			return x86::r10d;
		case X86_REG_R11D:
			return x86::r11d;
		case X86_REG_R12D:
			return x86::r12d;
		case X86_REG_R13D:
			return x86::r13d;
		case X86_REG_R14D:
			return x86::r14d;
		case X86_REG_R15D:
			return x86::r15d;
		case X86_REG_RAX:
			return x86::rax;
		case X86_REG_RBX:
			return x86::rbx;
		case X86_REG_RCX:
			return x86::rcx;
		case X86_REG_RDX:
			return x86::rdx;
		case X86_REG_RSI:
			return x86::rsi;
		case X86_REG_RDI:
			return x86::rdi;
		case X86_REG_RBP:
			return x86::rbp;
		case X86_REG_R8:
			return x86::r8;
		case X86_REG_R9:
			return x86::r9;
		case X86_REG_R10:
			return x86::r10;
		case X86_REG_R11:
			return x86::r11;
		case X86_REG_R12:
			return x86::r12;
		case X86_REG_R13:
			return x86::r13;
		case X86_REG_R14:
			return x86::r14;
		case X86_REG_R15:
			return x86::r15;
		default:
			abort();
		}
	}

	std::vector<Operand*>preprocess_instruction(const vtil::instruction& instr)
	{
		std::vector<Operand*> output(instr.base->operand_count());

		for (size_t i = 0; i < instr.base->operand_count(); i++)
		{
			auto op = instr.operands[i];
			if (op.is_register())
			{
				auto reg = op.reg();
				if (reg.is_physical())
				{
					vtil::logger::log("\tis_physical\n");
					if (reg.is_stack_pointer())
					{
						vtil::logger::log("\t\tis_stack_pointer\n");
						output.at(i) = new Operand(x86::rsp);
						continue;
					}
					else if (reg.is_flags())
					{
						vtil::logger::log("\t\tis_flags\n");

						fassert(reg.bit_count > 8);

						// If this is hit, we need to modify VTIL or create a VTIL pre-compile pass that removes partial offset shifted access to the flags register
						//
						fassert(reg.bit_offset == 0);

						bool other_is_ax = false;
						// Preserve full size ax
						//

						if (instr.base->operand_count() > 1)
						{
							size_t other_index = instr.base->operand_types[i] >= vtil::operand_type::write ? i + 1 : i - 1;
							auto other_reg = instr.operands[other_index];

							if (other_reg.is_register())
								other_is_ax = (other_reg.reg().combined_id == X86_REG_RAX || other_reg.reg().combined_id == X86_REG_EAX || other_reg.reg().combined_id == X86_REG_AX);
						}

						switch (reg.bit_count)//TODO: IDEA TO NOT REPEAT INSTR?
						{
						case 16:
							cc.push(other_is_ax ? x86::bx : x86::ax);
							cc.pushf();
							cc.pop(other_is_ax ? x86::bx : x86::ax);
							output.at(i) = new Operand(other_is_ax ? x86::bx : x86::ax);
							continue;
						case 32:
							cc.push(other_is_ax ? x86::ebx : x86::eax);
							cc.pushfd();
							cc.pop(other_is_ax ? x86::ebx : x86::eax);
							output.at(i) = new Operand(other_is_ax ? x86::ebx : x86::eax);
							continue;
						case 64:
							cc.push(other_is_ax ? x86::rbx : x86::rax);
							cc.pushfq();
							cc.pop(other_is_ax ? x86::rbx : x86::rax);
							output.at(i) = new Operand(other_is_ax ? x86::rbx : x86::rax);
							continue;
						}
						fassert(false);
						abort();
					}
					else
					{
						vtil::logger::log("\t\tmachine_register: %s\n", vtil::amd64::name(reg.combined_id));
						output.at(i) = new Operand(get_register_from_id(reg.combined_id));
						continue;
					}
				}
				else
				{
					vtil::logger::log("\tis_virtual\n");

					if (reg.is_image_base())
					{
						vtil::logger::log("\t\tis_image_base\n");
						// TODO: This obviously won't work for different
						// base addresses
						//
						x86::Gp base_reg = reg_for_size(reg);
						cc.mov(base_reg, base_address);
						output.at(i) = new Operand(base_reg);
						continue;
					}
					else if (reg.is_flags())
					{
						vtil::logger::log("\t\tis_flags\n");
						abort();
					}
					// Grab the register from the map, or create and insert otherwise.
					//
					else if (reg_map.count(reg))
					{
						output.at(i) = new Operand(reg_map[reg]);
						continue;
					}
					else
					{
						x86::Gp tmp = reg_for_size(reg);
						reg_map[reg] = tmp;
						output.at(i) = new Operand(tmp);
						continue;
					}
				}
			}
			else if (op.is_immediate())
			{
				vtil::logger::log("\t\tis_immediate\n");
				output.at(i) = new Imm(op.imm().ival);
				continue;
			}
			else
			{
				fassert(false);
			}
		}
		return output;
	}

	void process_implicit_changes(const vtil::instruction& instr, std::vector<Operand*> operands)
	{
		for (size_t i = 0; i < instr.base->operand_count(); i++)
		{			
			auto op = instr.operands[i];			

			if (!op.is_register())
				continue;

			if (!op.reg().is_flags())
				continue;

			auto flags = op.reg();

			if (instr.base->operand_types[i] >= vtil::operand_type::write)
			{
				//WRITE
				fassert(flags.bit_count > 8);

				auto other_reg = *reinterpret_cast<x86::Gpq*>(operands[0]);
				cc.push(other_reg);
				switch (flags.bit_count)
				{
				case 16:
					cc.popf();
					break;
				case 32:
					cc.popfd();
					break;
				case 64:
					cc.popfq();
					break;
				}
				// Restore preserved rax/rbx
				//
				cc.pop(other_reg);				
			}
			else if (instr.base->operand_types[i] != vtil::operand_type::invalid)
			{
				//READ
				cc.add(x86::rsp, flags.bit_count / 8);
				cc.pop(*reinterpret_cast<x86::Gpq*>(operands[1]));
			}
			else
			{
				fassert(false);
			}
		}

		for (Operand* op : operands)
			delete op;
	}
};

using fn_instruction_compiler_t = std::function<void(const vtil::il_iterator&, routine_state*)>;
static const std::map<vtil::instruction_desc, fn_instruction_compiler_t> handler_table = {
	{
		ins::ldd,
		[](const vtil::il_iterator& instr, routine_state* state) {
			auto dest = instr->operands[0].reg();
			auto src = instr->operands[1].reg();
			auto offset = instr->operands[2].imm();

			// FIXME: Figure out how to determine if the offset is signed or not
			//
			state->cc.mov(state->get_reg(dest), x86::ptr(state->get_reg(src), offset.ival));	
		},
	},
	{
		ins::str,
		[](const vtil::il_iterator& instr, routine_state* state) {
			auto base = instr->operands[0].reg();
			auto offset = instr->operands[1].imm();
			auto v = instr->operands[2];

			// FIXME: There is an issue here where it cannot deduce the size
			// of the move?
			//

			auto reg_base = state->get_reg(base);
			x86::Mem dest;
			switch (v.bit_count())
			{
			case 8:
				dest = x86::ptr_8(reg_base, offset.ival);
				break;
			case 16:
				dest = x86::ptr_16(reg_base, offset.ival);
				break;
			case 32:
				dest = x86::ptr_32(reg_base, offset.ival);
				break;
			case 64:
				dest = x86::ptr_64(reg_base, offset.ival);
				break;
			default:
				unreachable();
			}

			if (v.is_immediate())
			{
				state->cc.mov(dest, v.imm().ival);
			}
			else
			{
				state->cc.mov(dest, state->get_reg(v.reg()));
			}
		},
	},
	{
		ins::mov,
		[](const vtil::il_iterator& instr, routine_state* state) {
			auto operands = state->preprocess_instruction(*instr);

			if (operands[1]->isImm())
			{
				state->cc.mov(*reinterpret_cast<x86::Gp*>(operands[0]), *reinterpret_cast<Imm*>(operands[1]));
			}
			else
			{
				state->cc.mov(*reinterpret_cast<x86::Gp*>(operands[0]), *reinterpret_cast<x86::Gp*>(operands[1]));
			}
			state->process_implicit_changes(*instr, operands);

			/*auto dest = instr->operands[0].reg();
			auto src = instr->operands[1];

			if (src.is_immediate())
			{
				state->cc.mov(state->get_reg(dest), src.imm().ival);								
			}
			else
			{
				state->cc.mov(state->get_reg(dest), state->get_reg(src.reg()));
			}
			*/
		},
	},
	{
		ins::sub,
		[](const vtil::il_iterator& instr, routine_state* state) {
			auto operands = state->preprocess_instruction(*instr);

			if (operands[1]->isImm())
			{
				state->cc.sub(*reinterpret_cast<x86::Gp*>(operands[0]), *reinterpret_cast<Imm*>(operands[1]));
			}
			else
			{
				state->cc.sub(*reinterpret_cast<x86::Gp*>(operands[0]), *reinterpret_cast<x86::Gp*>(operands[1]));
			}
			state->process_implicit_changes(*instr, operands);
			/*auto dest = instr->operands[0].reg();
			auto src = instr->operands[1];

			if (src.is_immediate())
			{
				x86::Gp tmp = state->reg_for_size(src);
				state->cc.mov(tmp, src.imm().ival);
				state->cc.sub(state->get_reg(dest), tmp);

				// AsmJit shits its pants when I use this, so we move to a temporary
				// instead. TODO: Investigate
				// state->cc.sub( state->get_reg( dest ), src.imm().ival );
				//
			}
			else
			{
				state->cc.sub(state->get_reg(dest), state->get_reg(src.reg()));
			}*/
		},
	},
	{
		ins::add,
		[](const vtil::il_iterator& instr, routine_state* state) {
			auto operands = state->preprocess_instruction(*instr);

			if (operands[1]->isImm())
			{
				state->cc.add(*reinterpret_cast<x86::Gp*>(operands[0]), *reinterpret_cast<Imm*>(operands[1]));
			}
			else
			{
				state->cc.add(*reinterpret_cast<x86::Gp*>(operands[0]), *reinterpret_cast<x86::Gp*>(operands[1]));
			}
			state->process_implicit_changes(*instr, operands);
			/*auto lhs = instr->operands[0].reg();
			auto rhs = instr->operands[1];

			if (rhs.is_immediate())
			{
				x86::Gp tmp = state->reg_for_size(rhs);
				state->cc.mov(tmp, rhs.imm().ival);
				state->cc.add(state->get_reg(lhs), tmp);

				// See note on sub
				//
			}
			else
			{
				state->cc.add(state->get_reg(lhs), state->get_reg(rhs.reg()));
			}*/
		},
	},
	{
		ins::js,
		[](const vtil::il_iterator& it, routine_state* state) {
			auto cond = it->operands[0].reg();
			auto dst_1 = it->operands[1];
			auto dst_2 = it->operands[2];

			fassert(dst_1.is_immediate() && dst_2.is_immediate());

			// TODO: We should check if the block is compiled in order to avoid the
			// jump here, but I think the optimizer removes this?
			//
			state->cc.test(state->get_reg(cond), state->get_reg(cond));

			state->cc.jnz(state->get_label(dst_1.imm().uval));
			state->cc.jmp(state->get_label(dst_2.imm().uval));

			for (vtil::basic_block* destination : it.block->next)
			{
				if (!state->is_compiled.count(destination->entry_vip))
					compile(destination, state);
			}
		},
	},
	{
		ins::jmp,
		[](const vtil::il_iterator& it, routine_state* state) {
			vtil::debug::dump(*it);
			if (it->operands[0].is_register())
			{
				const vtil::operand::register_t cond = it->operands[0].reg();

				for (vtil::basic_block* destination : it.block->next)
				{
					state->cc.cmp(state->get_reg(cond), destination->entry_vip);
					state->cc.je(state->get_label(destination->entry_vip));

					if (!state->is_compiled.count(destination->entry_vip))
						compile(destination, state);
				}
			}
			else
			{
				fassert(it->operands[0].is_immediate());

				auto dest = it.block->next[0]->entry_vip;

				state->cc.jmp(state->get_label(dest));

				if (!state->is_compiled.count(dest))
					compile(it.block->next[0], state);
			}
		},
	},
	{
		ins::vexit,
		[](const vtil::il_iterator& it, routine_state* state) {
			// TODO: Call out into handler
			//
			state->cc.ret();
		},
	},
	{
		ins::vxcall,
		[](const vtil::il_iterator& it, routine_state* state) {
			// TODO: This should be a call, but you need to create
			// a call, etc. for the register allocator
			// if ( it->operands[ 0 ].is_immediate() )
			// {
			//     state->cc.jmp( it->operands[ 0 ].imm().uval );
			// }
			// else
			// {
			//     state->cc.jmp( state->get_reg( it->operands[ 0 ].reg() ) );
			// }
			//

			auto dest = it.block->next[0]->entry_vip;

			// Jump to next block.
			//
			state->cc.jmp(state->get_label(dest));

			if (!state->is_compiled.count(dest))
				compile(it.block->next[0], state);
		},
	},
	{
		ins::bshl,
		[](const vtil::il_iterator& it, routine_state* state) {
			auto dest = it->operands[0].reg();
			auto shift = it->operands[1];

			if (shift.is_immediate())
			{
				state->cc.shl(state->get_reg(dest), shift.imm().ival);
			}
			else
			{
				state->cc.shl(state->get_reg(dest), state->get_reg(shift.reg()));
			}
		},
	},
	{
		ins::bshr,
		[](const vtil::il_iterator& it, routine_state* state) {
			auto dest = it->operands[0].reg();
			auto shift = it->operands[1];

			if (shift.is_immediate())
			{
				state->cc.shr(state->get_reg(dest), shift.imm().ival);
			}
			else
			{
				state->cc.shr(state->get_reg(dest), state->get_reg(shift.reg()));
			}
		},
	},
	{
		ins::band,
		[](const vtil::il_iterator& it, routine_state* state) {
			auto dest = it->operands[0].reg();
			auto bit = it->operands[1];

			if (bit.is_immediate())
			{
				state->cc.and_(state->get_reg(dest), state->tmp_imm(bit));
			}
			else
			{
				state->cc.and_(state->get_reg(dest), state->get_reg(bit.reg()));
			}
		},
	},
	{
		ins::bor,
		[](const vtil::il_iterator& it, routine_state* state) {
			auto lhs = it->operands[0].reg();
			auto rhs = it->operands[1];

			if (rhs.is_immediate())
			{
				if (rhs.imm().bit_count > 32 || rhs.imm().ival > 0x7FFFFFFF)
				{
					auto temp_reg = state->cc.newGpq();
					state->cc.mov(temp_reg, rhs.imm().ival);
					state->cc.or_(state->get_reg(lhs), temp_reg);
				}					
				else
					state->cc.or_(state->get_reg(lhs), rhs.imm().ival);
			}
			else
			{
				state->cc.or_(state->get_reg(lhs), state->get_reg(rhs.reg()));
			}
		},
	},
	{
		ins::bxor,
		[](const vtil::il_iterator& it, routine_state* state) {
			auto lhs = it->operands[0].reg();
			auto rhs = it->operands[1];

			if (rhs.is_immediate())
			{
				state->cc.xor_(state->get_reg(lhs), rhs.imm().ival);
			}
			else
			{
				state->cc.xor_(state->get_reg(lhs), state->get_reg(rhs.reg()));
			}
		},
	},
	{
		ins::bnot,
		[](const vtil::il_iterator& it, routine_state* state) {
			state->cc.not_(state->get_reg(it->operands[0].reg()));
		},
	},
	{
		ins::neg,
		[](const vtil::il_iterator& it, routine_state* state) {

			auto operands = state->preprocess_instruction(*it);
			state->cc.neg(*reinterpret_cast<x86::Gp*>(operands[0]));
			state->process_implicit_changes(*it, operands);
		},
	},
	{
		ins::vemit,
		[](const vtil::il_iterator& it, routine_state* state) {
			auto data = it->operands[0].imm().uval;
			// TODO: Are we guarenteed that the registers used by these
			// embedded instructions are actually live at the point these are executed?
			//
			state->cc.embedUInt8((uint8_t)data);
		},
	},
#define MAP_CONDITIONAL(instrT, opcode, ropcode)                                    \
	{                                                                               \
		ins::instrT, [](const vtil::il_iterator& instr, routine_state* state) {     \
			vtil::logger::log("1_is_imm: %d\n", instr->operands[0].is_immediate()); \
			vtil::logger::log("2_is_imm: %d\n", instr->operands[1].is_immediate()); \
			vtil::logger::log("3_is_imm: %d\n", instr->operands[2].is_immediate()); \
			if (instr->operands[1].is_immediate())                                  \
			{                                                                       \
				x86::Gp tmp = state->reg_for_size(instr->operands[1]);              \
				state->cc.mov(tmp, instr->operands[1].imm().ival);                   \
				state->cc.cmp(state->get_reg(instr->operands[2].reg()), tmp);       \
				state->cc.ropcode(state->get_reg(instr->operands[0].reg()));        \
			}                                                                       \
			else                                                                    \
			{                                                                       \
				if (instr->operands[2].is_immediate())                              \
				{                                                                   \
					x86::Gp tmp = state->reg_for_size(instr->operands[2]);          \
					state->cc.mov(tmp, instr->operands[2].imm().ival);               \
					state->cc.cmp(state->get_reg(instr->operands[1].reg()), tmp);   \
				}                                                                   \
				else                                                                \
				{                                                                   \
					state->cc.cmp(state->get_reg(instr->operands[1].reg()),         \
						state->get_reg(instr->operands[2].reg()));                  \
				}                                                                   \
				state->cc.ropcode(state->get_reg(instr->operands[0].reg()));        \
			}                                                                       \
		},                                                                          \
	}
	MAP_CONDITIONAL(tg, setg, setle),
	MAP_CONDITIONAL(tge, setge, setl),
	MAP_CONDITIONAL(te, sete, setne),
	MAP_CONDITIONAL(tne, setne, sete),
	MAP_CONDITIONAL(tle, setle, setg),
	MAP_CONDITIONAL(tl, setl, setge),
	MAP_CONDITIONAL(tug, seta, setbe),
	MAP_CONDITIONAL(tuge, setae, setb),
	MAP_CONDITIONAL(tule, setbe, seta),
	MAP_CONDITIONAL(tul, setb, setae),
#undef MAP_CONDITIONAL
	{
		ins::ifs,
		[](const vtil::il_iterator& it, routine_state* state) {
			auto dest = it->operands[0].reg();
			auto cc = it->operands[1];
			auto res = it->operands[2];

			state->cc.xor_(state->get_reg(dest), state->get_reg(dest));
			// TODO: CC can be an immediate, how does that work?
			//
			state->cc.test(state->get_reg(cc.reg()), state->get_reg(cc.reg()));

			if (res.is_immediate())
			{
				x86::Gp tmp = state->reg_for_size(res);
				state->cc.mov(tmp, res.imm().ival);
				state->cc.cmovnz(state->get_reg(dest), tmp);
			}
			else
			{
				state->cc.cmovnz(state->get_reg(dest), state->get_reg(res.reg()));
			}
		},
	},
	{ ins::vpinr, [](const vtil::il_iterator& it, routine_state* state)
		{
		} },
	{ ins::vpinw, [](const vtil::il_iterator& it, routine_state* state)
		{
		} },
	{ ins::vpinrm, [](const vtil::il_iterator& it, routine_state* state)
		{
		} },
	{ ins::vpinwm, [](const vtil::il_iterator& it, routine_state* state)
		{
		} },
};

static void compile(vtil::basic_block* basic_block, routine_state* state)
{
	Label L_entry = state->get_label(basic_block->entry_vip);
	state->cc.bind(L_entry);
	state->is_compiled.insert(basic_block->entry_vip);

	for (auto it = basic_block->begin(); !it.is_end(); it++)
	{
		vtil::debug::dump(*it);
		auto handler = handler_table.find(*it->base);
		if (handler == handler_table.end())
		{
			vtil::logger::log("\n[!] ERROR: Unrecognized instruction '%s'\n\n", it->base->name);
			exit(1);
		}
		handler->second(it, state);
	}
}

class DemoErrorHandler : public ErrorHandler
{
public:
	void handleError(Error err, const char* message, BaseEmitter* origin) override
	{
		std::cerr << "AsmJit error: " << message << "\n";
	}
};

static args::Command command_compile(commands(), "compile", "Compile a .vtil file", [](args::Subparser& parser) {
	// Argument handling
	args::Positional<std::string> input(parser, "input", "Input .vtil file", args::Options::Required);	
	parser.Parse();

	// Command implementation
	auto rtn = vtil::load_routine(input.Get());

	JitRuntime rt;
	FileLogger logger(stdout);
	DemoErrorHandler errorHandler;
	CodeHolder code;

	code.init(rt.environment());
	code.setErrorHandler(&errorHandler);

	code.setLogger(&logger);
	logger.setFlags(
		FormatOptions::Flags::kFlagAnnotations |
		FormatOptions::Flags::kFlagDebugPasses |
		FormatOptions::Flags::kFlagDebugRA |
		FormatOptions::Flags::kFlagHexImms |
		FormatOptions::Flags::kFlagHexOffsets);

	x86::Compiler cc(&code);

	cc.addFunc(FuncSignatureT<void>());

	//TODO is that info available in the .VTIL file?
	//
	routine_state state(cc, 0x180'000'000);

	/**
	* DEBUG ROUTINE
	*/
	vtil::register_desc reg_rsp(vtil::register_stack_pointer | vtil::register_physical, 0, vtil::arch::bit_count, 0);

	vtil::register_desc reg_ax(vtil::register_physical, X86_REG_AX, vtil::arch::bit_count / 4, 0);
	vtil::register_desc reg_eax(vtil::register_physical, X86_REG_EAX, vtil::arch::bit_count / 2, 0);
	vtil::register_desc reg_rax(vtil::register_physical, X86_REG_RAX, vtil::arch::bit_count, 0);

	vtil::register_desc reg_bx(vtil::register_physical, X86_REG_BX, vtil::arch::bit_count / 4, 0);
	vtil::register_desc reg_ebx(vtil::register_physical, X86_REG_EBX, vtil::arch::bit_count / 2, 0);
	vtil::register_desc reg_rbx(vtil::register_physical, X86_REG_RBX, vtil::arch::bit_count, 0);

	auto block1 = vtil::basic_block::begin((uintptr_t)0x1000);
	{
		//INIT
		/*
		block1->mov(vtil::REG_FLAGS, 0x0);
		block1->vemit((uint64_t)~0uLL);
		//WRITE FLAGS
		block1->mov(vtil::REG_FLAGS.select(16, 0), (uint8_t)0x1);
		block1->vemit((uint64_t)~0uLL);
		block1->mov(vtil::REG_FLAGS.select(32, 0), (uint32_t)~0uL);
		block1->vemit((uint64_t)~0uLL);
		block1->mov(vtil::REG_FLAGS, (uint64_t)~0uLL);
		block1->vemit((uint64_t)~0uLL);
		block1->mov(vtil::REG_FLAGS.select(16,0), reg_bx);
		block1->vemit((uint64_t)~0uLL);
		block1->mov(vtil::REG_FLAGS.select(32, 0), reg_ebx);
		block1->vemit((uint64_t)~0uLL);
		block1->mov(vtil::REG_FLAGS, reg_rbx);
		block1->vemit((uint64_t)~0uLL);
		block1->mov(vtil::REG_FLAGS.select(16, 0), reg_ax);
		block1->vemit((uint64_t)~0uLL);
		block1->mov(vtil::REG_FLAGS.select(32, 0), reg_eax);
		block1->vemit((uint64_t)~0uLL);
		block1->mov(vtil::REG_FLAGS, reg_rax);
		block1->vemit((uint64_t)~0uLL);
		//READ FLAGS
		block1->mov(reg_bx, vtil::REG_FLAGS.select(16, 0));
		block1->vemit((uint64_t)~0uLL);
		block1->mov(reg_ebx, vtil::REG_FLAGS.select(32, 0));
		block1->vemit((uint64_t)~0uLL);
		block1->mov(reg_rbx, vtil::REG_FLAGS);
		block1->vemit((uint64_t)~0uLL);
		block1->mov(reg_ax, vtil::REG_FLAGS.select(16, 0));
		block1->vemit((uint64_t)~0uLL);
		block1->mov(reg_eax, vtil::REG_FLAGS.select(32, 0));
		block1->vemit((uint64_t)~0uLL);
		block1->mov(reg_rax, vtil::REG_FLAGS);
		block1->vemit((uint64_t)~0uLL);

		//COHEARANCE
		block1->mov(reg_bx, (uint8_t)~0u);
		block1->vemit((uint64_t)~0uLL);
		block1->mov(reg_bx, (uint16_t)~0u);
		block1->vemit((uint64_t)~0uLL);
		block1->mov(reg_ebx, (uint16_t)~0u);
		block1->vemit((uint64_t)~0uLL);
		block1->mov(reg_ebx, (uint32_t)~0u);
		block1->vemit((uint64_t)~0uLL);
		block1->mov(reg_rbx, (uint8_t)~0u);
		block1->add(reg_rbx, reg_rax);
		block1->neg(reg_rbx);*/

		block1->add(vtil::REG_FLAGS, reg_rax);
		block1->vemit((uint64_t)~0uLL);
		block1->add(vtil::REG_FLAGS.select(32, 0), reg_eax);
		block1->vemit((uint64_t)~0uLL);
		block1->add(vtil::REG_FLAGS.select(16, 0), reg_ax);
		block1->vemit((uint64_t)~0uLL);
		block1->add(vtil::REG_FLAGS, reg_rbx);
		block1->vemit((uint64_t)~0uLL);
		block1->add(vtil::REG_FLAGS.select(32, 0), reg_ebx);
		block1->vemit((uint64_t)~0uLL);
		block1->add(vtil::REG_FLAGS.select(16, 0), reg_bx);
		block1->vemit((uint64_t)~0uLL);
		block1->vemit((uint64_t)~0uLL);
		block1->vemit((uint64_t)~0uLL);
		block1->add(reg_ax, vtil::REG_FLAGS.select(16, 0));
		block1->vemit((uint64_t)~0uLL);
		block1->add(reg_eax, vtil::REG_FLAGS.select(32, 0));
		block1->vemit((uint64_t)~0uLL);
		block1->add(reg_rax, vtil::REG_FLAGS);
		block1->vemit((uint64_t)~0uLL);
		block1->add(reg_bx, vtil::REG_FLAGS.select(16, 0));
		block1->vemit((uint64_t)~0uLL);
		block1->add(reg_ebx, vtil::REG_FLAGS.select(32, 0));
		block1->vemit((uint64_t)~0uLL);
		block1->add(reg_rbx, vtil::REG_FLAGS);

		/*block1->mov(vtil::REG_FLAGS.select(8, 8), 0x4);

		block1->mov(reg_rax.select(8, 0), vtil::REG_FLAGS.select(8, 0));
		block1->mov(reg_rax.select(8, 8), vtil::REG_FLAGS.select(8, 8));*/
		block1->vexit((uintptr_t)0);
	}

	/*
	*/

	//compile(rtn->entry_point, &state);
	compile(block1->owner->entry_point, &state);

	cc.endFunc();
	cc.finalize();

	CodeBuffer& buffer = code.sectionById(0)->buffer();

	std::filesystem::path work_dir = std::filesystem::path(input.Get()).remove_filename() / "compiled/";
	std::filesystem::create_directory(work_dir);	

	//Thats a hacky way to do it in general, but it supports supplying commands like vtil.exe compile subfolder/file.vtil
	//
	work_dir += std::filesystem::path(input.Get()).replace_extension("bin").filename();
			
	std::ofstream fs(work_dir, std::ios::binary);
	if (!fs.is_open())
		throw std::runtime_error(vtil::format::str("Failed to open bin file '%s'", work_dir));

	fs.write((const char*)buffer.data(), buffer.size());
	fs.close();
});
