/* Copyright (c) 2011-2014 PLUMgrid, http://plumgrid.com
 * Copyright (c) 2016 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/filter.h>
#include <net/netlink.h>
#include <linux/file.h>
#include <linux/vmalloc.h>

/* bpf_check() is a static code analyzer that walks eBPF program
 * instruction by instruction and updates register/stack state.
 * All paths of conditional branches are analyzed until 'bpf_exit' insn.
 *
 * The first pass is depth-first-search to check that the program is a DAG.
 * It rejects the following programs:
 * - larger than BPF_MAXINSNS insns
 * - if loop is present (detected via back-edge)
 * - unreachable insns exist (shouldn't be a forest. program = one function)
 * - out of bounds or malformed jumps
 * The second pass is all possible path descent from the 1st insn.
 * Since it's analyzing all pathes through the program, the length of the
 * analysis is limited to 32k insn, which may be hit even if total number of
 * insn is less then 4K, but there are too many branches that change stack/regs.
 * Number of 'branches to be analyzed' is limited to 1k
 *
 * On entry to each instruction, each register has a type, and the instruction
 * changes the types of the registers depending on instruction semantics.
 * If instruction is BPF_MOV64_REG(BPF_REG_1, BPF_REG_5), then type of R5 is
 * copied to R1.
 *
 * All registers are 64-bit.
 * R0 - return register
 * R1-R5 argument passing registers
 * R6-R9 callee saved registers
 * R10 - frame pointer read-only
 *
 * At the start of BPF program the register R1 contains a pointer to bpf_context
 * and has type PTR_TO_CTX.
 *
 * Verifier tracks arithmetic operations on pointers in case:
 *    BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
 *    BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -20),
 * 1st insn copies R10 (which has PTR_TO_STACK) type into R1
 * and 2nd arithmetic instruction is pattern matched to recognize
 * that it wants to construct a pointer to some element within stack.
 * So after 2nd insn, the register R1 has type PTR_TO_STACK
 * (and -20 constant is saved for further stack bounds checking).
 * Meaning that this reg is a pointer to stack plus known immediate constant.
 *
 * Most of the time the registers have SCALAR_VALUE type, which
 * means the register has some value, but it's not a valid pointer.
 * (like pointer plus pointer becomes SCALAR_VALUE type)
 *
 * When verifier sees load or store instructions the type of base register
 * can be: PTR_TO_MAP_VALUE, PTR_TO_CTX, PTR_TO_STACK. These are three pointer
 * types recognized by check_mem_access() function.
 *
 * PTR_TO_MAP_VALUE means that this register is pointing to 'map element value'
 * and the range of [ptr, ptr + map's value_size) is accessible.
 *
 * registers used to pass values to function calls are checked against
 * function argument constraints.
 *
 * ARG_PTR_TO_MAP_KEY is one of such argument constraints.
 * It means that the register type passed to this function must be
 * PTR_TO_STACK and it will be used inside the function as
 * 'pointer to map element key'
 *
 * For example the argument constraints for bpf_map_lookup_elem():
 *   .ret_type = RET_PTR_TO_MAP_VALUE_OR_NULL,
 *   .arg1_type = ARG_CONST_MAP_PTR,
 *   .arg2_type = ARG_PTR_TO_MAP_KEY,
 *
 * ret_type says that this function returns 'pointer to map elem value or null'
 * function expects 1st argument to be a const pointer to 'struct bpf_map' and
 * 2nd argument should be a pointer to stack, which will be used inside
 * the helper function as a pointer to map element key.
 *
 * On the kernel side the helper function looks like:
 * u64 bpf_map_lookup_elem(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
 * {
 *    struct bpf_map *map = (struct bpf_map *) (unsigned long) r1;
 *    void *key = (void *) (unsigned long) r2;
 *    void *value;
 *
 *    here kernel can access 'key' and 'map' pointers safely, knowing that
 *    [key, key + map->key_size) bytes are valid and were initialized on
 *    the stack of eBPF program.
 * }
 *
 * Corresponding eBPF program may look like:
 *    BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),  // after this insn R2 type is PTR_TO_STACK
 *    BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4), // after this insn R2 type is PTR_TO_STACK
 *    BPF_LD_MAP_FD(BPF_REG_1, map_fd),      // after this insn R1 type is CONST_PTR_TO_MAP
 *    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
 * here verifier looks at prototype of map_lookup_elem() and sees:
 * .arg1_type == ARG_CONST_MAP_PTR and R1->type == CONST_PTR_TO_MAP, which is ok,
 * Now verifier knows that this map has key of R1->map_ptr->key_size bytes
 *
 * Then .arg2_type == ARG_PTR_TO_MAP_KEY and R2->type == PTR_TO_STACK, ok so far,
 * Now verifier checks that [R2, R2 + map's key_size) are within stack limits
 * and were initialized prior to this call.
 * If it's ok, then verifier allows this BPF_CALL insn and looks at
 * .ret_type which is RET_PTR_TO_MAP_VALUE_OR_NULL, so it sets
 * R0->type = PTR_TO_MAP_VALUE_OR_NULL which means bpf_map_lookup_elem() function
 * returns ether pointer to map value or NULL.
 *
 * When type PTR_TO_MAP_VALUE_OR_NULL passes through 'if (reg != 0) goto +off'
 * insn, the register holding that pointer in the true branch changes state to
 * PTR_TO_MAP_VALUE and the same register becomes a known-zero scalar in the false
 * branch. See check_cond_jmp_op().
 *
 * After the call R0 is set to return type of the function and registers R1-R5
 * are set to NOT_INIT to indicate that they are no longer readable.
 */

/* verifier_state + insn_idx are pushed to stack when branch is encountered */
struct bpf_verifier_stack_elem {
	/* verifer state is 'st'
	 * before processing instruction 'insn_idx'
	 * and after processing instruction 'prev_insn_idx'
	 */
	struct bpf_verifier_state st;
	int insn_idx;
	int prev_insn_idx;
	struct bpf_verifier_stack_elem *next;
};

#define BPF_COMPLEXITY_LIMIT_INSNS	131072
#define BPF_COMPLEXITY_LIMIT_STACK	1024

struct bpf_call_arg_meta {
	struct bpf_map *map_ptr;
	bool raw_mode;
	bool pkt_access;
	int regno;
	int access_size;
};

/* verbose verifier prints what it's seeing
 * bpf_check() is called under lock, so no race to access these global vars
 */
static u32 log_level, log_size, log_len;
static char *log_buf;

static DEFINE_MUTEX(bpf_verifier_lock);

/* log_level controls verbosity level of eBPF verifier.
 * verbose() is used to dump the verification trace to the log, so the user
 * can figure out what's wrong with the program
 */
static __printf(1, 2) void verbose(const char *fmt, ...)
{
	va_list args;

	if (log_level == 0 || log_len >= log_size - 1)
		return;

	va_start(args, fmt);
	log_len += vscnprintf(log_buf + log_len, log_size - log_len, fmt, args);
	va_end(args);
}

/* string representation of 'enum bpf_reg_type' */
static const char * const reg_type_str[] = {
	[NOT_INIT]		= "?",
	[SCALAR_VALUE]		= "inv",
	[PTR_TO_CTX]		= "ctx",
	[CONST_PTR_TO_MAP]	= "map_ptr",
	[PTR_TO_MAP_VALUE]	= "map_value",
	[PTR_TO_MAP_VALUE_OR_NULL] = "map_value_or_null",
	[PTR_TO_STACK]		= "fp",
	[PTR_TO_PACKET]		= "pkt",
	[PTR_TO_PACKET_END]	= "pkt_end",
	[PTR_TO_SOCKET]		= "sock",
	[PTR_TO_SOCKET_OR_NULL] = "sock_or_null",
	[PTR_TO_SOCK_COMMON] = "sock_common",
	[PTR_TO_SOCK_COMMON_OR_NULL] = "sock_common_or_null",
};

static void print_verifier_state(struct bpf_verifier_state *state)
{
	struct bpf_reg_state *reg;
	enum bpf_reg_type t;
	int i;

	for (i = 0; i < MAX_BPF_REG; i++) {
		reg = &state->regs[i];
		t = reg->type;
		if (t == NOT_INIT)
			continue;
		verbose(" R%d=%s", i, reg_type_str[t]);
		if ((t == SCALAR_VALUE || t == PTR_TO_STACK) &&
		    tnum_is_const(reg->var_off)) {
			/* reg->off should be 0 for SCALAR_VALUE */
			verbose("%lld", reg->var_off.value + reg->off);
		} else {
			verbose("(id=%d", reg->id);
			if (t != SCALAR_VALUE)
				verbose(",off=%d", reg->off);
			if (t == PTR_TO_PACKET)
				verbose(",r=%d", reg->range);
			else if (t == CONST_PTR_TO_MAP ||
				 t == PTR_TO_MAP_VALUE ||
				 t == PTR_TO_MAP_VALUE_OR_NULL)
				verbose(",ks=%d,vs=%d",
					reg->map_ptr->key_size,
					reg->map_ptr->value_size);
			if (reg->smin_value != reg->umin_value &&
			    reg->smin_value != S64_MIN)
				verbose(",smin_value=%lld",
					(long long)reg->smin_value);
			if (reg->smax_value != reg->umax_value &&
			    reg->smax_value != S64_MAX)
				verbose(",smax_value=%lld",
					(long long)reg->smax_value);
			if (reg->umin_value != 0)
				verbose(",umin_value=%llu",
					(unsigned long long)reg->umin_value);
			if (reg->umax_value != U64_MAX)
				verbose(",umax_value=%llu",
					(unsigned long long)reg->umax_value);
			if (!tnum_is_unknown(reg->var_off)) {
				char tn_buf[48];

				tnum_strn(tn_buf, sizeof(tn_buf), reg->var_off);
				verbose(",var_off=%s", tn_buf);
			}
			verbose(")");
		}
	}
	for (i = 0; i < MAX_BPF_STACK; i += BPF_REG_SIZE) {
		if (state->stack_slot_type[i] == STACK_SPILL)
			verbose(" fp%d=%s", -MAX_BPF_STACK + i,
				reg_type_str[state->spilled_regs[i / BPF_REG_SIZE].type]);
	}
	verbose("\n");
}

static const char *const bpf_class_string[] = {
	[BPF_LD]    = "ld",
	[BPF_LDX]   = "ldx",
	[BPF_ST]    = "st",
	[BPF_STX]   = "stx",
	[BPF_ALU]   = "alu",
	[BPF_JMP]   = "jmp",
	[BPF_RET]   = "BUG",
	[BPF_ALU64] = "alu64",
	[BPF_JMP32] = "jmp32",
};

static const char *const bpf_alu_string[16] = {
	[BPF_ADD >> 4]  = "+=",
	[BPF_SUB >> 4]  = "-=",
	[BPF_MUL >> 4]  = "*=",
	[BPF_DIV >> 4]  = "/=",
	[BPF_OR  >> 4]  = "|=",
	[BPF_AND >> 4]  = "&=",
	[BPF_LSH >> 4]  = "<<=",
	[BPF_RSH >> 4]  = ">>=",
	[BPF_NEG >> 4]  = "neg",
	[BPF_MOD >> 4]  = "%=",
	[BPF_XOR >> 4]  = "^=",
	[BPF_MOV >> 4]  = "=",
	[BPF_ARSH >> 4] = "s>>=",
	[BPF_END >> 4]  = "endian",
};

static const char *const bpf_ldst_string[] = {
	[BPF_W >> 3]  = "u32",
	[BPF_H >> 3]  = "u16",
	[BPF_B >> 3]  = "u8",
	[BPF_DW >> 3] = "u64",
};

static const char *const bpf_jmp_string[16] = {
	[BPF_JA >> 4]   = "jmp",
	[BPF_JEQ >> 4]  = "==",
	[BPF_JGT >> 4]  = ">",
	[BPF_JLT >> 4]  = "<",
	[BPF_JGE >> 4]  = ">=",
	[BPF_JLE >> 4]  = "<=",
	[BPF_JSET >> 4] = "&",
	[BPF_JNE >> 4]  = "!=",
	[BPF_JSGT >> 4] = "s>",
	[BPF_JSLT >> 4] = "s<",
	[BPF_JSGE >> 4] = "s>=",
	[BPF_JSLE >> 4] = "s<=",
	[BPF_CALL >> 4] = "call",
	[BPF_EXIT >> 4] = "exit",
};

static void print_bpf_insn(const struct bpf_verifier_env *env,
			   const struct bpf_insn *insn)
{
	u8 class = BPF_CLASS(insn->code);

	if (class == BPF_ALU || class == BPF_ALU64) {
		if (BPF_SRC(insn->code) == BPF_X)
			verbose("(%02x) %sr%d %s %sr%d\n",
				insn->code, class == BPF_ALU ? "(u32) " : "",
				insn->dst_reg,
				bpf_alu_string[BPF_OP(insn->code) >> 4],
				class == BPF_ALU ? "(u32) " : "",
				insn->src_reg);
		else
			verbose("(%02x) %sr%d %s %s%d\n",
				insn->code, class == BPF_ALU ? "(u32) " : "",
				insn->dst_reg,
				bpf_alu_string[BPF_OP(insn->code) >> 4],
				class == BPF_ALU ? "(u32) " : "",
				insn->imm);
	} else if (class == BPF_STX) {
		if (BPF_MODE(insn->code) == BPF_MEM)
			verbose("(%02x) *(%s *)(r%d %+d) = r%d\n",
				insn->code,
				bpf_ldst_string[BPF_SIZE(insn->code) >> 3],
				insn->dst_reg,
				insn->off, insn->src_reg);
		else if (BPF_MODE(insn->code) == BPF_XADD)
			verbose("(%02x) lock *(%s *)(r%d %+d) += r%d\n",
				insn->code,
				bpf_ldst_string[BPF_SIZE(insn->code) >> 3],
				insn->dst_reg, insn->off,
				insn->src_reg);
		else
			verbose("BUG_%02x\n", insn->code);
	} else if (class == BPF_ST) {
		if (BPF_MODE(insn->code) != BPF_MEM) {
			verbose("BUG_st_%02x\n", insn->code);
			return;
		}
		verbose("(%02x) *(%s *)(r%d %+d) = %d\n",
			insn->code,
			bpf_ldst_string[BPF_SIZE(insn->code) >> 3],
			insn->dst_reg,
			insn->off, insn->imm);
	} else if (class == BPF_LDX) {
		if (BPF_MODE(insn->code) != BPF_MEM) {
			verbose("BUG_ldx_%02x\n", insn->code);
			return;
		}
		verbose("(%02x) r%d = *(%s *)(r%d %+d)\n",
			insn->code, insn->dst_reg,
			bpf_ldst_string[BPF_SIZE(insn->code) >> 3],
			insn->src_reg, insn->off);
	} else if (class == BPF_LD) {
		if (BPF_MODE(insn->code) == BPF_ABS) {
			verbose("(%02x) r0 = *(%s *)skb[%d]\n",
				insn->code,
				bpf_ldst_string[BPF_SIZE(insn->code) >> 3],
				insn->imm);
		} else if (BPF_MODE(insn->code) == BPF_IND) {
			verbose("(%02x) r0 = *(%s *)skb[r%d + %d]\n",
				insn->code,
				bpf_ldst_string[BPF_SIZE(insn->code) >> 3],
				insn->src_reg, insn->imm);
		} else if (BPF_MODE(insn->code) == BPF_IMM &&
			   BPF_SIZE(insn->code) == BPF_DW) {
			/* At this point, we already made sure that the second
			 * part of the ldimm64 insn is accessible.
			 */
			u64 imm = ((u64)(insn + 1)->imm << 32) | (u32)insn->imm;
			bool map_ptr = insn->src_reg == BPF_PSEUDO_MAP_FD;

			if (map_ptr && !env->allow_ptr_leaks)
				imm = 0;

			verbose("(%02x) r%d = 0x%llx\n", insn->code,
				insn->dst_reg, (unsigned long long)imm);
		} else {
			verbose("BUG_ld_%02x\n", insn->code);
			return;
		}
	} else if (class == BPF_JMP || class == BPF_JMP32) {
		u8 opcode = BPF_OP(insn->code);

		if (opcode == BPF_CALL) {
			verbose("(%02x) call %d\n", insn->code, insn->imm);
		} else if (insn->code == (BPF_JMP | BPF_JA)) {
			verbose("(%02x) goto pc%+d\n",
				insn->code, insn->off);
		} else if (insn->code == (BPF_JMP | BPF_EXIT)) {
			verbose("(%02x) exit\n", insn->code);
		} else if (BPF_SRC(insn->code) == BPF_X) {
			verbose("(%02x) if r%d %s r%d goto pc%+d\n",
				insn->code, insn->dst_reg,
				bpf_jmp_string[BPF_OP(insn->code) >> 4],
				insn->src_reg, insn->off);
		} else {
			verbose("(%02x) if r%d %s 0x%x goto pc%+d\n",
				insn->code, insn->dst_reg,
				bpf_jmp_string[BPF_OP(insn->code) >> 4],
				insn->imm, insn->off);
		}
	} else {
		verbose("(%02x) %s\n", insn->code, bpf_class_string[class]);
	}
}

static int pop_stack(struct bpf_verifier_env *env, int *prev_insn_idx)
{
	struct bpf_verifier_stack_elem *elem;
	int insn_idx;

	if (env->head == NULL)
		return -1;

	memcpy(&env->cur_state, &env->head->st, sizeof(env->cur_state));
	insn_idx = env->head->insn_idx;
	if (prev_insn_idx)
		*prev_insn_idx = env->head->prev_insn_idx;
	elem = env->head->next;
	kfree(env->head);
	env->head = elem;
	env->stack_size--;
	return insn_idx;
}

static struct bpf_verifier_state *push_stack(struct bpf_verifier_env *env,
					     int insn_idx, int prev_insn_idx)
{
	struct bpf_verifier_stack_elem *elem;

	elem = kmalloc(sizeof(struct bpf_verifier_stack_elem), GFP_KERNEL);
	if (!elem)
		goto err;

	memcpy(&elem->st, &env->cur_state, sizeof(env->cur_state));
	elem->insn_idx = insn_idx;
	elem->prev_insn_idx = prev_insn_idx;
	elem->next = env->head;
	env->head = elem;
	env->stack_size++;
	if (env->stack_size > BPF_COMPLEXITY_LIMIT_STACK) {
		verbose("BPF program is too complex\n");
		goto err;
	}
	return &elem->st;
err:
	/* pop all elements and return */
	while (pop_stack(env, NULL) >= 0);
	return NULL;
}

#define CALLER_SAVED_REGS 6
static const int caller_saved[CALLER_SAVED_REGS] = {
	BPF_REG_0, BPF_REG_1, BPF_REG_2, BPF_REG_3, BPF_REG_4, BPF_REG_5
};

static void __mark_reg_not_init(struct bpf_reg_state *reg);

/* Mark the unknown part of a register (variable offset or scalar value) as
 * known to have the value @imm.
 */
static void __mark_reg_known(struct bpf_reg_state *reg, u64 imm)
{
	reg->id = 0;
	reg->var_off = tnum_const(imm);
	reg->smin_value = (s64)imm;
	reg->smax_value = (s64)imm;
	reg->umin_value = imm;
	reg->umax_value = imm;
}

/* Mark the 'variable offset' part of a register as zero.  This should be
 * used only on registers holding a pointer type.
 */
static void __mark_reg_known_zero(struct bpf_reg_state *reg)
{
	__mark_reg_known(reg, 0);
}

static void mark_reg_known_zero(struct bpf_reg_state *regs, u32 regno)
{
	if (WARN_ON(regno >= MAX_BPF_REG)) {
		verbose("mark_reg_known_zero(regs, %u)\n", regno);
		/* Something bad happened, let's kill all regs */
		for (regno = 0; regno < MAX_BPF_REG; regno++)
			__mark_reg_not_init(regs + regno);
		return;
	}
	__mark_reg_known_zero(regs + regno);
}

/* Attempts to improve min/max values based on var_off information */
static void __update_reg_bounds(struct bpf_reg_state *reg)
{
	/* min signed is max(sign bit) | min(other bits) */
	reg->smin_value = max_t(s64, reg->smin_value,
				reg->var_off.value | (reg->var_off.mask & S64_MIN));
	/* max signed is min(sign bit) | max(other bits) */
	reg->smax_value = min_t(s64, reg->smax_value,
				reg->var_off.value | (reg->var_off.mask & S64_MAX));
	reg->umin_value = max(reg->umin_value, reg->var_off.value);
	reg->umax_value = min(reg->umax_value,
			      reg->var_off.value | reg->var_off.mask);
}

/* Uses signed min/max values to inform unsigned, and vice-versa */
static void __reg_deduce_bounds(struct bpf_reg_state *reg)
{
	/* Learn sign from signed bounds.
	 * If we cannot cross the sign boundary, then signed and unsigned bounds
	 * are the same, so combine.  This works even in the negative case, e.g.
	 * -3 s<= x s<= -1 implies 0xf...fd u<= x u<= 0xf...ff.
	 */
	if (reg->smin_value >= 0 || reg->smax_value < 0) {
		reg->smin_value = reg->umin_value = max_t(u64, reg->smin_value,
							  reg->umin_value);
		reg->smax_value = reg->umax_value = min_t(u64, reg->smax_value,
							  reg->umax_value);
		return;
	}
	/* Learn sign from unsigned bounds.  Signed bounds cross the sign
	 * boundary, so we must be careful.
	 */
	if ((s64)reg->umax_value >= 0) {
		/* Positive.  We can't learn anything from the smin, but smax
		 * is positive, hence safe.
		 */
		reg->smin_value = reg->umin_value;
		reg->smax_value = reg->umax_value = min_t(u64, reg->smax_value,
							  reg->umax_value);
	} else if ((s64)reg->umin_value < 0) {
		/* Negative.  We can't learn anything from the smax, but smin
		 * is negative, hence safe.
		 */
		reg->smin_value = reg->umin_value = max_t(u64, reg->smin_value,
							  reg->umin_value);
		reg->smax_value = reg->umax_value;
	}
}

/* Attempts to improve var_off based on unsigned min/max information */
static void __reg_bound_offset(struct bpf_reg_state *reg)
{
	reg->var_off = tnum_intersect(reg->var_off,
				      tnum_range(reg->umin_value,
						 reg->umax_value));
}

/* Reset the min/max bounds of a register */
static void __mark_reg_unbounded(struct bpf_reg_state *reg)
{
	reg->smin_value = S64_MIN;
	reg->smax_value = S64_MAX;
	reg->umin_value = 0;
	reg->umax_value = U64_MAX;
}

/* Mark a register as having a completely unknown (scalar) value. */
static void __mark_reg_unknown(struct bpf_reg_state *reg)
{
	reg->type = SCALAR_VALUE;
	reg->id = 0;
	reg->off = 0;
	reg->var_off = tnum_unknown;
	__mark_reg_unbounded(reg);
}

static void mark_reg_unknown(struct bpf_reg_state *regs, u32 regno)
{
	if (WARN_ON(regno >= MAX_BPF_REG)) {
		verbose("mark_reg_unknown(regs, %u)\n", regno);
		/* Something bad happened, let's kill all regs */
		for (regno = 0; regno < MAX_BPF_REG; regno++)
			__mark_reg_not_init(regs + regno);
		return;
	}
	__mark_reg_unknown(regs + regno);
}

static void __mark_reg_not_init(struct bpf_reg_state *reg)
{
	__mark_reg_unknown(reg);
	reg->type = NOT_INIT;
}

static void mark_reg_not_init(struct bpf_reg_state *regs, u32 regno)
{
	if (WARN_ON(regno >= MAX_BPF_REG)) {
		verbose("mark_reg_not_init(regs, %u)\n", regno);
		/* Something bad happened, let's kill all regs */
		for (regno = 0; regno < MAX_BPF_REG; regno++)
			__mark_reg_not_init(regs + regno);
		return;
	}
	__mark_reg_not_init(regs + regno);
}

static void init_reg_state(struct bpf_reg_state *regs)
{
	int i;

	for (i = 0; i < MAX_BPF_REG; i++)
		mark_reg_not_init(regs, i);

	/* frame pointer */
	regs[BPF_REG_FP].type = PTR_TO_STACK;
	mark_reg_known_zero(regs, BPF_REG_FP);

	/* 1st arg to a function */
	regs[BPF_REG_1].type = PTR_TO_CTX;
	mark_reg_known_zero(regs, BPF_REG_1);
}

enum reg_arg_type {
	SRC_OP,		/* register is used as source operand */
	DST_OP,		/* register is used as destination operand */
	DST_OP_NO_MARK	/* same as above, check only, don't mark */
};

static int check_reg_arg(struct bpf_reg_state *regs, u32 regno,
			 enum reg_arg_type t)
{
	if (regno >= MAX_BPF_REG) {
		verbose("R%d is invalid\n", regno);
		return -EINVAL;
	}

	if (t == SRC_OP) {
		/* check whether register used as source operand can be read */
		if (regs[regno].type == NOT_INIT) {
			verbose("R%d !read_ok\n", regno);
			return -EACCES;
		}
	} else {
		/* check whether register used as dest operand can be written to */
		if (regno == BPF_REG_FP) {
			verbose("frame pointer is read only\n");
			return -EACCES;
		}
		if (t == DST_OP)
			mark_reg_unknown(regs, regno);
	}
	return 0;
}

static int bpf_size_to_bytes(int bpf_size)
{
	if (bpf_size == BPF_W)
		return 4;
	else if (bpf_size == BPF_H)
		return 2;
	else if (bpf_size == BPF_B)
		return 1;
	else if (bpf_size == BPF_DW)
		return 8;
	else
		return -EINVAL;
}

static bool is_spillable_regtype(enum bpf_reg_type type)
{
	switch (type) {
	case PTR_TO_MAP_VALUE:
	case PTR_TO_MAP_VALUE_OR_NULL:
	case PTR_TO_STACK:
	case PTR_TO_CTX:
	case PTR_TO_PACKET:
	case PTR_TO_PACKET_END:
	case CONST_PTR_TO_MAP:
	case PTR_TO_SOCKET:
	case PTR_TO_SOCKET_OR_NULL:
	case PTR_TO_SOCK_COMMON:
	case PTR_TO_SOCK_COMMON_OR_NULL:
		return true;
	default:
		return false;
	}
}

/* check_stack_read/write functions track spill/fill of registers,
 * stack boundary and alignment are checked in check_mem_access()
 */
static int check_stack_write(struct bpf_verifier_env *env,
			     struct bpf_verifier_state *state, int off,
			     int size, int value_regno, int insn_idx)
{
	int i, spi = (MAX_BPF_STACK + off) / BPF_REG_SIZE;
	/* caller checked that off % size == 0 and -MAX_BPF_STACK <= off < 0,
	 * so it's aligned access and [off, off + size) are within stack limits
	 */

	if (value_regno >= 0 &&
	    is_spillable_regtype(state->regs[value_regno].type)) {

		/* register containing pointer is being spilled into stack */
		if (size != BPF_REG_SIZE) {
			verbose("invalid size of register spill\n");
			return -EACCES;
		}

		/* save register state */
		state->spilled_regs[spi] = state->regs[value_regno];

		for (i = 0; i < BPF_REG_SIZE; i++) {
			if (state->stack_slot_type[MAX_BPF_STACK + off + i] == STACK_MISC &&
			    !env->allow_ptr_leaks) {
				int *poff = &env->insn_aux_data[insn_idx].sanitize_stack_off;
				int soff = off;

				/* detected reuse of integer stack slot with a pointer
				 * which means either llvm is reusing stack slot or
				 * an attacker is trying to exploit CVE-2018-3639
				 * (speculative store bypass)
				 * Have to sanitize that slot with preemptive
				 * store of zero.
				 */
				if (*poff && *poff != soff) {
					/* disallow programs where single insn stores
					 * into two different stack slots, since verifier
					 * cannot sanitize them
					 */
					verbose("insn %d cannot access two stack slots fp%d and fp%d",
						insn_idx, *poff, soff);
					return -EINVAL;
				}
				*poff = soff;
			}
			state->stack_slot_type[MAX_BPF_STACK + off + i] = STACK_SPILL;
		}
	} else {
		/* regular write of data into stack */
		state->spilled_regs[spi] = (struct bpf_reg_state) {};

		for (i = 0; i < size; i++)
			state->stack_slot_type[MAX_BPF_STACK + off + i] = STACK_MISC;
	}
	return 0;
}

static int check_stack_read(struct bpf_verifier_state *state, int off, int size,
			    int value_regno)
{
	u8 *slot_type;
	int i;

	slot_type = &state->stack_slot_type[MAX_BPF_STACK + off];

	if (slot_type[0] == STACK_SPILL) {
		if (size != BPF_REG_SIZE) {
			verbose("invalid size of register spill\n");
			return -EACCES;
		}
		for (i = 1; i < BPF_REG_SIZE; i++) {
			if (slot_type[i] != STACK_SPILL) {
				verbose("corrupted spill memory\n");
				return -EACCES;
			}
		}

		if (value_regno >= 0)
			/* restore register state from stack */
			state->regs[value_regno] =
				state->spilled_regs[(MAX_BPF_STACK + off) / BPF_REG_SIZE];
		return 0;
	} else {
		for (i = 0; i < size; i++) {
			if (slot_type[i] != STACK_MISC) {
				verbose("invalid read from stack off %d+%d size %d\n",
					off, i, size);
				return -EACCES;
			}
		}
		if (value_regno >= 0)
			/* have read misc data from the stack */
			mark_reg_unknown(state->regs, value_regno);
		return 0;
	}
}

/* check read/write into map element returned by bpf_map_lookup_elem() */
static int __check_map_access(struct bpf_verifier_env *env, u32 regno, s64 off,
			    int size)
{
	struct bpf_map *map = env->cur_state.regs[regno].map_ptr;

	if (off < 0 || size <= 0 || (u64)off + size > map->value_size) {
		verbose("invalid access to map value, value_size=%d off=%lld size=%d\n",
			map->value_size, (long long)off, size);
		return -EACCES;
	}
	return 0;
}

/* check read/write into a map element with possible variable offset */
static int check_map_access(struct bpf_verifier_env *env, u32 regno,
				int off, int size)
{
	struct bpf_verifier_state *state = &env->cur_state;
	struct bpf_reg_state *reg = &state->regs[regno];
	int err;

	/* We may have adjusted the register to this map value, so we
	 * need to try adding each of min_value and max_value to off
	 * to make sure our theoretical access will be safe.
	 */
	if (log_level)
		print_verifier_state(state);
	/* If the offset is variable, we will need to be stricter in state
	 * pruning from now on.
	 */
	/* The minimum value is only important with signed
	 * comparisons where we can't assume the floor of a
	 * value is 0.  If we are using signed variables for our
	 * index'es we need to make sure that whatever we use
	 * will have a set floor within our range.
	 */
	if (reg->smin_value < 0) {
		verbose("R%d min value is negative, either use unsigned index or do a if (index >=0) check.\n",
			regno);
		return -EACCES;
	}
	if (reg->umax_value >= BPF_MAX_VAR_OFF ||
	    (u64)reg->smin_value > reg->umax_value) {
		verbose("R%d unbounded or inconsistent map offset\n", regno);
		return -EACCES;
	}
	err = __check_map_access(env, regno, reg->smin_value + off, size);
	if (err) {
		verbose("R%d min value is outside of the array range\n", regno);
		return err;
	}

	err = __check_map_access(env, regno, reg->umax_value + off, size);
	if (err)
		verbose("R%d max value is outside of the array range\n", regno);
	return err;
}

#define MAX_PACKET_OFF 0xffff

static bool may_access_direct_pkt_data(struct bpf_verifier_env *env,
				       const struct bpf_call_arg_meta *meta)
{
	switch (env->prog->type) {
	case BPF_PROG_TYPE_SCHED_CLS:
	case BPF_PROG_TYPE_SCHED_ACT:
	case BPF_PROG_TYPE_XDP:
		if (meta)
			return meta->pkt_access;

		env->seen_direct_write = true;
		return true;
	case BPF_PROG_TYPE_CGROUP_SOCKOPT:
		return meta ? meta->pkt_access : true;
	default:
		return false;
	}
}

static int __check_packet_access(struct bpf_verifier_env *env, u32 regno,
				 int off, int size)
{
	struct bpf_reg_state *regs = env->cur_state.regs;
	struct bpf_reg_state *reg = &regs[regno];

	if (off < 0 || size <= 0 || (u64)off + size > reg->range) {
		verbose("invalid access to packet, off=%d size=%d, R%d(id=%d,off=%d,r=%d)\n",
			off, size, regno, reg->id, reg->off, reg->range);
		return -EACCES;
	}
	return 0;
}

static int check_packet_access(struct bpf_verifier_env *env, u32 regno, int off,
			       int size)
{
	struct bpf_reg_state *regs = env->cur_state.regs;
	struct bpf_reg_state *reg = &regs[regno];
	int err;

	/* We may have added a variable offset to the packet pointer; but any
	 * reg->range we have comes after that.  We are only checking the fixed
	 * offset.
	 */

	/* We don't allow negative numbers, because we aren't tracking enough
	 * detail to prove they're safe.
	 */
	if (reg->smin_value < 0) {
		verbose("R%d min value is negative, either use unsigned index or do a if (index >=0) check.\n",
			regno);
		return -EACCES;
	}
	err = __check_packet_access(env, regno, off, size);
	if (err) {
		verbose("R%d offset is outside of the packet\n", regno);
		return err;
	}
	return err;
}

/* check access to 'struct bpf_context' fields.  Supports fixed offsets only */
static int check_ctx_access(struct bpf_verifier_env *env, int insn_idx, int off, int size,
			    enum bpf_access_type t, enum bpf_reg_type *reg_type)
{
	/* for analyzer ctx accesses are already validated and converted */
	if (env->analyzer_ops)
		return 0;

	if (env->prog->aux->ops->is_valid_access &&
	    env->prog->aux->ops->is_valid_access(off, size, t, reg_type,
					      env->prog)) {
		/* remember the offset of last byte accessed in ctx */
		if (env->prog->aux->max_ctx_offset < off + size)
			env->prog->aux->max_ctx_offset = off + size;
		return 0;
	}

	verbose("invalid bpf_context access off=%d size=%d\n", off, size);
	return -EACCES;
}

static bool is_ctx_reg(struct bpf_verifier_env *env, int regno)
{
	const struct bpf_reg_state *reg = &env->cur_state.regs[regno];

	return reg->type == PTR_TO_CTX;
}

static int check_sock_access(int off, int size, enum bpf_access_type t,
			     enum bpf_reg_type type)
{
	bool valid = type == PTR_TO_SOCK_COMMON ?
		bpf_sock_common_is_valid_access(off, size, t) :
		bpf_sock_is_valid_access(off, size, t);

	if (valid)
		return 0;

	verbose("invalid bpf_sock access off=%d size=%d\n", off, size);
	return -EACCES;
}

static bool __is_pointer_value(bool allow_ptr_leaks,
			       const struct bpf_reg_state *reg)
{
	if (allow_ptr_leaks)
		return false;

	return reg->type != SCALAR_VALUE;
}

static bool is_pointer_value(struct bpf_verifier_env *env, int regno)
{
	return __is_pointer_value(env->allow_ptr_leaks, &env->cur_state.regs[regno]);
}

static int check_pkt_ptr_alignment(const struct bpf_reg_state *reg,
				   int off, int size, bool strict)
{
	struct tnum reg_off;
	int ip_align;

	/* Byte size accesses are always allowed. */
	if (!strict || size == 1)
		return 0;

	/* For platforms that do not have a Kconfig enabling
	 * CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS the value of
	 * NET_IP_ALIGN is universally set to '2'.  And on platforms
	 * that do set CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS, we get
	 * to this code only in strict mode where we want to emulate
	 * the NET_IP_ALIGN==2 checking.  Therefore use an
	 * unconditional IP align value of '2'.
	 */
	ip_align = 2;

	reg_off = tnum_add(reg->var_off, tnum_const((s64)ip_align + reg->off + off));
	if (!tnum_is_aligned(reg_off, size)) {
		char tn_buf[48];

		tnum_strn(tn_buf, sizeof(tn_buf), reg->var_off);
		verbose("misaligned packet access off %d+%s+%d+%d size %d\n",
			ip_align, tn_buf, reg->off, off, size);
		return -EACCES;
	}

	return 0;
}

static int check_generic_ptr_alignment(const struct bpf_reg_state *reg,
				       const char *pointer_desc,
				       int off, int size, bool strict)
{
	struct tnum reg_off;

	/* Byte size accesses are always allowed. */
	if (!strict || size == 1)
		return 0;

	reg_off = tnum_add(reg->var_off, tnum_const((s64)reg->off + off));
	if (!tnum_is_aligned(reg_off, size)) {
		char tn_buf[48];

		tnum_strn(tn_buf, sizeof(tn_buf), reg->var_off);
		verbose("misaligned %saccess off %s+%d+%d size %d\n",
			pointer_desc, tn_buf, reg->off, off, size);
		return -EACCES;
	}

	return 0;
}

static int check_ptr_alignment(struct bpf_verifier_env *env,
			       struct bpf_reg_state *reg, int off, int size)
{
	bool strict = env->strict_alignment;
	const char *pointer_desc = "";

	switch (reg->type) {
	case PTR_TO_PACKET:
		/* Sockopt buffers are kmalloc-aligned, unlike packet L3 data. */
		if (env->prog->type == BPF_PROG_TYPE_CGROUP_SOCKOPT)
			return check_generic_ptr_alignment(reg, "sockopt ", off,
						   size, strict);
		/* special case, because of NET_IP_ALIGN */
		return check_pkt_ptr_alignment(reg, off, size, strict);
	case PTR_TO_MAP_VALUE:
		pointer_desc = "value ";
		break;
	case PTR_TO_CTX:
		pointer_desc = "context ";
		break;
	case PTR_TO_STACK:
		strict = true;
		pointer_desc = "stack ";
		break;
	default:
		break;
	}
	return check_generic_ptr_alignment(reg, pointer_desc, off, size, strict);
}

/* check whether memory at (regno + off) is accessible for t = (read | write)
 * if t==write, value_regno is a register which value is stored into memory
 * if t==read, value_regno is a register which will receive the value from memory
 * if t==write && value_regno==-1, some unknown value is stored into memory
 * if t==read && value_regno==-1, don't care what we read from memory
 */
static int check_mem_access(struct bpf_verifier_env *env, int insn_idx, u32 regno, int off,
			    int bpf_size, enum bpf_access_type t,
			    int value_regno)
{
	struct bpf_verifier_state *state = &env->cur_state;
	struct bpf_reg_state *reg = &state->regs[regno];
	int size, err = 0;
	s64 effective_off;

	size = bpf_size_to_bytes(bpf_size);
	if (size < 0)
		return size;

	/* alignment checks will add in reg->off themselves */
	err = check_ptr_alignment(env, reg, off, size);
	if (err)
		return err;

	/* for access checks, reg->off is just part of off */
	effective_off = (s64)off + reg->off;
	if (effective_off < INT_MIN || effective_off > INT_MAX)
		return -EACCES;
	off = effective_off;

	if (reg->type == PTR_TO_MAP_VALUE) {
		if (t == BPF_WRITE && value_regno >= 0 &&
		    is_pointer_value(env, value_regno)) {
			verbose("R%d leaks addr into map\n", value_regno);
			return -EACCES;
		}

		err = check_map_access(env, regno, off, size);
		if (!err && t == BPF_READ && value_regno >= 0)
			mark_reg_unknown(state->regs, value_regno);

	} else if (reg->type == PTR_TO_CTX) {
		enum bpf_reg_type reg_type = SCALAR_VALUE;

		if (t == BPF_WRITE && value_regno >= 0 &&
		    is_pointer_value(env, value_regno)) {
			verbose("R%d leaks addr into ctx\n", value_regno);
			return -EACCES;
		}
		/* ctx accesses must be at a fixed offset, so that we can
		 * determine what type of data were returned.
		 */
		if (!tnum_is_const(reg->var_off)) {
			char tn_buf[48];

			tnum_strn(tn_buf, sizeof(tn_buf), reg->var_off);
			verbose("variable ctx access var_off=%s off=%d size=%d",
				tn_buf, off, size);
			return -EACCES;
		}
		if (reg->off || reg->var_off.value)
			return -EACCES;
		err = check_ctx_access(env, insn_idx, off, size, t, &reg_type);
		if (!err && t == BPF_READ && value_regno >= 0) {
			/* ctx access returns either a scalar, or a
			 * PTR_TO_PACKET[_END].  In the latter case, we know
			 * the offset is zero.
			 */
			if (reg_type == SCALAR_VALUE)
				mark_reg_unknown(state->regs, value_regno);
			else
				mark_reg_known_zero(state->regs, value_regno);
			state->regs[value_regno].id = 0;
			state->regs[value_regno].off = 0;
			state->regs[value_regno].range = 0;
			state->regs[value_regno].type = reg_type;
			if (reg_type == PTR_TO_SOCK_COMMON_OR_NULL)
				state->regs[value_regno].id = ++env->id_gen;
		}

	} else if (reg->type == PTR_TO_STACK) {
		/* stack accesses must be at a fixed offset, so that we can
		 * determine what type of data were returned.
		 * See check_stack_read().
		 */
		if (!tnum_is_const(reg->var_off)) {
			char tn_buf[48];

			tnum_strn(tn_buf, sizeof(tn_buf), reg->var_off);
			verbose("variable stack access var_off=%s off=%d size=%d",
				tn_buf, off, size);
			return -EACCES;
		}
		effective_off = (s64)((u64)(s64)off + reg->var_off.value);
		if (effective_off >= 0 || effective_off < -MAX_BPF_STACK ||
		    effective_off + size > 0) {
			verbose("invalid stack off=%d size=%d\n", off, size);
			return -EACCES;
		}
		off = effective_off;
		if (t == BPF_WRITE) {
			if (!env->allow_ptr_leaks &&
			    state->stack_slot_type[MAX_BPF_STACK + off] == STACK_SPILL &&
			    size != BPF_REG_SIZE) {
				verbose("attempt to corrupt spilled pointer on stack\n");
				return -EACCES;
			}
			err = check_stack_write(env, state, off, size,
						value_regno, insn_idx);
		} else {
			err = check_stack_read(state, off, size, value_regno);
		}
	} else if (reg->type == PTR_TO_PACKET) {
		if (t == BPF_WRITE && !may_access_direct_pkt_data(env, NULL)) {
			verbose("cannot write into packet\n");
			return -EACCES;
		}
		if (t == BPF_WRITE && value_regno >= 0 &&
		    is_pointer_value(env, value_regno)) {
			verbose("R%d leaks addr into packet\n", value_regno);
			return -EACCES;
		}
		err = check_packet_access(env, regno, off, size);
		if (!err && t == BPF_READ && value_regno >= 0)
			mark_reg_unknown(state->regs, value_regno);
	} else if (reg->type == PTR_TO_SOCKET || reg->type == PTR_TO_SOCK_COMMON) {
		if (reg->off || !tnum_equals_const(reg->var_off, 0))
			return -EACCES;
		err = check_sock_access(off, size, t, reg->type);
		if (!err && value_regno >= 0)
			mark_reg_unknown(state->regs, value_regno);
	} else {
		verbose("R%d invalid mem access '%s'\n",
			regno, reg_type_str[reg->type]);
		return -EACCES;
	}

	if (!err && size < BPF_REG_SIZE && value_regno >= 0 && t == BPF_READ &&
	    state->regs[value_regno].type == SCALAR_VALUE) {
		/* b/h/w load zero-extends, mark upper bits as known 0 */
		state->regs[value_regno].var_off = tnum_cast(
					state->regs[value_regno].var_off, size);
		__update_reg_bounds(&state->regs[value_regno]);
	}
	return err;
}

static int check_xadd(struct bpf_verifier_env *env, int insn_idx, struct bpf_insn *insn)
{
	struct bpf_reg_state *regs = env->cur_state.regs;
	int err;

	if ((BPF_SIZE(insn->code) != BPF_W && BPF_SIZE(insn->code) != BPF_DW) ||
	    insn->imm != 0) {
		verbose("BPF_XADD uses reserved fields\n");
		return -EINVAL;
	}

	/* check src1 operand */
	err = check_reg_arg(regs, insn->src_reg, SRC_OP);
	if (err)
		return err;

	/* check src2 operand */
	err = check_reg_arg(regs, insn->dst_reg, SRC_OP);
	if (err)
		return err;

	if (is_ctx_reg(env, insn->dst_reg)) {
		verbose("BPF_XADD stores into R%d context is not allowed\n",
			insn->dst_reg);
		return -EACCES;
	}

	if (is_pointer_value(env, insn->src_reg)) {
		verbose("R%d leaks addr into mem\n", insn->src_reg);
		return -EACCES;
	}

	/* check whether atomic_add can read the memory */
	err = check_mem_access(env, insn_idx, insn->dst_reg, insn->off,
			       BPF_SIZE(insn->code), BPF_READ, -1);
	if (err)
		return err;

	/* check whether atomic_add can write into the same memory */
	return check_mem_access(env, insn_idx, insn->dst_reg, insn->off,
				BPF_SIZE(insn->code), BPF_WRITE, -1);
}

/* Does this register contain a constant zero? */
static bool register_is_null(struct bpf_reg_state reg)
{
	return reg.type == SCALAR_VALUE && tnum_equals_const(reg.var_off, 0);
}

/* when register 'regno' is passed into function that will read 'access_size'
 * bytes from that pointer, make sure that it's within stack boundary
 * and all elements of stack are initialized.
 * Unlike most pointer bounds-checking functions, this one doesn't take an
 * 'off' argument, so it has to add in reg->off itself.
 */
static int check_stack_boundary(struct bpf_verifier_env *env, int regno,
				int access_size, bool zero_size_allowed,
				struct bpf_call_arg_meta *meta)
{
	struct bpf_verifier_state *state = &env->cur_state;
	struct bpf_reg_state *regs = state->regs;
	s64 off;
	int i;

	if (regs[regno].type != PTR_TO_STACK) {
		/* Allow zero-byte read from NULL, regardless of pointer type */
		if (zero_size_allowed && access_size == 0 &&
		    register_is_null(regs[regno]))
			return 0;

		verbose("R%d type=%s expected=%s\n", regno,
			reg_type_str[regs[regno].type],
			reg_type_str[PTR_TO_STACK]);
		return -EACCES;
	}

	/* Only allow fixed-offset stack reads */
	if (!tnum_is_const(regs[regno].var_off)) {
		char tn_buf[48];

		tnum_strn(tn_buf, sizeof(tn_buf), regs[regno].var_off);
		verbose("invalid variable stack read R%d var_off=%s\n",
			regno, tn_buf);
		return -EACCES;
	}
	off = (s64)((u64)(s64)regs[regno].off + regs[regno].var_off.value);
	if (off >= 0 || off < -MAX_BPF_STACK || off + access_size > 0 ||
	    access_size < 0 || (access_size == 0 && !zero_size_allowed)) {
		verbose("invalid stack type R%d off=%lld access_size=%d\n",
			regno, (long long)off, access_size);
		return -EACCES;
	}

	if (meta && meta->raw_mode) {
		meta->access_size = access_size;
		meta->regno = regno;
		return 0;
	}

	for (i = 0; i < access_size; i++) {
		if (state->stack_slot_type[MAX_BPF_STACK + off + i] != STACK_MISC) {
			verbose("invalid indirect read from stack off %lld+%d size %d\n",
				(long long)off, i, access_size);
			return -EACCES;
		}
	}
	return 0;
}

static int check_helper_mem_access(struct bpf_verifier_env *env, int regno,
				   int access_size, bool zero_size_allowed,
				   struct bpf_call_arg_meta *meta)
{
	struct bpf_reg_state *regs = env->cur_state.regs, *reg = &regs[regno];

	switch (reg->type) {
	case PTR_TO_PACKET:
		return check_packet_access(env, regno, reg->off, access_size);
	case PTR_TO_MAP_VALUE:
		return check_map_access(env, regno, reg->off, access_size);
	default: /* scalar_value|ptr_to_stack or invalid ptr */
		return check_stack_boundary(env, regno, access_size,
					    zero_size_allowed, meta);
	}
}

static int check_func_arg(struct bpf_verifier_env *env, u32 regno,
			  enum bpf_arg_type arg_type,
			  struct bpf_call_arg_meta *meta)
{
	struct bpf_reg_state *regs = env->cur_state.regs, *reg = &regs[regno];
	enum bpf_reg_type expected_type, type = reg->type;
	int err = 0;

	if (arg_type == ARG_DONTCARE)
		return 0;

	if (type == NOT_INIT) {
		verbose("R%d !read_ok\n", regno);
		return -EACCES;
	}

	if (arg_type == ARG_ANYTHING) {
		if (is_pointer_value(env, regno)) {
			verbose("R%d leaks addr into helper function\n", regno);
			return -EACCES;
		}
		return 0;
	}

	if (type == PTR_TO_PACKET && !may_access_direct_pkt_data(env, meta)) {
		verbose("helper access to the packet is not allowed\n");
		return -EACCES;
	}

	if (arg_type == ARG_PTR_TO_MAP_KEY ||
	    arg_type == ARG_PTR_TO_MAP_VALUE) {
		expected_type = PTR_TO_STACK;
		if (type != PTR_TO_PACKET && type != expected_type)
			goto err_type;
	} else if (arg_type == ARG_CONST_SIZE ||
		   arg_type == ARG_CONST_SIZE_OR_ZERO) {
		expected_type = SCALAR_VALUE;
		if (type != expected_type)
			goto err_type;
	} else if (arg_type == ARG_CONST_MAP_PTR) {
		expected_type = CONST_PTR_TO_MAP;
		if (type != expected_type)
			goto err_type;
	} else if (arg_type == ARG_PTR_TO_CTX) {
		expected_type = PTR_TO_CTX;
		if (type != expected_type)
			goto err_type;
	} else if (arg_type == ARG_PTR_TO_SOCK_COMMON) {
		expected_type = PTR_TO_SOCK_COMMON;
		if (type != PTR_TO_SOCK_COMMON && type != PTR_TO_SOCKET)
			goto err_type;
	} else if (arg_type == ARG_PTR_TO_SOCKET) {
		expected_type = PTR_TO_SOCKET;
		if (type != expected_type)
			goto err_type;
	} else if (arg_type == ARG_PTR_TO_MEM ||
		   arg_type == ARG_PTR_TO_UNINIT_MEM) {
		expected_type = PTR_TO_STACK;
		/* One exception here. In case function allows for NULL to be
		 * passed in as argument, it's a SCALAR_VALUE type. Final test
		 * happens during stack boundary checking.
		 */
		if (register_is_null(*reg))
			/* final test in check_stack_boundary() */;
		else if (type != PTR_TO_PACKET && type != PTR_TO_MAP_VALUE &&
			 type != expected_type)
			goto err_type;
		meta->raw_mode = arg_type == ARG_PTR_TO_UNINIT_MEM;
	} else {
		verbose("unsupported arg_type %d\n", arg_type);
		return -EFAULT;
	}

	if (arg_type == ARG_CONST_MAP_PTR) {
		/* bpf_map_xxx(map_ptr) call: remember that map_ptr */
		meta->map_ptr = reg->map_ptr;
	} else if (arg_type == ARG_PTR_TO_MAP_KEY) {
		/* bpf_map_xxx(..., map_ptr, ..., key) call:
		 * check that [key, key + map->key_size) are within
		 * stack limits and initialized
		 */
		if (!meta->map_ptr) {
			/* in function declaration map_ptr must come before
			 * map_key, so that it's verified and known before
			 * we have to check map_key here. Otherwise it means
			 * that kernel subsystem misconfigured verifier
			 */
			verbose("invalid map_ptr to access map->key\n");
			return -EACCES;
		}
		if (type == PTR_TO_PACKET)
			err = check_packet_access(env, regno, reg->off,
						  meta->map_ptr->key_size);
		else
			err = check_stack_boundary(env, regno,
						   meta->map_ptr->key_size,
						   false, NULL);
	} else if (arg_type == ARG_PTR_TO_MAP_VALUE) {
		/* bpf_map_xxx(..., map_ptr, ..., value) call:
		 * check [value, value + map->value_size) validity
		 */
		if (!meta->map_ptr) {
			/* kernel subsystem misconfigured verifier */
			verbose("invalid map_ptr to access map->value\n");
			return -EACCES;
		}
		if (type == PTR_TO_PACKET)
			err = check_packet_access(env, regno, reg->off,
						  meta->map_ptr->value_size);
		else
			err = check_stack_boundary(env, regno,
						   meta->map_ptr->value_size,
						   false, NULL);
	} else if (arg_type == ARG_CONST_SIZE ||
		   arg_type == ARG_CONST_SIZE_OR_ZERO) {
		bool zero_size_allowed = (arg_type == ARG_CONST_SIZE_OR_ZERO);

		/* bpf_xxx(..., buf, len) call will access 'len' bytes
		 * from stack pointer 'buf'. Check it
		 * note: regno == len, regno - 1 == buf
		 */
		if (regno == 0) {
			/* kernel subsystem misconfigured verifier */
			verbose("ARG_CONST_SIZE cannot be first argument\n");
			return -EACCES;
		}

		/* The register is SCALAR_VALUE; the access check
		 * happens using its boundaries.
		 */

		if (!tnum_is_const(reg->var_off))
			/* For unprivileged variable accesses, disable raw
			 * mode so that the program is required to
			 * initialize all the memory that the helper could
			 * just partially fill up.
			 */
			meta = NULL;

		if (reg->smin_value < 0) {
			verbose("R%d min value is negative, either use unsigned or 'var &= const'\n",
				regno);
			return -EACCES;
		}

		if (reg->umin_value == 0) {
			err = check_helper_mem_access(env, regno - 1, 0,
						      zero_size_allowed,
						      meta);
			if (err)
				return err;
		}

		if (reg->umax_value >= BPF_MAX_VAR_SIZ) {
			verbose("R%d unbounded memory access, use 'var &= const' or 'if (var < const)'\n",
				regno);
			return -EACCES;
		}
		err = check_helper_mem_access(env, regno - 1,
					      reg->umax_value,
					      zero_size_allowed, meta);
	}

	return err;
err_type:
	verbose("R%d type=%s expected=%s\n", regno,
		reg_type_str[type], reg_type_str[expected_type]);
	return -EACCES;
}

static int check_map_func_compatibility(struct bpf_map *map, int func_id)
{
	if (!map)
		return 0;

	/* We need a two way check, first is from map perspective ... */
	switch (map->map_type) {
	case BPF_MAP_TYPE_PROG_ARRAY:
		if (func_id != BPF_FUNC_tail_call)
			goto error;
		break;
	case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
		if (func_id != BPF_FUNC_perf_event_read &&
		    func_id != BPF_FUNC_perf_event_output)
			goto error;
		break;
	case BPF_MAP_TYPE_STACK_TRACE:
		if (func_id != BPF_FUNC_get_stackid)
			goto error;
		break;
	case BPF_MAP_TYPE_CGROUP_ARRAY:
		if (func_id != BPF_FUNC_skb_under_cgroup)
			goto error;
		break;
	case BPF_MAP_TYPE_ARRAY_OF_MAPS:
	case BPF_MAP_TYPE_HASH_OF_MAPS:
		if (func_id != BPF_FUNC_map_lookup_elem)
			goto error;
		break;
	default:
		break;
	}

	/* ... and second from the function itself. */
	switch (func_id) {
	case BPF_FUNC_tail_call:
		if (map->map_type != BPF_MAP_TYPE_PROG_ARRAY)
			goto error;
		break;
	case BPF_FUNC_perf_event_read:
	case BPF_FUNC_perf_event_output:
		if (map->map_type != BPF_MAP_TYPE_PERF_EVENT_ARRAY)
			goto error;
		break;
	case BPF_FUNC_get_stackid:
		if (map->map_type != BPF_MAP_TYPE_STACK_TRACE)
			goto error;
		break;
	case BPF_FUNC_skb_under_cgroup:
		if (map->map_type != BPF_MAP_TYPE_CGROUP_ARRAY)
			goto error;
		break;
	default:
		break;
	}

	return 0;
error:
	verbose("cannot pass map_type %d into func %d\n",
		map->map_type, func_id);
	return -EINVAL;
}

static int check_raw_mode(const struct bpf_func_proto *fn)
{
	int count = 0;

	if (fn->arg1_type == ARG_PTR_TO_UNINIT_MEM)
		count++;
	if (fn->arg2_type == ARG_PTR_TO_UNINIT_MEM)
		count++;
	if (fn->arg3_type == ARG_PTR_TO_UNINIT_MEM)
		count++;
	if (fn->arg4_type == ARG_PTR_TO_UNINIT_MEM)
		count++;
	if (fn->arg5_type == ARG_PTR_TO_UNINIT_MEM)
		count++;

	return count > 1 ? -EINVAL : 0;
}

/* Packet data might have moved, any old PTR_TO_PACKET[_END] are now invalid,
 * so turn them into unknown SCALAR_VALUE.
 */
static void clear_all_pkt_pointers(struct bpf_verifier_env *env)
{
	struct bpf_verifier_state *state = &env->cur_state;
	struct bpf_reg_state *regs = state->regs, *reg;
	int i;

	for (i = 0; i < MAX_BPF_REG; i++)
		if (regs[i].type == PTR_TO_PACKET ||
		    regs[i].type == PTR_TO_PACKET_END)
			mark_reg_unknown(regs, i);

	for (i = 0; i < MAX_BPF_STACK; i += BPF_REG_SIZE) {
		if (state->stack_slot_type[i] != STACK_SPILL)
			continue;
		reg = &state->spilled_regs[i / BPF_REG_SIZE];
		if (reg->type != PTR_TO_PACKET &&
		    reg->type != PTR_TO_PACKET_END)
			continue;
		__mark_reg_unknown(reg);
	}
}

static int check_call(struct bpf_verifier_env *env, int func_id, int insn_idx)
{
	struct bpf_verifier_state *state = &env->cur_state;
	const struct bpf_func_proto *fn = NULL;
	struct bpf_reg_state *regs = state->regs;
	struct bpf_reg_state *reg;
	struct bpf_call_arg_meta meta;
	bool changes_data;
	int i, err;

	/* find function prototype */
	if (func_id < 0 || func_id >= __BPF_FUNC_MAX_ID) {
		verbose("invalid func %d\n", func_id);
		return -EINVAL;
	}

	if (env->prog->aux->ops->get_func_proto)
		fn = env->prog->aux->ops->get_func_proto(func_id, env->prog);

	if (!fn) {
		verbose("unknown func %d\n", func_id);
		return -EINVAL;
	}

	/* eBPF programs must be GPL compatible to use GPL-ed functions */
	if (!env->prog->gpl_compatible && fn->gpl_only) {
		verbose("cannot call GPL only function from proprietary program\n");
		return -EINVAL;
	}

	changes_data = bpf_helper_changes_skb_data(fn->func);

	memset(&meta, 0, sizeof(meta));
	meta.pkt_access = fn->pkt_access;

	/* We only support one arg being in raw mode at the moment, which
	 * is sufficient for the helper functions we have right now.
	 */
	err = check_raw_mode(fn);
	if (err) {
		verbose("kernel subsystem misconfigured func %d\n", func_id);
		return err;
	}

	/* check args */
	err = check_func_arg(env, BPF_REG_1, fn->arg1_type, &meta);
	if (err)
		return err;
	err = check_func_arg(env, BPF_REG_2, fn->arg2_type, &meta);
	if (err)
		return err;
	if (func_id == BPF_FUNC_tail_call) {
		if (meta.map_ptr == NULL) {
			verbose("verifier bug\n");
			return -EINVAL;
		}
		env->insn_aux_data[insn_idx].map_ptr = meta.map_ptr;
	}
	err = check_func_arg(env, BPF_REG_3, fn->arg3_type, &meta);
	if (err)
		return err;
	err = check_func_arg(env, BPF_REG_4, fn->arg4_type, &meta);
	if (err)
		return err;
	err = check_func_arg(env, BPF_REG_5, fn->arg5_type, &meta);
	if (err)
		return err;

	/* Mark slots with STACK_MISC in case of raw mode, stack offset
	 * is inferred from register state.
	 */
	for (i = 0; i < meta.access_size; i++) {
		err = check_mem_access(env, insn_idx, meta.regno, i, BPF_B, BPF_WRITE, -1);
		if (err)
			return err;
	}

	/* reset caller saved regs */
	for (i = 0; i < CALLER_SAVED_REGS; i++) {
		reg = regs + caller_saved[i];
		__mark_reg_not_init(reg);
	}

	/* update return register */
	if (fn->ret_type == RET_INTEGER) {
		/* sets type to SCALAR_VALUE */
		mark_reg_unknown(regs, BPF_REG_0);
	} else if (fn->ret_type == RET_VOID) {
		regs[BPF_REG_0].type = NOT_INIT;
	} else if (fn->ret_type == RET_PTR_TO_MAP_VALUE_OR_NULL) {
		regs[BPF_REG_0].type = PTR_TO_MAP_VALUE_OR_NULL;
		/* There is no offset yet applied, variable or fixed */
		mark_reg_known_zero(regs, BPF_REG_0);
		regs[BPF_REG_0].off = 0;
		/* remember map_ptr, so that check_map_access()
		 * can check 'value_size' boundary of memory access
		 * to map element returned from bpf_map_lookup_elem()
		 */
		if (meta.map_ptr == NULL) {
			verbose("kernel subsystem misconfigured verifier\n");
			return -EINVAL;
		}
		regs[BPF_REG_0].map_ptr = meta.map_ptr;
		regs[BPF_REG_0].id = ++env->id_gen;
	} else if (fn->ret_type == RET_PTR_TO_SOCKET_OR_NULL) {
		mark_reg_unknown(regs, BPF_REG_0);
		mark_reg_known_zero(regs, BPF_REG_0);
		regs[BPF_REG_0].type = PTR_TO_SOCKET_OR_NULL;
		regs[BPF_REG_0].id = ++env->id_gen;
	} else {
		verbose("unknown return type %d of func %d\n",
			fn->ret_type, func_id);
		return -EINVAL;
	}

	err = check_map_func_compatibility(meta.map_ptr, func_id);
	if (err)
		return err;

	if (changes_data)
		clear_all_pkt_pointers(env);
	return 0;
}

static void coerce_reg_to_32(struct bpf_reg_state *reg)
{
	u64 mask = U32_MAX;

	reg->var_off = tnum_cast(reg->var_off, 4);
	if ((reg->umin_value & ~mask) == (reg->umax_value & ~mask)) {
		reg->umin_value &= mask;
		reg->umax_value &= mask;
	} else {
		reg->umin_value = 0;
		reg->umax_value = mask;
	}
	reg->smin_value = reg->umin_value;
	reg->smax_value = reg->umax_value;
}

static bool signed_add_overflows(s64 a, s64 b)
{
	/* Do the add in u64, where overflow is well-defined */
	s64 res = (s64)((u64)a + (u64)b);

	if (b < 0)
		return res > a;
	return res < a;
}

static bool signed_sub_overflows(s64 a, s64 b)
{
	/* Do the sub in u64, where overflow is well-defined */
	s64 res = (s64)((u64)a - (u64)b);

	if (b < 0)
		return res < a;
	return res > a;
}

/* Handles arithmetic on a pointer and a scalar: computes new min/max and var_off.
 * Caller should also handle BPF_MOV case separately.
 * If we return -EACCES, caller may want to try again treating pointer as a
 * scalar.  So we only emit a diagnostic if !env->allow_ptr_leaks.
 */
static int adjust_ptr_min_max_vals(struct bpf_verifier_env *env,
				   struct bpf_insn *insn,
				   const struct bpf_reg_state *ptr_reg,
				   const struct bpf_reg_state *off_reg)
{
	struct bpf_reg_state *regs = env->cur_state.regs, *dst_reg;
	bool known = tnum_is_const(off_reg->var_off);
	s64 smin_val = off_reg->smin_value, smax_val = off_reg->smax_value,
	    smin_ptr = ptr_reg->smin_value, smax_ptr = ptr_reg->smax_value;
	u64 umin_val = off_reg->umin_value, umax_val = off_reg->umax_value,
	    umin_ptr = ptr_reg->umin_value, umax_ptr = ptr_reg->umax_value;
	u8 opcode = BPF_OP(insn->code);
	u32 dst = insn->dst_reg;

	dst_reg = &regs[dst];

	if (WARN_ON_ONCE(known && (smin_val != smax_val))) {
		print_verifier_state(&env->cur_state);
		verbose("verifier internal error: known but bad sbounds\n");
		return -EINVAL;
	}
	if (WARN_ON_ONCE(known && (umin_val != umax_val))) {
		print_verifier_state(&env->cur_state);
		verbose("verifier internal error: known but bad ubounds\n");
		return -EINVAL;
	}

	if (BPF_CLASS(insn->code) != BPF_ALU64) {
		/* 32-bit ALU ops on pointers produce (meaningless) scalars */
		if (!env->allow_ptr_leaks)
			verbose("R%d 32-bit pointer arithmetic prohibited\n",
				dst);
		return -EACCES;
	}

	if (ptr_reg->type == PTR_TO_CTX ||
	    ptr_reg->type == PTR_TO_SOCKET ||
	    ptr_reg->type == PTR_TO_SOCKET_OR_NULL ||
	    ptr_reg->type == PTR_TO_SOCK_COMMON ||
	    ptr_reg->type == PTR_TO_SOCK_COMMON_OR_NULL) {
		verbose("R%d pointer arithmetic on %s prohibited\n",
			dst, reg_type_str[ptr_reg->type]);
		return -EACCES;
	}

	if (ptr_reg->type == PTR_TO_MAP_VALUE_OR_NULL) {
		if (!env->allow_ptr_leaks)
			verbose("R%d pointer arithmetic on PTR_TO_MAP_VALUE_OR_NULL prohibited, null-check it first\n",
				dst);
		return -EACCES;
	}
	if (ptr_reg->type == CONST_PTR_TO_MAP) {
		if (!env->allow_ptr_leaks)
			verbose("R%d pointer arithmetic on CONST_PTR_TO_MAP prohibited\n",
				dst);
		return -EACCES;
	}
	if (ptr_reg->type == PTR_TO_PACKET_END) {
		if (!env->allow_ptr_leaks)
			verbose("R%d pointer arithmetic on PTR_TO_PACKET_END prohibited\n",
				dst);
		return -EACCES;
	}

	/* In case of 'scalar += pointer', dst_reg inherits pointer type and id.
	 * The id may be overwritten later if we create a new variable offset.
	 */
	dst_reg->type = ptr_reg->type;
	dst_reg->id = ptr_reg->id;

	switch (opcode) {
	case BPF_ADD:
		/* We can take a fixed offset as long as it doesn't overflow
		 * the s32 'off' field
		 */
		if (known && !signed_add_overflows(ptr_reg->off, smin_val) &&
		    (ptr_reg->off + smin_val ==
			      (s64)(s32)(ptr_reg->off + smin_val))) {
			/* pointer += K.  Accumulate it into fixed offset */
			dst_reg->smin_value = smin_ptr;
			dst_reg->smax_value = smax_ptr;
			dst_reg->umin_value = umin_ptr;
			dst_reg->umax_value = umax_ptr;
			dst_reg->var_off = ptr_reg->var_off;
			dst_reg->off = ptr_reg->off + smin_val;
			dst_reg->range = ptr_reg->range;
			break;
		}
		/* A new variable offset is created.  Note that off_reg->off
		 * == 0, since it's a scalar.
		 * dst_reg gets the pointer type and since some positive
		 * integer value was added to the pointer, give it a new 'id'
		 * if it's a PTR_TO_PACKET.
		 * this creates a new 'base' pointer, off_reg (variable) gets
		 * added into the variable offset, and we copy the fixed offset
		 * from ptr_reg.
		 */
		if (signed_add_overflows(smin_ptr, smin_val) ||
		    signed_add_overflows(smax_ptr, smax_val)) {
			dst_reg->smin_value = S64_MIN;
			dst_reg->smax_value = S64_MAX;
		} else {
			dst_reg->smin_value = smin_ptr + smin_val;
			dst_reg->smax_value = smax_ptr + smax_val;
		}
		if (umin_ptr + umin_val < umin_ptr ||
		    umax_ptr + umax_val < umax_ptr) {
			dst_reg->umin_value = 0;
			dst_reg->umax_value = U64_MAX;
		} else {
			dst_reg->umin_value = umin_ptr + umin_val;
			dst_reg->umax_value = umax_ptr + umax_val;
		}
		dst_reg->var_off = tnum_add(ptr_reg->var_off, off_reg->var_off);
		dst_reg->off = ptr_reg->off;
		if (ptr_reg->type == PTR_TO_PACKET) {
			dst_reg->id = ++env->id_gen;
			/* something was added to pkt_ptr, set range to zero */
			dst_reg->range = 0;
		}
		break;
	case BPF_SUB:
		if (dst_reg == off_reg) {
			/* scalar -= pointer.  Creates an unknown scalar */
			if (!env->allow_ptr_leaks)
				verbose("R%d tried to subtract pointer from scalar\n",
					dst);
			return -EACCES;
		}
		/* We don't allow subtraction from FP, because (according to
		 * test_verifier.c test "invalid fp arithmetic", JITs might not
		 * be able to deal with it.
		 */
		if (ptr_reg->type == PTR_TO_STACK) {
			if (!env->allow_ptr_leaks)
				verbose("R%d subtraction from stack pointer prohibited\n",
					dst);
			return -EACCES;
		}
		if (known && !signed_sub_overflows(ptr_reg->off, smin_val) &&
		    (ptr_reg->off - smin_val ==
			      (s64)(s32)(ptr_reg->off - smin_val))) {
			/* pointer -= K.  Subtract it from fixed offset */
			dst_reg->smin_value = smin_ptr;
			dst_reg->smax_value = smax_ptr;
			dst_reg->umin_value = umin_ptr;
			dst_reg->umax_value = umax_ptr;
			dst_reg->var_off = ptr_reg->var_off;
			dst_reg->id = ptr_reg->id;
			dst_reg->off = ptr_reg->off - smin_val;
			dst_reg->range = ptr_reg->range;
			break;
		}
		/* A new variable offset is created.  If the subtrahend is known
		 * nonnegative, then any reg->range we had before is still good.
		 */
		if (signed_sub_overflows(smin_ptr, smax_val) ||
		    signed_sub_overflows(smax_ptr, smin_val)) {
			/* Overflow possible, we know nothing */
			dst_reg->smin_value = S64_MIN;
			dst_reg->smax_value = S64_MAX;
		} else {
			dst_reg->smin_value = smin_ptr - smax_val;
			dst_reg->smax_value = smax_ptr - smin_val;
		}
		if (umin_ptr < umax_val) {
			/* Overflow possible, we know nothing */
			dst_reg->umin_value = 0;
			dst_reg->umax_value = U64_MAX;
		} else {
			/* Cannot overflow (as long as bounds are consistent) */
			dst_reg->umin_value = umin_ptr - umax_val;
			dst_reg->umax_value = umax_ptr - umin_val;
		}
		dst_reg->var_off = tnum_sub(ptr_reg->var_off, off_reg->var_off);
		dst_reg->off = ptr_reg->off;
		if (ptr_reg->type == PTR_TO_PACKET) {
			dst_reg->id = ++env->id_gen;
			/* something was added to pkt_ptr, set range to zero */
			if (smin_val < 0)
				dst_reg->range = 0;
		}
		break;
	case BPF_AND:
	case BPF_OR:
	case BPF_XOR:
		/* bitwise ops on pointers are troublesome, prohibit for now.
		 * (However, in principle we could allow some cases, e.g.
		 * ptr &= ~3 which would reduce min_value by 3.)
		 */
		if (!env->allow_ptr_leaks)
			verbose("R%d bitwise operator %s on pointer prohibited\n",
				dst, bpf_alu_string[opcode >> 4]);
		return -EACCES;
	default:
		/* other operators (e.g. MUL,LSH) produce non-pointer results */
		if (!env->allow_ptr_leaks)
			verbose("R%d pointer arithmetic with %s operator prohibited\n",
				dst, bpf_alu_string[opcode >> 4]);
		return -EACCES;
	}

	__update_reg_bounds(dst_reg);
	__reg_deduce_bounds(dst_reg);
	__reg_bound_offset(dst_reg);
	return 0;
}

static int adjust_scalar_min_max_vals(struct bpf_verifier_env *env,
				      struct bpf_insn *insn,
				      struct bpf_reg_state *dst_reg,
				      struct bpf_reg_state src_reg)
{
	struct bpf_reg_state *regs = env->cur_state.regs;
	u8 opcode = BPF_OP(insn->code);
	bool src_known, dst_known;
	s64 smin_val, smax_val;
	u64 umin_val, umax_val;
	u64 insn_bitness = BPF_CLASS(insn->code) == BPF_ALU64 ? 64 : 32;

	if (BPF_CLASS(insn->code) != BPF_ALU64) {
		/* 32-bit ALU ops are (32,32)->64 */
		coerce_reg_to_32(dst_reg);
		coerce_reg_to_32(&src_reg);
	}
	smin_val = src_reg.smin_value;
	smax_val = src_reg.smax_value;
	umin_val = src_reg.umin_value;
	umax_val = src_reg.umax_value;
	src_known = tnum_is_const(src_reg.var_off);
	dst_known = tnum_is_const(dst_reg->var_off);

	if ((src_known && (smin_val != smax_val || umin_val != umax_val)) ||
	    smin_val > smax_val || umin_val > umax_val) {
		__mark_reg_unknown(dst_reg);
		return 0;
	}
	if (!src_known &&
	    opcode != BPF_ADD && opcode != BPF_SUB && opcode != BPF_AND) {
		__mark_reg_unknown(dst_reg);
		return 0;
	}

	switch (opcode) {
	case BPF_ADD:
		if (signed_add_overflows(dst_reg->smin_value, smin_val) ||
		    signed_add_overflows(dst_reg->smax_value, smax_val)) {
			dst_reg->smin_value = S64_MIN;
			dst_reg->smax_value = S64_MAX;
		} else {
			dst_reg->smin_value += smin_val;
			dst_reg->smax_value += smax_val;
		}
		if (dst_reg->umin_value + umin_val < umin_val ||
		    dst_reg->umax_value + umax_val < umax_val) {
			dst_reg->umin_value = 0;
			dst_reg->umax_value = U64_MAX;
		} else {
			dst_reg->umin_value += umin_val;
			dst_reg->umax_value += umax_val;
		}
		dst_reg->var_off = tnum_add(dst_reg->var_off, src_reg.var_off);
		break;
	case BPF_SUB:
		if (signed_sub_overflows(dst_reg->smin_value, smax_val) ||
		    signed_sub_overflows(dst_reg->smax_value, smin_val)) {
			/* Overflow possible, we know nothing */
			dst_reg->smin_value = S64_MIN;
			dst_reg->smax_value = S64_MAX;
		} else {
			dst_reg->smin_value -= smax_val;
			dst_reg->smax_value -= smin_val;
		}
		if (dst_reg->umin_value < umax_val) {
			/* Overflow possible, we know nothing */
			dst_reg->umin_value = 0;
			dst_reg->umax_value = U64_MAX;
		} else {
			/* Cannot overflow (as long as bounds are consistent) */
			dst_reg->umin_value -= umax_val;
			dst_reg->umax_value -= umin_val;
		}
		dst_reg->var_off = tnum_sub(dst_reg->var_off, src_reg.var_off);
		break;
	case BPF_MUL:
		dst_reg->var_off = tnum_mul(dst_reg->var_off, src_reg.var_off);
		if (smin_val < 0 || dst_reg->smin_value < 0) {
			/* Ain't nobody got time to multiply that sign */
			__mark_reg_unbounded(dst_reg);
			__update_reg_bounds(dst_reg);
			break;
		}
		/* Both values are positive, so we can work with unsigned and
		 * copy the result to signed (unless it exceeds S64_MAX).
		 */
		if (umax_val > U32_MAX || dst_reg->umax_value > U32_MAX) {
			/* Potential overflow, we know nothing */
			__mark_reg_unbounded(dst_reg);
			/* (except what we can learn from the var_off) */
			__update_reg_bounds(dst_reg);
			break;
		}
		dst_reg->umin_value *= umin_val;
		dst_reg->umax_value *= umax_val;
		if (dst_reg->umax_value > S64_MAX) {
			/* Overflow possible, we know nothing */
			dst_reg->smin_value = S64_MIN;
			dst_reg->smax_value = S64_MAX;
		} else {
			dst_reg->smin_value = dst_reg->umin_value;
			dst_reg->smax_value = dst_reg->umax_value;
		}
		break;
	case BPF_AND:
		if (src_known && dst_known) {
			__mark_reg_known(dst_reg, dst_reg->var_off.value &
						  src_reg.var_off.value);
			break;
		}
		/* We get our minimum from the var_off, since that's inherently
		 * bitwise.  Our maximum is the minimum of the operands' maxima.
		 */
		dst_reg->var_off = tnum_and(dst_reg->var_off, src_reg.var_off);
		dst_reg->umin_value = dst_reg->var_off.value;
		dst_reg->umax_value = min(dst_reg->umax_value, umax_val);
		if (dst_reg->smin_value < 0 || smin_val < 0) {
			/* Lose signed bounds when ANDing negative numbers,
			 * ain't nobody got time for that.
			 */
			dst_reg->smin_value = S64_MIN;
			dst_reg->smax_value = S64_MAX;
		} else {
			/* ANDing two positives gives a positive, so safe to
			 * cast result into s64.
			 */
			dst_reg->smin_value = dst_reg->umin_value;
			dst_reg->smax_value = dst_reg->umax_value;
		}
		/* We may learn something more from the var_off */
		__update_reg_bounds(dst_reg);
		break;
	case BPF_OR:
		if (src_known && dst_known) {
			__mark_reg_known(dst_reg, dst_reg->var_off.value |
						  src_reg.var_off.value);
			break;
		}
		/* We get our maximum from the var_off, and our minimum is the
		 * maximum of the operands' minima
		 */
		dst_reg->var_off = tnum_or(dst_reg->var_off, src_reg.var_off);
		dst_reg->umin_value = max(dst_reg->umin_value, umin_val);
		dst_reg->umax_value = dst_reg->var_off.value |
				      dst_reg->var_off.mask;
		if (dst_reg->smin_value < 0 || smin_val < 0) {
			/* Lose signed bounds when ORing negative numbers,
			 * ain't nobody got time for that.
			 */
			dst_reg->smin_value = S64_MIN;
			dst_reg->smax_value = S64_MAX;
		} else {
			/* ORing two positives gives a positive, so safe to
			 * cast result into s64.
			 */
			dst_reg->smin_value = dst_reg->umin_value;
			dst_reg->smax_value = dst_reg->umax_value;
		}
		/* We may learn something more from the var_off */
		__update_reg_bounds(dst_reg);
		break;
	case BPF_LSH:
		if (umax_val >= insn_bitness) {
			/* Shifts outside the instruction width are undefined. This includes
			 * shifts by a negative number.
			 */
			mark_reg_unknown(regs, insn->dst_reg);
			break;
		}
		/* We lose all sign bit information (except what we can pick
		 * up from var_off)
		 */
		dst_reg->smin_value = S64_MIN;
		dst_reg->smax_value = S64_MAX;
		/* If we might shift our top bit out, then we know nothing */
		if (dst_reg->umax_value > 1ULL << (63 - umax_val)) {
			dst_reg->umin_value = 0;
			dst_reg->umax_value = U64_MAX;
		} else {
			dst_reg->umin_value <<= umin_val;
			dst_reg->umax_value <<= umax_val;
		}
		if (src_known)
			dst_reg->var_off = tnum_lshift(dst_reg->var_off, umin_val);
		else
			dst_reg->var_off = tnum_lshift(tnum_unknown, umin_val);
		/* We may learn something more from the var_off */
		__update_reg_bounds(dst_reg);
		break;
	case BPF_RSH:
		if (umax_val >= insn_bitness) {
			/* Shifts outside the instruction width are undefined. This includes
			 * shifts by a negative number.
			 */
			mark_reg_unknown(regs, insn->dst_reg);
			break;
		}
		/* Unsigned shift changes sign information; infer it from the
		 * resulting bits and unsigned bounds instead.
		 */
		dst_reg->smin_value = S64_MIN;
		dst_reg->smax_value = S64_MAX;
		if (src_known)
			dst_reg->var_off = tnum_rshift(dst_reg->var_off,
						       umin_val);
		else
			dst_reg->var_off = tnum_rshift(tnum_unknown, umin_val);
		dst_reg->umin_value >>= umax_val;
		dst_reg->umax_value >>= umin_val;
		/* We may learn something more from the var_off */
		__update_reg_bounds(dst_reg);
		break;
	default:
		mark_reg_unknown(regs, insn->dst_reg);
		break;
	}

	if (BPF_CLASS(insn->code) != BPF_ALU64)
		coerce_reg_to_32(dst_reg);

	__reg_deduce_bounds(dst_reg);
	__reg_bound_offset(dst_reg);
	return 0;
}

/* Handles ALU ops other than BPF_END, BPF_NEG and BPF_MOV: computes new min/max
 * and var_off.
 */
static int adjust_reg_min_max_vals(struct bpf_verifier_env *env,
				   struct bpf_insn *insn)
{
	struct bpf_reg_state *regs = env->cur_state.regs, *dst_reg, *src_reg;
	struct bpf_reg_state *ptr_reg = NULL, off_reg = {0};
	u8 opcode = BPF_OP(insn->code);
	int rc;

	dst_reg = &regs[insn->dst_reg];
	src_reg = NULL;
	if (dst_reg->type != SCALAR_VALUE)
		ptr_reg = dst_reg;
	if (BPF_SRC(insn->code) == BPF_X) {
		src_reg = &regs[insn->src_reg];
		if (src_reg->type != SCALAR_VALUE) {
			if (dst_reg->type != SCALAR_VALUE) {
				/* Combining two pointers by any ALU op yields
				 * an arbitrary scalar.
				 */
				if (!env->allow_ptr_leaks) {
					verbose("R%d pointer %s pointer prohibited\n",
						insn->dst_reg,
						bpf_alu_string[opcode >> 4]);
					return -EACCES;
				}
				mark_reg_unknown(regs, insn->dst_reg);
				return 0;
			} else {
				/* scalar += pointer
				 * This is legal, but we have to reverse our
				 * src/dest handling in computing the range
				 */
				rc = adjust_ptr_min_max_vals(env, insn,
							     src_reg, dst_reg);
				if (rc == -EACCES && env->allow_ptr_leaks) {
					/* scalar += unknown scalar */
					__mark_reg_unknown(&off_reg);
					return adjust_scalar_min_max_vals(
							env, insn,
							dst_reg, off_reg);
				}
				return rc;
			}
		} else if (ptr_reg) {
			/* pointer += scalar */
			rc = adjust_ptr_min_max_vals(env, insn,
						     dst_reg, src_reg);
			if (rc == -EACCES && env->allow_ptr_leaks) {
				/* unknown scalar += scalar */
				__mark_reg_unknown(dst_reg);
				return adjust_scalar_min_max_vals(
						env, insn, dst_reg, *src_reg);
			}
			return rc;
		}
	} else {
		/* Pretend the src is a reg with a known value, since we only
		 * need to be able to read from this state.
		 */
		off_reg.type = SCALAR_VALUE;
		__mark_reg_known(&off_reg, insn->imm);
		src_reg = &off_reg;
		if (ptr_reg) { /* pointer += K */
			rc = adjust_ptr_min_max_vals(env, insn,
						     ptr_reg, src_reg);
			if (rc == -EACCES && env->allow_ptr_leaks) {
				/* unknown scalar += K */
				__mark_reg_unknown(dst_reg);
				return adjust_scalar_min_max_vals(
						env, insn, dst_reg, off_reg);
			}
			return rc;
		}
	}

	/* Got here implies adding two SCALAR_VALUEs */
	if (WARN_ON_ONCE(ptr_reg)) {
		print_verifier_state(&env->cur_state);
		verbose("verifier internal error: unexpected ptr_reg\n");
		return -EINVAL;
	}
	if (WARN_ON(!src_reg)) {
		print_verifier_state(&env->cur_state);
		verbose("verifier internal error: no src_reg\n");
		return -EINVAL;
	}
	return adjust_scalar_min_max_vals(env, insn, dst_reg, *src_reg);
}

/* check validity of 32-bit and 64-bit arithmetic operations */
static int check_alu_op(struct bpf_verifier_env *env, struct bpf_insn *insn)
{
	struct bpf_reg_state *regs = env->cur_state.regs;
	u8 opcode = BPF_OP(insn->code);
	int err;

	if (opcode == BPF_END || opcode == BPF_NEG) {
		if (opcode == BPF_NEG) {
			if (BPF_SRC(insn->code) != 0 ||
			    insn->src_reg != BPF_REG_0 ||
			    insn->off != 0 || insn->imm != 0) {
				verbose("BPF_NEG uses reserved fields\n");
				return -EINVAL;
			}
		} else {
			if (insn->src_reg != BPF_REG_0 || insn->off != 0 ||
			    (insn->imm != 16 && insn->imm != 32 && insn->imm != 64) ||
			    BPF_CLASS(insn->code) == BPF_ALU64) {
				verbose("BPF_END uses reserved fields\n");
				return -EINVAL;
			}
		}

		/* check src operand */
		err = check_reg_arg(regs, insn->dst_reg, SRC_OP);
		if (err)
			return err;

		if (is_pointer_value(env, insn->dst_reg)) {
			verbose("R%d pointer arithmetic prohibited\n",
				insn->dst_reg);
			return -EACCES;
		}

		/* check dest operand */
		err = check_reg_arg(regs, insn->dst_reg, DST_OP);
		if (err)
			return err;

	} else if (opcode == BPF_MOV) {

		if (BPF_SRC(insn->code) == BPF_X) {
			if (insn->imm != 0 || insn->off != 0) {
				verbose("BPF_MOV uses reserved fields\n");
				return -EINVAL;
			}

			/* check src operand */
			err = check_reg_arg(regs, insn->src_reg, SRC_OP);
			if (err)
				return err;
		} else {
			if (insn->src_reg != BPF_REG_0 || insn->off != 0) {
				verbose("BPF_MOV uses reserved fields\n");
				return -EINVAL;
			}
		}

		/* check dest operand, mark as required later */
		err = check_reg_arg(regs, insn->dst_reg, DST_OP_NO_MARK);
		if (err)
			return err;

		if (BPF_SRC(insn->code) == BPF_X) {
			struct bpf_reg_state *src_reg = regs + insn->src_reg;
			struct bpf_reg_state *dst_reg = regs + insn->dst_reg;

			if (BPF_CLASS(insn->code) == BPF_ALU64) {
				/* case: R1 = R2
				 * copy register state to dest reg
				 */
				*dst_reg = *src_reg;
			} else {
				/* R1 = (u32) R2 */
				if (is_pointer_value(env, insn->src_reg)) {
					verbose("R%d partial copy of pointer\n",
						insn->src_reg);
					return -EACCES;
				} else if (src_reg->type == SCALAR_VALUE) {
					*dst_reg = *src_reg;
				} else {
					mark_reg_unknown(regs, insn->dst_reg);
				}
				coerce_reg_to_32(dst_reg);
			}
		} else {
			/* case: R = imm
			 * remember the value we stored into this reg
			 */
			/* clear any state __mark_reg_known doesn't set */
			mark_reg_unknown(regs, insn->dst_reg);
			regs[insn->dst_reg].type = SCALAR_VALUE;
			if (BPF_CLASS(insn->code) == BPF_ALU64) {
				__mark_reg_known(regs + insn->dst_reg,
						 insn->imm);
			} else {
				__mark_reg_known(regs + insn->dst_reg,
						 (u32)insn->imm);
			}
		}

	} else if (opcode > BPF_END) {
		verbose("invalid BPF_ALU opcode %x\n", opcode);
		return -EINVAL;

	} else {	/* all other ALU ops: and, sub, xor, add, ... */

		if (BPF_SRC(insn->code) == BPF_X) {
			if (insn->imm != 0 || insn->off != 0) {
				verbose("BPF_ALU uses reserved fields\n");
				return -EINVAL;
			}
			/* check src1 operand */
			err = check_reg_arg(regs, insn->src_reg, SRC_OP);
			if (err)
				return err;
		} else {
			if (insn->src_reg != BPF_REG_0 || insn->off != 0) {
				verbose("BPF_ALU uses reserved fields\n");
				return -EINVAL;
			}
		}

		/* check src2 operand */
		err = check_reg_arg(regs, insn->dst_reg, SRC_OP);
		if (err)
			return err;

		if ((opcode == BPF_MOD || opcode == BPF_DIV) &&
		    BPF_SRC(insn->code) == BPF_K && insn->imm == 0) {
			verbose("div by zero\n");
			return -EINVAL;
		}

		if ((opcode == BPF_LSH || opcode == BPF_RSH ||
		     opcode == BPF_ARSH) && BPF_SRC(insn->code) == BPF_K) {
			int size = BPF_CLASS(insn->code) == BPF_ALU64 ? 64 : 32;

			if (insn->imm < 0 || insn->imm >= size) {
				verbose("invalid shift %d\n", insn->imm);
				return -EINVAL;
			}
		}

		/* check dest operand */
		err = check_reg_arg(regs, insn->dst_reg, DST_OP_NO_MARK);
		if (err)
			return err;

		return adjust_reg_min_max_vals(env, insn);
	}

	return 0;
}

static void find_good_pkt_pointers(struct bpf_verifier_state *state,
				   struct bpf_reg_state *dst_reg)
{
	struct bpf_reg_state *regs = state->regs, *reg;
	int i;

	if (dst_reg->off < 0)
		/* This doesn't give us any range */
		return;

	if (dst_reg->umax_value > MAX_PACKET_OFF ||
	    dst_reg->umax_value + dst_reg->off > MAX_PACKET_OFF)
		/* Risk of overflow.  For instance, ptr + (1<<63) may be less
		 * than pkt_end, but that's because it's also less than pkt.
		 */
		return;

	/* LLVM can generate two kind of checks:
	 *
	 * Type 1:
	 *
	 *   r2 = r3;
	 *   r2 += 8;
	 *   if (r2 > pkt_end) goto <handle exception>
	 *   <access okay>
	 *
	 *   Where:
	 *     r2 == dst_reg, pkt_end == src_reg
	 *     r2=pkt(id=n,off=8,r=0)
	 *     r3=pkt(id=n,off=0,r=0)
	 *
	 * Type 2:
	 *
	 *   r2 = r3;
	 *   r2 += 8;
	 *   if (pkt_end >= r2) goto <access okay>
	 *   <handle exception>
	 *
	 *   Where:
	 *     pkt_end == dst_reg, r2 == src_reg
	 *     r2=pkt(id=n,off=8,r=0)
	 *     r3=pkt(id=n,off=0,r=0)
	 *
	 * Find register r3 and mark its range as r3=pkt(id=n,off=0,r=8)
	 * so that range of bytes [r3, r3 + 8) is safe to access.
	 */

	/* If our ids match, then we must have the same max_value.  And we
	 * don't care about the other reg's fixed offset, since if it's too big
	 * the range won't allow anything.
	 * dst_reg->off is known < MAX_PACKET_OFF, therefore it fits in a u16.
	 */
	for (i = 0; i < MAX_BPF_REG; i++)
		if (regs[i].type == PTR_TO_PACKET && regs[i].id == dst_reg->id)
			/* keep the maximum range already checked */
			regs[i].range = max_t(u16, regs[i].range, dst_reg->off);

	for (i = 0; i < MAX_BPF_STACK; i += BPF_REG_SIZE) {
		if (state->stack_slot_type[i] != STACK_SPILL)
			continue;
		reg = &state->spilled_regs[i / BPF_REG_SIZE];
		if (reg->type == PTR_TO_PACKET && reg->id == dst_reg->id)
			reg->range = max_t(u16, reg->range, dst_reg->off);
	}
}

static int is_branch_taken(struct bpf_reg_state *reg, u64 val, u8 opcode,
			   bool is_jmp32)
{
	struct bpf_reg_state reg_lo;
	s64 sval;

	if (reg->type != SCALAR_VALUE)
		return -1;

	if (is_jmp32) {
		reg_lo = *reg;
		reg = &reg_lo;
		/* For JMP32, only low 32 bits are compared, coerce_reg_to_32
		 * could truncate high bits and update umin/umax according to
		 * information of low bits.
		 */
		coerce_reg_to_32(reg);
		/* smin/smax need special handling. For example, after coerce,
		 * if smin_value is 0x00000000ffffffffLL, the value is -1 when
		 * used as operand to JMP32. It is a negative number from s32's
		 * point of view, while it is a positive number when seen as
		 * s64. The smin/smax are kept as s64, therefore, when used with
		 * JMP32, they need to be transformed into s32, then sign
		 * extended back to s64.
		 *
		 * Also, smin/smax were copied from umin/umax. If umin/umax has
		 * different sign bit, then min/max relationship doesn't
		 * maintain after casting into s32, for this case, set smin/smax
		 * to safest range.
		 */
		if ((reg->umax_value ^ reg->umin_value) &
		    (1ULL << 31)) {
			reg->smin_value = S32_MIN;
			reg->smax_value = S32_MAX;
		}
		reg->smin_value = (s64)(s32)reg->smin_value;
		reg->smax_value = (s64)(s32)reg->smax_value;

		val = (u32)val;
		sval = (s64)(s32)val;
	} else {
		sval = (s64)val;
	}

	switch (opcode) {
	case BPF_JEQ:
		if (tnum_is_const(reg->var_off))
			return !!tnum_equals_const(reg->var_off, val);
		break;
	case BPF_JNE:
		if (tnum_is_const(reg->var_off))
			return !tnum_equals_const(reg->var_off, val);
		break;
	case BPF_JSET:
		if ((~reg->var_off.mask & reg->var_off.value) & val)
			return 1;
		if (!((reg->var_off.mask | reg->var_off.value) & val))
			return 0;
		break;
	case BPF_JGT:
		if (reg->umin_value > val)
			return 1;
		else if (reg->umax_value <= val)
			return 0;
		break;
	case BPF_JSGT:
		if (reg->smin_value > sval)
			return 1;
		else if (reg->smax_value < sval)
			return 0;
		break;
	case BPF_JLT:
		if (reg->umax_value < val)
			return 1;
		else if (reg->umin_value >= val)
			return 0;
		break;
	case BPF_JSLT:
		if (reg->smax_value < sval)
			return 1;
		else if (reg->smin_value >= sval)
			return 0;
		break;
	case BPF_JGE:
		if (reg->umin_value >= val)
			return 1;
		else if (reg->umax_value < val)
			return 0;
		break;
	case BPF_JSGE:
		if (reg->smin_value >= sval)
			return 1;
		else if (reg->smax_value < sval)
			return 0;
		break;
	case BPF_JLE:
		if (reg->umax_value <= val)
			return 1;
		else if (reg->umin_value > val)
			return 0;
		break;
	case BPF_JSLE:
		if (reg->smax_value <= sval)
			return 1;
		else if (reg->smin_value > sval)
			return 0;
		break;
	}

	return -1;
}

static u64 gen_hi_min(struct tnum var)
{
	return var.value & ~0xffffffffULL;
}

static u64 gen_hi_max(struct tnum var)
{
	return (var.value | var.mask) & ~0xffffffffULL;
}

static bool cmp_val_with_extended_s64(s64 sval, struct bpf_reg_state *reg)
{
	return ((s32)sval >= 0 &&
		reg->smin_value >= 0 && reg->smax_value <= S32_MAX) ||
	       ((s32)sval < 0 &&
		reg->smax_value <= 0 && reg->smin_value >= S32_MIN);
}

/* Adjusts the register min/max values in the case that the dst_reg is the
 * variable register that we are working on, and src_reg is a constant or we're
 * simply doing a BPF_K check.
 * In JEQ/JNE cases we also adjust the var_off values.
 */
static void reg_set_min_max(struct bpf_reg_state *true_reg,
			    struct bpf_reg_state *false_reg, u64 val,
			    u8 opcode, bool is_jmp32)
{
	s64 sval;

	/* If the dst_reg is a pointer, we can't learn anything about its
	 * variable offset from the compare (unless src_reg were a pointer into
	 * the same object, but we don't bother with that.
	 * Since false_reg and true_reg have the same type by construction, we
	 * only need to check one of them for pointerness.
	 */
	if (__is_pointer_value(false, false_reg))
		return;

	val = is_jmp32 ? (u32)val : val;
	sval = is_jmp32 ? (s64)(s32)val : (s64)val;

	switch (opcode) {
	case BPF_JEQ:
	case BPF_JNE:
	{
		struct bpf_reg_state *reg =
			opcode == BPF_JEQ ? true_reg : false_reg;

		/* For BPF_JEQ, if this is false we know nothing Jon Snow, but
		 * if it is true we know the value for sure. Likewise for
		 * BPF_JNE.
		 */
		if (is_jmp32) {
			u64 old_v = reg->var_off.value;
			u64 hi_mask = ~0xffffffffULL;

			reg->var_off.value = (old_v & hi_mask) | val;
			reg->var_off.mask &= hi_mask;
		} else {
			__mark_reg_known(reg, val);
		}
		break;
	}
	case BPF_JSET:
		false_reg->var_off = tnum_and(false_reg->var_off,
					      tnum_const(~val));
		if (is_power_of_2(val))
			true_reg->var_off = tnum_or(true_reg->var_off,
						    tnum_const(val));
		break;
	case BPF_JGE:
	case BPF_JGT:
	{
		u64 false_umax = opcode == BPF_JGT ? val    : val - 1;
		u64 true_umin = opcode == BPF_JGT ? val + 1 : val;

		if (is_jmp32) {
			false_umax += gen_hi_max(false_reg->var_off);
			true_umin += gen_hi_min(true_reg->var_off);
		}
		false_reg->umax_value = min(false_reg->umax_value, false_umax);
		true_reg->umin_value = max(true_reg->umin_value, true_umin);
		break;
	}
	case BPF_JSGE:
	case BPF_JSGT:
	{
		s64 false_smax = opcode == BPF_JSGT ? sval    : (s64)((u64)sval - 1);
		s64 true_smin = opcode == BPF_JSGT ? (s64)((u64)sval + 1) : sval;

		/* If the full s64 was not sign-extended from s32 then don't
		 * deduct further info.
		 */
		if (is_jmp32 && !cmp_val_with_extended_s64(sval, false_reg))
			break;
		false_reg->smax_value = min(false_reg->smax_value, false_smax);
		true_reg->smin_value = max(true_reg->smin_value, true_smin);
		break;
	}
	case BPF_JLE:
	case BPF_JLT:
	{
		u64 false_umin = opcode == BPF_JLT ? val    : val + 1;
		u64 true_umax = opcode == BPF_JLT ? val - 1 : val;

		if (is_jmp32) {
			false_umin += gen_hi_min(false_reg->var_off);
			true_umax += gen_hi_max(true_reg->var_off);
		}
		false_reg->umin_value = max(false_reg->umin_value, false_umin);
		true_reg->umax_value = min(true_reg->umax_value, true_umax);
		break;
	}
	case BPF_JSLE:
	case BPF_JSLT:
	{
		s64 false_smin = opcode == BPF_JSLT ? sval    : (s64)((u64)sval + 1);
		s64 true_smax = opcode == BPF_JSLT ? (s64)((u64)sval - 1) : sval;

		if (is_jmp32 && !cmp_val_with_extended_s64(sval, false_reg))
			break;
		false_reg->smin_value = max(false_reg->smin_value, false_smin);
		true_reg->smax_value = min(true_reg->smax_value, true_smax);
		break;
	}
	default:
		break;
	}

	__reg_deduce_bounds(false_reg);
	__reg_deduce_bounds(true_reg);
	/* We might have learned some bits from the bounds. */
	__reg_bound_offset(false_reg);
	__reg_bound_offset(true_reg);
	/* Intersecting with the old var_off might have improved our bounds
	 * slightly.  e.g. if umax was 0x7f...f and var_off was (0; 0xf...fc),
	 * then new var_off is (0; 0x7f...fc) which improves our umax.
	 */
	__update_reg_bounds(false_reg);
	__update_reg_bounds(true_reg);
}

/* Same as above, but for the case that dst_reg holds a constant and src_reg is
 * the variable reg.
 */
static void reg_set_min_max_inv(struct bpf_reg_state *true_reg,
				struct bpf_reg_state *false_reg, u64 val,
				u8 opcode, bool is_jmp32)
{
	s64 sval;

	if (__is_pointer_value(false, false_reg))
		return;

	val = is_jmp32 ? (u32)val : val;
	sval = is_jmp32 ? (s64)(s32)val : (s64)val;

	switch (opcode) {
	case BPF_JEQ:
	case BPF_JNE:
	{
		struct bpf_reg_state *reg =
			opcode == BPF_JEQ ? true_reg : false_reg;

		if (is_jmp32) {
			u64 old_v = reg->var_off.value;
			u64 hi_mask = ~0xffffffffULL;

			reg->var_off.value = (old_v & hi_mask) | val;
			reg->var_off.mask &= hi_mask;
		} else {
			__mark_reg_known(reg, val);
		}
		break;
	}
	case BPF_JSET:
		false_reg->var_off = tnum_and(false_reg->var_off,
					      tnum_const(~val));
		if (is_power_of_2(val))
			true_reg->var_off = tnum_or(true_reg->var_off,
						    tnum_const(val));
		break;
	case BPF_JGE:
	case BPF_JGT:
	{
		u64 false_umin = opcode == BPF_JGT ? val    : val + 1;
		u64 true_umax = opcode == BPF_JGT ? val - 1 : val;

		if (is_jmp32) {
			false_umin += gen_hi_min(false_reg->var_off);
			true_umax += gen_hi_max(true_reg->var_off);
		}
		false_reg->umin_value = max(false_reg->umin_value, false_umin);
		true_reg->umax_value = min(true_reg->umax_value, true_umax);
		break;
	}
	case BPF_JSGE:
	case BPF_JSGT:
	{
		s64 false_smin = opcode == BPF_JSGT ? sval    : (s64)((u64)sval + 1);
		s64 true_smax = opcode == BPF_JSGT ? (s64)((u64)sval - 1) : sval;

		if (is_jmp32 && !cmp_val_with_extended_s64(sval, false_reg))
			break;
		false_reg->smin_value = max(false_reg->smin_value, false_smin);
		true_reg->smax_value = min(true_reg->smax_value, true_smax);
		break;
	}
	case BPF_JLE:
	case BPF_JLT:
	{
		u64 false_umax = opcode == BPF_JLT ? val    : val - 1;
		u64 true_umin = opcode == BPF_JLT ? val + 1 : val;

		if (is_jmp32) {
			false_umax += gen_hi_max(false_reg->var_off);
			true_umin += gen_hi_min(true_reg->var_off);
		}
		false_reg->umax_value = min(false_reg->umax_value, false_umax);
		true_reg->umin_value = max(true_reg->umin_value, true_umin);
		break;
	}
	case BPF_JSLE:
	case BPF_JSLT:
	{
		s64 false_smax = opcode == BPF_JSLT ? sval    : (s64)((u64)sval - 1);
		s64 true_smin = opcode == BPF_JSLT ? (s64)((u64)sval + 1) : sval;

		if (is_jmp32 && !cmp_val_with_extended_s64(sval, false_reg))
			break;
		false_reg->smax_value = min(false_reg->smax_value, false_smax);
		true_reg->smin_value = max(true_reg->smin_value, true_smin);
		break;
	}
	default:
		break;
	}

	__reg_deduce_bounds(false_reg);
	__reg_deduce_bounds(true_reg);
	/* We might have learned some bits from the bounds. */
	__reg_bound_offset(false_reg);
	__reg_bound_offset(true_reg);
	/* Intersecting with the old var_off might have improved our bounds
	 * slightly.  e.g. if umax was 0x7f...f and var_off was (0; 0xf...fc),
	 * then new var_off is (0; 0x7f...fc) which improves our umax.
	 */
	__update_reg_bounds(false_reg);
	__update_reg_bounds(true_reg);
}

/* Regs are known to be equal, so intersect their min/max/var_off */
static void __reg_combine_min_max(struct bpf_reg_state *src_reg,
				  struct bpf_reg_state *dst_reg)
{
	src_reg->umin_value = dst_reg->umin_value = max(src_reg->umin_value,
							dst_reg->umin_value);
	src_reg->umax_value = dst_reg->umax_value = min(src_reg->umax_value,
							dst_reg->umax_value);
	src_reg->smin_value = dst_reg->smin_value = max(src_reg->smin_value,
							dst_reg->smin_value);
	src_reg->smax_value = dst_reg->smax_value = min(src_reg->smax_value,
							dst_reg->smax_value);
	src_reg->var_off = dst_reg->var_off = tnum_intersect(src_reg->var_off,
							     dst_reg->var_off);
	/* We might have learned new bounds from the var_off. */
	__update_reg_bounds(src_reg);
	__update_reg_bounds(dst_reg);
	/* We might have learned something about the sign bit. */
	__reg_deduce_bounds(src_reg);
	__reg_deduce_bounds(dst_reg);
	/* We might have learned some bits from the bounds. */
	__reg_bound_offset(src_reg);
	__reg_bound_offset(dst_reg);
	/* Intersecting with the old var_off might have improved our bounds
	 * slightly.  e.g. if umax was 0x7f...f and var_off was (0; 0xf...fc),
	 * then new var_off is (0; 0x7f...fc) which improves our umax.
	 */
	__update_reg_bounds(src_reg);
	__update_reg_bounds(dst_reg);
}

static void reg_combine_min_max(struct bpf_reg_state *true_src,
				struct bpf_reg_state *true_dst,
				struct bpf_reg_state *false_src,
				struct bpf_reg_state *false_dst,
				u8 opcode)
{
	switch (opcode) {
	case BPF_JEQ:
		__reg_combine_min_max(true_src, true_dst);
		break;
	case BPF_JNE:
		__reg_combine_min_max(false_src, false_dst);
		break;
	}
}

static void mark_ptr_or_null_reg(struct bpf_reg_state *regs, u32 regno, u32 id,
			 bool is_null)
{
	struct bpf_reg_state *reg = &regs[regno];

	if ((reg->type == PTR_TO_MAP_VALUE_OR_NULL ||
	     reg->type == PTR_TO_SOCKET_OR_NULL ||
	     reg->type == PTR_TO_SOCK_COMMON_OR_NULL) && reg->id == id) {
		/* Old offset (both fixed and variable parts) should
		 * have been known-zero, because we don't allow pointer
		 * arithmetic on pointers that might be NULL.
		 */
		if (WARN_ON_ONCE(reg->smin_value || reg->smax_value ||
				 !tnum_equals_const(reg->var_off, 0) ||
				 reg->off)) {
			__mark_reg_known_zero(reg);
			reg->off = 0;
		}
		if (is_null) {
			reg->type = SCALAR_VALUE;
		} else if (reg->type == PTR_TO_SOCKET_OR_NULL) {
			reg->type = PTR_TO_SOCKET;
		} else if (reg->type == PTR_TO_SOCK_COMMON_OR_NULL) {
			reg->type = PTR_TO_SOCK_COMMON;
		} else if (reg->map_ptr->inner_map_meta) {
			reg->type = CONST_PTR_TO_MAP;
			reg->map_ptr = reg->map_ptr->inner_map_meta;
		} else {
			reg->type = PTR_TO_MAP_VALUE;
		}
		/* We don't need id from this point onwards anymore, thus we
		 * should better reset it, so that state pruning has chances
		 * to take effect.
		 */
		reg->id = 0;
	}
}

/* The logic is similar to find_good_pkt_pointers(), both could eventually
 * be folded together at some point.
 */
static void mark_ptr_or_null_regs(struct bpf_verifier_state *state, u32 regno,
			  bool is_null)
{
	struct bpf_reg_state *regs = state->regs;
	u32 id = regs[regno].id;
	int i;

	for (i = 0; i < MAX_BPF_REG; i++)
		mark_ptr_or_null_reg(regs, i, id, is_null);

	for (i = 0; i < MAX_BPF_STACK; i += BPF_REG_SIZE) {
		if (state->stack_slot_type[i] != STACK_SPILL)
			continue;
		mark_ptr_or_null_reg(state->spilled_regs, i / BPF_REG_SIZE, id, is_null);
	}
}

static int check_cond_jmp_op(struct bpf_verifier_env *env,
			     struct bpf_insn *insn, int *insn_idx)
{
	struct bpf_verifier_state *this_branch = &env->cur_state;
	struct bpf_verifier_state *other_branch;
	struct bpf_reg_state *regs = this_branch->regs;
	struct bpf_reg_state *dst_reg, *other_branch_regs;
	u8 opcode = BPF_OP(insn->code);
	bool is_jmp32;
	int err;

	/* Only conditional jumps are expected to reach here. */
	if (opcode == BPF_JA || opcode == BPF_CALL ||
	    opcode == BPF_EXIT || opcode > BPF_JSLE) {
		verbose( "invalid BPF_JMP/JMP32 opcode %x\n", opcode);
		return -EINVAL;
	}

	if (BPF_SRC(insn->code) == BPF_X) {
		if (insn->imm != 0) {
			verbose( "BPF_JMP/JMP32 uses reserved fields\n");
			return -EINVAL;
		}

		/* check src1 operand */
		err = check_reg_arg(regs, insn->src_reg, SRC_OP);
		if (err)
			return err;

		if (is_pointer_value(env, insn->src_reg)) {
			verbose( "R%d pointer comparison prohibited\n",
				insn->src_reg);
			return -EACCES;
		}
	} else {
		if (insn->src_reg != BPF_REG_0) {
			verbose( "BPF_JMP/JMP32 uses reserved fields\n");
			return -EINVAL;
		}
	}

	/* check src2 operand */
	err = check_reg_arg(regs, insn->dst_reg, SRC_OP);
	if (err)
		return err;

	dst_reg = &regs[insn->dst_reg];
	is_jmp32 = BPF_CLASS(insn->code) == BPF_JMP32;
	if (is_jmp32 && (dst_reg->type != SCALAR_VALUE ||
	    (BPF_SRC(insn->code) == BPF_X &&
	     regs[insn->src_reg].type != SCALAR_VALUE))) {
		verbose("JMP32 pointer comparison prohibited\n");
		return -EACCES;
	}

	if (BPF_SRC(insn->code) == BPF_K) {
		int pred = is_branch_taken(dst_reg, insn->imm, opcode,
					   is_jmp32);

		if (pred == 1) {
			 /* only follow the goto, ignore fall-through */
			*insn_idx += insn->off;
			return 0;
		} else if (pred == 0) {
			/* only follow fall-through branch, since
			 * that's where the program will go
			 */
			return 0;
		}
	}

	other_branch = push_stack(env, *insn_idx + insn->off + 1, *insn_idx);
	if (!other_branch)
		return -EFAULT;
	other_branch_regs = other_branch->regs;

	/* detect if we are comparing against a constant value so we can adjust
	 * our min/max values for our dst register.
	 * this is only legit if both are scalars (or pointers to the same
	 * object, I suppose, but we don't support that right now), because
	 * otherwise the different base pointers mean the offsets aren't
	 * comparable.
	 */
	if (BPF_SRC(insn->code) == BPF_X) {
		struct bpf_reg_state *src_reg = &regs[insn->src_reg];
		struct bpf_reg_state lo_reg0 = *dst_reg;
		struct bpf_reg_state lo_reg1 = *src_reg;
		struct bpf_reg_state *src_lo, *dst_lo;

		dst_lo = &lo_reg0;
		src_lo = &lo_reg1;
		coerce_reg_to_32(dst_lo);
		coerce_reg_to_32(src_lo);

		if (dst_reg->type == SCALAR_VALUE &&
		    src_reg->type == SCALAR_VALUE) {
			if (tnum_is_const(src_reg->var_off) ||
			    (is_jmp32 && tnum_is_const(src_lo->var_off)))
				reg_set_min_max(&other_branch_regs[insn->dst_reg],
						dst_reg,
						is_jmp32
						? src_lo->var_off.value
						: src_reg->var_off.value,
						opcode, is_jmp32);
			else if (tnum_is_const(dst_reg->var_off) ||
				 (is_jmp32 && tnum_is_const(dst_lo->var_off)))
				reg_set_min_max_inv(&other_branch_regs[insn->src_reg],
						    src_reg,
						    is_jmp32
						    ? dst_lo->var_off.value
						    : dst_reg->var_off.value,
						    opcode, is_jmp32);
			else if (!is_jmp32 &&
				 (opcode == BPF_JEQ || opcode == BPF_JNE))
				/* Comparing for equality, we can combine knowledge */
				reg_combine_min_max(&other_branch_regs[insn->src_reg],
						    &other_branch_regs[insn->dst_reg],
						    src_reg, dst_reg, opcode);
		}
	} else if (dst_reg->type == SCALAR_VALUE) {
		reg_set_min_max(&other_branch_regs[insn->dst_reg],
					dst_reg, insn->imm, opcode, is_jmp32);
	}

	/* Refine nullable pointers after an explicit R == 0 check. */
	if (!is_jmp32 && BPF_SRC(insn->code) == BPF_K &&
	    insn->imm == 0 && (opcode == BPF_JEQ || opcode == BPF_JNE) &&
	    (dst_reg->type == PTR_TO_MAP_VALUE_OR_NULL ||
	     dst_reg->type == PTR_TO_SOCKET_OR_NULL ||
	     dst_reg->type == PTR_TO_SOCK_COMMON_OR_NULL)) {
		/* Mark all pointer aliases in each branch as either
		 * safe or unknown depending R == 0 or R != 0 conditional.
		 */
		mark_ptr_or_null_regs(this_branch, insn->dst_reg, opcode == BPF_JNE);
		mark_ptr_or_null_regs(other_branch, insn->dst_reg, opcode == BPF_JEQ);
	} else if (BPF_SRC(insn->code) == BPF_X && opcode == BPF_JGT &&
		   dst_reg->type == PTR_TO_PACKET &&
		   regs[insn->src_reg].type == PTR_TO_PACKET_END) {
		find_good_pkt_pointers(this_branch, dst_reg);
	} else if (BPF_SRC(insn->code) == BPF_X && opcode == BPF_JGE &&
		   dst_reg->type == PTR_TO_PACKET_END &&
		   regs[insn->src_reg].type == PTR_TO_PACKET) {
		find_good_pkt_pointers(other_branch, &regs[insn->src_reg]);
	} else if (BPF_SRC(insn->code) == BPF_X && opcode == BPF_JLE &&
		   dst_reg->type == PTR_TO_PACKET &&
		   regs[insn->src_reg].type == PTR_TO_PACKET_END) {
		find_good_pkt_pointers(other_branch, dst_reg);
	} else if (BPF_SRC(insn->code) == BPF_X && opcode == BPF_JLT &&
		   dst_reg->type == PTR_TO_PACKET_END &&
		   regs[insn->src_reg].type == PTR_TO_PACKET) {
		find_good_pkt_pointers(this_branch, &regs[insn->src_reg]);
	} else if (is_pointer_value(env, insn->dst_reg)) {
		verbose("R%d pointer comparison prohibited\n", insn->dst_reg);
		return -EACCES;
	}
	if (log_level)
		print_verifier_state(this_branch);
	return 0;
}

/* return the map pointer stored inside BPF_LD_IMM64 instruction */
static struct bpf_map *ld_imm64_to_map_ptr(struct bpf_insn *insn)
{
	u64 imm64 = ((u64) (u32) insn[0].imm) | ((u64) (u32) insn[1].imm) << 32;

	return (struct bpf_map *) (unsigned long) imm64;
}

/* verify BPF_LD_IMM64 instruction */
static int check_ld_imm(struct bpf_verifier_env *env, struct bpf_insn *insn)
{
	struct bpf_reg_state *regs = env->cur_state.regs;
	int err;

	if (BPF_SIZE(insn->code) != BPF_DW) {
		verbose("invalid BPF_LD_IMM insn\n");
		return -EINVAL;
	}
	if (insn->off != 0) {
		verbose("BPF_LD_IMM64 uses reserved fields\n");
		return -EINVAL;
	}

	err = check_reg_arg(regs, insn->dst_reg, DST_OP);
	if (err)
		return err;

	if (insn->src_reg == 0) {
		/* generic move 64-bit immediate into a register,
		 * only analyzer needs to collect the ld_imm value.
		 */
		u64 imm = ((u64)(insn + 1)->imm << 32) | (u32)insn->imm;

		regs[insn->dst_reg].type = SCALAR_VALUE;
		__mark_reg_known(&regs[insn->dst_reg], imm);
		return 0;
	}

	/* replace_map_fd_with_map_ptr() should have caught bad ld_imm64 */
	BUG_ON(insn->src_reg != BPF_PSEUDO_MAP_FD);

	regs[insn->dst_reg].type = CONST_PTR_TO_MAP;
	regs[insn->dst_reg].map_ptr = ld_imm64_to_map_ptr(insn);
	return 0;
}

static bool may_access_skb(enum bpf_prog_type type)
{
	switch (type) {
	case BPF_PROG_TYPE_SOCKET_FILTER:
	case BPF_PROG_TYPE_SCHED_CLS:
	case BPF_PROG_TYPE_SCHED_ACT:
		return true;
	default:
		return false;
	}
}

/* verify safety of LD_ABS|LD_IND instructions:
 * - they can only appear in the programs where ctx == skb
 * - since they are wrappers of function calls, they scratch R1-R5 registers,
 *   preserve R6-R9, and store return value into R0
 *
 * Implicit input:
 *   ctx == skb == R6 == CTX
 *
 * Explicit input:
 *   SRC == any register
 *   IMM == 32-bit immediate
 *
 * Output:
 *   R0 - 8/16/32-bit skb data converted to cpu endianness
 */
static int check_ld_abs(struct bpf_verifier_env *env, struct bpf_insn *insn)
{
	struct bpf_reg_state *regs = env->cur_state.regs;
	u8 mode = BPF_MODE(insn->code);
	struct bpf_reg_state *reg;
	int i, err;

	if (!may_access_skb(env->prog->type)) {
		verbose("BPF_LD_[ABS|IND] instructions not allowed for this program type\n");
		return -EINVAL;
	}

	if (insn->dst_reg != BPF_REG_0 || insn->off != 0 ||
	    BPF_SIZE(insn->code) == BPF_DW ||
	    (mode == BPF_ABS && insn->src_reg != BPF_REG_0)) {
		verbose("BPF_LD_[ABS|IND] uses reserved fields\n");
		return -EINVAL;
	}

	/* check whether implicit source operand (register R6) is readable */
	err = check_reg_arg(regs, BPF_REG_6, SRC_OP);
	if (err)
		return err;

	if (regs[BPF_REG_6].type != PTR_TO_CTX) {
		verbose("at the time of BPF_LD_ABS|IND R6 != pointer to skb\n");
		return -EINVAL;
	}

	if (mode == BPF_IND) {
		/* check explicit source operand */
		err = check_reg_arg(regs, insn->src_reg, SRC_OP);
		if (err)
			return err;
	}

	/* reset caller saved regs to unreadable */
	for (i = 0; i < CALLER_SAVED_REGS; i++) {
		reg = regs + caller_saved[i];
		__mark_reg_not_init(reg);
	}

	/* mark destination R0 register as readable, since it contains
	 * the value fetched from the packet
	 */
	mark_reg_unknown(regs, BPF_REG_0);
	return 0;
}

/* non-recursive DFS pseudo code
 * 1  procedure DFS-iterative(G,v):
 * 2      label v as discovered
 * 3      let S be a stack
 * 4      S.push(v)
 * 5      while S is not empty
 * 6            t <- S.pop()
 * 7            if t is what we're looking for:
 * 8                return t
 * 9            for all edges e in G.adjacentEdges(t) do
 * 10               if edge e is already labelled
 * 11                   continue with the next edge
 * 12               w <- G.adjacentVertex(t,e)
 * 13               if vertex w is not discovered and not explored
 * 14                   label e as tree-edge
 * 15                   label w as discovered
 * 16                   S.push(w)
 * 17                   continue at 5
 * 18               else if vertex w is discovered
 * 19                   label e as back-edge
 * 20               else
 * 21                   // vertex w is explored
 * 22                   label e as forward- or cross-edge
 * 23           label t as explored
 * 24           S.pop()
 *
 * convention:
 * 0x10 - discovered
 * 0x11 - discovered and fall-through edge labelled
 * 0x12 - discovered and fall-through and branch edges labelled
 * 0x20 - explored
 */

enum {
	DISCOVERED = 0x10,
	EXPLORED = 0x20,
	FALLTHROUGH = 1,
	BRANCH = 2,
};

#define STATE_LIST_MARK ((struct bpf_verifier_state_list *) -1L)

static int *insn_stack;	/* stack of insns to process */
static int cur_stack;	/* current stack index */
static int *insn_state;

/* t, w, e - match pseudo-code above:
 * t - index of current instruction
 * w - next instruction
 * e - edge
 */
static int push_insn(int t, int w, int e, struct bpf_verifier_env *env)
{
	if (e == FALLTHROUGH && insn_state[t] >= (DISCOVERED | FALLTHROUGH))
		return 0;

	if (e == BRANCH && insn_state[t] >= (DISCOVERED | BRANCH))
		return 0;

	if (w < 0 || w >= env->prog->len) {
		verbose("jump out of range from insn %d to %d\n", t, w);
		return -EINVAL;
	}

	if (e == BRANCH)
		/* mark branch target for state pruning */
		env->explored_states[w] = STATE_LIST_MARK;

	if (insn_state[w] == 0) {
		/* tree-edge */
		insn_state[t] = DISCOVERED | e;
		insn_state[w] = DISCOVERED;
		if (cur_stack >= env->prog->len)
			return -E2BIG;
		insn_stack[cur_stack++] = w;
		return 1;
	} else if ((insn_state[w] & 0xF0) == DISCOVERED) {
		verbose("back-edge from insn %d to %d\n", t, w);
		return -EINVAL;
	} else if (insn_state[w] == EXPLORED) {
		/* forward- or cross-edge */
		insn_state[t] = DISCOVERED | e;
	} else {
		verbose("insn state internal bug\n");
		return -EFAULT;
	}
	return 0;
}

/* non-recursive depth-first-search to detect loops in BPF program
 * loop == back-edge in directed graph
 */
static int check_cfg(struct bpf_verifier_env *env)
{
	struct bpf_insn *insns = env->prog->insnsi;
	int insn_cnt = env->prog->len;
	int ret = 0;
	int i, t;

	insn_state = kcalloc(insn_cnt, sizeof(int), GFP_KERNEL);
	if (!insn_state)
		return -ENOMEM;

	insn_stack = kcalloc(insn_cnt, sizeof(int), GFP_KERNEL);
	if (!insn_stack) {
		kfree(insn_state);
		return -ENOMEM;
	}

	insn_state[0] = DISCOVERED; /* mark 1st insn as discovered */
	insn_stack[0] = 0; /* 0 is the first instruction */
	cur_stack = 1;

peek_stack:
	if (cur_stack == 0)
		goto check_state;
	t = insn_stack[cur_stack - 1];

	if (BPF_CLASS(insns[t].code) == BPF_JMP ||
	    BPF_CLASS(insns[t].code) == BPF_JMP32) {
		u8 opcode = BPF_OP(insns[t].code);

		if (BPF_CLASS(insns[t].code) == BPF_JMP32 &&
		    (opcode == BPF_JA || opcode == BPF_CALL || opcode == BPF_EXIT)) {
			ret = -EINVAL;
			goto err_free;
		}

		if (opcode == BPF_EXIT) {
			goto mark_explored;
		} else if (opcode == BPF_CALL) {
			ret = push_insn(t, t + 1, FALLTHROUGH, env);
			if (ret == 1)
				goto peek_stack;
			else if (ret < 0)
				goto err_free;
			if (t + 1 < insn_cnt)
				env->explored_states[t + 1] = STATE_LIST_MARK;
		} else if (opcode == BPF_JA) {
			if (BPF_SRC(insns[t].code) != BPF_K) {
				ret = -EINVAL;
				goto err_free;
			}
			/* unconditional jump with single edge */
			ret = push_insn(t, t + insns[t].off + 1,
					FALLTHROUGH, env);
			if (ret == 1)
				goto peek_stack;
			else if (ret < 0)
				goto err_free;
			/* tell verifier to check for equivalent states
			 * after every call and jump
			 */
			if (t + 1 < insn_cnt)
				env->explored_states[t + 1] = STATE_LIST_MARK;
		} else {
			/* conditional jump with two edges */
			env->explored_states[t] = STATE_LIST_MARK;
			ret = push_insn(t, t + 1, FALLTHROUGH, env);
			if (ret == 1)
				goto peek_stack;
			else if (ret < 0)
				goto err_free;

			ret = push_insn(t, t + insns[t].off + 1, BRANCH, env);
			if (ret == 1)
				goto peek_stack;
			else if (ret < 0)
				goto err_free;
		}
	} else {
		/* all other non-branch instructions with single
		 * fall-through edge
		 */
		ret = push_insn(t, t + 1, FALLTHROUGH, env);
		if (ret == 1)
			goto peek_stack;
		else if (ret < 0)
			goto err_free;
	}

mark_explored:
	insn_state[t] = EXPLORED;
	if (cur_stack-- <= 0) {
		verbose("pop stack internal bug\n");
		ret = -EFAULT;
		goto err_free;
	}
	goto peek_stack;

check_state:
	for (i = 0; i < insn_cnt; i++) {
		if (insn_state[i] != EXPLORED) {
			verbose("unreachable insn %d\n", i);
			ret = -EINVAL;
			goto err_free;
		}
	}
	ret = 0; /* cfg looks good */

err_free:
	kfree(insn_state);
	kfree(insn_stack);
	return ret;
}

/* check %cur's range satisfies %old's */
static bool range_within(struct bpf_reg_state *old,
			 struct bpf_reg_state *cur)
{
	return old->umin_value <= cur->umin_value &&
	       old->umax_value >= cur->umax_value &&
	       old->smin_value <= cur->smin_value &&
	       old->smax_value >= cur->smax_value;
}

/* Maximum number of register states that can exist at once */
#define ID_MAP_SIZE	(MAX_BPF_REG + MAX_BPF_STACK / BPF_REG_SIZE)
struct idpair {
	u32 old;
	u32 cur;
};

/* If in the old state two registers had the same id, then they need to have
 * the same id in the new state as well.  But that id could be different from
 * the old state, so we need to track the mapping from old to new ids.
 * Once we have seen that, say, a reg with old id 5 had new id 9, any subsequent
 * regs with old id 5 must also have new id 9 for the new state to be safe.  But
 * regs with a different old id could still have new id 9, we don't care about
 * that.
 * So we look through our idmap to see if this old id has been seen before.  If
 * so, we require the new id to match; otherwise, we add the id pair to the map.
 */
static bool check_ids(u32 old_id, u32 cur_id, struct idpair *idmap)
{
	unsigned int i;

	for (i = 0; i < ID_MAP_SIZE; i++) {
		if (!idmap[i].old) {
			/* Reached an empty slot; haven't seen this id before */
			idmap[i].old = old_id;
			idmap[i].cur = cur_id;
			return true;
		}
		if (idmap[i].old == old_id)
			return idmap[i].cur == cur_id;
	}
	/* We ran out of idmap slots, which should be impossible */
	WARN_ON_ONCE(1);
	return false;
}

/* Returns true if (rold safe implies rcur safe) */
static bool regsafe(struct bpf_reg_state *rold,
		    struct bpf_reg_state *rcur,
		    struct idpair *idmap)
{
	if (memcmp(rold, rcur, sizeof(*rold)) == 0) {
		/* Equal registers still constrain aliases seen later. */
		if (rold->id && (rold->type == PTR_TO_MAP_VALUE_OR_NULL ||
				 rold->type == PTR_TO_PACKET ||
				 rold->type == PTR_TO_SOCKET_OR_NULL ||
				 rold->type == PTR_TO_SOCK_COMMON_OR_NULL))
			return check_ids(rold->id, rcur->id, idmap);
		return true;
	}

	if (rold->type == NOT_INIT)
		/* explored state can't have used this */
		return true;
	if (rcur->type == NOT_INIT)
		return false;
	switch (rold->type) {
	case SCALAR_VALUE:
		if (rcur->type == SCALAR_VALUE) {
			/* new val must satisfy old val knowledge */
			return range_within(rold, rcur) &&
			       tnum_in(rold->var_off, rcur->var_off);
		} else {
			/* We're trying to use a pointer in place of a scalar.
			 * Even if the scalar was unbounded, this could lead to
			 * pointer leaks because scalars are allowed to leak
			 * while pointers are not. We could make this safe in
			 * special cases if root is calling us, but it's
			 * probably not worth the hassle.
			 */
			return false;
		}
	case PTR_TO_MAP_VALUE:
		/* If the new min/max/var_off satisfy the old ones and
		 * everything else matches, we are OK.
		 * 'id' is not compared, since it's only used for maps with
		 * bpf_spin_lock inside map element and in such cases if
		 * the rest of the prog is valid for one map element then
		 * it's valid for all map elements regardless of the key
		 * used in bpf_map_lookup()
		 */
		return memcmp(rold, rcur, offsetof(struct bpf_reg_state, id)) == 0 &&
		       range_within(rold, rcur) &&
		       tnum_in(rold->var_off, rcur->var_off);
	case PTR_TO_MAP_VALUE_OR_NULL:
		/* a PTR_TO_MAP_VALUE could be safe to use as a
		 * PTR_TO_MAP_VALUE_OR_NULL into the same map.
		 * However, if the old PTR_TO_MAP_VALUE_OR_NULL then got NULL-
		 * checked, doing so could have affected others with the same
		 * id, and we can't check for that because we lost the id when
		 * we converted to a PTR_TO_MAP_VALUE.
		 */
		if (rcur->type != PTR_TO_MAP_VALUE_OR_NULL)
			return false;
		if (memcmp(rold, rcur, offsetof(struct bpf_reg_state, id)))
			return false;
		/* Check our ids match any regs they're supposed to */
		return check_ids(rold->id, rcur->id, idmap);
	case PTR_TO_PACKET:
		if (rcur->type != PTR_TO_PACKET)
			return false;
		/* We must have at least as much range as the old ptr
		 * did, so that any accesses which were safe before are
		 * still safe.  This is true even if old range < old off,
		 * since someone could have accessed through (ptr - k), or
		 * even done ptr -= k in a register, to get a safe access.
		 */
		if (rold->range > rcur->range)
			return false;
		/* If the offsets don't match, we can't trust our alignment;
		 * nor can we be sure that we won't fall out of range.
		 */
		if (rold->off != rcur->off)
			return false;
		/* id relations must be preserved */
		if (rold->id && !check_ids(rold->id, rcur->id, idmap))
			return false;
		/* new val must satisfy old val knowledge */
		return range_within(rold, rcur) &&
		       tnum_in(rold->var_off, rcur->var_off);
	case PTR_TO_CTX:
	case CONST_PTR_TO_MAP:
	case PTR_TO_STACK:
	case PTR_TO_PACKET_END:
		/* Only valid matches are exact, which memcmp() above
		 * would have accepted
		 */
	default:
		/* Don't know what's going on, just say it's not safe */
		return false;
	}

	/* Shouldn't get here; if we do, say it's not safe */
	WARN_ON_ONCE(1);
	return false;
}

/* compare two verifier states
 *
 * all states stored in state_list are known to be valid, since
 * verifier reached 'bpf_exit' instruction through them
 *
 * this function is called when verifier exploring different branches of
 * execution popped from the state stack. If it sees an old state that has
 * more strict register state and more strict stack state then this execution
 * branch doesn't need to be explored further, since verifier already
 * concluded that more strict state leads to valid finish.
 *
 * Therefore two states are equivalent if register state is more conservative
 * and explored stack state is more conservative than the current one.
 * Example:
 *       explored                   current
 * (slot1=INV slot2=MISC) == (slot1=MISC slot2=MISC)
 * (slot1=MISC slot2=MISC) != (slot1=INV slot2=MISC)
 *
 * In other words if current stack state (one being explored) has more
 * valid slots than old one that already passed validation, it means
 * the verifier can stop exploring and conclude that current state is valid too
 *
 * Similarly with registers. If explored state has register type as invalid
 * whereas register type in current state is meaningful, it means that
 * the current state will reach 'bpf_exit' instruction safely
 */
static bool states_equal(struct bpf_verifier_env *env,
			 struct bpf_verifier_state *old,
			 struct bpf_verifier_state *cur)
{
	struct idpair *idmap;
	bool ret = false;
	int i;

	idmap = kcalloc(ID_MAP_SIZE, sizeof(struct idpair), GFP_KERNEL);
	/* If we failed to allocate the idmap, just say it's not safe */
	if (!idmap)
		return false;

	for (i = 0; i < MAX_BPF_REG; i++) {
		if (!regsafe(&old->regs[i], &cur->regs[i],
			     idmap))
			goto out_free;
	}

	for (i = 0; i < MAX_BPF_STACK; i++) {
		if (old->stack_slot_type[i] == STACK_INVALID)
			continue;
		if (old->stack_slot_type[i] != cur->stack_slot_type[i])
			/* Ex: old explored (safe) state has STACK_SPILL in
			 * this stack slot, but current has has STACK_MISC ->
			 * this verifier states are not equivalent,
			 * return false to continue verification of this path
			 */
			goto out_free;
		if (i % BPF_REG_SIZE)
			continue;
		if (old->stack_slot_type[i] != STACK_SPILL)
			continue;
		if (!regsafe(&old->spilled_regs[i / BPF_REG_SIZE],
			     &cur->spilled_regs[i / BPF_REG_SIZE],
			     idmap))
			/* when explored and current stack slot are both storing
			 * spilled registers, check that stored pointers types
			 * are the same as well.
			 * Ex: explored safe path could have stored
			 * (bpf_reg_state) {.type = PTR_TO_STACK, .off = -8}
			 * but current path has stored:
			 * (bpf_reg_state) {.type = PTR_TO_STACK, .off = -16}
			 * such verifier states are not equivalent.
			 * return false to continue verification of this path
			 */
			goto out_free;
		else
			continue;
	}
	ret = true;
out_free:
	kfree(idmap);
	return ret;
}

static int is_state_visited(struct bpf_verifier_env *env, int insn_idx)
{
	struct bpf_verifier_state_list *new_sl;
	struct bpf_verifier_state_list *sl;

	sl = env->explored_states[insn_idx];
	if (!sl)
		/* this 'insn_idx' instruction wasn't marked, so we will not
		 * be doing state search here
		 */
		return 0;

	while (sl != STATE_LIST_MARK) {
		if (states_equal(env, &sl->state, &env->cur_state))
			/* reached equivalent register/stack state,
			 * prune the search
			 */
			return 1;
		sl = sl->next;
	}

	/* there were no equivalent states, remember current one.
	 * technically the current state is not proven to be safe yet,
	 * but it will either reach bpf_exit (which means it's safe) or
	 * it will be rejected. Since there are no loops, we won't be
	 * seeing this 'insn_idx' instruction again on the way to bpf_exit
	 */
	new_sl = kmalloc(sizeof(struct bpf_verifier_state_list), GFP_USER);
	if (!new_sl)
		return -ENOMEM;

	/* add new state to the head of linked list */
	memcpy(&new_sl->state, &env->cur_state, sizeof(env->cur_state));
	new_sl->next = env->explored_states[insn_idx];
	env->explored_states[insn_idx] = new_sl;
	return 0;
}

static int ext_analyzer_insn_hook(struct bpf_verifier_env *env,
				  int insn_idx, int prev_insn_idx)
{
	if (!env->analyzer_ops || !env->analyzer_ops->insn_hook)
		return 0;

	return env->analyzer_ops->insn_hook(env, insn_idx, prev_insn_idx);
}

/* Return true if it's OK to have the same insn return a different type. */
static bool reg_type_mismatch_ok(enum bpf_reg_type type)
{
	switch (type) {
	case PTR_TO_CTX:
	case PTR_TO_SOCKET:
	case PTR_TO_SOCKET_OR_NULL:
	case PTR_TO_SOCK_COMMON:
	case PTR_TO_SOCK_COMMON_OR_NULL:
		return false;
	default:
		return true;
	}
}
/* If an instruction was previously used with particular pointer types, then we
 * need to be careful to avoid cases such as the below, where it may be ok
 * for one branch accessing the pointer, but not ok for the other branch:
 *
 * R1 = sock_ptr
 * goto X;
 * ...
 * R1 = some_other_valid_ptr;
 * goto X;
 * ...
 * R2 = *(u32 *)(R1 + 0);
 */
static bool reg_type_mismatch(enum bpf_reg_type src, enum bpf_reg_type prev)
{
	return src != prev && (!reg_type_mismatch_ok(src) ||
			       !reg_type_mismatch_ok(prev));
}

static int check_return_code(struct bpf_verifier_env *env)
{
	struct bpf_reg_state *reg = &env->cur_state.regs[BPF_REG_0];

	if (env->prog->type != BPF_PROG_TYPE_CGROUP_SOCKOPT)
		return 0;
	if (reg->type != SCALAR_VALUE || reg->umax_value > 1) {
		verbose("sockopt programs must return 0 or 1\n");
		return -EINVAL;
	}
	return 0;
}

static int do_check(struct bpf_verifier_env *env)
{
	struct bpf_verifier_state *state = &env->cur_state;
	struct bpf_insn *insns = env->prog->insnsi;
	struct bpf_reg_state *regs = state->regs;
	int insn_cnt = env->prog->len;
	int insn_idx, prev_insn_idx = 0;
	int insn_processed = 0;
	bool do_print_state = false;

	init_reg_state(regs);
	insn_idx = 0;
	for (;;) {
		struct bpf_insn *insn;
		u8 class;
		int err;

		if (insn_idx >= insn_cnt) {
			verbose("invalid insn idx %d insn_cnt %d\n",
				insn_idx, insn_cnt);
			return -EFAULT;
		}

		insn = &insns[insn_idx];
		class = BPF_CLASS(insn->code);

		if (++insn_processed > BPF_COMPLEXITY_LIMIT_INSNS) {
			verbose("BPF program is too large. Proccessed %d insn\n",
				insn_processed);
			return -E2BIG;
		}

		err = is_state_visited(env, insn_idx);
		if (err < 0)
			return err;
		if (err == 1) {
			/* found equivalent state, can prune the search */
			if (log_level) {
				if (do_print_state)
					verbose("\nfrom %d to %d: safe\n",
						prev_insn_idx, insn_idx);
				else
					verbose("%d: safe\n", insn_idx);
			}
			goto process_bpf_exit;
		}

		if (signal_pending(current))
			return -EAGAIN;

		if (need_resched())
			cond_resched();

		if (log_level && do_print_state) {
			verbose("\nfrom %d to %d:", prev_insn_idx, insn_idx);
			print_verifier_state(&env->cur_state);
			do_print_state = false;
		}

		if (log_level) {
			verbose("%d: ", insn_idx);
			print_bpf_insn(env, insn);
		}

		err = ext_analyzer_insn_hook(env, insn_idx, prev_insn_idx);
		if (err)
			return err;

		env->insn_aux_data[insn_idx].seen = true;
		if (class == BPF_ALU || class == BPF_ALU64) {
			err = check_alu_op(env, insn);
			if (err)
				return err;

		} else if (class == BPF_LDX) {
			enum bpf_reg_type *prev_src_type, src_reg_type;

			/* check for reserved fields is already done */

			/* check src operand */
			err = check_reg_arg(regs, insn->src_reg, SRC_OP);
			if (err)
				return err;

			err = check_reg_arg(regs, insn->dst_reg, DST_OP_NO_MARK);
			if (err)
				return err;

			src_reg_type = regs[insn->src_reg].type;

			/* check that memory (src_reg + off) is readable,
			 * the state of dst_reg will be updated by this func
			 */
			err = check_mem_access(env, insn_idx, insn->src_reg, insn->off,
					       BPF_SIZE(insn->code), BPF_READ,
					       insn->dst_reg);
			if (err)
				return err;

			if (BPF_SIZE(insn->code) != BPF_W &&
			    BPF_SIZE(insn->code) != BPF_DW) {
				insn_idx++;
				continue;
			}

			prev_src_type = &env->insn_aux_data[insn_idx].ptr_type;

			if (*prev_src_type == NOT_INIT) {
				/* saw a valid insn
				 * dst_reg = *(u32 *)(src_reg + off)
				 * save type to validate intersecting paths
				 */
				*prev_src_type = src_reg_type;
			} else if (reg_type_mismatch(src_reg_type, *prev_src_type)) {
				/* ABuser program is trying to use the same insn
				 * dst_reg = *(u32*) (src_reg + off)
				 * with different pointer types:
				 * src_reg == ctx in one branch and
				 * src_reg == stack|map in some other branch.
				 * Reject it.
				 */
				verbose("same insn cannot be used with different pointers\n");
				return -EINVAL;
			}

		} else if (class == BPF_STX) {
			enum bpf_reg_type *prev_dst_type, dst_reg_type;

			if (BPF_MODE(insn->code) == BPF_XADD) {
				err = check_xadd(env, insn_idx, insn);
				if (err)
					return err;
				insn_idx++;
				continue;
			}

			/* check src1 operand */
			err = check_reg_arg(regs, insn->src_reg, SRC_OP);
			if (err)
				return err;
			/* check src2 operand */
			err = check_reg_arg(regs, insn->dst_reg, SRC_OP);
			if (err)
				return err;

			dst_reg_type = regs[insn->dst_reg].type;

			/* check that memory (dst_reg + off) is writeable */
			err = check_mem_access(env, insn_idx, insn->dst_reg, insn->off,
					       BPF_SIZE(insn->code), BPF_WRITE,
					       insn->src_reg);
			if (err)
				return err;

			prev_dst_type = &env->insn_aux_data[insn_idx].ptr_type;

			if (*prev_dst_type == NOT_INIT) {
				*prev_dst_type = dst_reg_type;
			} else if (reg_type_mismatch(dst_reg_type, *prev_dst_type)) {
				verbose("same insn cannot be used with different pointers\n");
				return -EINVAL;
			}

		} else if (class == BPF_ST) {
			if (BPF_MODE(insn->code) != BPF_MEM ||
			    insn->src_reg != BPF_REG_0) {
				verbose("BPF_ST uses reserved fields\n");
				return -EINVAL;
			}
			/* check src operand */
			err = check_reg_arg(regs, insn->dst_reg, SRC_OP);
			if (err)
				return err;

			if (is_ctx_reg(env, insn->dst_reg)) {
				verbose("BPF_ST stores into R%d context is not allowed\n",
					insn->dst_reg);
				return -EACCES;
			}

			/* check that memory (dst_reg + off) is writeable */
			err = check_mem_access(env, insn_idx, insn->dst_reg, insn->off,
					       BPF_SIZE(insn->code), BPF_WRITE,
					       -1);
			if (err)
				return err;

		} else if (class == BPF_JMP || class == BPF_JMP32) {
			u8 opcode = BPF_OP(insn->code);

			if (opcode == BPF_CALL && class == BPF_JMP) {
				if (BPF_SRC(insn->code) != BPF_K ||
				    insn->off != 0 ||
				    insn->src_reg != BPF_REG_0 ||
				    insn->dst_reg != BPF_REG_0) {
					verbose("BPF_CALL uses reserved fields\n");
					return -EINVAL;
				}

				err = check_call(env, insn->imm, insn_idx);
				if (err)
					return err;

			} else if (opcode == BPF_JA && class == BPF_JMP) {
				if (BPF_SRC(insn->code) != BPF_K ||
				    insn->imm != 0 ||
				    insn->src_reg != BPF_REG_0 ||
				    insn->dst_reg != BPF_REG_0) {
					verbose("BPF_JA uses reserved fields\n");
					return -EINVAL;
				}

				insn_idx += insn->off + 1;
				continue;

			} else if (opcode == BPF_EXIT && class == BPF_JMP) {
				if (BPF_SRC(insn->code) != BPF_K ||
				    insn->imm != 0 ||
				    insn->src_reg != BPF_REG_0 ||
				    insn->dst_reg != BPF_REG_0) {
					verbose("BPF_EXIT uses reserved fields\n");
					return -EINVAL;
				}

				/* eBPF calling convetion is such that R0 is used
				 * to return the value from eBPF program.
				 * Make sure that it's readable at this time
				 * of bpf_exit, which means that program wrote
				 * something into it earlier
				 */
				err = check_reg_arg(regs, BPF_REG_0, SRC_OP);
				if (err)
					return err;

				if (is_pointer_value(env, BPF_REG_0)) {
					verbose("R0 leaks addr as return value\n");
					return -EACCES;
				}

				err = check_return_code(env);
				if (err)
					return err;

process_bpf_exit:
				insn_idx = pop_stack(env, &prev_insn_idx);
				if (insn_idx < 0) {
					break;
				} else {
					do_print_state = true;
					continue;
				}
			} else {
				err = check_cond_jmp_op(env, insn, &insn_idx);
				if (err)
					return err;
			}
		} else if (class == BPF_LD) {
			u8 mode = BPF_MODE(insn->code);

			if (mode == BPF_ABS || mode == BPF_IND) {
				err = check_ld_abs(env, insn);
				if (err)
					return err;

			} else if (mode == BPF_IMM) {
				err = check_ld_imm(env, insn);
				if (err)
					return err;

				insn_idx++;
				env->insn_aux_data[insn_idx].seen = true;
			} else {
				verbose("invalid BPF_LD mode\n");
				return -EINVAL;
			}
		} else {
			verbose("unknown insn class %d\n", class);
			return -EINVAL;
		}

		insn_idx++;
	}

	verbose("processed %d insns\n", insn_processed);
	return 0;
}

/* look for pseudo eBPF instructions that access map FDs and
 * replace them with actual map pointers
 */
static int check_map_prog_compatibility(struct bpf_map *map,
					struct bpf_prog *prog)
{
	if (prog->type != BPF_PROG_TYPE_PERF_EVENT)
		return 0;

	for (; map; map = map->inner_map_meta) {
		if ((map->map_type == BPF_MAP_TYPE_HASH ||
		     map->map_type == BPF_MAP_TYPE_PERCPU_HASH ||
		     map->map_type == BPF_MAP_TYPE_HASH_OF_MAPS) &&
		    (map->map_flags & BPF_F_NO_PREALLOC)) {
			verbose("perf_event programs require preallocated hash maps\n");
			return -EINVAL;
		}
	}
	return 0;
}

static int replace_map_fd_with_map_ptr(struct bpf_verifier_env *env)
{
	struct bpf_insn *insn = env->prog->insnsi;
	int insn_cnt = env->prog->len;
	int i, j, err;

	err = bpf_prog_calc_tag(env->prog);
	if (err)
		return err;

	for (i = 0; i < insn_cnt; i++, insn++) {
		if (BPF_CLASS(insn->code) == BPF_LDX &&
		    (BPF_MODE(insn->code) != BPF_MEM || insn->imm != 0)) {
			verbose("BPF_LDX uses reserved fields\n");
			return -EINVAL;
		}

		if (BPF_CLASS(insn->code) == BPF_STX &&
		    ((BPF_MODE(insn->code) != BPF_MEM &&
		      BPF_MODE(insn->code) != BPF_XADD) || insn->imm != 0)) {
			verbose("BPF_STX uses reserved fields\n");
			return -EINVAL;
		}

		if (insn[0].code == (BPF_LD | BPF_IMM | BPF_DW)) {
			struct bpf_map *map;
			struct fd f;

			if (i == insn_cnt - 1 || insn[1].code != 0 ||
			    insn[1].dst_reg != 0 || insn[1].src_reg != 0 ||
			    insn[1].off != 0) {
				verbose("invalid bpf_ld_imm64 insn\n");
				return -EINVAL;
			}

			if (insn->src_reg == 0)
				/* valid generic load 64-bit imm */
				goto next_insn;

			if (insn->src_reg != BPF_PSEUDO_MAP_FD) {
				verbose("unrecognized bpf_ld_imm64 insn\n");
				return -EINVAL;
			}

			f = fdget(insn->imm);
			map = __bpf_map_get(f);
			if (IS_ERR(map)) {
				verbose("fd %d is not pointing to valid bpf_map\n",
					insn->imm);
				fdput(f);
				return PTR_ERR(map);
			}

			err = check_map_prog_compatibility(map, env->prog);
			if (err) {
				fdput(f);
				return err;
			}

			/* store map pointer inside BPF_LD_IMM64 instruction */
			insn[0].imm = (u32) (unsigned long) map;
			insn[1].imm = ((u64) (unsigned long) map) >> 32;

			/* check whether we recorded this map already */
			for (j = 0; j < env->used_map_cnt; j++)
				if (env->used_maps[j] == map) {
					fdput(f);
					goto next_insn;
				}

			if (env->used_map_cnt >= MAX_USED_MAPS) {
				fdput(f);
				return -E2BIG;
			}

			/* hold the map. If the program is rejected by verifier,
			 * the map will be released by release_maps() or it
			 * will be used by the valid program until it's unloaded
			 * and all maps are released in free_used_maps()
			 */
			map = bpf_map_inc(map, false);
			if (IS_ERR(map)) {
				fdput(f);
				return PTR_ERR(map);
			}
			env->used_maps[env->used_map_cnt++] = map;

			fdput(f);
next_insn:
			insn++;
			i++;
		}
	}

	/* now all pseudo BPF_LD_IMM64 instructions load valid
	 * 'struct bpf_map *' into a register instead of user map_fd.
	 * These pointers will be used later by verifier to validate map access.
	 */
	return 0;
}

/* drop refcnt of maps used by the rejected program */
static void release_maps(struct bpf_verifier_env *env)
{
	int i;

	for (i = 0; i < env->used_map_cnt; i++)
		bpf_map_put(env->used_maps[i]);
}

/* convert pseudo BPF_LD_IMM64 into generic BPF_LD_IMM64 */
static void convert_pseudo_ld_imm64(struct bpf_verifier_env *env)
{
	struct bpf_insn *insn = env->prog->insnsi;
	int insn_cnt = env->prog->len;
	int i;

	for (i = 0; i < insn_cnt; i++, insn++)
		if (insn->code == (BPF_LD | BPF_IMM | BPF_DW))
			insn->src_reg = 0;
}

/* single env->prog->insni[off] instruction was replaced with the range
 * insni[off, off + cnt).  Adjust corresponding insn_aux_data by copying
 * [0, off) and [off, end) to new locations, so the patched range stays zero
 */
static int adjust_insn_aux_data(struct bpf_verifier_env *env, u32 prog_len,
				u32 off, u32 cnt)
{
	struct bpf_insn_aux_data *new_data, *old_data = env->insn_aux_data;
	int i;

	if (cnt == 1)
		return 0;
	new_data = vzalloc(sizeof(struct bpf_insn_aux_data) * prog_len);
	if (!new_data)
		return -ENOMEM;
	memcpy(new_data, old_data, sizeof(struct bpf_insn_aux_data) * off);
	memcpy(new_data + off + cnt - 1, old_data + off,
	       sizeof(struct bpf_insn_aux_data) * (prog_len - off - cnt + 1));
	for (i = off; i < off + cnt - 1; i++)
		new_data[i].seen = true;
	env->insn_aux_data = new_data;
	vfree(old_data);
	return 0;
}

static struct bpf_prog *bpf_patch_insn_data(struct bpf_verifier_env *env, u32 off,
					    const struct bpf_insn *patch, u32 len)
{
	struct bpf_prog *new_prog;

	new_prog = bpf_patch_insn_single(env->prog, off, patch, len);
	if (!new_prog)
		return NULL;
	env->prog = new_prog;
	if (adjust_insn_aux_data(env, new_prog->len, off, len))
		return NULL;
	return new_prog;
}

/* The verifier does more data flow analysis than llvm and will not explore
 * branches that are dead at run time. Malicious programs can have dead code
 * too. Therefore replace all dead at-run-time code with nops.
 */
static void sanitize_dead_code(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux_data = env->insn_aux_data;
	struct bpf_insn nop = BPF_MOV64_REG(BPF_REG_0, BPF_REG_0);
	struct bpf_insn *insn = env->prog->insnsi;
	const int insn_cnt = env->prog->len;
	int i;

	for (i = 0; i < insn_cnt; i++) {
		if (aux_data[i].seen)
			continue;
		memcpy(insn + i, &nop, sizeof(nop));
	}
}

/* convert load instructions that access fields of 'struct __sk_buff'
 * into sequence of instructions that access fields of 'struct sk_buff'
 */
static int convert_ctx_accesses(struct bpf_verifier_env *env)
{
	const struct bpf_verifier_ops *ops = env->prog->aux->ops;
	const int insn_cnt = env->prog->len;
	struct bpf_insn insn_buf[16], *insn;
	struct bpf_prog *new_prog;
	enum bpf_access_type type;
	int i, cnt, delta = 0;

	if (ops->gen_prologue) {
		cnt = ops->gen_prologue(insn_buf, env->seen_direct_write,
					env->prog);
		if (cnt >= ARRAY_SIZE(insn_buf)) {
			verbose("bpf verifier is misconfigured\n");
			return -EINVAL;
		} else if (cnt) {
			new_prog = bpf_patch_insn_data(env, 0, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			env->prog = new_prog;
			delta += cnt - 1;
		}
	}

	insn = env->prog->insnsi + delta;

	for (i = 0; i < insn_cnt; i++, insn++) {
		if (insn->code == (BPF_LDX | BPF_MEM | BPF_W) ||
		    insn->code == (BPF_LDX | BPF_MEM | BPF_DW))
			type = BPF_READ;
		else if (insn->code == (BPF_STX | BPF_MEM | BPF_W) ||
			 insn->code == (BPF_STX | BPF_MEM | BPF_DW))
			type = BPF_WRITE;
		else
			continue;

		if (type == BPF_WRITE &&
		    env->insn_aux_data[i + delta].sanitize_stack_off) {
			struct bpf_insn patch[] = {
				/* Sanitize suspicious stack slot with zero.
				 * There are no memory dependencies for this store,
				 * since it's only using frame pointer and immediate
				 * constant of zero
				 */
				BPF_ST_MEM(BPF_DW, BPF_REG_FP,
					   env->insn_aux_data[i + delta].sanitize_stack_off,
					   0),
				/* the original STX instruction will immediately
				 * overwrite the same stack slot with appropriate value
				 */
				*insn,
			};

			cnt = ARRAY_SIZE(patch);
			new_prog = bpf_patch_insn_data(env, i + delta, patch, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			continue;
		}

		if (env->insn_aux_data[i + delta].ptr_type == PTR_TO_SOCKET ||
		    env->insn_aux_data[i + delta].ptr_type == PTR_TO_SOCK_COMMON) {
			cnt = bpf_sock_convert_ctx_access(type, insn->dst_reg,
						insn->src_reg, insn->off,
						insn_buf, env->prog);
		} else if (env->insn_aux_data[i + delta].ptr_type == PTR_TO_CTX &&
			   ops->convert_ctx_access) {
			cnt = ops->convert_ctx_access(type, insn->dst_reg,
						    insn->src_reg, insn->off,
						    insn_buf, env->prog);
		} else {
			continue;
		}
		if (cnt == 0 || cnt >= ARRAY_SIZE(insn_buf)) {
			verbose("bpf verifier is misconfigured\n");
			return -EINVAL;
		}

		new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
		if (!new_prog)
			return -ENOMEM;

		delta += cnt - 1;

		/* keep walking new program and skip insns we just inserted */
		env->prog = new_prog;
		insn      = new_prog->insnsi + i + delta;
	}

	return 0;
}

/* fixup insn->imm field of bpf_call instructions
 *
 * this function is called after eBPF program passed verification
 */
static int fixup_bpf_calls(struct bpf_verifier_env *env)
{
	struct bpf_prog *prog = env->prog;
	struct bpf_insn *insn = prog->insnsi;
	const struct bpf_func_proto *fn;
	const int insn_cnt = prog->len;
	struct bpf_insn insn_buf[16];
	struct bpf_prog *new_prog;
	struct bpf_map *map_ptr;
	int i, cnt, delta = 0;


	for (i = 0; i < insn_cnt; i++, insn++) {
		if (insn->code != (BPF_JMP | BPF_CALL))
			continue;

		if (insn->imm == BPF_FUNC_get_route_realm)
			prog->dst_needed = 1;
		if (insn->imm == BPF_FUNC_get_prandom_u32)
			bpf_user_rnd_init_once();
		if (insn->imm == BPF_FUNC_tail_call) {
			/* mark bpf_tail_call as different opcode to avoid
			 * conditional branch in the interpeter for every normal
			 * call and to prevent accidental JITing by JIT compiler
			 * that doesn't support bpf_tail_call yet
			 */
			insn->imm = 0;
			insn->code = BPF_JMP | BPF_TAIL_CALL;

			/* instead of changing every JIT dealing with tail_call
			 * emit two extra insns:
			 * if (index >= max_entries) goto out;
			 * index &= array->index_mask;
			 * to avoid out-of-bounds cpu speculation
			 */
			map_ptr = env->insn_aux_data[i + delta].map_ptr;
			if (!map_ptr->unpriv_array)
				continue;
			insn_buf[0] = BPF_JMP_IMM(BPF_JGE, BPF_REG_3,
						  map_ptr->max_entries, 2);
			insn_buf[1] = BPF_ALU32_IMM(BPF_AND, BPF_REG_3,
						    container_of(map_ptr,
								 struct bpf_array,
								 map)->index_mask);
			insn_buf[2] = *insn;
			cnt = 3;
			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			continue;
		}

		fn = prog->aux->ops->get_func_proto(insn->imm, prog);
		/* all functions that have prototype and verifier allowed
		 * programs to call them, must be real in-kernel functions
		 */
		if (!fn->func) {
			verbose("kernel subsystem misconfigured func %d\n",
				insn->imm);
			return -EFAULT;
		}
		insn->imm = fn->func - __bpf_call_base;
	}

	return 0;
}

static void free_states(struct bpf_verifier_env *env)
{
	struct bpf_verifier_state_list *sl, *sln;
	int i;

	if (!env->explored_states)
		return;

	for (i = 0; i < env->prog->len; i++) {
		sl = env->explored_states[i];

		if (sl)
			while (sl != STATE_LIST_MARK) {
				sln = sl->next;
				kfree(sl);
				sl = sln;
			}
	}

	kfree(env->explored_states);
}

int bpf_check(struct bpf_prog **prog, union bpf_attr *attr)
{
	char __user *log_ubuf = NULL;
	struct bpf_verifier_env *env;
	int ret = -EINVAL;

	if ((*prog)->len <= 0 || (*prog)->len > BPF_MAXINSNS)
		return -E2BIG;

	/* 'struct bpf_verifier_env' can be global, but since it's not small,
	 * allocate/free it every time bpf_check() is called
	 */
	env = kzalloc(sizeof(struct bpf_verifier_env), GFP_KERNEL);
	if (!env)
		return -ENOMEM;

	env->insn_aux_data = vzalloc(sizeof(struct bpf_insn_aux_data) *
				     (*prog)->len);
	ret = -ENOMEM;
	if (!env->insn_aux_data)
		goto err_free_env;
	env->prog = *prog;

	/* grab the mutex to protect few globals used by verifier */
	mutex_lock(&bpf_verifier_lock);

	if (attr->log_level || attr->log_buf || attr->log_size) {
		/* user requested verbose verifier output
		 * and supplied buffer to store the verification trace
		 */
		log_level = attr->log_level;
		log_ubuf = (char __user *) (unsigned long) attr->log_buf;
		log_size = attr->log_size;
		log_len = 0;

		ret = -EINVAL;
		/* log_* values have to be sane */
		if (log_size < 128 || log_size > UINT_MAX >> 8 ||
		    log_level == 0 || log_ubuf == NULL)
			goto err_unlock;

		ret = -ENOMEM;
		log_buf = vmalloc(log_size);
		if (!log_buf)
			goto err_unlock;
	} else {
		log_level = 0;
	}
	if (attr->prog_flags & BPF_F_STRICT_ALIGNMENT)
		env->strict_alignment = true;
	else
		env->strict_alignment = false;

	ret = replace_map_fd_with_map_ptr(env);
	if (ret < 0)
		goto skip_full_check;

	env->explored_states = kcalloc(env->prog->len,
				       sizeof(struct bpf_verifier_state_list *),
				       GFP_USER);
	ret = -ENOMEM;
	if (!env->explored_states)
		goto skip_full_check;

	ret = check_cfg(env);
	if (ret < 0)
		goto skip_full_check;

	env->allow_ptr_leaks = capable(CAP_SYS_ADMIN);

	ret = do_check(env);

skip_full_check:
	while (pop_stack(env, NULL) >= 0);
	free_states(env);

	if (ret == 0)
		sanitize_dead_code(env);

	if (ret == 0)
		/* program is valid, convert *(u32*)(ctx + off) accesses */
		ret = convert_ctx_accesses(env);

	if (ret == 0)
		ret = fixup_bpf_calls(env);

	if (log_level && log_len >= log_size - 1) {
		BUG_ON(log_len >= log_size);
		/* verifier log exceeded user supplied buffer */
		ret = -ENOSPC;
		/* fall through to return what was recorded */
	}

	/* copy verifier log back to user space including trailing zero */
	if (log_level && copy_to_user(log_ubuf, log_buf, log_len + 1) != 0) {
		ret = -EFAULT;
		goto free_log_buf;
	}

	if (ret == 0 && env->used_map_cnt) {
		/* if program passed verifier, update used_maps in bpf_prog_info */
		env->prog->aux->used_maps = kmalloc_array(env->used_map_cnt,
							  sizeof(env->used_maps[0]),
							  GFP_KERNEL);

		if (!env->prog->aux->used_maps) {
			ret = -ENOMEM;
			goto free_log_buf;
		}

		memcpy(env->prog->aux->used_maps, env->used_maps,
		       sizeof(env->used_maps[0]) * env->used_map_cnt);
		env->prog->aux->used_map_cnt = env->used_map_cnt;

		/* program is valid. Convert pseudo bpf_ld_imm64 into generic
		 * bpf_ld_imm64 instructions
		 */
		convert_pseudo_ld_imm64(env);
	}

free_log_buf:
	if (log_level)
		vfree(log_buf);
	if (!env->prog->aux->used_maps)
		/* if we didn't copy map pointers into bpf_prog_info, release
		 * them now. Otherwise free_used_maps() will release them.
		 */
		release_maps(env);
	*prog = env->prog;
err_unlock:
	mutex_unlock(&bpf_verifier_lock);
	vfree(env->insn_aux_data);
err_free_env:
	kfree(env);
	return ret;
}

int bpf_analyzer(struct bpf_prog *prog, const struct bpf_ext_analyzer_ops *ops,
		 void *priv)
{
	struct bpf_verifier_env *env;
	int ret;

	env = kzalloc(sizeof(struct bpf_verifier_env), GFP_KERNEL);
	if (!env)
		return -ENOMEM;

	env->insn_aux_data = vzalloc(sizeof(struct bpf_insn_aux_data) *
				     prog->len);
	ret = -ENOMEM;
	if (!env->insn_aux_data)
		goto err_free_env;
	env->prog = prog;
	env->analyzer_ops = ops;
	env->analyzer_priv = priv;

	/* grab the mutex to protect few globals used by verifier */
	mutex_lock(&bpf_verifier_lock);

	log_level = 0;
	env->strict_alignment = false;

	env->explored_states = kcalloc(env->prog->len,
				       sizeof(struct bpf_verifier_state_list *),
				       GFP_KERNEL);
	ret = -ENOMEM;
	if (!env->explored_states)
		goto skip_full_check;

	ret = check_cfg(env);
	if (ret < 0)
		goto skip_full_check;

	env->allow_ptr_leaks = capable(CAP_SYS_ADMIN);

	ret = do_check(env);

skip_full_check:
	while (pop_stack(env, NULL) >= 0);
	free_states(env);

	mutex_unlock(&bpf_verifier_lock);
	vfree(env->insn_aux_data);
err_free_env:
	kfree(env);
	return ret;
}
EXPORT_SYMBOL_GPL(bpf_analyzer);
