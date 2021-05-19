#pragma once
#include "vmtracer.hpp"

namespace vmp2
{
	enum class exec_type_t
	{
		forward,
		backward
	};

	enum class version_t
	{
		invalid,
		v1 = 0x101
	};

	struct file_header
	{
		u32 magic; // VMP2!
		u64 epoch_time;
		u64 module_base;
		exec_type_t advancement;
		version_t version;

		u32 entry_count;
		u32 entry_offset;
	};

	struct entry_t
	{
		u8 handler_idx;
		u64 decrypt_key;
		u64 vip;

		union
		{
			struct
			{
				u64 r15;
				u64 r14;
				u64 r13;
				u64 r12;
				u64 r11;
				u64 r10;
				u64 r9;
				u64 r8;
				u64 rbp;
				u64 rdi;
				u64 rsi;
				u64 rdx;
				u64 rcx;
				u64 rbx;
				u64 rax;
				u64 rflags;
			};
			u64 raw[16];
		} regs;

		union
		{
			u64 qword[0x28];
			u8 raw[0x140];
		} vregs;

		union
		{
			u64 qword[0x20];
			u8 raw[0x100];
		} vsp;
	};
}