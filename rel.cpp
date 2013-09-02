/*
 *  IDA Nintendo Wii Rel Loader Plugin
 *  (C) Copyright 2013 Stephen Simpson
 *
 */

#include <ida.hpp>
#include <fpro.h>
#include <idp.hpp>
#include <loader.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <offset.hpp>
#include <segment.hpp>
#include <srarea.hpp>
#include <fixup.hpp>
#include <entry.hpp>
#include <auto.hpp>
#include <diskio.hpp>
#include <kernwin.hpp>
#include <nalt.hpp>

#include "rel.h"

#define DEBUG 1

uint32_t GetHighestRegisterRoundedUp()
{
	return 0x80680000;
}
void PatchByte(uint32_t address, unsigned char value)
{
	patch_byte((ea_t)address, (ulong)value);
}
uint32_t GetSectionAddress(uint32_t section, uint32_t offset)
{
	char buf[0x100];
	qsnprintf(buf, 0x100, ".section%u", section);
	segment_t * segm = get_segm_by_name(buf);
	if (segm)
	{
		return segm->startEA + offset;
	}
	return 0xFFFFFFFF;
}
void PatchAddress32(uint32_t section, uint32_t offset, uint32_t value)
{
	/* S + A */
	uint32_t where = GetSectionAddress(section, offset);
	patch_long(where, value);
	//PatchByte(where + 0, (value >> 24) & 0xFF);
	//PatchByte(where + 1, (value >> 16) & 0xFF);
	//PatchByte(where + 2, (value >>  8) & 0xFF);
	//PatchByte(where + 3, (value >>  0) & 0xFF);
}
void PatchAddressLO(uint32_t section, uint32_t offset, uint32_t value)
{
	/* lo(S + A) */
	uint32_t where = GetSectionAddress(section, offset);
	patch_word(where, value&0xFFFF);
	//PatchByte(where + 0, (value >> 8) & 0xFF);
	//PatchByte(where + 1, (value >> 0) & 0xFF);
}
void PatchAddressHI(uint32_t section, uint32_t offset, uint32_t value)
{
	/* hi(S + A) */
	uint32_t where = GetSectionAddress(section, offset);
	patch_word(where, (value >> 16) & 0xFFFF);
	//PatchByte(where + 0, (value >> 24) & 0xFF);
	//PatchByte(where + 1, (value >> 16) & 0xFF);
}
void PatchAddressHA(uint32_t section, uint32_t offset, uint32_t value)
{
	/* ha(S + A) */
	uint32_t where = GetSectionAddress(section, offset);
	if ((value & 0x8000) == 0x8000)
	{
		value += 0x00010000;
	}
	patch_word(where, (value >> 16) & 0xFFFF);
	//PatchByte(where + 0, (value >> 24) & 0xFF);
	//PatchByte(where + 1, (value >> 16) & 0xFF);
}
void PatchAddress24(uint32_t section, uint32_t offset, uint32_t value)
{
	/* (S + A - P) >> 2 */
	uint32_t where = GetSectionAddress(section, offset);
	value -= where;
	ulong orig = get_original_long(where);
	orig &= 0xFC000003;
	orig |= value & 0x03FFFFFC;
	PatchByte(where + 0, (orig >> 24) & 0xFF);
	PatchByte(where + 1, (orig >> 16) & 0xFF);
	PatchByte(where + 2, (orig >>  8) & 0xFF);
	PatchByte(where + 3, (orig >>  0) & 0xFF);
}
int read_header(linput_t *fp, rsohdr *rhdr)
{
	/* read in rsoheader */
	qlseek(fp, 0, SEEK_SET);
	int retval = qlread(fp, rhdr, sizeof(rsohdr));
	//if(qlread((linput_t*)fp, rhdr, sizeof(rsohdr)) != sizeof(rsohdr))
	if (retval != sizeof(rsohdr))
	{
#if DEBUG
		msg("Nintendo Rso Loader Plugin 0.1 read_header() : 1\n");
#endif
		return(0);
	}

	/* convert header */
#if USING_RSO
	rhdr->ModuleID = swap32(rhdr->ModuleID);
#endif
	rhdr->Prev = swap32(rhdr->Prev);
	rhdr->Next = swap32(rhdr->Next);
	rhdr->SectionCount = swap32(rhdr->SectionCount);
	rhdr->SectionOffset = swap32(rhdr->SectionOffset);
	rhdr->PathOffset = swap32(rhdr->PathOffset);
	rhdr->PathLength = swap32(rhdr->PathLength);
	rhdr->Version = swap32(rhdr->Version);
	rhdr->BssSize = swap32(rhdr->BssSize);
	rhdr->RelOffset = swap32(rhdr->RelOffset);
	rhdr->ImpOffset = swap32(rhdr->ImpOffset);
	rhdr->ImpSize = swap32(rhdr->ImpSize);
	rhdr->Prolog = swap32(rhdr->Prolog);
	rhdr->Epilog = swap32(rhdr->Epilog);
	rhdr->Unresolved = swap32(rhdr->Unresolved);
#if DEBUG
	msg("Prev:%X\n", rhdr->Prev);
	msg("Next:%X\n", rhdr->Next);
	msg("Section Count: %X\n", rhdr->SectionCount);
	msg("Section Offset: %X\n", rhdr->SectionOffset);
	msg("Path Offset: %X\n", rhdr->PathOffset);
	msg("Path Length: %X\n", rhdr->PathLength);
	msg("Version: %d\n", rhdr->Version);
	msg("BssSize: %08x\n", rhdr->BssSize);
	msg("RelOffset: %08x\n", rhdr->RelOffset);
	msg("ImpOffset: %08x\n", rhdr->ImpOffset);
	msg("ImpSize: %08x\n", rhdr->ImpSize);
	msg("PrologS:%d EpilogS:%d UnresolvedS:%d BssS:%d\n",
			rhdr->PrologSection,
			rhdr->EpilogSection,
			rhdr->UnresolvedSection,
			rhdr->BssSection);
	msg("Prolog:%08x Epilog:%08x Unresolved:%08x\n",
			rhdr->Prolog, rhdr->Epilog, rhdr->Unresolved);
#endif
	if (rhdr->Version >= 2)
	{
		rhdr->align = swap32(rhdr->align);
		rhdr->bssAlign = swap32(rhdr->bssAlign);
	}
	if (rhdr->Version >= 3)
	{
		rhdr->fixSize = swap32(rhdr->fixSize);
	}
	return(1);
}
int read_section_table(linput_t *fp, section_entry *entries, int offset, int count)
{
	int i;
#if DEBUG
	msg("read_section_table(*,*,%08x, %d);\n", offset, count);
#endif
	/* read in section table */
	qlseek(fp, offset, SEEK_SET);
	if(qlread(fp, entries, sizeof(section_entry)*count) != sizeof(section_entry)*count) return(0);

	for(i=0; i<count; i++) {
		entries[i].Offset = swap32(entries[i].Offset);
		entries[i].Length = swap32(entries[i].Length);
#if DEBUG
		msg("Section Offset:%08x Length:%08x\n", entries[i].Offset, entries[i].Length);
#endif
	}
	return(1);
}
int read_import_table(linput_t *fp, import_entry *entries, int offset, int count)
{
	qlseek(fp, offset, SEEK_SET);
	if (qlread(fp, entries, sizeof(import_entry)*count) != sizeof(import_entry)*count) return (0);

	for (uint32_t ii = 0; ii < count; ii++)
	{
		entries[ii].ModuleID = swap32(entries[ii].ModuleID);
		entries[ii].Offset = swap32(entries[ii].Offset);
	}
	return (1);
}

/***************************************************************
* Function:	 init
* Description:
* Parameters:   none
* Returns:	  PLUGIN_OK
***************************************************************/
int idaapi init(void)
{
	return PLUGIN_OK;
}

/***************************************************************
* Function:	 term
* Description:  term
* Parameters:   none
* Returns:	  none
***************************************************************/
void idaapi term(void)
{
}


/******************************************************************
* Function:	 run
* Description:  entry function of the plugin
* Parameters:   int arg
* Returns:	  none
******************************************************************/
void idaapi run(int ZF_arg)
{
	rsohdr rhdr;
	//FILE* fp = NULL;
	linput_t * fp = NULL;

	/* Hello here I am */
	msg("---------------------------------------\n");
	msg("Nintendo Rel Loader Plugin 0.1\n");
	msg("---------------------------------------\n");

	char tBuf1[0x80] = {0};
	get_input_file_path(tBuf1, 0x80);

	char *tBuf3 = NULL;
	char *tBuf4 = NULL;
	qsplitfile(tBuf1, &tBuf3, &tBuf4);

	char filename[0x80] = {0};
	const char* ext = ".rel";
	set_file_ext(filename, 0x80, tBuf3, ext);

	//fp = qlopen(filename, "r+b");
	fp = open_linput(filename, false);
	if(!fp) {
		msg("Error opening file %s\n", filename);
		char* chosen_name = askfile_c(false, "*.rel", "Please choose a .rel file");
		//fp = qlopen(chosen_name, "r+b");
		fp = open_linput(chosen_name, false);
		if(!fp)
			return;
	}
  
	/* get file size */
	qlseek(fp, 0, SEEK_END);
	long filesize = qltell(fp);
	qlseek(fp, 0, SEEK_SET);
#if DEBUG
	msg("File length: %d bytes\n", filesize);
#endif
	/* read rel header into memory */
	if (read_header(fp, &rhdr)==0)
	{
		msg("Error reading rel header into memory\n");
		return;
	}
 
	section_entry* sections = new section_entry[rhdr.SectionCount];
	if(read_section_table(fp, sections, rhdr.SectionOffset, rhdr.SectionCount) == 0) qexit(1);
	qlseek(fp, 0, SEEK_SET);

	/* GET LOWEST ALIGNED MEMORY SPACE */
	uint32_t space = GetHighestRegisterRoundedUp();

	/* SHOW A WAIT BOX TO LET EU KNOW WE MEAN BUSINESS */
	show_wait_box("Doing something cool");

	uint32_t seg_off = space;
	/* create all segments */
	for (uint32_t i = 0; i < rhdr.SectionCount; i++)
	{
		char buf[0x100];

		/* 0 == no segment */
		if ((sections[i].Length != 0) && (sections[i].Offset == 0))
		{
			/* FOUND OUR BSS */
		}
		else if ((sections[i].Length == 0) && (sections[i].Offset == 0))
		{
			continue;
		}

		qsnprintf(buf, 0x50, ".section%u", i);

#if DEBUG
		msg("Section Offset: %08x\n", sections[i].Offset);
		msg("Section Length: %08x\n", sections[i].Length);
#endif
		
		/* add the segment */
		/* is_ephemeral_segm */
		if (sections[i].Offset & SECTION_EXEC)
		{
			//add_segm_ex(1, seg_off, seg_off+sections[i].Length, buf, "CODE", ADDSEG_OR_DIE|ADDSEG_QUIET);
			if (!add_segm(1, seg_off, seg_off+sections[i].Length, buf, "CODE")) qexit(1);
		}
		else
		{
			//if (!add_segm(1, seg_off, seg_off+sections[i].Length, buf, "DATA")) qexit(1);
			if (!add_segm(1, seg_off, seg_off+sections[i].Length, buf, "CONST")) qexit(1);
			//add_segm_ex(1, seg_off, seg_off+sections[i].Length, buf, "CONST", ADDSEG_OR_DIE|ADDSEG_QUIET);
		}

		/* set addressing to 32 bit */
		set_segm_addressing(getseg(seg_off), 1);

		/* and get the content from the file */
		if (sections[i].Offset)
		{
			file2base((linput_t*)fp, SECTION_OFF(sections[i].Offset), seg_off, seg_off+sections[i].Length, FILEREG_PATCHABLE);
		}

		/* update the segment offset */
		seg_off += sections[i].Length;
	}

	if (rhdr.ImpOffset)
	{
		uint32_t count = rhdr.ImpSize / sizeof(import_entry);
		import_entry * entries = new import_entry [count];
		int imps = read_import_table(fp, entries, rhdr.ImpOffset, count);
		if (imps)
		{
			for (uint32_t ii = 0; ii < count; ii++)
			{
				if (entries[ii].ModuleID == 0)
				{ /* HANDLE MAIN DOL */
					msg("Handling main dol\n");
					uint32_t current_section = 0;
					uint32_t current_offset  = 0;
					qlseek(fp, entries[ii].Offset, SEEK_SET);
					rel_t rel;
					if (qlread(fp, &rel, sizeof(rel_t)) == (sizeof(rel_t)))
					{
						rel.offset = swap16(rel.offset);
						rel.addend = swap32(rel.addend);
						while (rel.type != R_DOLPHIN_END)
						{
							if (rel.type == R_DOLPHIN_SECTION)
							{
								current_section = rel.section;
								current_offset  = 0;
							}
							else if (rel.type == R_DOLPHIN_NOP)
							{
								current_offset += rel.offset;
							}
							else if (rel.type == R_PPC_ADDR32)
							{
								current_offset += rel.offset;
								PatchAddress32(current_section, current_offset, rel.addend);
							}
							else if (rel.type == R_PPC_ADDR16_LO)
							{
								current_offset += rel.offset;
								PatchAddressLO(current_section, current_offset, rel.addend);
							}
							else if (rel.type == R_PPC_ADDR16_HA)
							{
								current_offset += rel.offset;
								PatchAddressHA(current_section, current_offset, rel.addend);
							}
							else if (rel.type == R_PPC_REL24)
							{
								current_offset += rel.offset;
								PatchAddress24(current_section, current_offset, rel.addend);
							}
							else
							{
								msg("BAD RELOC TYPE: %d\n", rel.type);
								break;
							}
							if (qlread(fp, &rel, sizeof(rel_t)) != sizeof(rel_t))
							{
								break;
							}
							rel.offset = swap16(rel.offset);
							rel.addend = swap32(rel.addend);
						}
					}
				}
				else if (entries[ii].ModuleID == rhdr.ModuleID)
				{ /* HANDLE THIS MODULE */
					msg("Handling this module\n");
					uint32_t current_section = 0;
					uint32_t current_offset  = 0;
					qlseek(fp, entries[ii].Offset, SEEK_SET);
					rel_t rel;
					if (qlread(fp, &rel, sizeof(rel_t)) == (sizeof(rel_t)))
					{
						rel.offset = swap16(rel.offset);
						rel.addend = swap32(rel.addend);
						while (rel.type != R_DOLPHIN_END)
						{
							if (rel.type == R_DOLPHIN_SECTION)
							{
								current_section = rel.section;
								current_offset  = 0;
							}
							else if (rel.type == R_DOLPHIN_NOP)
							{
								current_offset += rel.offset;
							}
							else if (rel.type == R_PPC_ADDR32)
							{
								current_offset += rel.offset;
								PatchAddress32(current_section, current_offset, GetSectionAddress(rel.section, rel.addend));
							}
							else if (rel.type == R_PPC_ADDR16_LO)
							{
								current_offset += rel.offset;
								PatchAddressLO(current_section, current_offset, GetSectionAddress(rel.section, rel.addend));
							}
							else if (rel.type == R_PPC_ADDR16_HA)
							{
								current_offset += rel.offset;
								PatchAddressHA(current_section, current_offset, GetSectionAddress(rel.section, rel.addend));
							}
							else if (rel.type == R_PPC_REL24)
							{
								current_offset += rel.offset;
								PatchAddress24(current_section, current_offset, GetSectionAddress(rel.section, rel.addend));
							}
							else
							{
								msg("BAD RELOC TYPE: %d\n", rel.type);
								break;
							}
							if (qlread(fp, &rel, sizeof(rel_t)) != sizeof(rel_t))
							{
								break;
							}
							rel.offset = swap16(rel.offset);
							rel.addend = swap32(rel.addend);
						}
					}
				}
				else
				{ /* LINKING AGAINST ANOTHER REL */
					msg("Need to link against another module\n");
				}
			}
		}
		delete [] entries;
	}
	delete [] sections;

	close_linput(fp);
	//qfclose(fp);

	/* HIDE THAT DARNED WAIT BOX BECAUSE WE FINISHED */
	hide_wait_box();
}

//-----------------------------------------------------------------
char comment[] = "This links a rel file into a dol.";
char help[]	= "Import REL file\n\n";
char wanted_name[]   = "REL Loader";
char wanted_hotkey[] = "Alt-X";

//-----------------------------------------------------------------
//
//	  PLUGIN DESCRIPTION BLOCK
//
//-----------------------------------------------------------------

#ifdef _WIN32
#define EXPORT __declspec( dllexport )
#else
#define EXPORT
#endif
extern "C" plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  0,				// plugin flags
  init,				// initialize
  term,				// terminate. this pointer may be NULL.
  run,				// invoke plugin
  comment,			// long comment about the plugin
					// it could appear in the status line
					// or as a hint
  help,				// multiline help about the plugin
  wanted_name,		// the preferred short name of the plugin
  wanted_hotkey		// the preferred hotkey to run the plugin
};

