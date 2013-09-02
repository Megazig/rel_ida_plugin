/*
 *  IDA Nintendo Wii Rel Loader Plugin
 *  (C) Copyright 2013 Stephen Simpson
 *
 */

#ifndef __RSO_H__
#define __RSO_H__

//#define START	0x80500000
#include <cstdint>

/* Header Size = 100h bytes */
typedef struct {
	void * head;
	void * tail;
} queue_t;

typedef struct {
	void * next;
	void * prev;
} link_t;

typedef struct {
	uint32_t align;
	uint32_t bssAlign;
} module_v2;

typedef struct {
	uint32_t fixSize;
} module_v3;

#define USING_RSO 1
typedef struct {
	/* in .rso or .rel, not in .sel */
#if USING_RSO
	uint32_t ModuleID;
#endif
	/* in .rso or .rel or .sel */
	uint32_t Prev;
	uint32_t Next;
	uint32_t SectionCount;
	uint32_t SectionOffset;
	uint32_t PathOffset;
	uint32_t PathLength;
	uint32_t Version;

	/* type 1 or later */
	uint32_t BssSize;
	uint32_t RelOffset;
	uint32_t ImpOffset;
	uint32_t ImpSize;
	unsigned char PrologSection;
	unsigned char EpilogSection;
	unsigned char UnresolvedSection;
	unsigned char BssSection;
	uint32_t Prolog;
	uint32_t Epilog;
	uint32_t Unresolved;

	/* type 2 or later */
	uint32_t align;
	uint32_t bssAlign;

	/* type 3 or later */
	uint32_t fixSize;
} rsohdr;

typedef struct {
	uint32_t internal_table_offset; // 30
	uint32_t internal_table_length; // 34
	uint32_t external_table_offset; // 38
	uint32_t external_table_length; // 3C
	uint32_t export_table_offset; // 40
	uint32_t export_table_length; // 44
	uint32_t export_table_names; // 48
	uint32_t import_table_offset; // 4C
	uint32_t import_table_length; // 50
	uint32_t import_table_names; // 54
} module_v1_extra;

/* usually right after header */
typedef struct {
	uint32_t Offset;
	uint32_t Length;
} section_entry;

/* usually after section list */
/* usually an export then import */
typedef struct {
	uint32_t offset;
	uint32_t length;
	uint32_t names;
} ex_im_port_entry;

typedef struct {
	uint32_t name_off;
	uint32_t section_off;
	uint32_t section_num;
	uint32_t elf_hash;
} export_table_entry;

typedef struct {
	uint32_t ModuleID;
	uint32_t Offset;
} import_entry;

#define SECTION_EXEC 0x1
#define SECTION_OFF(off) (off&~1)

typedef struct {
	uint32_t id;
	uint32_t offset;
} import_info;

typedef struct {
	uint16_t offset; // byte offset from previous entry
	unsigned char  type;
	unsigned char  section;
	uint32_t   addend;
} rel_t;

const char * rel_names[] = {
	"R_PPC_NONE",
	"R_PPC_ADDR32",
	"R_PPC_ADDR24",
	"R_PPC_ADDR16",
	"R_PPC_ADDR16_LO",
	"R_PPC_ADDR16_HI",
	"R_PPC_ADDR16_HA",
	"R_PPC_ADDR14",
	"R_PPC_ADDR14_BRTAKEN",
	"R_PPC_ADDR14_BRNTAKEN",
	"R_PPC_REL24",
	"R_PPC_REL14",
};
                                    /* calculation */
#define R_PPC_NONE            0     /* none */
#define R_PPC_ADDR32          1     /* S + A */
#define R_PPC_ADDR24          2     /* (S + A) >> 2 */
#define R_PPC_ADDR16          3     /* S + A */
#define R_PPC_ADDR16_LO       4
#define R_PPC_ADDR16_HI       5
#define R_PPC_ADDR16_HA       6
#define R_PPC_ADDR14          7
#define R_PPC_ADDR14_BRTAKEN  8
#define R_PPC_ADDR14_BRNTAKEN 9
#define R_PPC_REL24           10   /* (S + A - P) >> 2 */
#define R_PPC_REL14           11

#define R_DOLPHIN_NOP     201 // C9h current offset += rel.offset
#define R_DOLPHIN_SECTION 202 // CAh current offset = rel.section
#define R_DOLPHIN_END     203 // CBh
#define R_DOLPHIN_MRKREF  204 // CCh

/* OSSetStringTable(const void * stringTable);
 * OSLink(OSModuleInfo* newModule, void* bss);
 * OSLinkFixed(OSModuleInfo* newModule, void* bss);
 * OSUnlink(OSModuleInfo* oldModule);
 * OSSearchModule(void* ptr, u32* section, u32* offset);
 * OSNotifyLink
 * OSNotifyUnlink
 * OSNotifyPreLink
 * OSNotifyPostLink
 */

#endif
