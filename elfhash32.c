#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/user.h>
#include "elf.h"
#include "elfhash.h"

#ifndef PAGE_SIZE
  #define PAGE_SIZE (getpagesize())
#endif

#ifndef ELFCLASS
#define ELFCLASS 32
#endif

#if ( ELFCLASS == 32)
  #define ElfXX Elf32
  #define ElfXX_Ehdr  Elf32_Ehdr
  #define ElfXX_Shdr  Elf32_Shdr
  #define ElfXX_Phdr  Elf32_Phdr
  #define ElfXX_Addr  Elf32_Addr
  #define ElfXX_Word  Elf32_Word
  #define ElfXX_Sword Elf32_Sword
  #define ElfXX_Sym   Elf32_Sym
  #define ElfXX_Dyn   Elf32_Dyn
  #define ElfXX_Half  Elf32_Half
  #define ELFXX_ST_TYPE(I) ELF32_ST_TYPE(I)
  #define ELFXX_BloomWord Elf32_Addr
  #define ELFXX_Verneed Elf32_Verneed
  #define ELFXX_Vernaux Elf32_Vernaux
  #define ELFXX_Verndef Elf32_Verdef
#elif ( ELFCLASS == 64)
  #define ElfXX Elf64
  #define ElfXX_Ehdr  Elf64_Ehdr
  #define ElfXX_Shdr  Elf64_Shdr
  #define ElfXX_Phdr  Elf64_Phdr
  #define ElfXX_Addr  Elf64_Addr
  #define ElfXX_Word  Elf64_Word
  #define ElfXX_Sword Elf64_Sword
  #define ElfXX_Sym   Elf64_Sym
  #define ElfXX_Dyn   Elf64_Dyn
  #define ElfXX_Half  Elf64_Half
  #define ELFXX_ST_TYPE(I) ELF64_ST_TYPE(I)
  #define ELFXX_BloomWord Elf64_Addr
  #define ELFXX_Verneed Elf64_Verneed
  #define ELFXX_Vernaux Elf64_Vernaux
  #define ELFXX_Verndef Elf64_Verdef
#else
  #error "ELFCLASS undefined."
#endif

typedef struct _ElfGnuHashHdr {
	ElfXX_Word nbuckets;
	ElfXX_Word symndx;
	ElfXX_Word maskwords;
	ElfXX_Word shift2;
}ElfGnuHashHdr;
/** section header types names. Only used for debug output */
static const char*sh_types[] =
  {
    [0]  = "NULL",
    [1]  = "PROGBITS",
    [2]  = "SYMTAB",
    [3]  = "STRTAB",
    [4]  = "RELA",
    [5]  = "HASH",
    [6]  = "DYNAMIC",
    [7]  = "NOTE",
    [8]  = "NOBITS",
    [9]  = "REL",
    [10] = "SHLIB",
    [11] = "DYNSYM"
  };

/** program header types names. Only used for debug output */
static const char*ph_types[] =
  {
    [0] = "NULL",
    [1] = "LOAD",
    [2] = "DYNAMIC",
    [3] = "INTERP",
    [4] = "NOTE",
    [5] = "SHLIB",
    [6] = "PHDR"
  };

//zzz add begin, ref: https://blogs.oracle.com/ali/gnu-hash-elf-sections
typedef struct _obj_state_t {
    const char           *os_dynstr;      /* Dynamic string table */
    ElfXX_Sym            *os_dynsym;      /* Dynamic symbol table */
    ElfXX_Word            os_nbuckets;     /* # hash buckets */
    ElfXX_Word            os_symndx;       /* Index of 1st dynsym in hash */
    ElfXX_Word            os_maskwords_bm; /* # Bloom filter words, minus 1 */
    ElfXX_Word            os_shift2;       /* Bloom filter hash shift */
    ELFXX_BloomWord      *os_bloom;       /* Bloom filter words */
    ElfXX_Word           *os_buckets;     /* Hash buckets */
    ElfXX_Word           *os_hashval;     /* Hash value array */
    int dynsymcount;
} obj_state_t;
static ElfXX_Addr dl_new_hash (const char *s)
{
	ElfXX_Addr h = 5381;
	for (unsigned char c = *s; c != '\0'; c = *++s)
          h = h * 33 + c;
    return h & 0xffffffff;
}
static ElfXX_Sym *symhash_lookup(obj_state_t *os, const char *symname)
{
	ElfXX_Word            c;
	ElfXX_Word            h1, h2;
	ElfXX_Word            n;
	ELFXX_BloomWord       bitmask;
	const ElfXX_Sym       *sym;
    ElfXX_Word            *hashval;

	/*
	 * Hash the name, generate the "second" hash
	 * from it for the Bloom filter.
	 */
	h1 = dl_new_hash(symname);
	h2 = h1 >> os->os_shift2;

	/* Test against the Bloom filter */
	c = sizeof (ELFXX_BloomWord) * 8;
	n = (h1 / c) % os->os_maskwords_bm;
	printf("symhash_lookup: %s, bloom n=%d\n", symname);

	// debug begin
	// debug end

	bitmask = (1L << (h1 % c)) | (1L << (h2 % c));
	printf("symhash_lookup %s\n h1=0x%x, n=%d, bitmask=0x%x, bloom[%d]=0x%x\n", symname, h1, n, bitmask, n, os->os_bloom[n]);
	if ((os->os_bloom[n] & bitmask) != bitmask)
			return (NULL);

	/* Locate the hash chain, and corresponding hash value element */
	int bucket = h1 % os->os_nbuckets;
	n = os->os_buckets[bucket];
	if (n == 0)    /* Empty hash chain, symbol not present */
			return (NULL);
	sym = &os->os_dynsym[n];
	hashval = &os->os_hashval[n - os->os_symndx];
	printf("symhash_lookup bucket=%d, bucket[%d]=%d, hash_n=%d, hashval=0x%x\n", bucket, bucket, n, n - os->os_symndx, (*hashval));

	/*
	 * Walk the chain until the symbol is found or
	 * the chain is exhausted.
	 */
	for (h1 &= ~1L; 1L; sym++) {
			h2 = *hashval++;

			/*
			 * Compare the strings to verify match. Note that
			 * a given hash chain can contain different hash
			 * values. We'd get the right result by comparing every
			 * string, but comparing the hash values first lets us
			 * screen obvious mismatches at very low cost and avoid
			 * the relatively expensive string compare.
			 *
			 * We are intentionally glossing over some things here:
			 *
			 * - We could test sym->st_name for 0, which indicates
			 *   a NULL string, and avoid a strcmp() in that case.
			 *
			 * - The real runtime linker must also take symbol
			 *   versioning into account. This is an orthogonal
			 *   issue to hashing, and is left out of this
			 *    example for simplicity.
			 *
			 * A real implementation might test (h1 == (h2 & ~1), and then
			 * call a (possibly inline) function to validate the rest.
			 */
			 if ((h1 == (h2 & ~1L)) &&
				 !strcmp(symname, os->os_dynstr + sym->st_name))
					 return (sym);

			 /* Done if at end of chain */
			 if (h2 & 1)
					 break;
	}

	/* This object does not have the desired symbol */
	return (NULL);
}

static int symhash_rebuild(obj_state_t *os, const char* test_str){
	//recalculate nbucket
	int nbucket = os->os_nbuckets;
	int bloomwords = os->os_maskwords_bm;
	int c = sizeof(ELFXX_BloomWord)*8;
	int hashval_cnt = (os->dynsymcount-os->os_symndx);
	ELFXX_BloomWord *bloom = (ELFXX_BloomWord *)malloc(sizeof(ELFXX_BloomWord)*bloomwords);
	ElfXX_Word *buckets = (ElfXX_Word *)malloc(sizeof(ElfXX_Word)*nbucket);
	ElfXX_Word *hashval = (ElfXX_Word *)malloc(sizeof(ElfXX_Word)*hashval_cnt);
	memset(bloom, 0, sizeof(ELFXX_BloomWord)*bloomwords);
	memset(buckets, 0, sizeof(ElfXX_Word)*nbucket);
	memset(hashval, 0, sizeof(ElfXX_Word)*hashval_cnt);

	// rearrange the sym index, make sure same [h1%nbuckets] objects stay together
	// simple bubble sort
	ElfXX_Sym *backup_syms = (ElfXX_Sym *)malloc(sizeof(ElfXX_Sym)*(os->dynsymcount-os->os_symndx));
	memcpy(backup_syms, &os->os_dynsym[os->os_symndx], sizeof(ElfXX_Sym)*(os->dynsymcount-os->os_symndx));

	int* array1 = (int*)malloc(sizeof(int)*(os->dynsymcount-os->os_symndx));
	int* array2 = (int*)malloc(sizeof(int)*(os->dynsymcount-os->os_symndx));
	memset(array1, 0, sizeof(int)*(os->dynsymcount-os->os_symndx));
	memset(array2, 0, sizeof(int)*(os->dynsymcount-os->os_symndx));
	for(int i=os->os_symndx;i<os->dynsymcount;i++){
		ElfXX_Sym *sym = (ElfXX_Sym *)&os->os_dynsym[i];
		const char *name = (const char *)&os->os_dynstr[sym->st_name];
		ElfXX_Word h1 = dl_new_hash(name);
		int bucket = h1%nbucket;
		printf("i=%d, bucket=%d\n", i, bucket);
		array1[i-os->os_symndx]=bucket;
		array2[i-os->os_symndx]=i;
	}
	for(int i=0; i<os->dynsymcount-os->os_symndx;i++){
		for(int j=i+1;j<os->dynsymcount-os->os_symndx; j++){
			if(array1[i]>array1[j]){
				int tmp = array1[i];
				array1[i]=array1[j];
				array1[j]=tmp;
				tmp = array2[i];
				array2[i]=array2[j];
				array2[j]=tmp;
			}
		}
	}

	for(int i=os->os_symndx;i<os->dynsymcount;i++){
		if(array2[i-os->os_symndx] != i){
			printf("i=%d, bucket=%d, newi=%d\n", i, array1[i-os->os_symndx], array2[i-os->os_symndx]);
			// change
			memcpy(&os->os_dynsym[i], &backup_syms[array2[i-os->os_symndx]-os->os_symndx], sizeof(ElfXX_Sym));
		}
	}
	free(array1);
	free(array2);
	free(backup_syms);

	for(int i=os->os_symndx;i<os->dynsymcount;i++){
		ElfXX_Sym *sym = (ElfXX_Sym *)&os->os_dynsym[i];
		const char *name = (const char *)&os->os_dynstr[sym->st_name];
		ElfXX_Word h1 = dl_new_hash(name);
		ElfXX_Word h2 = h1>>os->os_shift2;
		ElfXX_Word n = ((h1/c)%bloomwords);

		// bloom
		ELFXX_BloomWord bitmask = (1L<<(h1%c))|(1L<<(h2%c));
		bloom[n] |= bitmask;

		if(!strcmp(name, test_str)){
			printf("symhash_rebuild %s\n h1=0x%x, n=%d, bitmask=0x%x, bloom[%d]=0x%x\n", name, h1, n, bitmask, n, bloom[n]);
		}
		// bucket
		int bucket = h1%nbucket;
		if(buckets[bucket]==0){
			buckets[bucket] = i;
		}
		if(!strcmp(name, test_str)){
			printf(" bucket=%d, buckets[%d]=%d\n", bucket, bucket, buckets[bucket]);
		}
		// hashval
		int lsb = 1;
		if(i< os->dynsymcount-1){
			ElfXX_Sym *next_sym = (ElfXX_Sym *)&os->os_dynsym[i+1];
			const char *next_name = (const char *)&os->os_dynstr[next_sym->st_name];
			ElfXX_Word next_h1 = dl_new_hash(next_name);
			int next_bucket = next_h1%nbucket;
			if(bucket == next_bucket){
				lsb = 0;
			}
		}
		int hash_n = i-os->os_symndx;
		hashval[hash_n]=(h1&~1L)|lsb;
		if(!strcmp(name, test_str)){
			printf(" hash_n=%d, hashval[%d]=0x%x\n", hash_n, hash_n, hashval[hash_n]);
		}

		if(os->os_hashval[hash_n]!= hashval[hash_n]){
			printf("i=%d, name=%s, n=%d\n", i, name, n);
			printf("i=%d, hashval hash_n=%d, old=0x%x, new=0x%x\n", i,  hash_n, os->os_hashval[hash_n], hashval[hash_n]);
		}
	}
	// compare bloom
	if(memcmp(bloom, os->os_bloom, sizeof(ELFXX_BloomWord)*bloomwords)){
		printf("symhash_rebuild: blooms changed\n");
		memcpy(os->os_bloom, bloom, sizeof(ELFXX_BloomWord)*bloomwords);
	}else{
		printf("symhash_rebuild: blooms unchanged\n");
	}
	// compare buckets
	if(memcmp(buckets, os->os_buckets, sizeof(ElfXX_Word)*nbucket)){
		printf("symhash_rebuild: buckets changed\n");
		memcpy(os->os_buckets, buckets, sizeof(ElfXX_Word)*nbucket);
	}else{
		printf("symhash_rebuild: buckets unchanged\n");
	}

	// compare buckets
	if(memcmp(hashval, os->os_hashval, sizeof(ElfXX_Word)*hashval_cnt)){
		printf("symhash_rebuild: hashval changed\n");
		memcpy(os->os_hashval, hashval, sizeof(ElfXX_Word)*hashval_cnt);
	}else{
		printf("symhash_rebuild: hashval unchanged\n");
	}
	free(bloom);
	free(buckets);
	free(hashval);

	return 1;
}
//zzz add end
/** Get a section header from its index */
static ElfXX_Shdr *elf_get_shdr(char*_base, int i)
{
  ElfXX_Ehdr*_ehdr = (ElfXX_Ehdr*)_base;
  return (ElfXX_Shdr*)(_base + _ehdr->e_shoff + i * _ehdr->e_shentsize);
}

static char *elf_get_section_name(char*_base, ElfXX_Shdr*_shdr)
{
  ElfXX_Ehdr*_ehdr = (ElfXX_Ehdr*)_base;
  ElfXX_Shdr*strtab_hdr = elf_get_shdr(_base, _ehdr->e_shstrndx);
  char*strtab_base = _base + strtab_hdr->sh_offset;
  return (strtab_base + _shdr->sh_name);
}

static ElfXX_Shdr *elf_get_section_bytype(char*_base, ElfXX_Word type)
{
  int j;
  ElfXX_Ehdr*_ehdr = (ElfXX_Ehdr*)_base;
  for(j = 0; j < _ehdr->e_shnum; j++)
    {
      ElfXX_Shdr*_shdr = elf_get_shdr(_base, j);
      if(_shdr->sh_type == type)
	return _shdr;
    }
  return NULL;
}

static ElfXX_Shdr *elf_get_section_byname(char*_base, const char*name)
{
  int j;
  ElfXX_Ehdr*_ehdr = (ElfXX_Ehdr*)_base;
  for(j = 0; j < _ehdr->e_shnum; j++) {
    ElfXX_Shdr*_shdr = elf_get_shdr(_base, j);
    const char*n = elf_get_section_name(_base, _shdr);
    if(strcmp(name, n) == 0)
      return _shdr;
  }
  return NULL;
}

/** Get a program header from its index */
static ElfXX_Phdr *elf_get_phdr(char*_base, int i)
{
  const ElfXX_Ehdr*_ehdr = (ElfXX_Ehdr*)_base;
  return (ElfXX_Phdr*)(_base + _ehdr->e_phoff + i * _ehdr->e_phentsize);
}

/** find a '_DYNAMIC' entry for a given tag */
static ElfXX_Dyn *elf_get_dynamic_entry(char*_base, ElfXX_Sword tag)
{
  int i;
  const ElfXX_Ehdr*_ehdr = (ElfXX_Ehdr*)_base;
  ElfXX_Phdr*dynamic_phdr = NULL;
  for(i = 0; i < _ehdr->e_phnum; i++) {
    ElfXX_Phdr*phdr = elf_get_phdr(_base, i);
    if(phdr->p_type == PT_DYNAMIC) {
      dynamic_phdr = phdr;
      break;
    }
  }
  ElfXX_Dyn*_DYNAMIC = (ElfXX_Dyn*)(_base + dynamic_phdr->p_offset);
  for(i = 0; _DYNAMIC[i].d_tag != DT_NULL ; i++) {
    if(_DYNAMIC[i].d_tag == tag)
      return &_DYNAMIC[i];
  }
  return NULL;
}

/** The ELF symbol Sys V hashing function */
static unsigned long elf_hash(const unsigned char*name)
{
  unsigned long h = 0, g = 0;
  while(*name) {
    h = (h << 4) + *name++;
    if((g = h & 0xf0000000))
      h ^= g >> 24;
    h &= ~g;
  }
  return h;
}

/** The ELF symbol GNU hashing function */
static unsigned long elf_gnu_hash(const unsigned char*name)
{
  unsigned long h = 5381;
  unsigned char c;
  while ((c = *name++) != '\0') {
    h = (h << 5) + h + c;
  }
  return h & 0xffffffff;
}

/** Compute the gap to insert in the ELF file (including padding for alignment)
 */
#if ( ELFCLASS == 32 )
unsigned long elfhash_compute_gap32(void*base)
#elif (ELFCLASS == 64 )
unsigned long elfhash_compute_gap64(void*base)
#endif
{
  const ElfXX_Ehdr*ehdr = (ElfXX_Ehdr*)base;
  unsigned long gap = 32768;
  /* TODO: check that it is enough for .dynstr and .hash */
  int i;
  for(i = 0; i < ehdr->e_phnum; i++) {
    ElfXX_Phdr*phdr = elf_get_phdr(base, i);
    if(phdr->p_type == PT_LOAD) {
      const unsigned long align = (phdr->p_align > 1)?phdr->p_align:PAGE_SIZE;
      if(gap % align != 0) {
	gap += align - (gap % align);
      }
      assert(gap % align == 0);
      assert(gap % PAGE_SIZE == 0);
    }
  }
  return gap;
}

/** re-builds a full SysV-compliant symbol hashtable.
 */
static void elfhash_rebuild_hashtable_sysv(void*base, ElfXX_Word*hash_base)
{
  int i;
  unsigned long offset;
  long int nbucket = hash_base[0];
  long int nchain  = hash_base[1];
  ElfXX_Word*bucket = &hash_base[2];
  ElfXX_Word*chain  = &hash_base[2 + nbucket];
  ElfXX_Shdr*dynsyms_shdr = elf_get_section_bytype(base, SHT_DYNSYM);
  ElfXX_Shdr*dynstr_shdr  = elf_get_shdr(base, dynsyms_shdr->sh_link);
  
  //printf("- rebuild hash table- nbucket=%ld; nchain=%ld (%ld symbols in section .dynsym)\n",
	// nbucket, nchain, (long)(dynsyms_shdr->sh_size / dynsyms_shdr->sh_entsize));
  for(i = 0 ; i < nbucket ; i++)
    bucket[i] = STN_UNDEF;
  for(i = 0 ; i < nchain ; i++)
    chain[i] = STN_UNDEF;
  //printf("- hashing...\n");
  ElfXX_Word k = 0;
  for(offset = 0; offset < dynsyms_shdr->sh_size; offset += dynsyms_shdr->sh_entsize) {
    ElfXX_Sym*sym = (ElfXX_Sym*)(base + dynsyms_shdr->sh_offset + offset);
    unsigned char*symbol = (unsigned char*)(base + dynstr_shdr->sh_offset + sym->st_name);
    unsigned long x = elf_hash(symbol);
    if(bucket[x % nbucket] == STN_UNDEF)
      bucket[x % nbucket] = k;
    else {
      ElfXX_Word y = bucket[x % nbucket];
      while(chain[y] != STN_UNDEF)
	y = chain[y];
      chain[y] = k;
    }
    k++;
  }
}

/** builds a full SysV-compliant symbol hashtable from scratch
 */
static void elfhash_create_hashtable_sysv(void*base, ElfXX_Word*hash_base, ElfXX_Shdr*hash_shdr)
{
  ElfXX_Shdr*dynsyms_shdr = elf_get_section_bytype(base, SHT_DYNSYM);
  long int nchain = dynsyms_shdr->sh_size / dynsyms_shdr->sh_entsize;
  long int nbucket = nchain * 2 + 1;
  //printf("- creating full SysV hash table- nbucket=%ld; nchain=%ld (%ld symbols in section .dynsym)\n",
	// nbucket, nchain, (long)(dynsyms_shdr->sh_size / dynsyms_shdr->sh_entsize));
  hash_base[0] = nbucket;
  hash_base[1] = nchain;
  elfhash_rebuild_hashtable_sysv(base, hash_base);

  const long new_offset = (void*)hash_base - base;
  const long shift = new_offset - hash_shdr->sh_offset;
  char*hashname = elf_get_section_name(base, hash_shdr);
  if(strcmp(hashname, ".hash") != 0) {
    strcpy(hashname, ".hash");
  }
  hash_shdr->sh_type = SHT_HASH;
  hash_shdr->sh_offset += shift;
  hash_shdr->sh_addr   += shift;

  ElfXX_Dyn*d = elf_get_dynamic_entry(base, DT_HASH);
  if(d) {
    //printf("- adjusting .hash ptr in _DYNAMIC segment\n");
  }
  else {
#ifdef DT_GNU_HASH
    d = elf_get_dynamic_entry(base, DT_GNU_HASH);
    if(d) {
      //printf("- converting .gnu.hash in _DYNAMIC segment into .hash\n");
    }
#endif
  }
  if(!d) {
    fprintf(stderr, "Cannot register hashtable in _DYNAMIC segment.\n");
    return;
  }
  d->d_un.d_ptr = hash_shdr->sh_addr;
  d->d_tag = DT_HASH;
}


/** lists ELF content to screen for debug.
 */
#if ( ELFCLASS == 32 )
void elfhash_listcontent32(char* base)
#elif (ELFCLASS == 64 )
void elfhash_listcontent64(char* base)
#endif
{
  ElfXX_Ehdr*ehdr = (ElfXX_Ehdr*)base;
  int i;
  /* ELF header */
  printf("** ELF headers\n");
  printf("- machine: 0x%02x\n", ehdr->e_machine);
  printf("- section header: offset=0x%08lX; ends=0x%08lX\n", (unsigned long)ehdr->e_shoff,
	 (unsigned long)ehdr->e_shoff+ehdr->e_shnum*ehdr->e_shentsize);
  printf("- program header: offset=0x%08lX; ends=0x%08lX\n", (unsigned long)ehdr->e_phoff,
	 (unsigned long)ehdr->e_phoff+ehdr->e_phnum*ehdr->e_phentsize);

  /* Sections headers */
  printf("** Listing sections\n");
  printf("section | ____________name | type_________________ | vaddr________________ | offset_______________ | ____size | _align \n");
  for(i = 0; i < ehdr->e_shnum; i++) {
    ElfXX_Shdr*shdr = elf_get_shdr(base, i);
    printf(" #%2d    | %16s | 0x%08lX (%8s) | 0x%08lX:0x%08lX | 0x%08lX:0x%08lX | %8lX | 0x%04lX\n", i, 
	   elf_get_section_name(base, shdr),
	   (unsigned long)shdr->sh_type, (shdr->sh_type<12?sh_types[shdr->sh_type]:"--"), 
	   (unsigned long)shdr->sh_addr,  (unsigned long)shdr->sh_addr+shdr->sh_size,
	   (unsigned long)shdr->sh_offset, (unsigned long)shdr->sh_offset+shdr->sh_size, (unsigned long)shdr->sh_size,
	   (unsigned long)shdr->sh_addralign);
  }

  /* Program header */
  printf("** Listing segments\n");
  printf("segment | type__________________ | vaddr________________ | ___vsize | offset_______________ | ___fsize | _align \n");
  for(i = 0; i < ehdr->e_phnum; i++) {
    const ElfXX_Phdr*phdr = elf_get_phdr(base, i);
    printf(" #%2d    | 0x%08lX (_%8s) | 0x%08lX:0x%08lX | %8lX | 0x%08lX:0x%08lX | %8lX | 0x%04lX\n", i,
	   (unsigned long)phdr->p_type, (phdr->p_type<7?ph_types[phdr->p_type]:"--"), 
	   (unsigned long)phdr->p_vaddr,  (unsigned long)phdr->p_vaddr + phdr->p_memsz, (unsigned long)phdr->p_memsz,
	   (unsigned long)phdr->p_offset, (unsigned long)phdr->p_offset+phdr->p_filesz, (unsigned long)phdr->p_filesz,
	   (unsigned long)phdr->p_align);
  }
}



#if ( ELFCLASS == 32 )
int is_32bit_elf(char *base)
{
  ElfXX_Ehdr*ehdr = (ElfXX_Ehdr*)base;
  if(ehdr->e_ident[EI_CLASS] == ELFCLASS32)
    return 1;
  return 0;
}
#elif ( ELFCLASS == 64 )
int is_64bit_elf(char *base)
{
  ElfXX_Ehdr*ehdr = (ElfXX_Ehdr*)base;
  if(ehdr->e_ident[EI_CLASS] == ELFCLASS64)
    return 1;
  return 0;
}
#endif


#if ( ELFCLASS == 32 )
int is_valid_elf32(char *base)
#elif (ELFCLASS == 64 )
int is_valid_elf64(char *base)
#endif
{
  /* ** sanity checks */
  ElfXX_Ehdr*ehdr = (ElfXX_Ehdr*)base;
  if(! (ehdr->e_ident[EI_MAG0] == 0x7f &&
        ehdr->e_ident[EI_MAG1] == 'E'  &&
        ehdr->e_ident[EI_MAG2] == 'L'  &&
        ehdr->e_ident[EI_MAG3] == 'F') ) {
    return 0;
  }
  if(ehdr->e_type != ET_DYN) {
    return 0;
  }
  return 1;
}

#if ( ELFCLASS == 32 )
int convert_gnu_to_sysv32(char *base, unsigned long size, unsigned long gap) 
#elif (ELFCLASS == 64 )
int convert_gnu_to_sysv64(char *base, unsigned long size, unsigned long gap) 
#endif
{

    printf("** Find GNU style hash, convert to SysV.\n");

    ElfXX_Ehdr * ehdr = (ElfXX_Ehdr*)base;

    /* Extend segment containing '.dynstr' and move following segments */
    //printf("- looking for _LOAD segment containing .dynstr\n");
    ElfXX_Shdr*dynsyms_shdr = elf_get_section_bytype(base, SHT_DYNSYM);
    if(dynsyms_shdr == NULL) {
      fprintf(stderr, "cannot find _DYNSYM section.\n");
      return 0;
    }
    ElfXX_Shdr*dynstr_shdr = elf_get_shdr(base, dynsyms_shdr->sh_link);
    if(dynstr_shdr == NULL || dynstr_shdr->sh_type != SHT_STRTAB) {
      fprintf(stderr, "cannot find section with name '.dynstr' and type 'STRTAB'.\n");
      return 0;
    }
    int i;
    unsigned long breakpoint = 0;
    for(i = 0; i < ehdr->e_phnum; i++) {
      ElfXX_Phdr*phdr = elf_get_phdr(base, i);
      if(phdr->p_type == PT_LOAD &&
        dynstr_shdr->sh_offset >= phdr->p_offset &&
        dynstr_shdr->sh_offset <= phdr->p_offset + phdr->p_filesz) {
          breakpoint = phdr->p_offset + phdr->p_filesz;
          phdr->p_filesz += gap;
          phdr->p_memsz  += gap;
          phdr->p_align = PAGE_SIZE;
          memmove(base + breakpoint + gap, 
            base + breakpoint,
            size - (gap + breakpoint));
          memset(base + breakpoint, 0, gap);
          break;
      }
    }
    if(breakpoint == 0) {
      fprintf(stderr, "'.dynstr' section found in no _LOAD segment. ignore.\n");
      return 0;
    }

    /* Adjust offsets in ELF hdr */
    if(ehdr->e_entry >= breakpoint) {
      //printf("- adjusting entry point in ELF header\n");
      ehdr->e_entry += gap;
    }
    if(ehdr->e_phoff >= breakpoint) {
      //printf("- adjusting program header offset in ELF header\n");
      ehdr->e_phoff += gap;
    }
    if(ehdr->e_shoff >= breakpoint) {
      //printf("- adjusting section header offset in ELF header\n");
      ehdr->e_shoff += gap;
    }

    /* Calculate new segment boundaries */
    for(i = 0; i < ehdr->e_phnum; i++) {
      ElfXX_Phdr*phdr = elf_get_phdr(base, i);
      if(phdr->p_offset >= breakpoint)
        phdr->p_offset += gap;
    }

    /* Calculate new section boundaries */
    for(i = 0; i < ehdr->e_shnum; i++) {
      ElfXX_Shdr*shdr = elf_get_shdr(base, i);
      if(shdr->sh_offset >= breakpoint)
        shdr->sh_offset += gap;
    }

    /* Move .dynstr */
    //printf("- moving .dynstr section at end of segment\n");
    dynsyms_shdr = elf_get_section_bytype(base, SHT_DYNSYM);
    dynstr_shdr = elf_get_shdr(base, dynsyms_shdr->sh_link);
    char*old_dynstr_base = base + dynstr_shdr->sh_offset;
    char*new_dynstr_base = base + breakpoint;
    const unsigned long dynstr_shift = new_dynstr_base - old_dynstr_base;
    //printf("- .dynstr shift=0x%lX (%p -> %p)\n", dynstr_shift, old_dynstr_base, new_dynstr_base);
    memcpy(new_dynstr_base, old_dynstr_base, dynstr_shdr->sh_size);
    dynstr_shdr->sh_offset += dynstr_shift;
    dynstr_shdr->sh_addr   += dynstr_shift;
    /* Translating dynamic symbols */
    unsigned long dynstr_offset = dynstr_shdr->sh_size + 1; /* used to allocate new symbols */
    //printf("** Translating symbols\n");

    //printf("- looking for symbol version table .version\n");
    ElfXX_Shdr*versym_shdr = elf_get_section_bytype(base, SHT_GNU_versym);
  
    unsigned long sym_offset = 0;
    unsigned long ver_offset = 0;
    for(sym_offset = 0, ver_offset = 0;
        sym_offset < dynsyms_shdr->sh_size;
        sym_offset += dynsyms_shdr->sh_entsize, ver_offset += versym_shdr->sh_entsize) {
          ElfXX_Sym*sym = (ElfXX_Sym*)(base + dynsyms_shdr->sh_offset + sym_offset);
          ElfXX_Half*ver = (versym_shdr == NULL) ? NULL : ((ElfXX_Half*)(base + versym_shdr->sh_offset + ver_offset));
          if((ELFXX_ST_TYPE(sym->st_info) == STT_FUNC) ) {
              /*&& (sym->st_shndx == SHN_UNDEF)*/ /*this means not local symbols*/ 
            char*symbol = base + dynstr_shdr->sh_offset + sym->st_name;
            const int version = (ver == NULL) ? 1 : (int)*ver;
          }
    }
    dynstr_shdr->sh_size = dynstr_offset;

    /* adjust .dynstr in _DYNAMIC segment */
    //printf("- adjusting .dynstr ptr and size in _DYNAMIC segment\n");
    ElfXX_Dyn*d = elf_get_dynamic_entry(base, DT_STRTAB);
    d->d_un.d_ptr += dynstr_shift;
    d = elf_get_dynamic_entry(base, DT_STRSZ);
    d->d_un.d_val = dynstr_offset;

    /* Hashtable */
    //printf("** Rewriting dynamic symbols hash table\n");
    d = elf_get_dynamic_entry(base, DT_HASH);
    const ElfXX_Addr dyn_hash_ptr = (d != NULL)?d->d_un.d_ptr:0;
#ifdef DT_GNU_HASH
    d = elf_get_dynamic_entry(base, DT_GNU_HASH);
    const ElfXX_Addr dyn_gnuhash_ptr = (d != NULL)?d->d_un.d_ptr:0;
#endif

    ElfXX_Shdr*hash_shdr = elf_get_section_bytype(base, SHT_HASH);
#ifdef SHT_GNU_HASH
    ElfXX_Shdr*gnuhash_shdr = elf_get_section_bytype(base, SHT_GNU_HASH);
#else
    ElfXX_Shdr*gnuhash_shdr = NULL;
#endif
    if(gnuhash_shdr && !hash_shdr) {
      //printf("** Existing hashtable is GNU style. Creating new SysV-compliant hashtable.\n");
      const long new_offset = dynstr_shdr->sh_offset + dynstr_shdr->sh_size;
      ElfXX_Word*new_hash_table = (ElfXX_Word*)(base + new_offset);
      //printf("- new hash offset = 0x%lx\n", new_offset);
      elfhash_create_hashtable_sysv(base, new_hash_table, gnuhash_shdr);
    }
    else if(!gnuhash_shdr && !hash_shdr) {
      fprintf(stderr, "elfhash: non-standard ELF layout detected. Cannot get any .hash section.\n");
      return 0;
    }
    else if(hash_shdr) {
      if(gnuhash_shdr) {
        //printf("- removing GNU hash table: removing section '.gnu.hash'\n");
        char*gnuhash = elf_get_section_name(base, gnuhash_shdr);
        if(gnuhash && strcmp(".gnu.hash", gnuhash) == 0) {
          strcpy(gnuhash, ".old.hash");
          gnuhash_shdr->sh_type = SHN_UNDEF;
        }
        else {
          //printf("- section '.gnu.hash' not found!\n");
        }
      }
      ElfXX_Word*hash_base = (ElfXX_Word*)(base + hash_shdr->sh_offset);
      if(hash_shdr->sh_offset != dyn_hash_ptr) {
        fprintf(stderr, "elfhash: WARNING: Library is likely pre-linked.\n");
      }
      elfhash_rebuild_hashtable_sysv(base, hash_base);
    }

  //printf("- done.\n");

  return 1;
} 

#if ( ELFCLASS == 32 )
int has_gnuhash32(char *base) 
#elif (ELFCLASS == 64 )
int has_gnuhash64(char *base) 
#endif
{
  ElfXX_Shdr *isgnuhash = elf_get_section_bytype(base, SHT_GNU_HASH);
  if(isgnuhash)
    return 1;
  return 0;
}

#if ( ELFCLASS == 32 )
int dump_gnuhash32(char *base)
#elif (ELFCLASS == 64 )
int dump_gnuhash64(char *base)
#endif
{
  ElfXX_Shdr *gnuhash = elf_get_section_bytype(base, SHT_GNU_HASH);
  if(!gnuhash)
    return -1;
  ElfGnuHashHdr *hash_hdr = (ElfGnuHashHdr*)(base + gnuhash->sh_offset);
  ElfXX_Shdr *dynsym = elf_get_section_bytype(base, SHT_DYNSYM);
  if(!dynsym){
	  printf("not found section .dynsym\n");
	  return -1;
  }else{
	  printf("zzz dump .dynsym offset=0x%x, sh_size=%d, sh_entsize=%d\n", dynsym->sh_offset, dynsym->sh_size, dynsym->sh_entsize);
  }
  ElfXX_Shdr *dynstr = elf_get_section_byname(base, ".dynstr");
  if(!dynstr){
	  printf("not found section .dynstr\n");
	  return -1;
  }else{
	  printf("zzz dump .dynstr offset=0x%x, sh_size=%d, sh_entsize=%d\n", dynstr->sh_offset, dynstr->sh_size, dynstr->sh_entsize);
  }
  ElfXX_Shdr*versym_shdr = elf_get_section_bytype(base, SHT_GNU_versym);
  if(versym_shdr == NULL){
	  printf("not found section .gnu.version\n");
	  return -1;
  }else{
	  printf("zzz dump .gnu.version offset=0x%x, size=%d, entsize=%d\n", versym_shdr->sh_offset, versym_shdr->sh_size, versym_shdr->sh_entsize);
  }
  ElfXX_Shdr*ver_r_shdr = elf_get_section_bytype(base, SHT_GNU_verneed);//elf_get_section_byname(base, ".gnu.version_r");
    if(ver_r_shdr == NULL){
  	  printf("not found section .gnu.version_r\n");
  	  return -1;
    }else{
  	  printf("zzz dump .gnu.version_r offset=0x%x, size=%d, entsize=%d\n", ver_r_shdr->sh_offset, ver_r_shdr->sh_size, ver_r_shdr->sh_entsize);
    }

    ElfXX_Shdr* ver_def_shdr = elf_get_section_bytype(base, SHT_GNU_verdef);//elf_get_section_byname(base, '.gnu.version_d');
	if(ver_def_shdr == NULL){
	  printf("not found section SHT_GNU_verdef\n");
	}else{
	  printf("zzz dump SHT_GNU_verdef offset=0x%x, size=%d, entsize=%d\n", ver_def_shdr->sh_offset, ver_def_shdr->sh_size, ver_def_shdr->sh_entsize);
	}
  //https://lists.debian.org/lsb-spec/1999/12/msg00017.html

  int dynsymcnt = dynsym->sh_size/dynsym->sh_entsize;
  ElfXX_Sym *syms = (ElfXX_Sym*)(base+dynsym->sh_offset);
  const char* pstr = (const char*)(base+dynstr->sh_offset);
  ElfXX_Half *versions = (ElfXX_Half *)(base+versym_shdr->sh_offset);
  for(int i=0;i<dynsymcnt; i++){
	  ElfXX_Sym *sym = &syms[i];
	  printf("zzz dump sym %d: name:%s, offset=0x%x, name:0x%x, value:0x%x, size:0x%x,  info:0x%x,shndx=0x%x, version=0x%x\n",
			  i, &pstr[sym->st_name], dynsym->sh_offset+i*(sizeof(ElfXX_Sym)), sym->st_name, sym->st_value, sym->st_size, sym->st_info, sym->st_shndx, versions[i]);
  }

  obj_state_t* os = (obj_state_t*)malloc(sizeof(obj_state_t));
  os->dynsymcount = dynsym->sh_size/dynsym->sh_entsize;
  os->os_dynsym = (ElfXX_Sym*)(base+dynsym->sh_offset);
  os->os_dynstr = (const char*)(base+dynstr->sh_offset);
  os->os_nbuckets = hash_hdr->nbuckets;
  os->os_symndx = hash_hdr->symndx;
  os->os_maskwords_bm = hash_hdr->maskwords;
  os->os_shift2 = hash_hdr->shift2;
  os->os_bloom = (ELFXX_BloomWord*)(base + gnuhash->sh_offset+sizeof(ElfGnuHashHdr));
  os->os_buckets = (ElfXX_Word*)(base + gnuhash->sh_offset+sizeof(ElfGnuHashHdr)+hash_hdr->maskwords*sizeof(ELFXX_BloomWord));
  os->os_hashval = (ElfXX_Word*)(base + gnuhash->sh_offset+sizeof(ElfGnuHashHdr)+
		  hash_hdr->maskwords*sizeof(ELFXX_BloomWord)+hash_hdr->nbuckets*sizeof(ElfXX_Word));

  printf("os_buckets=%d\n", os->os_nbuckets);
  char *test_str = "Java_android_media_AudioCoder_EncodeInitJni";
  printf("hash(%s)=0x%x\n", test_str, dl_new_hash(test_str));
  ElfXX_Sym *sym = symhash_lookup(os, test_str);
  if(sym){
	  printf("sym found for %s\n", test_str);
  }else{
	  printf("sym not found for %s\n", test_str);
  }
  test_str = "_ZN7android14SecAudioRecord25native_read_in_byte_arrayEPciiS1_";
  printf("hash(%s)=0x%x\n", test_str, dl_new_hash(test_str));
  sym = symhash_lookup(os, test_str);
    if(sym){
  	  printf("sym found for %s\n", test_str);
    }else{
  	  printf("sym not found for %s\n", test_str);
    }

  free(os);

  return 0;
}

#if ( ELFCLASS == 32 )
int rehash32(char *base) 
#elif (ELFCLASS == 64 )
int rehash64(char *base) 
#endif
{
	ElfXX_Shdr *hash_shdr = elf_get_section_bytype(base, SHT_GNU_HASH);
	if(hash_shdr){
		printf("** Rebuild gnu style hash table.\n");
		printf("zzz dump .gnu.hash offset=0x%x, size=%d, entsize=%d\n", hash_shdr->sh_offset, hash_shdr->sh_size, hash_shdr->sh_entsize);

		ElfGnuHashHdr *gnuhash = (ElfGnuHashHdr*)(base + hash_shdr->sh_offset);
		ElfXX_Shdr *dynsym = elf_get_section_bytype(base, SHT_DYNSYM);
		if(!dynsym){
			printf("dynsym not found.\n");
			return 0;
		}else if(dynsym->sh_entsize <=0 || dynsym->sh_size<=0){
			printf("bad dynsym fromat: sh_size=%d, sh_entsize=%d.\n", dynsym->sh_size, dynsym->sh_entsize);
			return 0;
		}else{
			printf("zzz dump .dynsym offset=0x%x, sh_size=%d, sh_entsize=%d\n", dynsym->sh_offset, dynsym->sh_size, dynsym->sh_entsize);
		}
		ElfXX_Shdr *dynstr = elf_get_section_byname(base, ".dynstr");
		if(!dynstr){
			printf("not found section .dynstr\n");
			return 0;
		}else{
			printf("zzz dump .dynstr offset=0x%x, sh_size=%d, sh_entsize=%d\n", dynstr->sh_offset, dynstr->sh_size, dynstr->sh_entsize);
		}
		obj_state_t* os = (obj_state_t*)malloc(sizeof(obj_state_t));
		os->dynsymcount = dynsym->sh_size/dynsym->sh_entsize;
		os->os_dynsym = (ElfXX_Sym*)(base+dynsym->sh_offset);
		os->os_dynstr = (const char*)(base+dynstr->sh_offset);
		os->os_nbuckets = gnuhash->nbuckets;
		os->os_symndx = gnuhash->symndx;
		os->os_maskwords_bm = gnuhash->maskwords;
		os->os_shift2 = gnuhash->shift2;
		os->os_bloom = (ELFXX_BloomWord*)(base + hash_shdr->sh_offset+sizeof(ElfGnuHashHdr));
		os->os_buckets = (ElfXX_Word*)(base + hash_shdr->sh_offset+sizeof(ElfGnuHashHdr)+gnuhash->maskwords*sizeof(ELFXX_BloomWord));
		os->os_hashval = (ElfXX_Word*)(base + hash_shdr->sh_offset+sizeof(ElfGnuHashHdr)+
				gnuhash->maskwords*sizeof(ELFXX_BloomWord)+gnuhash->nbuckets*sizeof(ElfXX_Word));
		int ret = symhash_rebuild(os, "_ZN7android14SecAudioRecord25native_read_in_byte_arrayEPciiS1_");
		free(os);
		return ret;
	}else {
		printf("** Rebuild sysv style hash table.\n");
		//rebuild hash table
		hash_shdr = elf_get_section_bytype(base, SHT_HASH);

		ElfXX_Word*hash_base = (ElfXX_Word*)(base + hash_shdr->sh_offset);

		elfhash_rebuild_hashtable_sysv(base, hash_base);
	}
    return 1; 
}

#if ( ELFCLASS == 32 )
int rename_func32(char *base, const char *old_func, const char *new_func) 
#elif (ELFCLASS == 64 )
int rename_func64(char *base, const char *old_func, const char *new_func) 
#endif
{
#if 1 //hongbiao.zhang@2017.9.14: check
	if(!old_func || !new_func) {
		fprintf(stderr, "bad names.\n");
		return 0;
	}
	if(!strcmp(old_func, new_func)){
		fprintf(stderr, "same names.\n");
		return 0;
	}
	if(strlen(old_func) != strlen(new_func)){
		fprintf(stderr, "two names should have same length.\n");
		return 0;
	}
	ElfXX_Shdr *dynstr = elf_get_section_byname(base, ".dynstr");
	if(!dynstr){
		 printf("not found section .dynstr\n");
		 return 0;
	}else{
		 printf("dynstr: offset=0x%x, size=%d, entsize=%d, link=0x%x\n", dynstr->sh_offset, dynstr->sh_size, dynstr->sh_entsize, dynstr->sh_link);
	}
#endif

  ElfXX_Shdr*dynsyms_shdr = elf_get_section_bytype(base, SHT_DYNSYM);
  if(dynsyms_shdr == NULL) {
    fprintf(stderr, "cannot find _DYNSYM section.\n");
    return 0;
  }
  printf("SHT_DYNSYM: offset=0x%x, size=%d, entsize=%d, link=0x%x\n", dynsyms_shdr->sh_offset, dynsyms_shdr->sh_size, dynsyms_shdr->sh_entsize,dynsyms_shdr->sh_link);

  ElfXX_Shdr*dynstr_shdr = elf_get_shdr(base, dynsyms_shdr->sh_link);
  if(dynstr_shdr == NULL || dynstr_shdr->sh_type != SHT_STRTAB) {
    fprintf(stderr, "cannot find section with name '.dynstr' and type 'STRTAB'.\n");
    return 0;
  }
  printf("SHT_STRTAB: offset=0x%x, size=%d, entsize=%d, link=0x%x\n", dynstr_shdr->sh_offset, dynstr_shdr->sh_size, dynstr_shdr->sh_entsize, dynstr_shdr->sh_link);

#if 1 //hongbiao.zhang@2017.9.14: check
    int dynsymcnt = 0;
    if(dynsyms_shdr->sh_size > 0&& dynsyms_shdr->sh_entsize>0){
    	dynsymcnt = dynsyms_shdr->sh_size/dynsyms_shdr->sh_entsize;
    }
    ElfXX_Sym* Syms = (ElfXX_Sym*)(base+dynsyms_shdr->sh_offset);
    const char *Dynstr = (const char*)(base+dynstr_shdr->sh_offset);
	for(int i=0;i<dynsymcnt;i++){
		ElfXX_Sym *sym = (ElfXX_Sym *)&Syms[i];
		const char *name = (const char *)&Dynstr[sym->st_name];
		if(!strcmp(name, new_func)){
		    fprintf(stderr, "new func '%s' already existed in string table.\n", name);
			return 0;
		}
	}
#endif

  int result = 0;

  ElfXX_Shdr*versym_shdr = elf_get_section_bytype(base, SHT_GNU_versym);
  if(versym_shdr != NULL){
	  printf("SHT_GNU_versym: offset=0x%x, size=%d, entsize=%d\n", versym_shdr->sh_offset, versym_shdr->sh_size, versym_shdr->sh_entsize);
  }

  unsigned long sym_offset = 0;
  unsigned long ver_offset = 0;
  for(sym_offset = 0, ver_offset = 0;
      sym_offset < dynsyms_shdr->sh_size;
      sym_offset += dynsyms_shdr->sh_entsize, ver_offset += versym_shdr->sh_entsize) {
        ElfXX_Sym*sym = (ElfXX_Sym*)(base + dynsyms_shdr->sh_offset + sym_offset);
        ElfXX_Half*ver = (versym_shdr == NULL) ? NULL : ((ElfXX_Half*)(base + versym_shdr->sh_offset + ver_offset));
        if((ELFXX_ST_TYPE(sym->st_info) == STT_FUNC) ) {
          char*symbol = base + dynstr_shdr->sh_offset + sym->st_name;
          const int version = (ver == NULL) ? 1 : (int)*ver;
          if(symbol && old_func && strcmp(old_func, symbol) == 0) {
            printf("** Rename dynamic symbol: %s -> %s, ver_offset=0x%x, version=%d\n", old_func, new_func, (versym_shdr->sh_offset + ver_offset), version);
            if(version > 1) {
              *ver = 1;
            }
            strcpy(base + dynstr_shdr->sh_offset + sym->st_name, new_func);
            result = 1; //setup return values.
            break;
          }
        }
  }
  if(!result)
    printf("** Did not find symbol '%s' in .dynstr section, ignore.\n", old_func);
  return result;
}

