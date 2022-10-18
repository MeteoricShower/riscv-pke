/*
 * routines that scan and load a (host) Executable and Linkable Format (ELF) file
 * into the (emulated) memory.
 */

#include "elf.h"
#include "string.h"
#include "riscv.h"
#include "spike_interface/spike_utils.h"


#define ELF_64_ST_TYPE(i) ((i)&0xf)
#define STT_FUN 2

typedef struct elf_info_t {
  spike_file_t *f;
  process *p;
} elf_info;

//
// the implementation of allocater. allocates memory space for later segment loading
//
static void *elf_alloc_mb(elf_ctx *ctx, uint64 elf_pa, uint64 elf_va, uint64 size) {
  // directly returns the virtual address as we are in the Bare mode in lab1_x
  return (void *)elf_va;
}

//
// actual file reading, using the spike file interface.
//
static uint64 elf_fpread(elf_ctx *ctx, void *dest, uint64 nb, uint64 offset) {
  elf_info *msg = (elf_info *)ctx->info;
  // call spike file utility to load the content of elf file into memory.
  // spike_file_pread will read the elf file (msg->f) from offset to memory (indicated by
  // *dest) for nb bytes.
  return spike_file_pread(msg->f, dest, nb, offset);
}

//
// init elf_ctx, a data structure that loads the elf.
//
elf_status elf_init(elf_ctx *ctx, void *info) {
  ctx->info = info;

  // load the elf header
  if (elf_fpread(ctx, &ctx->ehdr, sizeof(ctx->ehdr), 0) != sizeof(ctx->ehdr)) return EL_EIO;

  // check the signature (magic value) of the elf
  if (ctx->ehdr.magic != ELF_MAGIC) return EL_NOTELF;

  return EL_OK;
}

//
// load the elf segments to memory regions as we are in Bare mode in lab1
//
elf_status elf_load(elf_ctx *ctx) {
  // elf_prog_header structure is defined in kernel/elf.h
  elf_prog_header ph_addr;
  int i, off;

  // traverse the elf program segment headers
  for (i = 0, off = ctx->ehdr.phoff; i < ctx->ehdr.phnum; i++, off += sizeof(ph_addr)) {
    // read segment headers
    if (elf_fpread(ctx, (void *)&ph_addr, sizeof(ph_addr), off) != sizeof(ph_addr)) return EL_EIO;

    if (ph_addr.type != ELF_PROG_LOAD) continue;
    if (ph_addr.memsz < ph_addr.filesz) return EL_ERR;
    if (ph_addr.vaddr + ph_addr.memsz < ph_addr.vaddr) return EL_ERR;

    // allocate memory block before elf loading
    void *dest = elf_alloc_mb(ctx, ph_addr.vaddr, ph_addr.vaddr, ph_addr.memsz);

    // actual loading
    if (elf_fpread(ctx, dest, ph_addr.memsz, ph_addr.off) != ph_addr.memsz)
      return EL_EIO;
  }

  return EL_OK;
}

typedef union {
  uint64 buf[MAX_CMDLINE_ARGS];
  char *argv[MAX_CMDLINE_ARGS];
} arg_buf;

//
// returns the number (should be 1) of string(s) after PKE kernel in command line.
// and store the string(s) in arg_bug_msg.
//
static size_t parse_args(arg_buf *arg_bug_msg) {
  // HTIFSYS_getmainvars frontend call reads command arguments to (input) *arg_bug_msg
  long r = frontend_syscall(HTIFSYS_getmainvars, (uint64)arg_bug_msg,
      sizeof(*arg_bug_msg), 0, 0, 0, 0, 0);
  kassert(r == 0);

  size_t pk_argc = arg_bug_msg->buf[0];
  uint64 *pk_argv = &arg_bug_msg->buf[1];

  int arg = 1;  // skip the PKE OS kernel string, leave behind only the application name
  for (size_t i = 0; arg + i < pk_argc; i++)
    arg_bug_msg->argv[i] = (char *)(uintptr_t)pk_argv[arg + i];

  //returns the number of strings after PKE kernel in command line
  return pk_argc - arg;
}

//
// load the elf of user application, by using the spike file interface.
//
void load_bincode_from_host_elf(process *p) {
  arg_buf arg_bug_msg;

  // retrieve command line arguements
  size_t argc = parse_args(&arg_bug_msg);
  if (!argc) panic("You need to specify the application program!\n");

  sprint("Application: %s\n", arg_bug_msg.argv[0]);

  //elf loading. elf_ctx is defined in kernel/elf.h, used to track the loading process.
  elf_ctx elfloader;
  // elf_info is defined above, used to tie the elf file and its corresponding process.
  elf_info info;

  info.f = spike_file_open(arg_bug_msg.argv[0], O_RDONLY, 0);
  info.p = p;
  // IS_ERR_VALUE is a macro defined in spike_interface/spike_htif.h
  if (IS_ERR_VALUE(info.f)) panic("Fail on openning the input application program.\n");

  // init elfloader context. elf_init() is defined above.
  if (elf_init(&elfloader, &info) != EL_OK)
    panic("fail to init elfloader.\n");

  // load elf. elf_load() is defined above.
  if (elf_load(&elfloader) != EL_OK) panic("Fail on loading elf.\n");

  // entry (virtual, also physical in lab1_x) address
  p->trapframe->epc = elfloader.ehdr.entry;

  // close the host spike file
  spike_file_close( info.f );

  sprint("Application program entry point (virtual address): 0x%lx\n", p->trapframe->epc);
}


uint64 get_fun_name(uint64 depth, uint64 s0){
  arg_buf arg_bug_msg;

  // retrieve command line arguements
  size_t argc = parse_args(&arg_bug_msg);
  if (!argc) panic("You need to specify the application program!\n");

  sprint("Application: %s\n", arg_bug_msg.argv[0]);

  //elf loading. elf_ctx is defined in kernel/elf.h, used to track the loading process.
  elf_ctx elfloader;
  // elf_info is defined above, used to tie the elf file and its corresponding process.
  elf_info info;

  info.f = spike_file_open(arg_bug_msg.argv[0], O_RDONLY, 0);
  info.p = current;
  // IS_ERR_VALUE is a macro defined in spike_interface/spike_htif.h
  if (IS_ERR_VALUE(info.f)) panic("Fail on openning the input application program.\n");

  // init elfloader context. elf_init() is defined above.
  if (elf_init(&elfloader, &info) != EL_OK)
    panic("fail to init elfloader.\n");

  // load elf. elf_load() is defined above.
  if (elf_load(&elfloader) != EL_OK) panic("Fail on loading elf.\n");

  elf_sec_header elf_sh;

  uint64 off = elfloader.ehdr.shoff + elfloader.ehdr.shstrndx * sizeof(elf_sh);
  if (elf_fpread(&elfloader, (void *)&elf_sh, sizeof(elf_sh), off) != sizeof(elf_sh))     
      return EL_EIO;

  
  char elf_shstrtab[elf_sh.size];

  if (elf_fpread(&elfloader, elf_shstrtab, elf_sh.size, elf_sh.offset) != elf_sh.size)
    return EL_EIO;

  uint64 symtab_size = sizeof(Elf_symtab) * 32;
  char elf_symtab[symtab_size];

  uint64 strtab_size = 256;
  char elf_strtab[strtab_size];

  for(int i = 0, off = elfloader.ehdr.shoff; i < elfloader.ehdr.shnum; i++, off += sizeof(elf_sh)) {
    if (elf_fpread(&elfloader, (void *)&elf_sh, sizeof(elf_sh), off) != sizeof(elf_sh)) return EL_EIO;

    if (!strcmp(elf_shstrtab + elf_sh.name, ".symtab")) {

      if (elf_fpread(&elfloader, (void *)elf_symtab, symtab_size, elf_sh.offset) != symtab_size)
        return EL_EIO;
        
    } else if (!strcmp(elf_shstrtab + elf_sh.name, ".strtab")) {

      if (elf_fpread(&elfloader, (void *)elf_strtab, strtab_size, elf_sh.offset) != strtab_size)
        return EL_EIO;
    }

  }


  uint64 sym_num = symtab_size / sizeof(Elf_symtab);
  Elf_symtab* symbols = (Elf_symtab*)elf_symtab;

  
  /*
  for(int i=0;i<64;i++){
    sprint("addr:%x value:%x\n",fp,*(uint64 *)fp);
    fp += 8;
  }

  sprint("\n");
  fp = s0;
  for(int i=0;i<64;i++){
    sprint("addr:%x value:%x\n",fp,*(uint64 *)fp);
    fp -= 8;
  }
*/

/*
  uint64 fp = s0 - 8;
  uint64 ra = *(uint64 *)(fp);
*/  

  uint64 fp = s0;
  uint64 ra = *(uint64 *)(fp + 8);
  fp = *(uint64 *)(fp);

  while(depth){
    uint64 max_dis = 0xffffffffffffffff;
    uint64 index = -1;
    //sprint("depth:%d fp:%x ra:%x\n",depth, fp, ra);

    for(int i = 0;i < sym_num; i++){
      //sprint("%d: name:%d info:%d shndx:%d\n", i, symbols[i].st_name,symbols[i].st_info,symbols[i].st_shndx);
      if(ELF_64_ST_TYPE(symbols[i].st_info) == STT_FUN && symbols[i].st_value < ra && ra - symbols[i].st_value < max_dis){
        max_dis = ra - symbols[i].st_value;
        index = i;
      }
    }
    if(index == -1){
      //sprint("%x : %s\n", symbols[index].st_value, elf_strtab + symbols[index].st_name);
      panic("Not found");
      return 1;
    }
    else{
      sprint("%s\n", elf_strtab + symbols[index].st_name);
      if(!strcmp(elf_strtab + symbols[index].st_name, "main")) break;
    }

    ra = (*(uint64 *)(fp - 8));
    fp = (*(uint64 *)(fp - 16));
    
    --depth;
  }
/*
  fp = *(uint64 *)(fp-8);
  uint64 faddr = *(uint64 *)(fp-8)-0xe;

  sprint("fp:%x faddr:%x\n",fp,faddr);

  fp = *(uint64 *)(fp-16);
  faddr = *(uint64 *)(fp-8)-0xc;

  sprint("fp:%x faddr:%x\n",fp,faddr);

  fp = *(uint64 *)(fp-16);
  faddr = *(uint64 *)(fp-8)-0xc;

  sprint("fp:%x faddr:%x\n",fp,faddr);

  if(depth >= 1){
    for(int i = 0;i < sym_num; i++){
      //sprint("%d: name:%d info:%d shndx:%d\n", i, symbols[i].st_name,symbols[i].st_info,symbols[i].st_shndx);
      if(ELF_64_ST_TYPE(symbols[i].st_info) == STT_FUN && )

        sprint("%x : %s\n", symbols[i].st_value, elf_strtab + symbols[i].st_name);
    }
    depth--;
  }
  */
  return 0;
}