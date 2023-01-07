#include "kernel/riscv.h"
#include "kernel/process.h"
#include "spike_interface/spike_utils.h"
#include "util/string.h"

void print_errorline(){
    addr_line* temp_line = current->line;
  //read mepc to find the address of the illegal instruction
  uint64 mepc = read_csr(mepc);
  //find which line cause exception
  while(temp_line->addr != mepc){
    temp_line++;
  }

  addr_line* error_line = temp_line;
  uint64 error_line_num = error_line->line;
  //length of the directory name
  uint64 dir_len = strlen((char*)current->dir[current->file[error_line->file].dir]);
  //length of the file name
  uint64 file_name_len = strlen((char*)current->file[error_line->file].file);

  //construct the path of the file
  char path[dir_len + file_name_len + 10];
  strcpy(path, current->dir[current->file[error_line->file].dir]);
  path[dir_len] = '/';
  strcpy(path + dir_len + 1, current->file[error_line->file].file);
  
  sprint("Runtime error at %s:%lld\n",path,error_line_num);

  //find the corresponding code of the illegal instruction 
  char code_buffer[256];
  spike_file_t *f = spike_file_open(path, O_RDONLY, 0);
  for(int i = 1; i < error_line_num;){
    spike_file_read(f, code_buffer, 1);
    if(code_buffer[0]=='\n') i++;
  }
  while(TRUE){
    spike_file_read(f,code_buffer,1);
    sprint("%c",code_buffer[0]);
    if(code_buffer[0]=='\n') break;
  }
  spike_file_close(f);
  return;
}

static void handle_instruction_access_fault() { 
  panic("Instruction access fault!"); 
}

static void handle_load_access_fault() { 
  panic("Load access fault!"); 
}

static void handle_store_access_fault() { panic("Store/AMO access fault!"); }

// added @lab1_challenge2
static void handle_illegal_instruction() {
  panic("Illegal instruction!"); 
}

static void handle_misaligned_load() { panic("Misaligned Load!"); }

static void handle_misaligned_store() { panic("Misaligned AMO!"); }

// added @lab1_3
static void handle_timer() {
  int cpuid = 0;
  // setup the timer fired at next time (TIMER_INTERVAL from now)
  *(uint64*)CLINT_MTIMECMP(cpuid) = *(uint64*)CLINT_MTIMECMP(cpuid) + TIMER_INTERVAL;

  // setup a soft interrupt in sip (S-mode Interrupt Pending) to be handled in S-mode
  write_csr(sip, SIP_SSIP);
}

//
// handle_mtrap calls a handling function according to the type of a machine mode interrupt (trap).
//
void handle_mtrap() {
  
  uint64 mcause = read_csr(mcause);
  switch (mcause) {
    case CAUSE_MTIMER:
      handle_timer();
      break;
    case CAUSE_FETCH_ACCESS:
      print_errorline();
      handle_instruction_access_fault();
      break;
    case CAUSE_LOAD_ACCESS:
      print_errorline();
      handle_load_access_fault();
    case CAUSE_STORE_ACCESS:
      print_errorline();
      handle_store_access_fault();
      break;
    case CAUSE_ILLEGAL_INSTRUCTION:
      // TODO (lab1_2): call handle_illegal_instruction to implement illegal instruction
      // interception, and finish lab1_2.
      print_errorline();
      handle_illegal_instruction();
      //panic( "call handle_illegal_instruction to accomplish illegal instruction interception for lab1_2.\n" );

      break;
    case CAUSE_MISALIGNED_LOAD:
      print_errorline();
      handle_misaligned_load();
      break;
    case CAUSE_MISALIGNED_STORE:
      print_errorline();
      handle_misaligned_store();
      break;

    default:
      print_errorline();
      sprint("machine trap(): unexpected mscause %p\n", mcause);
      sprint("            mepc=%p mtval=%p\n", read_csr(mepc), read_csr(mtval));
      panic( "unexpected exception happened in M-mode.\n" );
      break;
  }
}
