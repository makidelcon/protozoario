/*
  -   Find the .dynamic
    -  Find all entries
  -   Find the DT_RELA
    -   Find all entries (DT_RELAENT)
    -   Find file offset of relocations
  -> Find the .init_array section
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#define TMP ".proto"

int is_Elf(Elf64_Ehdr *elf_ehdr) {
  /* ELF magic bytes are 0x7f,'E','L','F'
   * Using  octal escape sequence to represent 0x7f
   */
  if(!strncmp((char*)elf_ehdr->e_ident, "\177ELF", 4UL)) {
    return 1;
  } else {
    return 0;
  }
}

struct dynamic_t{
  int count;
  Elf64_Dyn *entries;
};

struct rela_t{
  int count;
  Elf64_Rela *entries;
};

struct dynamic_t get_dynamic_segment(Elf64_Phdr dyn_phdr, int host_fd){
  /*
  [+]-------- Finding the .dynamic  --------[+]
  .dynamic This section holds dynamic linking information. The section’s attributes will 
  include the SHF_ALLOC bit. Whether the SHF_WRITE bit is set is processor specific.
  */
  struct dynamic_t section;

  /* .dynamic */
  Elf64_Off   dyn_start;
  Elf64_Off   dyn_filesz;
  Elf64_Off   edyn_start;
  Elf64_Off   dyn_end;
  Elf64_Dyn*  dyn_entries;
  
  dyn_start = dyn_phdr.p_offset;
  dyn_filesz = dyn_phdr.p_filesz;
  dyn_end = dyn_start + dyn_filesz;

  /* getting dyn_entries */
  dyn_entries = (Elf64_Dyn *)malloc(dyn_filesz);
  if (dyn_entries == NULL) {
    perror("malloc");
    close(host_fd);
    free(dyn_entries);
  }

  printf("[+] .dynamic segment Found!\n    Start at 0x%x and end at 0x%x\n", dyn_start, dyn_end);
  int j = 0;
  for(Elf64_Off edyn_start = dyn_start; edyn_start < dyn_end; edyn_start = edyn_start + sizeof(Elf64_Dyn)){
    Elf64_Dyn   dyn_entry;
    if(lseek(host_fd, edyn_start, SEEK_SET) == -1) {
      perror("lseek");
      close(host_fd);
    }
    read(host_fd, &dyn_entry, sizeof(Elf64_Dyn));
    
    dyn_entries[j] = dyn_entry;
    j++;
    
    // DT_NULL An entry with a DT_NULL tag marks the end of the _DYNAMIC array.
    if(dyn_entry.d_tag == DT_NULL) break;
  }
  printf("[+] Found %i (Elf64_Dyn)entries\n", j);
  section.count = j;
  section.entries = dyn_entries;
  return section;
}

struct rela_t get_relocation_table(struct dynamic_t dyn_segment, int host_fd) {
  // [+]-------- Finding the relocation table --------[+]
  struct rela_t table;

  /* DT_RELA DT_RELAENT */
  Elf64_Off   rela_start;
  Elf64_Off   rela_count;
  Elf64_Off   rela_end;
  Elf64_Rela *rela_entries;
  Elf64_Rela  rela_entry;

  for(int k = 0; k < dyn_segment.count; k++){
    if(dyn_segment.entries[k].d_tag == DT_RELA){
      rela_start = dyn_segment.entries[k].d_un.d_val;
      printf("[+] DT_RELA found in 0x%x\n",rela_start);
    }

    if(dyn_segment.entries[k].d_tag == DT_RELAENT){
      rela_count = dyn_segment.entries[k].d_un.d_val;
      printf("[+] Found %d (Elf64_Rela) entries\n",rela_count);
    }
  }

  rela_end = rela_start + (rela_count * sizeof(Elf64_Rela));
  rela_entries = (Elf64_Rela *)malloc(sizeof(Elf64_Rela));

  /* TODO: fazer o for usando rela_count */
  int y = 0;
  for(Elf64_Off size = sizeof(Elf64_Rela); rela_start < rela_end; rela_start += size){
    Elf64_Rela rela_entry;
    if(lseek(host_fd, rela_start, SEEK_SET) == -1) {
      perror("[-] Error seeking to offset");
      close(host_fd);
    }
    // printf("[+] Rela entry found in 0x%x\n", rela_start);
    read(host_fd, &rela_entry, sizeof(Elf64_Rela));
    
    // // 0000000000001139 <msg>:
    // if(rela_entry.r_addend == 0x1139){
    //   printf("[+] Infecting 0x1139 <msg> symbol\n");
    //   rela_entry.r_addend = 0x117b;
    //   write(host_fd, rela_entry, sizeof(Elf64_Rela));
    // }
    
    rela_entries[y] = rela_entry;
    y++;
  }

  printf("[+] DT_RELA Entires:\nINDEX\tADDEND\tOFFSET\tINFO\tTYPE\n");
  for(int k = 0; k < y; k++){
    if(rela_entries[k].r_info == R_X86_64_RELATIVE){
      printf("%i\t0x%x\t0x%x\t0x%x\tR_X86_64_RELATIVE\n", k, rela_entries[k].r_addend, rela_entries[k].r_offset, rela_entries[k].r_info);
      
    }
  }
  table.count = y;
  table.entries = rela_entries;
  return table; 
}

int main(int argc, char *argv[]) {
  Elf64_Ehdr *ehdr;
  Elf64_Phdr *phdr;
  Elf64_Shdr *shdr;

  int host_fd, ofd;
  struct stat st;
  char *host_mem;
  const uint8_t addr[2] = {0x7b, 0x11};  

  if ((host_fd = open(argv[1], O_RDWR)) < 0) return 1;

  fstat(host_fd, &st);
  host_mem = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, host_fd, 0);
  if (host_mem == NULL) return 2;

  ehdr = (Elf64_Ehdr *)host_mem;
  
  if(!(is_Elf(ehdr))) return 3;

  phdr = (Elf64_Phdr *)(host_mem + ehdr->e_phoff);
  shdr = (Elf64_Shdr *)(host_mem + ehdr->e_shoff);

  for (int i = 0; i < ehdr->e_phnum; i++) {
    if (phdr[i].p_type == PT_DYNAMIC){
  		    
      struct dynamic_t dyn_segment = get_dynamic_segment(phdr[i], host_fd);
      struct rela_t relocation_table = get_relocation_table(dyn_segment, host_fd); 
      
      printf("[+] .dynamic has %i entries\n", dyn_segment.count);
      printf("[+] relocation table has %i entries\n", relocation_table.count);

      host_mem[relocation_table.entries[1].r_offset - 0x1000] = 0x7b;
      host_mem[relocation_table.entries[1].r_offset - 0x1000 + 1] = 0x11;

      if(lseek(host_fd, 0, SEEK_SET) == -1) {
        perror("lseek");
        close(host_fd);
      }
      write(host_fd, host_mem, st.st_size);
      free(relocation_table.entries);
      free(dyn_segment.entries);
    }
  }
  close(host_fd);
  munmap(host_mem, st.st_size);
  return 0;
}
