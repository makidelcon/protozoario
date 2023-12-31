#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdbool.h>

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

struct phdrs_t{
  int count;
  Elf64_Phdr *list;
};

struct shdrs_t{
  int count;
  Elf64_Shdr *list;
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
    perror("dyn malloc");
    close(host_fd);
    free(dyn_entries);
  }

  printf("[+] .dynamic segment Found!\n    Start at 0x%x and end at 0x%x\n", dyn_start, dyn_end);
  int j = 0;
  for(Elf64_Off edyn_start = dyn_start; edyn_start < dyn_end; edyn_start = edyn_start + sizeof(Elf64_Dyn)){
    Elf64_Dyn   dyn_entry;
    if(lseek(host_fd, edyn_start, SEEK_SET) == -1) {
      perror("dyn lseek");
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
  if (rela_entries == NULL) {
    perror("rela malloc");
    close(host_fd);
    free(rela_entries);
  }

  /* TODO: fazer o for usando rela_count */
  int y = 0;
  for(Elf64_Off size = sizeof(Elf64_Rela); rela_start < rela_end; rela_start += size){
    Elf64_Rela rela_entry;
    if(lseek(host_fd, rela_start, SEEK_SET) == -1) {
      perror("rela lseek");
      close(host_fd);
    }
    // printf("[+] Rela entry found in 0x%x\n", rela_start);
    read(host_fd, &rela_entry, sizeof(Elf64_Rela));
    rela_entries[y] = rela_entry;
    y++;
  }
  table.count = y;
  table.entries = rela_entries;
  return table; 
}

Elf64_Addr get_file_offset(struct phdrs_t phdrs, Elf64_Addr offset) {
  Elf64_Addr file_offset = 0;
  for(int i = 0; i < phdrs.count; i++) {
    Elf64_Addr endAddr = phdrs.list[i].p_vaddr + phdrs.list[i].p_memsz;
    if(offset >= phdrs.list[i].p_vaddr && offset <= endAddr) {
      file_offset = offset - phdrs.list[i].p_vaddr + phdrs.list[i].p_offset;
      break;
    }
  }
  return file_offset;
}

bool withinSection(struct shdrs_t shdrs, char *section_name,  Elf64_Addr offset) {
  size_t section_size = 8;
  size_t actual_section_size = 0;
  for(int i = 0; i < shdrs.count; i++){
    unsigned char *actual_section_name = (unsigned char *)(&shdrs.list[i].sh_name);
    while(*actual_section_name++ != '\0'){
      actual_section_size += 1;
    }
    if((*actual_section_name == '\0') || (actual_section_size != section_size)){
      return 1;
    }
  }
  return 0;
}

int main(int argc, char *argv[]) {
  Elf64_Ehdr *ehdr;
  Elf64_Phdr *phdr;
  Elf64_Shdr *shdr;
  Elf64_Rela *victim_rela;
  struct phdrs_t phdrs;
  struct shdrs_t shdrs;
  struct dynamic_t dyn_segment;
  struct rela_t relocation_table;

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

  phdrs.list = (Elf64_Phdr *)(host_mem + ehdr->e_phoff);
  phdrs.count = ehdr->e_phnum;
  
  shdrs.list = (Elf64_Shdr *)(host_mem + ehdr->e_shoff);
  shdrs.count = ehdr->e_shoff;

  for (int i = 0; i < phdrs.count; i++) {
    if (phdrs.list[i].p_type == PT_DYNAMIC){
      dyn_segment = get_dynamic_segment(phdrs.list[i], host_fd);
      relocation_table = get_relocation_table(dyn_segment, host_fd);
      
      printf("[+] .dynamic has %i entries\n", dyn_segment.count);
      printf("[+] relocation table has %i entries\n", relocation_table.count);

      printf("[+] DT_RELA Entires:\nINDEX\tADDEND\tOFFSET\tINFO\tTYPE\n");
      for(int j = 0; j < relocation_table.count; j++){
        if(relocation_table.entries[j].r_info == R_X86_64_RELATIVE){
          if(withinSection(shdrs, ".init_array", relocation_table.entries[1].r_offset) == 0){
            printf("%i is in .init_array\n", j);
          }
          printf("%i\t0x%x\t0x%x\t0x%x\tR_X86_64_RELATIVE\n", j, relocation_table.entries[j].r_addend, relocation_table.entries[j].r_offset, relocation_table.entries[j].r_info);
        }
      }


      
      /* Writing to the mmaped page and copying the mmaped page to the host */
      printf("[+] File offset of the victim relocation entry 0x%x\n", get_file_offset(phdrs, relocation_table.entries[1].r_offset));
      printf("[+] %x\n", host_mem[get_file_offset(phdrs, relocation_table.entries[1].r_offset)]);
      host_mem[get_file_offset(phdrs, relocation_table.entries[1].r_offset)] = 0x7b;
      //host_mem[relocation_table.entries[1].r_offset - 0x1000 + 1] = 0x11;

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