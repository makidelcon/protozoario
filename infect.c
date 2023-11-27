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

int is_ELF(Elf64_Ehdr *elf_ehdr) {
  /* ELF magic bytes are 0x7f,'E','L','F'
   * Using  octal escape sequence to represent 0x7f
   */
  if(!strncmp((char*)elf_ehdr->e_ident, "\177ELF", 4UL)) {
    return 1;
  } else {
    return 0;
  }
}

int main(int argc, char *argv[]) {
  Elf64_Ehdr *ehdr;
  Elf64_Phdr *phdr;
  Elf64_Shdr *shdr;

  int host_fd, ofd;
  struct stat st;
  char *host_mem;

  if ((host_fd = open(argv[1], O_RDWR)) < 0) return 1;

  fstat(host_fd, &st);
  host_mem = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, host_fd, 0);

  if (host_mem == NULL) return 2;

  ehdr = (Elf64_Ehdr *)host_mem;
  
  if(!(is_ELF(ehdr))) return 3;

  phdr = (Elf64_Phdr *)(host_mem + ehdr->e_phoff);
  shdr = (Elf64_Shdr *)(host_mem + ehdr->e_shoff);


  /*
  [+]-------- Finding the .dynamic  --------[+]
  .dynamic This section holds dynamic linking information. The section’s attributes will 
  include the SHF_ALLOC bit. Whether the SHF_WRITE bit is set is processor specific.
  */

  /* .dynamic */
  Elf64_Off   dyn_start;
  Elf64_Off   dyn_filesz;
  Elf64_Off   edyn_start;
  Elf64_Off   dyn_end;
  Elf64_Dyn*  dyn_entries;

  /* DT_RELA DT_RELAENT */
  Elf64_Off   rela_start;
  Elf64_Off   erela_count;
  Elf64_Off   rela_end;
  Elf64_Off   rela_entrysz;
  Elf64_Rela *rela_entries;
  Elf64_Rela  rela_entry;

  for(int i = 0; i < ehdr->e_phnum; i++) {
    if (phdr[i].p_type == PT_DYNAMIC){
      
      dyn_start = phdr[i].p_offset;
      dyn_filesz = phdr[i].p_filesz;
      dyn_end = dyn_start + dyn_filesz;
      dyn_entries = (Elf64_Dyn *)malloc(dyn_filesz);
      if (dyn_entries == NULL) {
        perror("Error on allocation");
        close(host_fd);
        free(dyn_entries);
        munmap(host_mem, st.st_size);
        return 5;
      }

      printf("[+] .dynamic segment Found!\n    Start at 0x%x and end at 0x%x\n", dyn_start, dyn_end);

      int j = 0;
      for(Elf64_Off edyn_start = dyn_start; edyn_start < dyn_end; edyn_start = edyn_start + sizeof(Elf64_Dyn)){
        Elf64_Dyn   dyn_entry;
        if (lseek(host_fd, edyn_start, SEEK_SET) == -1) {
          perror("[-] Error seeking to offset");
          close(host_fd);
          return 5;
        }
        read(host_fd, &dyn_entry, sizeof(Elf64_Dyn));
        
        dyn_entries[j] = dyn_entry;
        j++;
        
        // DT_NULL An entry with a DT_NULL tag marks the end of the _DYNAMIC array.
        if(dyn_entry.d_tag == DT_NULL) break;
      }
      
      //[+]-------- Finding the DT_RELA DT_RELAENT --------[+]*/
      printf("[+] Found %i (Elf64_Dyn)entries\n", j);
      for(int k = 0; k < j; k++){
        if(dyn_entries[k].d_tag == DT_RELAENT){
          erela_count = dyn_entries[k].d_un.d_val;
        }

        if(dyn_entries[k].d_tag == DT_RELA){
          rela_start = dyn_entries[k].d_un.d_val;
        }
      }

      printf("[+] File offset of realocations 0x%x\n", rela_start);
      rela_entrysz = sizeof(Elf64_Rela);
      rela_end = rela_start + (erela_count * rela_entrysz);
      rela_entries = (Elf64_Rela *)malloc(rela_entrysz);

      int y = 0;
      for(Elf64_Off s = rela_entrysz; rela_start < rela_end; rela_start += s){
        Elf64_Rela rela_entry;
        if (lseek(host_fd, rela_start, SEEK_SET) == -1) {
          perror("[-] Error seeking to offset");
          close(host_fd);
          return 5;
        }
        read(host_fd, &rela_entry, sizeof(Elf64_Rela));
        rela_entries[y] = rela_entry;
        y++;
      }

      printf("\tADDEND\tOFFSET\tINFO\tTYPE\n");
      for(int k = 0; k < y; k++){
        if(rela_entries[k].r_info == R_X86_64_RELATIVE){
          printf("\t0x%x\t0x%x\t0x%x\tR_X86_64_RELATIVE\n", rela_entries[k].r_addend, rela_entries[k].r_offset, rela_entries[k].r_info);
        }
      }
    }
  }
  
  close(host_fd);
  free(dyn_entries);
  free(rela_entries);
  munmap(host_mem, st.st_size);
  return 0;
}