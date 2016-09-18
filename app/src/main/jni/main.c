#define NDKLOG

#include <elf.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include "android_log.h"
#include "com_andr0day_soencrypt_MainActivity.h"

#define PAGE_SIZE 4096

typedef struct _funcInfo{
    Elf32_Addr st_value;
    Elf32_Word st_size;
}funcInfo;

static unsigned elfhash(const char *_name)
{
    const unsigned char *name = (const unsigned char *) _name;
    unsigned h = 0, g;

    while(*name) {
        h = (h << 4) + *name++;
        g = h & 0xf0000000;
        h ^= g;
        h ^= g >> 24;
    }
    return h;
}

static unsigned long getLibAddr(){
    unsigned long ret = 0;
    char name[] = "libencrypt.so";
    char buf[4096], *temp;
    int pid;
    FILE *fp;
    pid = getpid();
    sprintf(buf, "/proc/%d/maps", pid);
    fp = fopen(buf, "r");
    if(fp == NULL)
    {
        LOGE("open failed");
        goto _error;
    }
    while(fgets(buf, sizeof(buf), fp)){
        if(strstr(buf, name)){
            temp = strtok(buf, "-");
            ret = strtoul(temp, NULL, 16);
            break;
        }
    }
    _error:
    fclose(fp);
    return ret;
}

static char getTargetFuncInfo(unsigned long base, const char *funcName, funcInfo *info){
    char flag = -1, *dynstr;
    int i;
    Elf32_Ehdr *ehdr;
    Elf32_Phdr *phdr;
    Elf32_Off dyn_vaddr;
    Elf32_Word dyn_size, dyn_strsz;
    Elf32_Dyn *dyn;
    Elf32_Addr dyn_symtab, dyn_strtab, dyn_hash;
    Elf32_Sym *funSym;
    unsigned funHash, nbucket;
    unsigned *bucket, *chain;

    ehdr = (Elf32_Ehdr *)base;
    phdr = (Elf32_Phdr *)(base + ehdr->e_phoff);
    for (i = 0; i < ehdr->e_phnum; ++i) {
        if(phdr->p_type ==  PT_DYNAMIC){
            flag = 0;
            LOGE("Find .dynamic segment");
            break;
        }
        phdr ++;
    }
    if(flag)
        goto _error;
    dyn_vaddr = phdr->p_vaddr + base;
    dyn_size = phdr->p_filesz;
    LOGE("dyn_vadd =  0x%x, dyn_size =  0x%x", dyn_vaddr, dyn_size);
    flag = 0;
    int dyn_num = dyn_size/ sizeof(Elf32_Dyn);
    for (i = 0; i < dyn_num; ++i) {
        dyn = (Elf32_Dyn *)(dyn_vaddr + i * sizeof(Elf32_Dyn));
        if(dyn->d_tag == DT_SYMTAB){
            dyn_symtab = (dyn->d_un).d_ptr;
            flag += 1;
            LOGE("Find .dynsym section, addr = 0x%x\n", dyn_symtab);
        }
        if(dyn->d_tag == DT_HASH){
            dyn_hash = (dyn->d_un).d_ptr;
            flag += 2;
            LOGE("Find .hash section, addr = 0x%x\n", dyn_hash);
        }
        if(dyn->d_tag == DT_STRTAB){
            dyn_strtab = (dyn->d_un).d_ptr;
            flag += 4;
            LOGE("Find .dynstr section, addr = 0x%x\n", dyn_strtab);
        }
        if(dyn->d_tag == DT_STRSZ){
            dyn_strsz = (dyn->d_un).d_val;
            flag += 8;
            LOGE("Find strsz size = 0x%x\n", dyn_strsz);
        }
    }
    if((flag & 0x0f) != 0x0f){
        LOGE("Find needed .section failed\n");
        goto _error;
    }
    dyn_symtab += base;
    dyn_hash += base;
    dyn_strtab += base;
    dyn_strsz += base;

    funHash = elfhash(funcName);
    funSym = (Elf32_Sym *) dyn_symtab;
    dynstr = (char*) dyn_strtab;
    nbucket = *((int *) dyn_hash);
    bucket = (int *)(dyn_hash + 8);
    chain = (unsigned int *)(dyn_hash + 4 * (2 + nbucket));

    flag = -1;
    LOGE("hash = 0x%x, nbucket = 0x%x\n", funHash, nbucket);
    for(i = bucket[funHash % nbucket]; i != 0; i = chain[i]){
        LOGE("Find index = %d\n", i);
        if(strcmp(dynstr + (funSym + i)->st_name, funcName) == 0){
            flag = 0;
            LOGE("Find %s\n", funcName);
            break;
        }
    }
    if(flag) goto _error;
    info->st_value = (funSym + i)->st_value;
    info->st_size = (funSym + i)->st_size;
    LOGE("st_value = %d, st_size = %d", info->st_value, info->st_size);
    return 0;
    _error:
    return -1;
}


__attribute__((constructor)) static void init_getString(){
    const char target_fun[] = "Java_com_andr0day_soencrypt_MainActivity_getStr";
    funcInfo info;
    int i;
    unsigned int npage, base = getLibAddr();
    LOGE("base addr =  0x%x", base);

    if(getTargetFuncInfo(base, target_fun, &info) == -1){
        LOGE("Find Java_com_andr0day_soencrypt_MainActivity_getStr failed");
        return ;
    }
    npage = info.st_size / PAGE_SIZE + ((info.st_size % PAGE_SIZE == 0) ? 0 : 1);
    if(mprotect((void *) ((base + info.st_value) / PAGE_SIZE * PAGE_SIZE), npage, PROT_READ | PROT_EXEC | PROT_WRITE) != 0){
        LOGE("mem privilege change failed");
    }

    for(i=0;i< info.st_size - 1; i++){
        char *addr = (char*)(base + info.st_value -1 + i);
        *addr = ~(*addr);
    }

    if(mprotect((void *) ((base + info.st_value) / PAGE_SIZE * PAGE_SIZE), npage, PROT_READ | PROT_EXEC) != 0){
        LOGE("mem privilege change failed");
    }
}

JNIEXPORT jstring JNICALL Java_com_andr0day_soencrypt_MainActivity_getStr(JNIEnv *env, jclass clazz){
    return (*env)->NewStringUTF(env, "Str from native");
}