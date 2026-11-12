/* SPDX-License-Identifier: GPL-2.0-only
 * PD2454 stage-1 binder: patch only undefined function-symbol records.
 * No instruction edits, kernel-data snapshots, section growth or init stubs.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    unsigned char ident[16]; uint16_t type, machine; uint32_t version;
    uint64_t entry, phoff, shoff; uint32_t flags;
    uint16_t ehsize, phentsize, phnum, shentsize, shnum, shstrndx;
} Ehdr;
typedef struct {
    uint32_t name, type; uint64_t flags, addr, offset, size;
    uint32_t link, info; uint64_t align, entsize;
} Shdr;
typedef struct {
    uint32_t name; unsigned char info, other; uint16_t shndx;
    uint64_t value, size;
} Sym;
typedef struct { uint64_t offset, info; int64_t addend; } Rela;
_Static_assert(sizeof(Ehdr)==64 && sizeof(Shdr)==64 && sizeof(Sym)==24 && sizeof(Rela)==24, "ELF64 layout");

enum { PROGBITS=1, SYMTAB=2, STRTAB=3, RELA=4, NOBITS=8, ALLOC=2, EXEC=4, ABS=0xfff1 };
struct target { const char *name; uint64_t address; };
static const struct target functions[] = {
    {"path_umount", UINT64_C(0xffffffc0803fdda8)},
    {"strncpy_from_user_nofault", UINT64_C(0xffffffc0802de9a0)},
    {"filp_open", UINT64_C(0xffffffc0803ca354)},
    {"__arm64_sys_close", UINT64_C(0xffffffc0803cad60)},
    {"kallsyms_lookup_size_offset", UINT64_C(0xffffffc0801ace8c)},
    {"anon_inode_getfile_secure", UINT64_C(0xffffffc080436724)},
    {"ns_get_path", UINT64_C(0xffffffc08041f914)},
    {"ksys_unshare", UINT64_C(0xffffffc0800af430)},
    {"path_mount", UINT64_C(0xffffffc0803ff7e4)},
    {"__arm64_sys_setns", UINT64_C(0xffffffc0800e39b8)},
    {"set_fs_pwd", UINT64_C(0xffffffc08041de04)},
    {"kallsyms_lookup_name", UINT64_C(0xffffffc0801ac59c)},
    {"kallsyms_lookup", UINT64_C(0xffffffc0801ad0b4)},
    {"kallsyms_on_each_symbol", UINT64_C(0xffffffc0801acb84)},
    {"strrchr", UINT64_C(0xffffffc081033ff8)},
    {"kernel_read", UINT64_C(0xffffffc0803cbcc8)},
    {"task_work_add", UINT64_C(0xffffffc0800ddd30)},
    {"kernel_write", UINT64_C(0xffffffc0803cc2e0)},
    {"groups_alloc", UINT64_C(0xffffffc0800ea114)},
    {"groups_sort", UINT64_C(0xffffffc0800ea1a4)},
    {"set_groups", UINT64_C(0xffffffc0800ea250)},
    {"alloc_uid", UINT64_C(0xffffffc0800c3a84)},
    {"set_cred_ucounts", UINT64_C(0xffffffc0800e5c80)},
    {"commit_creds", UINT64_C(0xffffffc0800e5cf4)},
    {"seccomp_filter_release", UINT64_C(0xffffffc0801ddbfc)},
    {"abort_creds", UINT64_C(0xffffffc0800e5698)},
    {"strchrnul", UINT64_C(0xffffffc08105306c)},
    {"kstrtoull", UINT64_C(0xffffffc08071c494)},
    {"ext4_unregister_sysfs", UINT64_C(0xffffffc080506df0)},
    {"copy_from_user_nofault", UINT64_C(0xffffffc0802de754)},
    {"copy_to_user_nofault", UINT64_C(0xffffffc0802de86c)},
    {"security_secctx_to_secid", UINT64_C(0xffffffc080633a48)},
    {"avc_ss_reset", UINT64_C(0xffffffc080636924)},
    {"selnl_notify_policyload", UINT64_C(0xffffffc080647de4)},
    {"selinux_status_update_policyload", UINT64_C(0xffffffc080648da8)},
    {"symtab_search", UINT64_C(0xffffffc08064a24c)},
    {"symtab_insert", UINT64_C(0xffffffc08064a150)},
    {"ebitmap_set_bit", UINT64_C(0xffffffc0806491e0)},
    {"ebitmap_get_bit", UINT64_C(0xffffffc080649180)},
    {"policydb_filenametr_search", UINT64_C(0xffffffc08064cc2c)},
    {"__hashtab_insert", UINT64_C(0xffffffc080649dbc)},
    {"policydb_destroy", UINT64_C(0xffffffc08064cde0)},
    {"policydb_write", UINT64_C(0xffffffc08064f3cc)},
    {"policydb_read", UINT64_C(0xffffffc08064d634)},
    {"avtab_search_node", UINT64_C(0xffffffc08064ba1c)},
    {"avtab_alloc", UINT64_C(0xffffffc08064bcb0)},
    {"avtab_destroy", UINT64_C(0xffffffc08064bbe8)},
    {"avtab_search_node_next", UINT64_C(0xffffffc08064bb60)},
    {"avtab_insert_nonunique", UINT64_C(0xffffffc08064b7c0)},
    {"change_pid", UINT64_C(0xffffffc0800dd044)},
};
static const char vermagic[] = "vermagic=6.6.127-android15-8-gd489d4ad2a70-abogki567717946-4k SMP preempt mod_unload modversions aarch64";
static const char *forbidden[] = {
    "selinux_state", "selinux_blob_sizes", "mntns_operations", "init_mm", "__tracepoint_sys_enter",
};
struct image {
    unsigned char *bytes; size_t size; Ehdr *header; Shdr *sections;
    Shdr *symtab, *strings, *names; Sym *symbols; size_t nsymbols;
};
static int fail(const char *message) { fprintf(stderr,"ksupatch: %s\n",message); return -1; }
static int argument_error(const char *message) { fail(message); return 2; }
static int range(const struct image *m, uint64_t off, uint64_t len)
{ return off<=m->size && len<=m->size-off; }
static const char *string_at(const struct image *m, const Shdr *s, uint32_t offset)
{
    if (offset>=s->size || !range(m,s->offset,s->size)) return NULL;
    const char *p=(char *)m->bytes+s->offset+offset;
    return memchr(p,0,s->size-offset)?p:NULL;
}
static const char *symname(const struct image *m, size_t index)
{ return index<m->nsymbols?string_at(m,m->strings,m->symbols[index].name):NULL; }
static Shdr *section_named(const struct image *m,const char *name)
{
    for (size_t i=0;i<m->header->shnum;i++) {
        const char *s=string_at(m,m->names,m->sections[i].name);
        if (s && !strcmp(s,name)) return &m->sections[i];
    }
    return NULL;
}
static Sym *symbol_named(const struct image *m,const char *name)
{
    for (size_t i=1;i<m->nsymbols;i++) if (!strcmp(symname(m,i),name)) return &m->symbols[i];
    return NULL;
}
static int parse(struct image *m)
{
    if (m->size<64) return fail("short ELF");
    Ehdr *h=(Ehdr *)m->bytes; m->header=h;
    if (memcmp(h->ident,"\177ELF\2\1\1",7) || h->type!=1 || h->machine!=183 || h->version!=1 ||
        h->ehsize!=64 || h->phnum || h->shentsize!=64 || !h->shnum || h->shnum>1024 ||
        h->shstrndx>=h->shnum || h->shoff%8 || !range(m,h->shoff,(uint64_t)h->shnum*64))
        return fail("requires an ordinary little-endian AArch64 relocatable module");
    m->sections=(Shdr *)(m->bytes+h->shoff);
    for (size_t i=0;i<h->shnum;i++) {
        Shdr *s=&m->sections[i];
        if (s->type!=NOBITS && !range(m,s->offset,s->size)) return fail("section outside file");
        if (s->type==SYMTAB) {
            if (m->symtab || s->entsize!=24 || s->size%24 || s->offset%8 || s->link>=h->shnum)
                return fail("invalid symbol table");
            m->symtab=s;
        }
    }
    /* Binding must not be able to overwrite headers or string tables through
     * a malformed overlapping symbol section. NOBITS has no file extent. */
    for (size_t i=1;i<h->shnum;i++) {
        Shdr *a=&m->sections[i]; if (!a->size || a->type==NOBITS) continue;
        uint64_t finish=a->offset+a->size;
        if (a->offset<64 || (a->offset<h->shoff+(uint64_t)h->shnum*64 && finish>h->shoff))
            return fail("section overlaps ELF headers");
        for (size_t j=1;j<i;j++) {
            Shdr *b=&m->sections[j]; if (!b->size || b->type==NOBITS) continue;
            if (a->offset<b->offset+b->size && b->offset<finish) return fail("overlapping file sections");
        }
    }
    m->names=&m->sections[h->shstrndx];
    if (!m->symtab || m->names->type!=STRTAB) return fail("missing symbol/name table");
    m->strings=&m->sections[m->symtab->link];
    if (m->strings->type!=STRTAB) return fail("invalid symbol strings");
    m->symbols=(Sym *)(m->bytes+m->symtab->offset); m->nsymbols=m->symtab->size/24;
    for (size_t i=0;i<h->shnum;i++) if (!string_at(m,m->names,m->sections[i].name)) return fail("invalid section name");
    for (size_t i=0;i<m->nsymbols;i++) {
        if (!symname(m,i)) return fail("invalid symbol name");
        if (m->symbols[i].shndx>=h->shnum && m->symbols[i].shndx!=ABS)
            return fail("unsupported symbol section index");
    }
    return 0;
}
static int metadata_has(const struct image *m,const char *key)
{
    Shdr *s=section_named(m,".modinfo"); if (!s || s->type!=PROGBITS) return 0;
    size_t off=0;
    while (off<s->size) {
        const char *p=(char *)m->bytes+s->offset+off;
        const char *end=memchr(p,0,s->size-off); if (!end) return 0;
        if (!strcmp(p,key)) return 1;
        off+=(size_t)(end-p)+1;
    }
    return 0;
}
static unsigned char *function_body(const struct image *m,Sym *s)
{
    if (!s || (s->info&15)!=2 || !s->shndx || s->shndx>=m->header->shnum) return NULL;
    Shdr *sec=&m->sections[s->shndx];
    if (sec->type!=PROGBITS || (sec->flags&(ALLOC|EXEC))!=(ALLOC|EXEC) || s->value>sec->size || s->size>sec->size-s->value ||
        !range(m,sec->offset+s->value,s->size)) return NULL;
    return m->bytes+sec->offset+s->value;
}
static int profile(const struct image *m)
{
    if (!metadata_has(m,"ksu_no_text_poke=1") || !metadata_has(m,"ksu_self_resolved_data=1") || !metadata_has(m,vermagic))
        return fail("wrong profile or target vermagic");
    Shdr *v=section_named(m,"__versions"),*mod=section_named(m,".gnu.linkonce.this_module");
    if (!v || v->size || !mod || mod->size!=0x600) return fail("module ABI/version metadata mismatch");
    Sym *stub=symbol_named(m,"ksu_patch_text"); unsigned char *body=function_body(m,stub);
    static const unsigned char expected[]={0xc0,0x0b,0x80,0x12,0xc0,0x03,0x5f,0xd6};
    if (!body || stub->size!=8 || memcmp(body,expected,8)) return fail("text-poke refusal stub missing");
    const char *required[]={"init_module","ksu_kernel_data_init","ksu_probe_fallback_init","ksu_syscall_hook_init"};
    static const unsigned char neutered[]={0,0,0x80,0x52,0xc0,0x03,0x5f,0xd6};
    for (size_t i=0;i<sizeof(required)/sizeof(required[0]);i++) {
        Sym *s=symbol_named(m,required[i]); body=function_body(m,s);
        if (!body || s->size<=8 || !memcmp(body,neutered,8)) return fail("required initialization function missing or neutered");
    }
    const char *unused[]={"phys_from_virt","ksu_selinux_hide_init","ksu_module_blacklist_init","backup_sepolicy"};
    for (size_t i=0;i<sizeof(unused)/sizeof(unused[0]);i++) if (symbol_named(m,unused[i])) return fail("obsolete component still present");
    for (size_t i=0;i<sizeof(forbidden)/sizeof(forbidden[0]);i++) if (symbol_named(m,forbidden[i])) return fail("private data import still present");
    Sym *data=symbol_named(m,"ksu_kernel_data");
    if (!data || !data->shndx || data->shndx>=m->header->shnum || data->size!=24) return fail("typed data storage missing");
    Shdr *storage=&m->sections[data->shndx];
    if ((storage->flags&3)!=3 || data->value>storage->size || data->size>storage->size-data->value)
        return fail("typed data storage is not writable/allocated or is outside its section");
    return 0;
}
static int map_index(const char *name)
{
    if (!name) return -1;
    for (size_t i=0;i<sizeof(functions)/sizeof(functions[0]);i++) if (!strcmp(name,functions[i].name)) return (int)i;
    return -1;
}
static int relocations(const struct image *m)
{
    int init=0,exit=0;
    for (size_t i=0;i<m->header->shnum;i++) {
        Shdr *s=&m->sections[i]; if (s->type!=RELA) continue;
        if (s->entsize!=24 || s->size%24 || s->offset%8 || s->info>=m->header->shnum || s->link!=(size_t)(m->symtab-m->sections))
            return fail("invalid relocation table");
        Shdr *target=&m->sections[s->info];
        for (size_t o=0;o<s->size;o+=24) {
            Rela *r=(Rela *)(m->bytes+s->offset+o); uint32_t type=(uint32_t)r->info; uint64_t index=r->info>>32;
            const char *name=symname(m,index); if (!name) return fail("relocation symbol outside table");
            if (!(target->flags&ALLOC)) continue;
            size_t width=type==257?8:4;
            if (type && (r->offset>target->size || width>target->size-r->offset)) return fail("relocation outside loaded section");
            if (map_index(name)>=0 && type && type!=282 && type!=283 && type!=257)
                return fail("mapped function has unsupported non-call relocation");
            if (target==section_named(m,".gnu.linkonce.this_module")) {
                if (!strcmp(name,"init_module") && type==257 && r->offset==0x188) init=1;
                if (!strcmp(name,"cleanup_module") && type==257 && r->offset==0x5b8) exit=1;
            }
        }
    }
    return init && exit?0:fail("module init/exit fields do not match target ABI");
}
static int bind_symbols(struct image *m,uint64_t slide)
{
    unsigned seen[sizeof(functions)/sizeof(functions[0])]={0}; unsigned count=0;
    for (size_t i=1;i<m->nsymbols;i++) {
        Sym *s=&m->symbols[i]; int k=map_index(symname(m,i)); if (k<0) continue;
        if (s->shndx || (s->info>>4)!=1 || seen[k]) return fail("expected fresh unique undefined function import");
        if (slide>UINT64_MAX-functions[k].address) return fail("function address overflow");
        s->shndx=ABS; s->value=functions[k].address+slide; seen[k]=1; count++;
    }
    for (size_t i=0;i<sizeof(seen)/sizeof(seen[0]);i++) if (!seen[i]) return fail("required function import absent");
    printf("KSUPATCH_BOUND %u function symbols; no instruction or section changes\n",count);
    return 0;
}
static int write_atomic(const struct image *m,const char *path)
{
    size_t n=strlen(path)+40; char *tmp=malloc(n); if (!tmp) return fail("allocation failed");
    snprintf(tmp,n,"%s.tmp.%ld",path,(long)getpid());
    FILE *f=fopen(tmp,"wbx"); if (!f) {free(tmp);return fail("cannot create temporary output");}
    int ok=fwrite(m->bytes,1,m->size,f)==m->size;
    if (fclose(f)) ok=0;
    if (ok && rename(tmp,path)) ok=0;
    if (!ok) unlink(tmp);
    free(tmp); return ok?0:fail("output write failed");
}
int main(int argc,char **argv)
{
    if (argc!=4) {fprintf(stderr,"usage: %s <current-boot-slide-hex> <self-data-module.ko> <output.ko>\n",argv[0]);return 2;}
    char *end=NULL; errno=0; uint64_t slide=strtoull(argv[1],&end,16);
    if (errno || !end || !*argv[1] || argv[1][0]=='-' || argv[1][0]=='+' || *end || !slide || slide>=UINT64_C(0x3f80000000) || (slide&UINT64_C(0x1fffff)))
        return argument_error("invalid explicit KASLR slide");
    struct stat in,out;
    if (stat(argv[2],&in) || in.st_size<64 || in.st_size>64*1024*1024) return argument_error("invalid input size");
    if (!stat(argv[3],&out) && in.st_dev==out.st_dev && in.st_ino==out.st_ino) return argument_error("input and output are the same file");
    struct image m={.size=(size_t)in.st_size}; m.bytes=malloc(m.size); if (!m.bytes) return 1;
    FILE *f=fopen(argv[2],"rb"); if (!f) {free(m.bytes);return 1;}
    int ok=fread(m.bytes,1,m.size,f)==m.size; fclose(f);
    if (!ok || parse(&m) || profile(&m) || relocations(&m) || bind_symbols(&m,slide) || write_atomic(&m,argv[3])) {free(m.bytes);return 1;}
    printf("KSUPATCH_OK %s slide=%#llx\n",argv[3],(unsigned long long)slide);
    free(m.bytes);return 0;
}
