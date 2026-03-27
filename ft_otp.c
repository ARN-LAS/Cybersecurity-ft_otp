#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/mman.h>
#include <termios.h>
#include <syslog.h>
#include <time.h>
#include <endian.h>
#include <stdarg.h>
#include <sys/syscall.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/prctl.h>

#define PASSWORD_MAX 64
#define NV_COUNTER_INDEX 0x01000001
#define TPM_KEY_BASE 0x81000000

#define ERR_TPM_INIT         -1
#define ERR_NV_COUNTER       -2
#define ERR_KEY_ROTATION     -3
#define ERR_OTP_GENERATION   -4
#define ERR_PASSWORD_READ    -5

void secure_clear(void *buf, size_t len) {
    if (!buf) return;
    volatile uint8_t *p = buf;
    while (len--) *p++ = 0;
}

int read_password_secure(int fd, char *password, size_t max_len, size_t *out_len) {
    struct termios oldt, newt;
    if (tcgetattr(fd, &oldt) != 0) return -1;
    newt = oldt;
    newt.c_lflag &= ~(ECHO | ISIG);
    if (tcsetattr(fd, TCSAFLUSH, &newt) != 0) return -1;
    ssize_t n = read(fd, password, max_len - 1);
    if (n >= 0) password[n] = '\0';
    tcsetattr(fd, TCSAFLUSH, &oldt);
    if (n < 0) return -1;
    if (n > 0 && password[n-1] == '\n') n--;
    *out_len = (size_t)n;
    return 0;
}

void setup_seccomp(void) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_read, 0, 11),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_write, 0, 10),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_ioctl, 0, 9),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit_group, 0, 8),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit, 0, 7),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_close, 0, 6),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_nanosleep, 0, 5),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_pselect6, 0, 4),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getrandom, 0, 3),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_brk, 0, 2),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_mmap, 0, 1),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_munmap, 0, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)
    };
    struct sock_fprog prog = { .len = sizeof(filter)/sizeof(filter[0]), .filter = filter };
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}

int setup_nv_counter(ESYS_CONTEXT *ctx, TPMI_RH_NV_INDEX nv_index) {
    TPM2B_AUTH auth = { .size = 0 }; 
    TPM2B_NV_PUBLIC publicInfo = {
        .size = sizeof(TPMS_NV_PUBLIC),
        .nvPublic = {
            .nvIndex = nv_index,
            .nameAlg = TPM2_ALG_SHA256,
            .attributes = TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD,
            .dataSize = 8 
        }
    };
    ESYS_TR nv_handle_out = ESYS_TR_NONE; 
    TSS2_RC rc = Esys_NV_DefineSpace(ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, 
                                    ESYS_TR_NONE, ESYS_TR_NONE, 
                                    &auth, &publicInfo, &nv_handle_out);

    if (rc == 0x0000014c) return 0;
    if (rc == TSS2_RC_SUCCESS) {
        TPM2B_MAX_NV_BUFFER zero_buf = { .size = 8, .buffer = {0} };
        Esys_NV_Write(ctx, nv_handle_out, nv_handle_out, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &zero_buf, 0);
        Esys_FlushContext(ctx, nv_handle_out);
        return 0;
    }
    return -1;
}

int increment_manual_counter(ESYS_CONTEXT *ctx, ESYS_TR nv_handle) {
    TPM2B_MAX_NV_BUFFER *read_data = NULL;
    TPM2B_AUTH auth_empty = { .size = 0 };
    Esys_TR_SetAuth(ctx, nv_handle, &auth_empty);

    TSS2_RC rc = Esys_NV_Read(ctx, nv_handle, nv_handle, 
                             ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, 
                             8, 0, &read_data);
    if (rc != TSS2_RC_SUCCESS || !read_data) return -1;

    uint64_t count;
    memcpy(&count, read_data->buffer, 8);
    uint64_t val = be64toh(count) + 1;
    count = htobe64(val);
    
    TPM2B_MAX_NV_BUFFER write_data = { .size = 8 };
    memcpy(write_data.buffer, &count, 8);
    rc = Esys_NV_Write(ctx, nv_handle, nv_handle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &write_data, 0);
    
    if (read_data) Esys_Free(read_data);
    return (rc == TSS2_RC_SUCCESS) ? 0 : -1;
}

int rotate_tpm_key(ESYS_CONTEXT *ctx, ESYS_TR *key_handle, TPM2_HANDLE key_index, char *pass, size_t pass_len) {
    TPM2B_SENSITIVE_CREATE inSens = {0};
    TPM2B_PUBLIC inPub = {0};
    inSens.sensitive.userAuth.size = (uint16_t)pass_len;
    if (pass_len > 0) memcpy(inSens.sensitive.userAuth.buffer, pass, pass_len);
    inPub.publicArea.type = TPM2_ALG_KEYEDHASH;
    inPub.publicArea.nameAlg = TPM2_ALG_SHA256;
    inPub.publicArea.objectAttributes = (TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN);
    inPub.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_HMAC;
    inPub.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = TPM2_ALG_SHA256;
    ESYS_TR trans = ESYS_TR_NONE;
    TSS2_RC rc = Esys_CreatePrimary(ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &inSens, &inPub, NULL, NULL, &trans, NULL, NULL, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS) return -1;
    rc = Esys_EvictControl(ctx, ESYS_TR_RH_OWNER, trans, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, key_index, key_handle);
    Esys_FlushContext(ctx, trans);
    return (rc == TSS2_RC_SUCCESS) ? 0 : -1;
}

int generate_totp(ESYS_CONTEXT *ctx, ESYS_TR key, char *pass, size_t pass_len, uint32_t *out_otp) {
    uint64_t interval = htobe64(time(NULL) / 30);
    TPM2B_MAX_BUFFER buf = { .size = sizeof(interval) };
    memcpy(buf.buffer, &interval, sizeof(interval));
    TPM2B_AUTH auth = { .size = (uint16_t)pass_len };
    memcpy(auth.buffer, pass, pass_len);
    Esys_TR_SetAuth(ctx, key, &auth);
    TPM2B_DIGEST *hmac_out = NULL;
    TSS2_RC rc = Esys_HMAC(ctx, key, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &buf, TPM2_ALG_SHA256, &hmac_out);
    if (rc != TSS2_RC_SUCCESS) return -1;
    int offset = hmac_out->buffer[hmac_out->size - 1] & 0xf;
    uint32_t bin_code;
    memcpy(&bin_code, &hmac_out->buffer[offset], sizeof(bin_code));
    *out_otp = (be32toh(bin_code) & 0x7fffffff) % 1000000;
    Esys_Free(hmac_out);
    return 0;
}

int main(void) {
    // Désactiver les logs polluants de la bibliothèque TSS2
    setenv("TSS2_LOG", "all+none", 1);
    
    prctl(PR_SET_DUMPABLE, 0);
    ESYS_CONTEXT *ctx = NULL;
    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
    ESYS_TR tpm_key = ESYS_TR_NONE, nv_handle = ESYS_TR_NONE;
    char password[PASSWORD_MAX];
    size_t password_len = 0;
    int status_rc = 0, tty_fd = open("/dev/tty", O_RDWR | O_CLOEXEC);
    if (tty_fd < 0) return ERR_PASSWORD_READ;

    if (Tss2_TctiLdr_Initialize("device:/dev/tpmrm0", &tcti_ctx) != TSS2_RC_SUCCESS) {
        status_rc = ERR_TPM_INIT; goto cleanup;
    }
    if (Esys_Initialize(&ctx, tcti_ctx, NULL) != TSS2_RC_SUCCESS) {
        status_rc = ERR_TPM_INIT; goto cleanup;
    }

    mlock(password, sizeof(password));
    dprintf(tty_fd, "\r\033[KEnter TPM Password: ");
    read_password_secure(tty_fd, password, sizeof(password), &password_len);

    uid_t uid = getuid();
    TPM2_HANDLE k_idx = TPM_KEY_BASE + (uid * 997 % 0x1000);
    if (Esys_TR_FromTPMPublic(ctx, k_idx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &tpm_key) != TSS2_RC_SUCCESS) {
        if (rotate_tpm_key(ctx, &tpm_key, k_idx, password, password_len) != 0) {
            status_rc = ERR_KEY_ROTATION; goto cleanup;
        }
    }

    TPMI_RH_NV_INDEX nv_idx = NV_COUNTER_INDEX;
    setup_nv_counter(ctx, nv_idx);
    if (Esys_TR_FromTPMPublic(ctx, nv_idx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &nv_handle) != TSS2_RC_SUCCESS) {
        status_rc = ERR_NV_COUNTER; goto cleanup;
    }

    setup_seccomp();
    uint32_t otp = 0;
    if (generate_totp(ctx, tpm_key, password, password_len, &otp) == 0) {
        increment_manual_counter(ctx, nv_handle);
        dprintf(tty_fd, "\nYour OTP: \033[1;33m%06u\033[0m\n", otp);

        dprintf(tty_fd, "Verify OTP: ");
        char input_buf[10] = {0};
        struct termios v_term;
        tcgetattr(tty_fd, &v_term);
        v_term.c_lflag |= ECHO;
        tcsetattr(tty_fd, TCSAFLUSH, &v_term);

        if (read(tty_fd, input_buf, sizeof(input_buf) - 1) > 0) {
            if ((uint32_t)atoi(input_buf) == otp) {
                dprintf(tty_fd, "\033[32m[SUCCESS]\033[0m Access Granted.\n");
            } else {
                dprintf(tty_fd, "\033[31m[FAILURE]\033[0m Access Denied.\n");
                status_rc = -6;
            }
        }
    } else {
        status_rc = ERR_OTP_GENERATION;
    }

cleanup:
    secure_clear(password, sizeof(password));
    munlock(password, sizeof(password));
    if (tty_fd >= 0) close(tty_fd);
    if (ctx) Esys_Finalize(&ctx);
    if (tcti_ctx) Tss2_TctiLdr_Finalize(&tcti_ctx);
    return status_rc;
}
