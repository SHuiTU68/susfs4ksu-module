// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * mctl - userspace client for the susfs_kpm command channel.
 *
 * WHY IT IS A BINARY AND NOT A SHELL SCRIPT
 *
 * The engine is controlled through a syscall, not through a file: susfs_kpm
 * hooks the kcmp syscall (number 272 on arm64) and treats
 *
 *     syscall(272, SUSFS_CMD_MAGIC, cmd_buf, out_buf, out_len, &rc_out)
 *
 * as a control channel.  That route exists because KernelPatch's
 * SUPERCALL_KPM_CONTROL sits behind `if (!is_authed) return -EPERM;` and is
 * only reachable by the APatch manager APK (signature match) or with the
 * superkey - neither of which a root shell has (see the long comment above
 * before_cmd_channel() in kpm/susfs_kpm.c).  kcmp needs no authorisation, and
 * a shell cannot issue it: Android's toybox sh/mksh has no `syscall`.  So the
 * client has to be a small static aarch64 binary, which is what this is.
 *
 * The wire protocol is the same text protocol ctl0 speaks:
 *
 *     "<CMD_HEX>|<arg1>|<arg2>|..."
 *
 * It is assembled here rather than in the caller so that metamount.sh can stay
 * a shell script: it hands over NUL-separated `virtual\0real\0` records on
 * stdin and does not have to know a single command number.
 *
 * EXIT CODES (metamount.sh and action.sh gate on some of them)
 *
 *   0  success
 *   1  no channel / the command failed (engine not loaded, or an engine that
 *      predates the E7 commands)
 *   2  usage error (bad arguments, or `rule add` with a terminal on stdin)
 *   3  unsupported request (E7 v1 has no whiteout support - see below)
 *   4  the listing did not fit in the reply buffer and is truncated
 *
 * THE --whiteout FLAG
 *
 * nomount's client speaks `nm rule add [--whiteout]`; we mirror the command
 * names so the two are interchangeable while we migrate.  E7 v1 deliberately
 * does not implement whiteouts (a module asking for deletion needs a
 * negative-dentry keeper or an i_op shadow - see the E7 design note), and
 * metamount.sh routes any module that needs one to overlayfs *before* calling
 * us.  If the flag shows up here anyway, refusing loudly beats silently
 * mounting a file the module wanted gone: that is a correctness bug, not a
 * missing feature.
 */
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#ifndef __NR_kcmp
#define __NR_kcmp 272 /* arm64; exists on every Android 4.x+ kernel */
#endif

/* ===== the channel =====
 *
 * Mirror of kpm/susfs_kpm.c.  SUSFS_CMD_MAGIC is the value the hook compares
 * against syscall argument 0, and the sentinel is the opt-in handshake for the
 * 5th argument: the kernel only writes the real return value there when the int
 * it points to already holds the sentinel.  Without it, an old client that
 * passes four arguments would have the kernel poke a stale register value into
 * a random address of its own process.
 */
#define SUSFS_CMD_MAGIC 0x5355534653595343ULL /* "SUSFSYSC" */
#define SUSFS_RC_SENTINEL 0x7fffffff

/* Command codes - mirror of kpm/include/susfs_kpm.h.  Only what this client
 * sends is spelled out; the KPM's table is the authoritative one. */
#define CMD_SUSFS_SHOW_VERSION 0x555E1u
#define CMD_SUSFS_SHOW_VARIANT 0x555E3u
#define CMD_SUSFS_KPM_DC_RULE_ADD 0x55565u
#define CMD_SUSFS_KPM_DC_RULE_CLEAR 0x55566u
#define CMD_SUSFS_KPM_DC_RULE_COUNT 0x55567u
#define CMD_SUSFS_KPM_DC_RULE_LIST 0x55568u
#define CMD_SUSFS_KPM_DC_CAPS 0x55569u
#define CMD_SUSFS_KPM_DC_STATUS 0x5556Au

/* The KPM copies ctl_args into a 2048-byte stack buffer (susfs_ctl0), so a
 * longer command would be silently truncated there.  Refuse it here instead,
 * where the caller can be told which rule was skipped. */
#define CMD_BUFSIZE 2048

/* Same size as the kernel side's static listing buffer. */
#define OUT_BUFSIZE 65536

/* Reading `rule add' input: 10^4 rules of ~300 bytes is ~3 MB, so start at
 * 1 MB and double.  The cap is a runaway guard, not a design limit. */
#define IN_START (1u << 20)
#define IN_MAX (64u << 20)

#define EX_OK 0
#define EX_FAIL 1
#define EX_USAGE 2
#define EX_UNSUPPORTED 3
#define EX_TRUNCATED 4

static const char *progname = "mctl";

static void warn(const char *fmt, ...)
    __attribute__((format(printf, 1, 2)));
static void warn(const char *fmt, ...)
{
    va_list ap;

    fprintf(stderr, "%s: ", progname);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

static void usage(FILE *out)
{
    fprintf(out,
        "usage: mctl <command> [args]\n"
        "\n"
        "  version              engine version (fails if the channel is dead)\n"
        "  caps                 capabilities the engine advertises, e.g.\n"
        "                       \"rule-store\" - metamount.sh needs \"readdir\"\n"
        "  status               one status line (rule count, errors, caps)\n"
        "  rule add [--whiteout]\n"
        "                       read NUL-separated 'virtual\\0real\\0' records\n"
        "                       on stdin and install them as dcache rules\n"
        "  rule clear           drop every rule\n"
        "  rule count           number of installed rules\n"
        "  rule list            'virtual=real' per line\n"
        "  raw <CMD_HEX> [args...]\n"
        "                       send a raw command (debugging)\n"
        "\n"
        "exit: 0 ok, 1 no channel/failed, 2 usage, 3 unsupported, 4 truncated\n");
}

/* ===== channel plumbing ===== */

/* The real rc comes back two ways: through the armed 5th argument (always
 * works) and as the syscall's own return value (only when KernelPatch honours
 * skip_origin, which is why the 5th argument exists).  A negative syscall
 * return from an *unarmed* 5th argument means the hook never ran - i.e. either
 * susfs_kpm is not loaded, or it is a build from before the channel existed -
 * and in that case what just happened is a real kcmp(pid1=<magic>,...) that
 * returned -ESRCH. */
static int kpm_send(const char *cmd, char *out, size_t outlen, long *rcp)
{
    int rc_out = SUSFS_RC_SENTINEL;
    long ret;

    if (out && outlen) out[0] = '\0';

    ret = syscall(__NR_kcmp, (long)SUSFS_CMD_MAGIC, (long)cmd,
                  (long)(out ? out : ""), (long)outlen, (long)&rc_out);

    if (rc_out != SUSFS_RC_SENTINEL) {
        *rcp = rc_out;
        return 0;
    }
    if (ret >= 0) {
        *rcp = ret;
        return 0;
    }
    return -1;
}

static void no_channel(void)
{
    fprintf(stderr, "%s: no reply from the susfs_kpm command channel\n",
            progname);
    fprintf(stderr, "%s: is susfs_kpm loaded (and new enough to have it)?\n",
            progname);
}

static void print_rc_error(long rc)
{
    fprintf(stderr, "%s: engine returned %ld (%s)\n", progname, rc,
            rc < 0 ? strerror((int)-rc) : "error");
}

/* ===== commands ===== */

static int cmd_version(void)
{
    char out[64], variant[64];
    long rc;

    if (kpm_send("555E1", out, sizeof(out), &rc) != 0) {
        no_channel();
        return EX_FAIL;
    }
    if (rc != 0) {
        print_rc_error(rc);
        return EX_FAIL;
    }

    if (kpm_send("555E3", variant, sizeof(variant), &rc) == 0 && rc == 0 &&
        variant[0] != '\0') {
        printf("%s (%s)\n", out, variant);
        return EX_OK;
    }
    printf("%s\n", out);
    return EX_OK;
}

static int cmd_caps(void)
{
    char out[256];
    long rc;

    if (kpm_send("55569", out, sizeof(out), &rc) != 0) {
        no_channel();
        return EX_FAIL;
    }
    /* An engine from before the E7 work answers -ENOSYS here, which is exactly
     * what metamount.sh wants to see: no caps means no readdir. */
    if (rc != 0) {
        print_rc_error(rc);
        return EX_FAIL;
    }
    printf("%s\n", out);
    return out[0] ? EX_OK : EX_FAIL;
}

static int cmd_status(void)
{
    char out[256];
    long rc;

    if (kpm_send("5556A", out, sizeof(out), &rc) != 0) {
        no_channel();
        return EX_FAIL;
    }
    if (rc != 0) {
        print_rc_error(rc);
        return EX_FAIL;
    }
    printf("%s", out);
    return EX_OK;
}

static int cmd_rule_clear(void)
{
    char out[8];
    long rc;

    if (kpm_send("55566", out, sizeof(out), &rc) != 0) {
        no_channel();
        return EX_FAIL;
    }
    if (rc != 0) {
        print_rc_error(rc);
        return EX_FAIL;
    }
    return EX_OK;
}

static int cmd_rule_count(void)
{
    char out[8];
    long rc;

    if (kpm_send("55567", out, sizeof(out), &rc) != 0) {
        no_channel();
        return EX_FAIL;
    }
    if (rc < 0) {
        print_rc_error(rc);
        return EX_FAIL;
    }
    printf("%ld\n", rc);
    return EX_OK;
}

static int cmd_rule_list(void)
{
    static char out[OUT_BUFSIZE];
    long rc;

    if (kpm_send("55568", out, sizeof(out), &rc) != 0) {
        no_channel();
        return EX_FAIL;
    }

    fputs(out, stdout);

    /* The engine returns the number of rules it wrote, or -ENOSPC when they
     * did not all fit.  Either way what is in the buffer is what it managed,
     * and this warning makes the truncation visible in the caller's log. */
    if (rc < 0) {
        warn("listing truncated: the rule set does not fit in %d bytes",
             (int)sizeof(out));
        return EX_TRUNCATED;
    }
    if (rc > 0 && out[0] == '\0')
        warn("engine reported %ld rule(s) but returned no text", rc);
    return EX_OK;
}

static char *read_all_stdin(size_t *lenp)
{
    size_t cap = IN_START, len = 0;
    char *buf = malloc(cap);

    if (!buf) {
        warn("out of memory");
        return NULL;
    }
    for (;;) {
        ssize_t n = read(STDIN_FILENO, buf + len, cap - len - 1);

        if (n < 0) {
            if (errno == EINTR) continue;
            warn("read(stdin): %s", strerror(errno));
            free(buf);
            return NULL;
        }
        if (n == 0) break;
        len += (size_t)n;
        if (len + 1 >= cap) {
            char *nb;

            if (cap >= IN_MAX) {
                warn("input larger than %u bytes, giving up", (unsigned)IN_MAX);
                free(buf);
                return NULL;
            }
            cap *= 2;
            nb = realloc(buf, cap);
            if (!nb) {
                warn("out of memory");
                free(buf);
                return NULL;
            }
            buf = nb;
        }
    }
    buf[len] = '\0';
    *lenp = len;
    return buf;
}

/* Add one rule.  Returns 0 on success, -1 when the engine refused it. */
static int rule_add_one(const char *virt, const char *realp)
{
    char cmd[CMD_BUFSIZE];
    char out[8];
    long rc;
    int n;

    n = snprintf(cmd, sizeof(cmd), "%X|%s|%s", CMD_SUSFS_KPM_DC_RULE_ADD, virt,
                 realp);
    if (n < 0 || (size_t)n >= sizeof(cmd)) {
        warn("rule too long for the control buffer, skipped: %s", virt);
        return -1;
    }
    if (kpm_send(cmd, out, sizeof(out), &rc) != 0) {
        no_channel();
        return -1;
    }
    if (rc != 0) {
        /* One bad rule must not abort the batch: metamount.sh feeds us a whole
         * module set, and the rest of it should still be installed.  The
         * exception is a full table, where the next add would fail too. */
        if (rc == -22) /* EINVAL */
            warn("rejected (not an absolute path, or too long?): %s", virt);
        else if (rc == -28) /* ENOSPC */
            warn("rule table full, stopping at %s", virt);
        else
            warn("rule add failed for %s: %ld (%s)", virt, rc,
                 strerror((int)-rc));
        return -1;
    }
    return 0;
}

static int cmd_rule_add(int argc, char **argv)
{
    char *buf;
    size_t len = 0, i = 0;
    int added = 0, failed = 0;
    int k;

    for (k = 0; k < argc; k++) {
        if (strcmp(argv[k], "--whiteout") == 0) {
            fprintf(stderr,
                    "%s: --whiteout is not supported by the E7 engine (a "
                    "whiteout hides a file, and E7 v1 only adds them)\n",
                    progname);
            fprintf(stderr,
                    "%s: metamount.sh sends whiteout-bearing modules to "
                    "overlayfs instead; refusing rather than mounting a file "
                    "the module wanted gone\n",
                    progname);
            return EX_UNSUPPORTED;
        }
        warn("unknown option: %s", argv[k]);
        return EX_USAGE;
    }

    if (isatty(STDIN_FILENO)) {
        warn("'rule add' reads NUL-separated 'virtual\\0real\\0' records on "
             "stdin; none given");
        return EX_USAGE;
    }

    buf = read_all_stdin(&len);
    if (!buf) return EX_FAIL;

    while (i < len) {
        const char *virt = buf + i, *realp;
        size_t vlen, rlen;

        vlen = strnlen(virt, len - i);
        if (vlen == len - i) { /* no NUL: truncated tail */
            warn("input ends inside a record (%lu byte(s) left over)",
                 (unsigned long)(len - i));
            failed++;
            break;
        }
        i += vlen + 1;
        if (vlen == 0) continue; /* blank record */

        if (i >= len) {
            warn("input ends after a virtual path with no real path: %s", virt);
            failed++;
            break;
        }
        realp = buf + i;
        rlen = strnlen(realp, len - i);
        if (rlen == len - i) {
            warn("input ends inside the real path of %s", virt);
            failed++;
            break;
        }
        i += rlen + 1;
        if (rlen == 0) {
            warn("empty real path for %s, skipped", virt);
            failed++;
            continue;
        }

        if (rule_add_one(virt, realp) == 0)
            added++;
        else
            failed++;
    }

    free(buf);
    printf("rules installed: %d", added);
    if (failed) printf(", failed: %d", failed);
    putchar('\n');
    return failed ? EX_FAIL : EX_OK;
}

static int cmd_raw(int argc, char **argv)
{
    static char out[OUT_BUFSIZE];
    char cmd[CMD_BUFSIZE];
    size_t pos = 0;
    long rc;
    int i;

    if (argc < 1) {
        warn("raw needs a command value, e.g. 'raw 555E1'");
        return EX_USAGE;
    }
    for (i = 0; i < argc; i++) {
        int n = snprintf(cmd + pos, sizeof(cmd) - pos, "%s%s", i ? "|" : "",
                         argv[i]);

        if (n < 0 || (size_t)n >= sizeof(cmd) - pos) {
            warn("raw command too long");
            return EX_USAGE;
        }
        pos += (size_t)n;
    }

    if (kpm_send(cmd, out, sizeof(out), &rc) != 0) {
        no_channel();
        return EX_FAIL;
    }
    if (out[0]) fputs(out, stdout);
    fprintf(stderr, "%s: rc=%ld\n", progname, rc);
    return rc < 0 ? EX_FAIL : EX_OK;
}

int main(int argc, char **argv)
{
    const char *cmd;

    if (argc < 2) {
        usage(stderr);
        return EX_USAGE;
    }
    cmd = argv[1];
    argc -= 2;
    argv += 2;

    if (strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0 ||
        strcmp(cmd, "help") == 0) {
        usage(stdout);
        return EX_OK;
    }
    if (strcmp(cmd, "version") == 0) return cmd_version();
    if (strcmp(cmd, "caps") == 0) return cmd_caps();
    if (strcmp(cmd, "status") == 0) return cmd_status();
    if (strcmp(cmd, "raw") == 0) return cmd_raw(argc, argv);
    if (strcmp(cmd, "rule") == 0) {
        const char *sub = argc >= 1 ? argv[0] : "";

        if (strcmp(sub, "add") == 0) return cmd_rule_add(argc - 1, argv + 1);
        if (strcmp(sub, "clear") == 0) return cmd_rule_clear();
        if (strcmp(sub, "count") == 0) return cmd_rule_count();
        if (strcmp(sub, "list") == 0) return cmd_rule_list();
        warn("unknown 'rule' subcommand: %s", sub[0] ? sub : "(none)");
        usage(stderr);
        return EX_USAGE;
    }

    warn("unknown command: %s", cmd);
    usage(stderr);
    return EX_USAGE;
}
