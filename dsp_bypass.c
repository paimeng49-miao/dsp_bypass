/*
 * dsp_bypass — APatch / KernelPatch KPM that masks root-framework
 * sepolicy rules from userspace SELinux probes (e.g. DirtySepolicy).
 *
 * It wraps security_compute_av_user, the kernel path behind
 * SELinux.checkSELinuxAccess() / writes to /sys/fs/selinux/access, and
 * zeroes avd->allowed for queries that target a "dirty" SID or match a
 * known dirty (scon, tcon) pair. In-kernel AVC checks via
 * security_compute_av are untouched, so the root framework itself keeps
 * working.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <compiler.h>
#include <kpmodule.h>
#include <kallsyms.h>
#include <hook.h>
#include <log.h>
#include <linux/string.h>
#include <linux/gfp.h>
#include <uapi/asm-generic/errno.h>

KPM_NAME("dsp_bypass");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Cvm");
KPM_DESCRIPTION("Hide root sepolicy rules from userspace SELinux probes");

/* KP's gfp.h leaves these undefined (value varies by kernel). 0xcc0
 * matches modern AOSP GKI: __GFP_RECLAIM | __GFP_IO | __GFP_FS. */
#ifndef GFP_KERNEL
#define GFP_KERNEL ((gfp_t)0xcc0u)
#endif

/* ---- editable tables --------------------------------------------------- */

/* Targets whose mere appearance in a query is suspicious. */
static const char * const dirty_targets[] = {
    /* Magisk */
    "u:r:magisk:s0", "u:r:magisk_client:s0",
    "u:object_r:magisk_file:s0", "u:object_r:magisk_exec:s0",
    /* KernelSU */
    "u:r:ksu:s0", "u:r:su:s0",
    "u:object_r:ksu_exec:s0", "u:object_r:ksu_file:s0",
    /* APatch */
    "u:r:apatch:s0", "u:r:apatch_lite:s0",
    "u:object_r:apatch_exec:s0", "u:object_r:apatch_file:s0",
    /* LSPosed / Xposed */
    "u:object_r:lsposed_file:s0", "u:object_r:xposed_data:s0",
    /* adb_root */
    "u:r:adbroot:s0",
    0
};

/* (scon, tcon) pairs that are dirty only as a combination — both endpoints
 * are legitimate AOSP types, but the allow rule itself shouldn't exist. */
static const struct { const char *s, *t; } dirty_pairs_cfg[] = {
    { "u:r:zygote:s0",         "u:object_r:adb_data_file:s0" }, /* ZygiskNext */
    { "u:r:system_server:s0",  "u:r:system_server:s0"        }, /* execmem neverallow */
    { "u:r:fsck_untrusted:s0", "u:r:fsck_untrusted:s0"       }, /* sys_admin neverallow */
    { 0, 0 }
};

/* ---- kernel ABI we touch ----------------------------------------------- */

/*
 * security_compute_av_user, security_context_to_sid and avc_ss_reset all
 * gained a `struct selinux_state *` first argument in 5.0 and lost it
 * again in 6.6. We detect that ABI by probing for the `selinux_state`
 * global symbol — it only exists when the parameter does.
 */
struct av_decision_compat {
    uint32_t allowed, auditallow, auditdeny, seqno, flags;
};

typedef int (*ctx_to_sid_4_t)(const char *, uint32_t, uint32_t *, gfp_t);
typedef int (*ctx_to_sid_5_t)(void *, const char *, uint32_t, uint32_t *, gfp_t);
typedef int (*avc_reset_1_t)(uint32_t);

/* ---- module state ------------------------------------------------------ */

#define MAX_TARGETS 64
#define MAX_PAIRS   16

static void *fn_ctx_to_sid, *fn_avc_reset, *selinux_state_p;
static void *fn_compute_av_user, *fn_load_policy;
static int   has_state;

static uint32_t dirty_target_sids[MAX_TARGETS];
static int      dirty_target_count;

static struct { uint32_t s, t; } dirty_pair_sids[MAX_PAIRS];
static int      dirty_pair_count;

static int      cache_ready;

/* ---- SID resolution ---------------------------------------------------- */

static int ctx_to_sid(const char *ctx, uint32_t *out)
{
    if (!fn_ctx_to_sid)
        return -1;
    if (has_state)
        return ((ctx_to_sid_5_t)fn_ctx_to_sid)(selinux_state_p, ctx, strlen(ctx), out, GFP_KERNEL);
    return ((ctx_to_sid_4_t)fn_ctx_to_sid)(ctx, strlen(ctx), out, GFP_KERNEL);
}

static void resolve_sids(void)
{
    uint32_t s, t;
    int i, n = 0, p = 0;

    for (i = 0; dirty_targets[i] && n < MAX_TARGETS; i++)
        if (ctx_to_sid(dirty_targets[i], &t) == 0 && t)
            dirty_target_sids[n++] = t;
    dirty_target_count = n;

    for (i = 0; dirty_pairs_cfg[i].s && p < MAX_PAIRS; i++)
        if (ctx_to_sid(dirty_pairs_cfg[i].s, &s) == 0 && s &&
            ctx_to_sid(dirty_pairs_cfg[i].t, &t) == 0 && t) {
            dirty_pair_sids[p].s = s;
            dirty_pair_sids[p].t = t;
            p++;
        }
    dirty_pair_count = p;
    cache_ready = (n || p);

    logkd("dsp_bypass: cached %d targets, %d pairs\n", n, p);

    /* In the state-passing era avc_ss_reset takes (avc, seqno); we'd
     * have to guess the field offset, so skip it there. Stale 'allow'
     * decisions age out of the AVC within seconds anyway. */
    if (!has_state && fn_avc_reset)
        ((avc_reset_1_t)fn_avc_reset)(0);
}

/* ---- hot path ---------------------------------------------------------- */

static int scrub(uint32_t ssid, uint32_t tsid, struct av_decision_compat *avd)
{
    int i;
    if (!cache_ready || !avd)
        return 0;
    for (i = 0; i < dirty_target_count; i++)
        if (tsid == dirty_target_sids[i])
            goto hit;
    for (i = 0; i < dirty_pair_count; i++)
        if (ssid == dirty_pair_sids[i].s && tsid == dirty_pair_sids[i].t)
            goto hit;
    return 0;
hit:
    avd->allowed = avd->auditallow = 0;
    avd->auditdeny = ~0u;
    logkd("dsp_bypass: scrubbed ssid=%u tsid=%u\n", ssid, tsid);
    return 1;
}

/* 4-arg: (ssid, tsid, tclass, avd) */
static void post_compute_av_4(hook_fargs4_t *f, void *ud)
{
    scrub((uint32_t)f->arg0, (uint32_t)f->arg1,
          (struct av_decision_compat *)(uintptr_t)f->arg3);
}

/* 5-arg: (state, ssid, tsid, tclass, avd) — fargs5_t aliases fargs8_t */
static void post_compute_av_5(hook_fargs8_t *f, void *ud)
{
    scrub((uint32_t)f->arg1, (uint32_t)f->arg2,
          (struct av_decision_compat *)(uintptr_t)f->arg4);
}

static void post_load_policy(hook_fargs2_t *f, void *ud)
{
    if ((long)f->ret == 0)
        resolve_sids();
}

/* ---- entry points ------------------------------------------------------ */

static long dsp_init(const char *args, const char *event, void *__user reserved)
{
    hook_err_t err;

    selinux_state_p = (void *)kallsyms_lookup_name("selinux_state");
    has_state       = selinux_state_p != 0;

    fn_ctx_to_sid      = (void *)kallsyms_lookup_name("security_context_to_sid");
    fn_compute_av_user = (void *)kallsyms_lookup_name("security_compute_av_user");
    fn_avc_reset       = (void *)kallsyms_lookup_name("avc_ss_reset");
    fn_load_policy     = (void *)kallsyms_lookup_name("security_load_policy");
    if (!fn_load_policy)
        fn_load_policy = (void *)kallsyms_lookup_name("selinux_policy_load");

    if (!fn_ctx_to_sid || !fn_compute_av_user) {
        logkd("dsp_bypass: missing kernel symbols\n");
        return -ENOENT;
    }

    logkd("dsp_bypass: ABI=%s\n", has_state ? "5.0-6.5" : "<5.0 || >=6.6");
    resolve_sids();

    err = has_state
        ? hook_wrap5(fn_compute_av_user, 0, post_compute_av_5, 0)
        : hook_wrap4(fn_compute_av_user, 0, post_compute_av_4, 0);
    if (err) {
        logkd("dsp_bypass: hook(compute_av_user) failed: %d\n", err);
        return -EFAULT;
    }

    if (fn_load_policy)
        hook_wrap2(fn_load_policy, 0, post_load_policy, 0);

    return 0;
}

/* `apd module control dsp_bypass <anything>` re-resolves SIDs — handy
 * after pushing extra rules at runtime. */
static long dsp_ctl0(const char *args, char *__user out, int outlen)
{
    resolve_sids();
    return 0;
}

static long dsp_exit(void *__user reserved)
{
    if (fn_compute_av_user) unhook(fn_compute_av_user);
    if (fn_load_policy)     unhook(fn_load_policy);
    return 0;
}

KPM_INIT(dsp_init);
KPM_CTL0(dsp_ctl0);
KPM_EXIT(dsp_exit);
