/*
 * KSU SEL context-oracle filter  (injected by .github/scripts/apply_sel_context_filter.py)
 *
 * /sys/fs/selinux/context is mode 0666, so any app can write a candidate
 * context string and read the return code: EINVAL means "no such type",
 * any other result means the type exists in the live policy. That is a
 * complete type-existence oracle, and a detector replaying a list of
 * root-related type names uses it to prove that a root solution is
 * installed even when every file and mount is hidden.
 *
 * selinux_hide already filters this through patch_write_op(), but that
 * table (write_op[]) is only consulted by sel_write() on older layouts.
 * On GKI 6.5+ the SEL_CONTEXT inode carries its own file_operations and
 * dispatches sel_context_ops.write -> handle_sel_write_context, so the
 * write_op[] entry is dead code and the oracle stays open.
 *
 * This patches the .write slot of sel_context_ops instead. Only contexts
 * whose type component is a root-related name are answered with -EINVAL;
 * everything else - including the sentinel names a detector writes first
 * to check that the oracle itself has not been tampered with - reaches
 * the original handler unchanged.
 */

typedef ssize_t (*ksu_sel_ctx_write_fn)(struct file *file, const char __user *ubuf, size_t size, loff_t *ppos);

static ksu_sel_ctx_write_fn ksu_sel_ctx_write_orig;
static unsigned long *ksu_sel_ctx_write_slot;

/* Matched as a whole type component, or as the prefix of one followed by
 * '_' -- so "su" covers su/su_file but never surfaceflinger. */
static const char *const ksu_sel_ctx_hidden_roots[] = {
    "ksu", "su", "magisk", "xposed", "lsposed", "kernelsu",
    "apatch", "kernelpatch", "kpm", "susfs", "ksu_susfs",
    NULL,
};

static bool ksu_sel_ctx_type_is_hidden(const char *s, size_t len)
{
    const char *p, *end = s + len, *type = NULL, *type_end;
    size_t tlen;
    int i, colons = 0;

    /* user:role:type[:mls] -- the type is the field after the 2nd colon */
    for (p = s; p < end; p++) {
        if (*p != ':')
            continue;
        if (++colons == 2) {
            type = p + 1;
            break;
        }
    }
    if (colons != 2 || !type)
        return false;

    for (type_end = type; type_end < end && *type_end != ':'; type_end++)
        ;
    tlen = (size_t)(type_end - type);
    if (!tlen)
        return false;

    for (i = 0; ksu_sel_ctx_hidden_roots[i]; i++) {
        const char *root = ksu_sel_ctx_hidden_roots[i];
        size_t rlen = strlen(root);

        if (tlen < rlen || strncmp(type, root, rlen))
            continue;
        if (tlen == rlen || type[rlen] == '_')
            return true;
    }
    return false;
}

static ssize_t ksu_sel_ctx_write_hook(struct file *file, const char __user *ubuf, size_t size, loff_t *ppos)
{
    char tmp[256];

    /* Root and below keep the stock behaviour: only app uids are probing. */
    if (likely(!size || size >= sizeof(tmp) || current_uid().val < 10000))
        return ksu_sel_ctx_write_orig(file, ubuf, size, ppos);

    if (copy_from_user(tmp, ubuf, size))
        return ksu_sel_ctx_write_orig(file, ubuf, size, ppos);

    if (ksu_sel_ctx_type_is_hidden(tmp, size)) {
        pr_info_ratelimited("selinux_hide: blocked a root-context probe\n");
        return -EINVAL;
    }
    return ksu_sel_ctx_write_orig(file, ubuf, size, ppos);
}

static int ksu_sel_ctx_patch(void)
{
    void **ops;
    unsigned long target, page;
    unsigned long *slot = NULL;
    int i, ret;

    if (ksu_sel_ctx_write_slot)
        return 0;

    ops = (void **)find_kernel_symbol_exact("sel_context_ops");
    if (!ops) {
        pr_warn("selinux_hide: sel_context_ops not in kallsyms, context oracle stays open\n");
        return -ENOENT;
    }

    target = find_kernel_symbol_exact("handle_sel_write_context");
    if (!target)
        target = find_kernel_symbol_exact("sel_write_context");
    if (!target) {
        pr_warn("selinux_hide: sel_write_context not found, refusing to patch\n");
        return -ENOENT;
    }

    /* struct file_operations is ~30 pointers; stay inside the object. */
    for (i = 0; i < 32; i++) {
        if ((unsigned long)ops[i] == target) {
            slot = (unsigned long *)&ops[i];
            break;
        }
    }
    if (!slot) {
        pr_warn("selinux_hide: no .write slot in sel_context_ops, refusing to patch\n");
        return -ENOENT;
    }

    page = (unsigned long)slot & PAGE_MASK;
    ret = set_memory_rw(page, 1);
    if (ret) {
        pr_err("selinux_hide: set_memory_rw failed (%d), context oracle stays open\n", ret);
        return ret;
    }
    ksu_sel_ctx_write_orig = (ksu_sel_ctx_write_fn)target;
    WRITE_ONCE(*slot, (unsigned long)ksu_sel_ctx_write_hook);
    set_memory_ro(page, 1);
    ksu_sel_ctx_write_slot = slot;
    pr_info("selinux_hide: sel_context_ops.write hooked (orig %pS)\n", ksu_sel_ctx_write_orig);
    return 0;
}
