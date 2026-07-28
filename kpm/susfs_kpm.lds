/* susfs_kpm.lds — linker script for the susfs_kpm KPM.
 *
 * Mirrors AuditPatch-KPM/kpm_audit_patch.lds.  The KernelPatch loader does
 * not apply PLT relocations, so we discard the PLT / init-PLT /
 * ftrace-trampoline sections by marking them NOLOAD with a single padding
 * byte.  The resulting .kpm only carries relocations the in-kernel loader
 * (kernel/patch/module/relo.c) understands.
 */
SECTIONS {
	.plt (NOLOAD) : { BYTE(0) }
	.init.plt (NOLOAD) : { BYTE(0) }
	.text.ftrace_trampoline (NOLOAD) : { BYTE(0) }
}
