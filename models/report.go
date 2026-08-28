package models

import "talaria/scanners"

type ScanReport struct {
	ScanTime           string                             `json:"scan_time"`
	TargetUser         string                             `json:"target_user"`
	TargetScanPath     string                             `json:"target_scan_path"`
	StealthMode        bool                               `json:"stealth_mode"`
	Secrets            []scanners.SensitiveFileResult     `json:"secrets,omitempty"`
	SecretContent      []scanners.SensitiveContentResult  `json:"secret_content,omitempty"`
	Capabilities       []scanners.CapabilityResult        `json:"capabilities,omitempty"`
	CronJobs           []scanners.CronJobResult           `json:"cron_jobs,omitempty"`
	FilePermissions    []scanners.FilePermissionResult    `json:"file_permissions,omitempty"`
	FilePermsExploit   []scanners.FilePermExploitResult   `json:"file_perms_exploit,omitempty"`
	NetworkConnections []scanners.NetworkConnectionResult `json:"network_connections,omitempty"`
	NFSExports         []scanners.NFSExportResult         `json:"nfs_exports,omitempty"`
	Processes          []scanners.ProcessResult           `json:"processes,omitempty"`
	Sockets            []scanners.SocketResult            `json:"sockets,omitempty"`
	SudoPrivileges     []scanners.SudoPrivilegeResult     `json:"sudo_privileges,omitempty"`
	SUID               []scanners.SUIDResult              `json:"suid,omitempty"`
	SGID               []scanners.SGIDResult              `json:"sgid,omitempty"`
	Vulnerabilities    []scanners.VersionInfo             `json:"vulnerabilities,omitempty"`
	Writeable          []scanners.WriteableResult         `json:"writeable,omitempty"`
	SystemdTimers      []scanners.SystemdTimerResult      `json:"systemd_timers,omitempty"`
	Groups             []scanners.GroupResult             `json:"groups,omitempty"`
	PATHHijack         []scanners.PATHHijackResult        `json:"path_hijack,omitempty"`
	SSHKeys            []scanners.SSHKeyResult            `json:"ssh_keys,omitempty"`
	PtraceScope        *scanners.PtraceScopeResult        `json:"ptrace_scope,omitempty"`
	ContainerEscape    []scanners.ContainerEscapeResult   `json:"container_escape,omitempty"`
	DBusPolicy         []scanners.DBusPolicyResult        `json:"dbus_policy,omitempty"`
	Services           []scanners.ServiceAuditResult      `json:"services,omitempty"`
	Packages           []scanners.PackageAuditResult      `json:"packages,omitempty"`
	SessionHijack      []scanners.SessionHijackResult     `json:"session_hijack,omitempty"`
	KernelConfig       []scanners.KernelConfigResult      `json:"kernel_config,omitempty"`
	PolkitRules        []scanners.PolkitRuleResult        `json:"polkit_rules,omitempty"`
	HistorySecrets     []scanners.HistorySecretResult     `json:"history_secrets,omitempty"`
	XAuthority         []scanners.XAuthorityResult        `json:"xauthority,omitempty"`
	Logrotate          []scanners.LogrotateResult         `json:"logrotate,omitempty"`
	EnvFileResults     []scanners.EnvFileResult           `json:"env_file_results,omitempty"`
	PAMResults         []scanners.PAMResult               `json:"pam_results,omitempty"`
	SysctlResults      []scanners.SysctlResult            `json:"sysctl_results,omitempty"`
	SystemdOverrides   []scanners.SystemdOverrideResult   `json:"systemd_overrides,omitempty"`
	SubUIDResults      []scanners.SubUIDResult            `json:"subuid_results,omitempty"`
	MountResults       []scanners.MountResult             `json:"mount_results,omitempty"`
	ELFRPathResults    []scanners.ELFRPathResult          `json:"elf_rpath_results,omitempty"`
	AuditdResults      []scanners.AuditdResult            `json:"auditd_results,omitempty"`
	UdevResults        []scanners.UdevResult              `json:"udev_results,omitempty"`
	CronDirResults     []scanners.CronDirResult           `json:"cron_dir_results,omitempty"`
	ProcEnvResults     []scanners.ProcEnvResult           `json:"proc_env_results,omitempty"`
	LDNSSResults       []scanners.LDNSSResult             `json:"ld_nss_results,omitempty"`
	ModprobeResults    []scanners.ModprobeResult          `json:"modprobe_results,omitempty"`
	CloudMetaResults   []scanners.CloudMetaResult         `json:"cloud_meta_results,omitempty"`
	VenvWrapResults    []scanners.VenvWrapResult          `json:"venv_wrap_results,omitempty"`
}