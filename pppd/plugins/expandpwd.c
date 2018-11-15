/* ###################################################################################
 *
 *  expandpwd.c - pppd用户密码获取扩展,调用外部程序获取pap和chap认证密码
 *
 *  Copyright 2018 Reamyx Liou, Xi'an China.
 *
 *  本程序拦截常规pap和chap认证过程,调用外部程序并从标准输出获取认证密码用于对端认证,
 *  外部程序被同步调用并提供用户名称等作为参考信息,外部过程返回非0表示指定的账户名称
 *  无效或无法提供有效密码信息,这将直接导致认证失败,否则表示其标准输出首行提供的内容
 *  为有效密码数据且次行为描述字串,外部密码获取程序本身只需提供密码信息,认证操作将由
 *  插件完成.
 *
 * ################################################################################ */

#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <syslog.h>
#include <string.h>
#include "pppd.h"
#include "chap-new.h"

// 返回密码串缓冲区大小
#define BFSIZE 255
#define PMSIZE 1023
#define UUIDSZ 39
#define UUIDFL "/proc/sys/kernel/random/uuid"
#define UUIDCM "uuidgen"

// 插件适用版本说明
char pppd_version[] = VERSION;

// 选项定义: pwdprovider,提供凭据信息的外部程序路径
static char pwdprovider[PATH_MAX+1];
static option_t provider_options[] = {
    { "pwdprovider", o_string, pwdprovider,
      "External passwod provider program.",
      OPT_STATIC, NULL, PATH_MAX },
    { NULL }
};

// ipparam将传递给扩展程序
extern char *ipparam, our_name[MAXNAMELEN];

char *get_ssuuid(char *, size_t);

// 外部过程的输出内容存储到*pwbuff,其与extdesc分别指示密码和描述串
// asessid为用于关联认证和IPCP脚本的会话ID,uuidfl,uuidgen指示UUID生成相关文件或命令
static char pwbuff[BFSIZE+1], *extdesc, asessid[UUIDSZ+1], ssidinit = 1;

// 凭据提取过程,返回值为非0时指示目标凭据有效,0则无效或过程异常
static char getpwd(char *path, char *method, char *user, char *peerpwd, char *ipparam) {
	int p[2], kid, kst, readbytes = 0, readok = 0
    char *sp, *parm[PMSIZE+1], *argv[3]; void (*khd)(int) = NULL;
	// 重置数据缓存
	memset(pwbuff, '\0', sizeof(pwbuff)); extdesc = pwbuff + BFSIZE;	
	memset(parm,  '\0', sizeof(parm));
    //初始化会话ID,配置脚本环境变量,仅首次配置即可 script_unsetenv("SESS_UUID");
    if (ssidinit) {
        get_ssuuid(asessid, sizeof(asessid));
        script_setenv("SRV_NAME", our_name, 0);
        script_setenv("SESS_UUID", asessid, 0); ssidinit = 0; }
	// 路径配置错误(未配置路径或目标不可执行),管道资源错误
	if (path[0] == 0 || access(path, X_OK) < 0) {
		error("External program path config error: %s", path); return 0; }
	if (pipe(p)) { error("Fail to create a pipe for %s", path); return 0; }
	// FORK子进程
    khd = signal(SIGCHLD, SIG_DFL);
	if ((kid = fork()) < 0) {
		error("Fail to fork to run %s", path); close(p[0]); close(p[1]); return 0; }
	// 子进程: 执行外部程序并通过父进程的读取管道提供目标数据
	if (!kid) {
		close(p[0]); sys_close(); closelog(); seteuid(getuid()); setegid(getgid());
		if(dup2(p[1], 1) < 0) _exit(126); close(p[1]);
		// 构造JSON格式的参数递交至外部程序
        snprintf(parm, sizeof(parm),
            "{ %s%s%s, %s%s%s, %s%s%s, %s%s%s, %s%u%s, %s%s%s, %s%s%s }",
            "\"method\": \"",    method,    "\"",
            "\"usercnm\": \"",   user,      "\"",
            "\"usercpw\": \"",   peerpwd,   "\"",
            "\"ipparm\": \"",    ipparam,   "\"",
            "\"srvpid\": \"",    getpid(),  "\"",
            "\"asessid\": \"",   asessid,   "\"",
            "\"srvname\": \"",   our_name,  "\"");
		argv[0] = path; argv[1] = parm; argv[2] = NULL;
		execv(path, argv); _exit(127); }
	// 主程序: 从管道读取外部程序的标准输出,首行明文密码,次行描述信息
	close(p[1]);
	while (readbytes = read(p[0], pwbuff + readok, BFSIZE - readok)) {
		if (readbytes < 0) if (errno == EINTR) readbytes = 0;
        else { error("Can't read secret from stdout of %s.", path); return 0; }
		readok += readbytes; }
    close(p[0]); pwbuff[BFSIZE] = '\0';
    // 等待子进程终止并获取退出状态码
    while (waitpid(kid, &kst, 0) < 0)
		if (errno != EINTR) { error("Error waiting for %s.", path); return 0; }
    signal(SIGCHLD, khd);
	// 子程序异常终止或返回非0时返回错误
	if (WIFSIGNALED(kst)) {
        error("Expand program exception terminated with singnal %u", WTERMSIG(status)); return 0; }
    if (WEXITSTATUS(kst)) {
        error("Expand program exit whit code: %u", WEXITSTATUS(kst)); return 0; }
	// 成功获取密码数据时进行字串分离('\n'转换为'\0)
	while (sp = memchr(pwbuff, '\n', BFSIZE)) *sp = '\0';
	if ((sp = pwbuff + strlen(pwbuff) + 1) < extdesc) extdesc = sp; return 1; }
	
// pap认证检查过程 返回值: 1成功 0失败 -1常规pap-secrets检查, 凭据表意明文文本密码
static int pppd_pap_auth(char *user, char *passwd, char **msgp, 
	struct wordlist **paddrs, struct wordlist **popts) {
	// 提取密码成功时执行验证
	return getpwd(pwdprovider, "PAP", user, passwd, ipparam) && strcmp(passwd, pwbuff) == 0; }
	
// chap认证检查过程 返回值: 1成功 0失败
static int pppd_chap_verify(char *user, char *ourname, int id,
	struct chap_digest_type *digest,unsigned char *challenge,
	unsigned char *response, char *message, int message_space) {
	// 提取密码成功时执行验证
	return getpwd(pwdprovider, "CHAP", user, "", ipparam) && digest->verify_response(
    id, user, pwbuff, strlen(pwbuff), challenge, response, message, message_space); }

    
// 使用linux提供的功能生成UUID字串并格式化,失败时返回NULL
char *get_ssuuid(char *bfp, size_t bflen) {
    char *sp, *tp, *mp = bfp, uuid[UUIDSZ+1], uuidfl[] = UUIDFL, uuidcm[]= UUIDCM;
    FILE *fp, *knl; memset(uuid, '\0', sizeof(uuid)); memset(bfp, '\0', bflen);
    // 尝试读取kernel相关文件或执行系统命令生成UUID串
    if ((knl = fp = fopen(uuidfl, "r")) || (fp = popen(uuidcm, "r"))) {
        fgets(uuid, sizeof(uuid), fp); knl ? fclose(fp) : pclose(fp); }
    // 执行字串格式化后作为ppp连接会话ID安全复制到缓存区
    while (sp = memchr(uuid, '\n', sizeof(uuid))) *sp = '\0';
    while (sp = memchr(uuid, '-',  sizeof(uuid))) *sp = '\0';
    for (sp = uuid, tp = uuid + sizeof(uuid); sp++; sp < tp) {
        if (*sp == '\0') continue; if (mp >= bfp + bflen) break; *mp++ = *sp; }
    *(bfp+bflen-1) = '\0'; return *bfp ? bfp : NULL; }

// ###################################################################################


// 返回对端pap认证确认 1认证 0不认证 -1常规pap-secrets文件认证
static int pppd_pap_check(void) { return 1; }

// 返回对端chap认证确认 1认证 0不认证 -1常规chap-secrets文件认证
static int pppd_chap_check(void) { return 1; }

// 返回对端地址确认: 1允许 0拒绝 -1常规处理
static int check_address_allowed(unsigned int addr) { return 1; }

// 插件: 功能注册
void plugin_init(void) {
	//选项注册,返回时选项值并未完成解析,将在此后某个阶段执行解析
	add_options(provider_options);
	//PAP认证注册
	pap_check_hook = pppd_pap_check;
	pap_auth_hook = pppd_pap_auth;
	//CHAP认证注册
	chap_check_hook = pppd_chap_check;
	chap_verify_hook = pppd_chap_verify;
	//地址配置确认
	allowed_address_hook = check_address_allowed; }

