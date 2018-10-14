/* ###################################################################################
 *
 *  expandpwd.c - pppd用户密码获取扩展,调用外部程序获取pap和chap认证密码
 *
 *  Copyright 2018 Reamyx Liou, Xi'an China.
 *
 *  本程序拦截常规pap和chap认证过程,调用外部过程并从标准输出获取认证凭据,同步调用并提
 *  供用户名称作为参考信息,外部过程返回0表示其标准输出首行提供的内容为有效密码数据且次
 *  行为描述字串,否则表示未能提供相关账户的有效凭据,此时标准输出首行为错误描述内容.
 *  插件本身仅执行密码验证过程,账户有效性管理可通过外部过程完成.用户凭据可以是任意可打
 *  印字符序列,由凭据检查过程解释其表意.
 * ################################################################################ */

#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <syslog.h>
#include <string.h>
#include "pppd.h"
#include "chap-new.h"

// 返回密码串缓冲区大小
#define BFSIZE 256
#define IDSIZE 16

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

// ipparam将传递给扩展程序做参考
extern char *ipparam;

// 外部过程的输出内容存储到全局变量pwbuff,extcrdl和extdesc分别指示凭据信息和描述信息
static char pwbuff[BFSIZE+1], *extdesc;

// 凭据提取过程,返回值为非0时指示目标凭据有效,0则无效或过程异常
static char getpwd(char *path, char *method,
    char *user, char *challenge, char *pwresp, char *ipparam) {
	// 重置数据缓存
	memset(pwbuff, 0, BFSIZE+1); extdesc = pwbuff + BFSIZE
	
	int p[2], kid, kst, readbytes = 0, readok = 0; char *sp, mypid[IDSIZE+1];
	
	// 路径配置错误(未配置路径或目标不可执行)
	if (path[0] == 0 || access(path, X_OK) < 0) {
		error("External program path config error: %s", path); return 0; }
	// 管道资源错误
	if (pipe(p)) {error("Fail to create a pipe for %s", path); return 0; }
	
	// 获取当前进程PID的字符串形式准备传递到脚本
	memset(mypid, 0, IDSIZE+1); sprintf(mypid, "%d", getpid());
	
	// FORK子进程失败
	if ((kid = fork()) < 0) {
		error("Fail to fork to run %s", path);
		close(p[0]); close(p[1]); return 0; }
    
	// 子进程: 执行外部程序并通过父进程的读取管道提供目标数据
	if (!kid) {
		// 相关资源初始化,重定向标准输出,
		close(p[0]); sys_close(); closelog(); seteuid(getuid()); setegid(getgid());
		if(dup2(p[1], 1) < 0) _exit(126); close(p[1]);
		// 配置参数并运行程序: 用户名称 用户提供的密码或摘要 主进程PID ipparam
		char *argv[8]; argv[0] = path; argv[1] = method; argv[2] = user;
        argv[3] = challenge; argv[4] = pwresp; argv[5] = ipparam; argv[6] = mypid; argv[7] = NULL;
		execv(path, argv); _exit(127); }
    
	// 主程序: 从管道读取外部程序的标准输出,首行明文密码,次行描述信息
	close(p[1]);
	while (readbytes = read(p[0], pwbuff + readok, BFSIZE - readok)) {
		if (readbytes < 0) if (errno == EINTR) readbytes = 0;
        else { error("Can't read secret from %s: %m", path); return 0; }
		readok += readbytes; }
    close(p[0]); pwbuff[BFSIZE] = '\0';
    
    // 等待子进程终止并获取退出状态码
    while (waitpid(kid, &kst, 0) < 0)
		if (errno != EINTR) { error("error waiting for %s: %m", path); return 0; }
	// 子程序返回非0时返回错误
	if (kst) { error("The passwod provider program exit whit code: %d", kst); return 0; }
	
	// 成功获取密码数据时进行字串分离('\n'转换为'\0)
	while (sp = memchr(pwbuff, '\n', BFSIZE)) *sp = '\0';
	if ((sp = pwbuff + strlen(pwbuff) + 1) < extdesc) extdesc = sp; return 1; }
	
    
// pap认证检查过程 返回值: 1成功 0失败 -1常规pap-secrets检查, 凭据表意明文文本密码
static int pppd_pap_auth(char *user, char *passwd, char **msgp, 
	struct wordlist **paddrs, struct wordlist **popts) {
	// 提取密码成功时执行验证
	return getpwd(pwdprovider, "PAP", user, "", passwd, ipparam) && strcmp(passwd, pwbuff) == 0; }
	
// chap认证检查过程 返回值: 1成功 0失败
static int pppd_chap_verify(char *user, char *ourname, int id,
	struct chap_digest_type *digest,unsigned char *challenge,
	unsigned char *response, char *message, int message_space) {
	// 提取密码成功时执行验证
	return getpwd(pwdprovider, "CHAP", user, challenge, response, ipparam) && digest->verify_response(
    id, user, pwbuff, strlen(pwbuff), challenge, response, message, message_space); }


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




