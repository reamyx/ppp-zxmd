/* ###################################################################################
 *
 *  extparam.c - pppd脚本扩展参数选项提供插件
 *
 *  Copyright 2017 Reamyx Liou, Xi'an China.
 *
 *  本程序从选项文件或命令行读取特定字串内容并配置到PPPD脚本运行环境变量
 * ################################################################################ */

//	gcc  -fPIC -c -O envset.c
//  gcc -shared -o envset.so envset.o

#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <syslog.h>
#include <string.h>
#include "pppd.h"

// 长度256
#define ENVLEN 256

// 插件适用版本说明
char pppd_version[] = VERSION;

// 选项定义: extparam
static char extparam[ENVLEN + 1];
static option_t extoptions[] = {
    { "extparam", o_string, extparam,
      "Configure envionment variables EXTPARAM to external script.",
      OPT_STATIC, NULL, ENVLEN },
    { NULL }
};


//###################################################################################

//变量值初始化
static void init_option_var() { memset(extparam,  0, ENVLEN + 1); }

//加入环境变量到脚本
static void set_to_script() {
	if(extparam[0])  script_setenv("EXTPARAM",  extparam,  0); }

// 插件注册
void plugin_init(void) {
	init_option_var();
	add_options(extoptions);
	set_to_script(); }
    
//###################################################################################
