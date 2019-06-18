
// exfuncpy.c - Hook点pyhton3转换插件
// Copyright 2019 Reamyx Liou, Xi'an in China.
// 本插件构造适用参数并转换pppd插件部分回调(包括Hook和notify)到python3过程调用
// 除回调过程规定的参数外,插件还将封装其它适用的数据结构和过程到默认参数表尾部


#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <ctype.h>
#include <python3.7m/Python.h>

#include "pppd.h"
#include "chap-new.h"

static void notify_callpy(void *, int);

// 插件适用版本
char pppd_version[] = VERSION;

// 选项exfuncpy_options指定将要导入的python3模块文件路径
static char modulepath [PATH_MAX+1];
static option_t exfuncpy_options[] = {
    { "pymodulepath", o_string, modulepath,
      "External python model-file path.",
      OPT_STATIC, NULL, PATH_MAX },
    { NULL } };

// 名称和计数
wchar_t *PyProName = L"pppdextpy";

// 命名过程指针
static PyObject
    *extpy_init_func,
    //*idle_time_func,
    //*holdoff_func,
    *pap_check_func,
    //*pap_passwd_func,
    *pap_auth_func,
    *chap_check_func,
    //*chap_passwd_func,
    *chap_verify_func,
    //*null_auth_func,
    //*ip_choose_func,
    *allowed_address_func,
    //*snoop_recv_func,
    //*snoop_send_func,
    //*multilink_join_func,
    *M, *AL;

// pppd通知链"名称"映射表
static struct{
    char              *name;
    struct notifier  **chp;
    PyObject          *ncb;
    } ntmap[] = {
        //{"ncb_pidchange",         &pidchange,          NULL},
        //{"ncb_phasechange",       &phasechange,        NULL},
        {"ncb_exitnotify",          &exitnotify,         NULL},
        {"ncb_sigreceived",         &sigreceived,        NULL},
        {"ncb_ip_up_notifier",      &ip_up_notifier,     NULL},
        {"ncb_ip_down_notifier",    &ip_down_notifier,   NULL},
        {"ncb_auth_up_notifier",    &auth_up_notifier,   NULL},
        //{"ncb_link_down_notifier",&link_down_notifier, NULL},
        //{"ncb_vfork_notifier",    &fork_notifier,      NULL},
        {NULL}};

// python环境初始化和回调导出
static void py_env_init() {
    // 设置环境中程序名称,初始化(反初始化: Py_Finalize();)
    Py_SetProgramName(PyProName); 
    if(!Py_IsInitialized())Py_Initialize();
    
    // 导入目标模块,需要修正模块路径参数
    M = PyImport_Import(PyString_FromString(modulepath));
    
    // 从目标模块导出通知回调过程
    for(int i=0;ntmap[i].name;i++){
        ntmap[i].ncb = PyObject_GetAttrString(M, ntmap[i].name);}
    
    // 从目标模块导出HOOK回调过程
    //idle_time_func     = PyObject_GetAttrString(M, "idle_time"      );
    //holdoff_func       = PyObject_GetAttrString(M, "holdoff"        );
    pap_check_func       = PyObject_GetAttrString(M, "pap_check"      );
    //pap_passwd_func    = PyObject_GetAttrString(M, "pap_passwd"     );
    pap_auth_func        = PyObject_GetAttrString(M, "pap_auth"       );
    chap_check_func      = PyObject_GetAttrString(M, "chap_check"     );
    //chap_passwd_func   = PyObject_GetAttrString(M, "chap_passwd"    );
    chap_verify_func     = PyObject_GetAttrString(M, "chap_verify"    );
    //null_auth_func     = PyObject_GetAttrString(M, "null_auth"      );
    //ip_choose_func     = PyObject_GetAttrString(M, "ip_choose"      );
    allowed_address_func = PyObject_GetAttrString(M, "allowed_address");
    //snoop_recv_func    = PyObject_GetAttrString(M, "snoop_recv"     );
    //snoop_send_func    = PyObject_GetAttrString(M, "snoop_send"     );
    //multilink_join_func= PyObject_GetAttrString(M, "multilink_join" );
    extpy_init_func      = PyObject_GetAttrString(M, "extpy_init"     );}

// 初始化回调,传入pppd本地名称our_name和ipparm
static void extpy_init_callpy(){
    if(!extpy_init_func)return;
    PyObject *args;
    args = PyTuple_New(2);
    PyTuple_SetItem(args,0, PyString_FromString(our_name));
    PyTuple_SetItem(args,1, PyString_FromString(ipparam));
    PyObject_CallObject(extpy_init_func, args);}


// 通知注册
static void notify_callback_reg() {
    for(int i=0;ntmap[i].name;i++){
    if(ntmap[i].ncb)
    add_notifier(ntmap[i].chp, notify_callpy, (void*)(ntmap[i].ncb));}}

// 通知回调: 根据注册时邦定的回调对象ncb确定具体回调方法
static void notify_callpy(void *ncb, int IntArg){
    PyObject *args;
    for(int i=0;ntmap[i].name;i++){
        if((void*)(ntmap[i].ncb)!=ncb)continue;
        args = PyTuple_New(1);
        PyTuple_SetItem(args,0, PyLong_FromLong(IntArg));
        PyObject_CallObject(pap_check_func, args);
        break;}}

// 对端pap认证指示,返回: 1认证 0不认证 -1常规pap-secrets文件认证
static int pap_check_callpy(void) {
    return pap_check_func ?
    PyLong_AsLong(PyObject_CallObject(pap_check_func, NULL)) : -1; }

// pap认证检查过程 返回: 1成功 0失败 -1常规pap-secrets检查
static int pap_auth_callpy(char *user, char *passwd,
    char **msgp, struct wordlist **paddrs, struct wordlist **popts) {
    
    if(!pap_auth_func)return -1;
    
    struct wordlist *wtp;
    PyObject *args, *res, *msg, *addrs, *opts;

    // 构造调用参数msg列表用于回写
    msg = PyList_New(0);
    PyList_Append(msg, PyString_FromString(*msgp));

    // 构造调用参数addrs列表用于回写
    addrs = PyList_New(0); wtp = *paddrs;
    while(wtp){
        PyList_Append(addrs, PyString_FromString(wtp->word));
        wtp = wtp->next;};
    
    // 构造调用参数opts列表用于回写
    opts = PyList_New(0); wtp = *popts;
    while(wtp){
        PyList_Append(opts, PyString_FromString(wtp->word));
        wtp = wtp->next;};

    // 构造调用参数组,执行调用
    args = PyTuple_New(5);
    PyTuple_SetItem(args,0, PyString_FromString(user));
    PyTuple_SetItem(args,1, PyString_FromString(passwd));
    PyTuple_SetItem(args,2, msg);
    PyTuple_SetItem(args,3, addrs);
    PyTuple_SetItem(args,4, opts);
    res = PyObject_CallObject(pap_auth_func, args);

    // 回写字符串列表msg,addrs和opts在目标过程中的变更
    
    // 解析返回值返回
    return 0; }

// 对端chap认证指示,返回: 1认证 0不认证 -1常规chap-secrets文件认证
static int chap_check_callpy(void) {
    return chap_check_func ?
    PyLong_AsLong(PyObject_CallObject(chap_check_func, NULL)) : -1; }

// chap认证检查过程 返回: 1成功 0失败
static int chap_verify_callpy(char *user, char *ourname,
    int id, struct chap_digest_type *digest,unsigned char *challenge,
    unsigned char *response, char *message, int message_space) {

    return digest->verify_response(
        id, user, pwbuff, strlen(pwbuff),
        challenge, response, message, message_space);}

// 返回对端地址确认: 1允许 0拒绝 -1常规处理
static int allowed_address_callpy(unsigned int addr) {
    PyObject *args; args = PyTuple_New(1);
    PyTuple_SetItem(args,0, PyInt_FromLong(addr));
    return allowed_address_func ?
    PyInt_AsLong(PyObject_CallObject(allowed_address_func, args)) : -1; }


// 插件: 功能注册
void plugin_init(void) {
    // 选项注册,返回时选项值并未完成解析,将在此后某个阶段执行解析
    add_options(exfuncpy_options);
    
    // (这里需要执行选项解析)
    
    // 环境初始化:
    py_env_init();
    extpy_init_callpy();
    
    // 通知注册:
    notify_callback_reg();

    // Hook注册:
    //idle_time_func      ? idle_time_hook=idle_time_callpy             :0;
    //holdoff_func        ? holdoff_hook=holdoff_callpy                 :0;
    pap_check_func        ? pap_check_hook=pap_check_callpy             :0;
    //pap_passwd_func     ? pap_passwd_hook=pap_passwd_callpy           :0;
    pap_auth_func         ? pap_auth_hook=pap_auth_callpy               :0;
    chap_check_func       ? chap_check_hook=chap_check_callpy           :0;
    //chap_passwd_func    ? chap_passwd_hook=chap_passwd_callpy         :0;
    chap_verify_func      ? chap_verify_hook=chap_verify_callpy         :0;
    //null_auth_func      ? null_auth_hook=null_auth_callpy             :0;
    //ip_choose_func      ? ip_choose_hook=ip_choose_callpy             :0;
    allowed_address_func  ? allowed_address_hook=allowed_address_callpy :0;
    //snoop_recv_func     ? snoop_recv_hook=snoop_recv_callpy           :0;
    //snoop_send_func     ? snoop_send_hook=snoop_send_callpy           :0;
    //multilink_join_func ? multilink_join_hook=multilink_join_callpy   :0;
    }
