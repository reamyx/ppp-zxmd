#!/bin/env python3
#coding:utf-8
#
#--------------------------------------------------------------------
# exfuncpy插件目标模块,可被pppd插件exfuncpy导入以提供以提供pppd功能扩展.
#
# exfuncpy是一个pppd插件程序,它运行时导入目标模块并转换pppd插件每一个回调(包括
# Hook和notify)到该模块中对应的命名过程,即当前模块中特定名称的可调用对象.
# (当前仅实现部分必要的HOOK和通知回调用于对端认证).
#
# 特定命名过程的缺失将将使忽略对应的插件回调操作.
# 除回调过程规定的参数外,插件还可能封装其它适用的数据结构和过程到默认参数表尾部.
#
# 目标模块文件的路径名称通过exfuncpy插件提供的pppd选项"pymodulepath"指定.
#--------------------------------------------------------------------

import os, sys

#不允许做为主程序执行功能.
if __name__ == '__main__':
    print("DO NOT run this program as main!")
    sys.exit(0)

#插件初始化完成指示,无返回值
def extpy_init(ourname,ipparm):
    pass


############################## 通知回调 ##############################
#事件通知类型:
# pidchange, phasechange, exitnotify, sigreceived, ip_up_notifier,
# ip_down_notifier, auth_up_notifier, link_down_notifier
#
#事件回调过程: 无返回值,整数IntArg值和通知类型相关,可选参数取决于具体的事件类型
# def ncb_<event-class-name>(IntArg)

#ip_up_notifier: 
def ncb_ip_up_notifier(IntArg):
    pass

#ip_down_notifier: 
def ncb_ip_down_notifier(IntArg):
    pass


#通知事件项拉取,返回元组表示的的事件表用于注册到通告回调.
#其元素为一个二元组,表示一个注册项: ((事件类型, 回调过程), ...)
def notify_fetch():
    return (
    ("ip_up_notifier", notify_ip_up_notifier),
    ("ip_down_notifier", notify_ip_down_notifier))





############################## Hook回调 ##############################

#对端pap认证指示 1认证 0不认证 -1常规pap-secrets文件认证
def pap_check():
    pass

#pap认证过程 返回值: 1成功 0失败 -1常规pap-secrets检查
# user, passwd:字符串,msgp: 字符串列表
def pap_auth(user, passwd, msgp, paddrs, popts):
    pass

#对端chap认证指示 1认证 0不认证 -1常规chap-secrets文件认证
def chap_check():
    pass

#chap认证过程 返回值: 1成功 0失败
def chap_verify(user, ourname, id, digest, 
    challenge, response, message, message_space):
    pass

#对端地址确认: 1允许 0拒绝 -1常规处理
# addr: INT表示的IP地址
def allowed_address(addr):
    return 1
