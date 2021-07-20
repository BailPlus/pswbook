#Copyright Bail 2021
#com.Bail.pswbook 密码本 v1.0_1
#2021.6.23

#加密层:最终文件(原始shelve文件=>b85encode(head键(总密码的sha1),note键(每对密码字典(名称:(帐号，处理后密码=>总密码md5加密(用户输入的密码=>b85encode)，备注)))))

import shelve,        hashlib,     base64,        getpass,         sys, getopt
#      密码本核心组件 哈希表散列化 base85加密解密 输入密码不被看到 退出 获取参数

VER = 'v1.0_1'	#版本号
HELP = '''
用法: pswbook
      pswbook 文件名
      pswbook -c 文件名
      pswbook -e
      pswbook --help/version/uplog

-c\t\t创建新密码本
-e\t\t显示错误码对照表
--help\t\t显示此帮助
--version\t显示版本信息
--uplog\t\t显示更新日志

注:1.本软件目前暂时仅支持gnu/linux系统
   2.必须按照本帮助文件规则传递参数，使用参数不合法可能导致密码本文件损坏'''	#帮助文件
SALT = 'gzFUJ/f-Ghr\\'.encode()	#md5与sha1加密混淆码
arg = {'create':False}	#参数表
CMDHELP = '''
add:向密码本中添加项目
get:从密码本中获取项目
exit:安全退出'''	#软件内命令帮助
ERROR = '''错误码(返回值)列表:
0:正常
1:密码错误
2:系统不支持，请关注本软件更新
3:安全退出警告
4:不能指定多个文件
127:未知错误'''
UPLOG = '''更新日志
v1.1:
     +适配Windows版本
v1.0.1:
       +列出密码本条目(隐藏密码)
----↓已发布，↑预计更新----
v1.0:2021.7.20
     +创建密码本
     +向密码本添加条目
     +从密码本获取条目'''
VERINFO = f'pswbook {VER}'	#版本信息
DEFAULTFILE = b'CVFLFXD~5&LPsz$c|u1pFfcGMFfn;TM>0M<dpR&Mc|u2WR9|m<Fg7b`Brq^AFfd?#Re5|cFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFf&?BS1>RzFfcGPT1{6lFfcGMFj7)EF)%PNFfd;?G($EpFfcGMGfq)scQ7z8FfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMQc^iFd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfdq8MKexXW_)u*Ff~C~Z7?t}FfcJsPGK}LUO;m;d`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMd`@#iFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfe>hb3-sNFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMT4sE6L}o)rN>ng3Kul{eFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGMFfcGM'

def getarg():
    opts,args = getopt.getopt(sys.argv[1:],'ce',['help','version','uplog'])
##    print(opts)
    isskip = False
    for i in opts:
        if i[0] == '-c':
            arg['create'] = True
            continue
        if i[0] == '-e':
            isskip = True
            print(ERROR)
            exit()
        if i[0] == '--help':
            isskip = True
            print(HELP)
            exit()
        if i[0] == '--version':
            isskip = True
            print(VERINFO)
            exit()
        if i[0] == '--uplog':
            isskip = True
            print(UPLOG)
            exit()

    if not isskip:
        if len(args) == 0:
            pass
        elif len(args) == 1:
            arg['file'] = args[0]
        else:
            print('不能指定多个文件')
            exit(4)
'''
def checkarg():	#用于检验并上传参数
##    global arg
##    argl = sys.argv
    lenth = len(sys.argv)
    if lenth == 1:
        pass
    elif lenth == 2:
        arg1 = sys.argv[1]
        if args == '--help':
            arg['help'] = True
            print(HELP)
            exit()
        elif args == '-e':
            arg['errlist'] = True
        elif args == '--version':
            arg['verinfo'] = True
        else:
            arg['file'] = argl[1]
    elif lenth == 3:
        _,arg1,arg2 = sys.argv
        if arg1 == '-c':
            arg['create'] = True
            arg['file'] = arg2
        else:
            arg['help'] = True
'''
def getfile()->str:	#用于接受密码本文件名称
    if 'file' in arg.keys():
        fn = arg['file']
    else:
        fn = input('请输入文件名 >')
    return fn
def askpsw()->int:	#用于接受并处理用户输入的总密码
    #接受密码后立即散列化，md5用于加密解密，sha1用于验证。
    md5 = hashlib.md5(SALT)
    sha1 = hashlib.sha1(SALT)
    psw = getpass.getpass('请输入总密码 >').encode()
    md5.update(psw)	#转为md5
    sha1.update(psw)	#转为sha1
    pswen = (md5.hexdigest(),sha1.hexdigest())	#转化为编码，(md5,sha1)
    psw = '\0'*1024;del psw	#安全起见，防止密码被非法读取内存
    return pswen
def strback(s:str):
    while True:
        for i in s:
            yield i
def myende(isen:bool,psw:str,key:str)->str:	#自己的算法，用总密码的md5加密解密
    res = ''
    key = strback(key)
    if isen:
        for i in psw:
            res += chr(ord(i)+ord(next(key))*2)
    else:
        for i in psw:
            res += chr(ord(i)-ord(next(key))*2)
    return res
def endefile(isen:bool,fn:str):	#文件的加密解密
    if isen:	#文件加密
        with open(fn,'rb') as file:
            f = file.read()
        with open(fn,'wb') as filew:
            filew.write(base64.b85encode(f))
    else:	#文件解密
        with open(fn,'rb') as file:
            f = file.read()
        with open(fn,'wb') as filew:
            filew.write(base64.b85decode(f))
    del f	#节省内存
def createfile(fn:str):	#创建新文件格式
    with open(fn,'wb') as f:
        f.write(base64.b85decode(DEFAULTFILE))
##    input()
    endefile(False,fn)
    dic = readfile(fn)
    pswen = askpsw()
    dic['head'] = pswen[1]
    dic.close()
    endefile(True,fn)
    #现在问题:如何安全地创建新文件
    #实验1:查看b85decode空字节的结果:返回空字节:可
def readfile(fn:str):	#读取密码本并转化为shelve对象
    dic = shelve.open(fn,writeback=True)
    return dic
def checkpsw(dic,sha1)->bool:	#检验总密码的正确性
    if sha1 == dic['head']:
        return True
    else:
        return False
def ask()->str:
    cmd = input('>>')
    return cmd
def add(dic,key):
    name = input('账号 >')
    psw = getpass.getpass('密码 >').encode()
    pswen = myende(True,base64.b85encode(psw).decode(),key)
    #实验2:b85encode后再decode(),查看返回值类型:str:可
    note = input('备注 >')
    dic['note'][name] = (pswen,note)
def get(dic,key):
    name = input('账号 >')
    try:
        pswen,note = dic['note'][name]
    except KeyError:
        print('无此账号')
        return
    psw = base64.b85decode(myende(False,pswen,key).encode()).decode()
    print(f'密码:{psw}\n备注:{note}')
def loop(dic,key:str):	#主循环
    while True:
        cmd = ask()
        '''
        match cmd:
            case 'add':
                add(dic)
            case 'get':
                get(dic)
            case 'exit':
                dic.close()
                break
            case 'help':
                print(CMDHELP)
            case:
                print('未知命令，请使用help查看')
        '''
        if cmd == 'add':
             add(dic,key)
        elif cmd == 'get':
            get(dic,key)
        elif cmd == 'exit':
            dic.close()
            break
        elif cmd == 'help':
            print(CMDHELP)
        else:
            print('未知命令，请使用help查看')
def main():
    getarg()
    fn = getfile()
    if arg['create']:
        print('警告:使用了"-c"(创建密码本)选项，原文件内容将清空')
        createfile(fn)
    endefile(False,fn)
    try:
        dic = readfile(fn)
    except dbm.error as e:
        if 'gnu' in e:
            raise EnvironmentError('系统暂不支持，请关注本软件更新')
        else:
            print('文件格式错误')
            return 2
    try:
        pswen = askpsw()
        if not checkpsw(dic,pswen[1]):
            print('密码错误')
            return 1
        loop(dic,pswen[0])
    except KeyboardInterrupt:
        print("警告:请使用`exit'安全退出")
        return 3
    except Exception as e:
        print(f'错误:{e}')
        return 127
    finally:
        dic.close()
        endefile(True,fn)
    return 0

if __name__ == '__main__':
    sys.exit(main())

