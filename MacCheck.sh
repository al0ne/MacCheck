#!/usr/bin/env bash

echo ""
echo " ========================================================= "
echo " \                 Mac应急响应/信息搜集脚本 V1.0          / "
echo " ========================================================= "
echo " # Mac OS 系统检测脚本                    "
echo " # author：al0ne                    "
echo " # https://github.com/al0ne                    "
echo -e "\n"

# 重点搜集MAC下系统信息，检测挖矿病毒以及其他常见病毒，开箱即用

filename='result_'$(date +%s)'.log'

xsdk() {
    echo -e "\n\033[31m[+]xsdk挖矿检测\033[0m" | tee -a $filename
    result=$(ps aux | egrep "mgo|xsdk" | grep -v 'grep')
    if [ -n "$result" ]; then
        echo "存在xsdk挖矿进程!" | tee -a $filename
        echo $result | tee -a $filename
        echo -e "\n" | tee -a $filename
    fi
    result=$(ls -a /etc/bbrj /etc/evtconf /etc/mach_inlt /etc/periodoc.d ~/Documents/Tunings 2>/dev/null)
    if [ -n "$result" ]; then
        echo "存在xsdk挖矿文件!" | tee -a $filename
        echo $result | tee -a $filename

    fi
}

ssl3() {
    echo -e "\n\033[31m[+]ssl3挖矿检测\033[0m" | tee -a $filename
    result=$(ps -ef | egrep "ssl\d.plist")
    if [ -n "$result" ]; then
        echo "存在ssl3挖矿进程!" | tee -a $filename
        echo $result | tee -a $filename
        echo -e "\n" | tee -a $filename
    fi
    result=$(find ~ -name 'ssl?.plist' 2>/dev/null)
    if [ -n "$result" ]; then
        echo "存在ssl3挖矿文件!" | tee -a $filename
        echo $result | tee -a $filename
        echo -e "\n" | tee -a $filename

    fi
    result=$(find ~/Library/Caches -name '*.plist' | egrep 'com.apple.[a-zA-Z0-9]+.plist' 2>/dev/null)
    if [ -n "$result" ]; then
        echo "可疑ssl3挖矿文件!" | tee -a $filename
        echo $result | tee -a $filename
        echo -e "\n" | tee -a $filename

    fi
}

autorun() {
    echo -e "\033[31m[+]可疑启动项检测\033[0m" | tee -a $filename
    ls -a /Library/LaunchDaemons /Library/LaunchAgents ~/Library/LaunchAgents /System/Library/LaunchAgents /System/Library/LaunchDaemons | egrep '\bLibrary|com\.\w{2,6}.plist|yahoo|ssl|unioncrypto|^\.\w+' | egrep -v "\->" | tee -a $filename
    echo -e "\n" | tee -a $filename

}

file_check() {
    echo -e "\033[31m[+]可疑文件检测\033[0m" | tee -a $filename
    ls -alh /Library/search.amp 2>/dev/null | tee -a $filename
    ls -alh ~/Library/search.amp 2>/dev/null | tee -a $filename
    ls -alh /Library/UnionCrypto 2>/dev/null | tee -a $filename
    echo -e "\n" | tee -a $filename
}

main_check() {
    echo -e "\033[31m[+]环境检测\033[0m" | tee -a $filename
    # 验证是否为root权限
    if [ $UID -ne 0 ]; then
        echo -e "\n\033[31m请使用root权限运行! \033[00m"
        echo -e "\033[31mchmod u+x ./MacCheck.sh \033[00m"
        echo -e "\033[31msudo ./MacCheck.sh \033[00m"
        exit 1
    else
        echo -e "\033[00;32m当前为root权限 \033[00m"
    fi
    #当前用户
    echo -e "USER:\t\t" $(whoami) 2>/dev/null | tee -a $filename
    #主机名
    echo -e "Hostname: \t" $(hostname -s) | tee -a $filename
    #uptime
    echo -e "Uptime: \t" $(uptime | awk -F ',' '{print $1}') | tee -a $filename
    #CPU占用TOP 15
    cpu=$(ps aux | grep -v ^'USER' | sort -rn -k3 | head -15) 2>/dev/null
    echo -e "\n" | tee -a $filename
    echo -e "\033[00;31m[+]CPU TOP15:  \033[00m\n${cpu}\n" | tee -a $filename
    echo -e "\n" | tee -a $filename
    #ifconfig
    echo -e "\033[00;31m[+]ifconfig\033[00m" | tee -a $filename
    ifconfig | egrep '192.|172.' | tee -a $filename
    echo -e "\n" | tee -a $filename
    #端口监听
    echo -e "\033[00;31m[+]端口监听\033[00m" | tee -a $filename
    lsof -nP -iTCP | grep LISTEN | tee -a $filename
    echo -e "\n" | tee -a $filename
    #网络连接
    echo -e "\033[00;31m[+]网络连接\033[00m" | tee -a $filename
    lsof -nP -iTCP | grep 'ESTABLISHED' | egrep -v 'Google|Microsoft|Cisco' | tee -a $filename
    echo -e "\n" | tee -a $filename
    #DNS
    echo -e "\033[00;31m[+]DNS Server\033[00m" | tee -a $filename
    cat /etc/resolv.conf | egrep -v '#' | tee -a $filename
    echo -e "\n" | tee -a $filename
    #passwd信息
    echo -e "\033[00;31m[+]可登陆用户\033[00m" | tee -a $filename
    cat /etc/passwd | egrep -v 'nologin$|false$|#' | tee -a $filename
    echo -e "\n" | tee -a $filename
    echo -e "\033[00;31m[+]sudoers(请注意NOPASSWD)\033[00m" | tee -a $filename
    cat /etc/sudoers | egrep -v '#' | sed -e '/^$/d' | tee -a $filename
    echo -e "\n" | tee -a $filename
    #tmp目录
    echo -e "\033[00;31m[+]/tmp \033[00m" | tee -a $filename
    ls -alht /tmp /var/tmp /private/tmp/ | tee -a $filename
    echo -e "\n" | tee -a $filename
    echo -e "\033[00;31m[+]lsof +L1 \033[00m" | tee -a $filename
    lsof +L1 | egrep -v 'cache|messages|/private/' | tee -a $filename
    echo -e "\n" | tee -a $filename
    #检查ssh key
    echo -e "\033[00;31m[+]SSH key\033[00m" | tee -a $filename
    sshkey=${HOME}/.ssh/authorized_keys
    if [ -e "${sshkey}" ]; then
        cat ${sshkey} | tee -a $filename
    else
        echo -e "SSH key文件不存在\n" | tee -a $filename
    fi
    echo -e "\033[00;31m[+]用户启动项\033[00m" | tee -a $filename
    ls -alht /Library/LaunchDaemons /Library/LaunchAgents ~/Library/LaunchAgents

}

# 开始检查
main_check
# xsdk挖矿检查
xsdk
# ssl3挖矿检测
ssl3
# 启动项检测
autorun
# 可疑文件检测
file_check
