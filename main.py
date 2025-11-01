#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""模块说明：这里写模块描述
1、
2、
3、
"""

"""================= 引入模块区 ================="""
import datetime
import os
import sys

from modules.DotDnsTester import DnsIpBallot
from modules.PingInBatch import ping_ip as PingIp

"""================ 定义程序信息 ================"""
# 以下信息应按实填入，但可缺省
InfoProgramName = ""  # 指定程序名，缺省为      get_program_name()
InfoProgramVer = "v1"  # 设置项目版本号，缺省为   get_program_ver()
InfoAuthor = "Tony"  # 指定程序猿名字，缺省为   get_author()
InfoStartDate = ""  # 设置项目口径日期，缺省为 get_start_date()
# 以上信息应按实填入，但可缺省

"""================ 日志和报错模式 ================"""
NeedTheLog = False   # 调试完后根据情况取消日志为False
DebugModeErr = False  # 需要显示详尽的错误信息时True
""" 当需要实现详尽报错信息时,用下面这段代码实现：
except Exception as e:
    add2log(f"未处理的异常: {str(e)}")
    if DebugModeErr: add2log(f"异常位置: {get_error_location(e)}")
"""
"""================= 公共变量 ================="""
DomainListIni = "Domains2HOST.ini"
OutPutFile = "HOST.txt"

"""================= 主程序入口 ================="""

PgmExitCode = 0


def main():
    # 标准化启始记录
    add2log("=" * 50)
    add2log(f"程序【{get_program_name()}】启动")
    add2log(f"当前版本：{get_program_ver()}")
    add2log(f"程 序 猿：{get_author()}")
    add2log(f"口径日期：{get_start_date()}")
    add2log(f"日志模式：{'Debug_Mode' if DebugModeErr else 'Release_Mode'}")
    if DebugModeErr: DebugModeInfo()

    mainExitCode = 0  # 默认正常退出
    global DomainListIni, OutPutFile
    try:
        if DebugModeErr: add2log(f"主代码 {sys._getframe().f_code.co_name}() 运行时间戳")
        """================= 主程序代码 ================="""
        # DomainListIni="Domains2HOST"
        # OutPutFile = "HOST.txt"

        DomainList = load_domains_from_ini(DomainListIni)
        ResultList = []
        ErrorIpList = []
        add2log("=" * 50)
        for Domain in DomainList:
            print("="*50)
            print(f"正在获取{Domain}的IP地址清单")
            add2log(f"正在获取{Domain}的IP地址清单")
            ResultIPs, ErrorIpList = DnsIpBallot(Domain)

            IPAddress = [[ip, count] for ip, count in ResultIPs.items()]
            add2log(f"获取结果")
            add2log(IPAddress)
            add2log(f"{ErrorIpList=}")
            items_counter = len(IPAddress)

            # 汇报污染情况
            if ErrorIpList:
                for ErrorIp in ErrorIpList:
                    print(f"检测到DNS污染IP：{ErrorIp}")
            # 告知用户开始测试
                print(f"开始测试无污染IP集：共{items_counter}个条目")
            else:
                print(f"开始测试IP集：共{items_counter}个条目")

            add2log("开始测试IP集")
            for ip, counter in IPAddress:
                SuccessCount, Delay, SuccessRate, _, _ = PingIp(ip,
                                                                1000,
                                                                10)  # 测试IP地址，返回：成功次数，平均延迟，掉包率
                FaleRate = 1 - SuccessRate
                Delay = round(Delay, 4)
                FaleRate = round(FaleRate, 4)
                ResultLine = [ip, Domain, Delay, FaleRate, counter]
                ResultList += [ResultLine]
                # =====================
                ip = ResultLine[0]
                domain = ResultLine[1]
                delay = ResultLine[2]
                loss_rate = ResultLine[3]
                counter = ResultLine[4]
                host_entry = f"{ip}\t\t\t{domain}  # 延迟: {delay:.2f}ms, 丢包率: {loss_rate:.2%}, 可信权重: {counter}"
                print(host_entry)
                # =====================

            add2log("测试结果")

        add2log(f"将结果写入{OutPutFile}")
        Result_to_HOST(ResultList, OutPutFile)

        """================= 主程序代码 ================="""
        if DebugModeErr: add2log(f"主代码 {sys._getframe().f_code.co_name}() 结束时间戳")
    except Exception as e:
        add2log(f"未处理的异常: {str(e)}")
        if DebugModeErr: add2log(f"异常位置: {get_error_location(e)}")
        mainExitCode = 1  # 表示异常退出
    finally:
        return mainExitCode


# end main

"""================= 辅助函数区 ================="""
funcExitCode = -1  # 初始化为未执行(-1)


def Result_to_HOST(ResultList, OutPutFile="hosts.txt", max_entries=10):  # 将结果写入HOST
    global funcExitCode
    func_error = 0  # 初始化无错误
    try:
        if DebugModeErr: add2log(f"模块 {sys._getframe().f_code.co_name}() 运行时间戳")
        """示例函数"""
        # 按域名分组
        domain_groups = {}

        for entry in ResultList:
            domain = entry[1]
            if domain not in domain_groups:
                domain_groups[domain] = []
            domain_groups[domain].append(entry)

        with open(OutPutFile, "w", encoding="utf-8") as f:
            # 文件头
            host_header = """# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host



# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost


            """
            print("=" * 50)
            print(f"开始写入{OutPutFile}")
            f.write(host_header)
            f.write("# ====== 自动生成的HOSTS条目 ======\n")
            # f.write("# 格式说明: IP地址 + 2个TAB + 域名 + 2个TAB + 注释信息\n")
            # f.write("# 注释包含: 延迟(ms), 丢包率(%), 可信权重\n\n")

            for domain, entries in domain_groups.items():
                # 过滤无效IP (delay=inf)
                valid_entries = [e for e in entries if e[2] != float('inf')]

                if not valid_entries:
                    # 没有有效IP
                    f.write(f"#{domain}\n")
                    # f.write("# 未找到有效IP\n\n")
                    continue

                # 排序: 丢包率优先(升序), 延迟其次(升序)
                sorted_entries = sorted(valid_entries, key=lambda x: (x[3], x[2]))

                # 限制最大条目数
                top_entries = sorted_entries[:max_entries]

                # 写入域名标题
                f.write(f"#{domain}\n")
                f.write("#---------------\n")

                # 写入每个IP条目
                for entry in top_entries:
                    ip, domain, delay, loss_rate, weight = entry
                    # 格式化行: IP + 2个TAB + 域名 + 2个TAB + 注释
                    line = f"{ip}\t\t{domain}\t\t# 延迟: {delay:.2f}ms, 丢包率: {loss_rate:.2%}, 可信权重: {weight}\n"
                    f.write(line)

                # 添加备份IP计数
                if len(valid_entries) > max_entries:
                    backup_count = len(valid_entries) - max_entries
                    f.write(f"# 另有 {backup_count} 个备份IP未显示\n\n")
                else:
                    f.write("\n")

            print(f"{OutPutFile}写入完成")

        """示例函数"""
    except Exception as e:
        add2log(f"未处理的异常: {str(e)}")
        if DebugModeErr: add2log(f"异常位置: {get_error_location(e)}")
        func_error = 1  # 表示异常退出
    finally:
        funcExitCode = max(func_error, funcExitCode)  # 传递最大错误码
        if DebugModeErr: add2log(f"模块 {sys._getframe().f_code.co_name}() 结束时间戳")


# end Result_to_HOST

def load_domains_from_ini(filename="Domains2HOST.ini"):  # 读取ini
    global funcExitCode
    func_error = 0  # 初始化无错误
    try:
        if DebugModeErr: add2log(f"模块 {sys._getframe().f_code.co_name}() 运行时间戳")
        """示例函数"""

        domains = []

        # 如果文件不存在，创建默认配置文件
        if not os.path.exists(filename):
            print(f"配置文件 {filename} 不存在，创建默认文件")
            with open(filename, 'w', encoding='utf-8') as f:
                default_ini_text = """# 列出需要写入HOST的域名
# 每个域名一行

# TheMovieDb
api.themoviedb.org
image.tmdb.org

#The TV Db
api.thetvdb.com
artworks.thetvdb.com
www.thetvdb.com

# OpenSubtitles
api.opensubtitles.org

# Fanart.tv
webservice.fanart.tv

# Others
api.trakt.tv
"""
                f.write(default_ini_text)

        try:
            with open(filename, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    # 跳过空行和注释
                    if line and not line.startswith('#'):
                        domains.append(line)

            if not domains:
                print(f"警告: 配置文件 {filename} 中没有有效域名，使用默认列表")
                domains = [
                    "image.tmdb.org",
                    "api.themoviedb.org",
                    "api.opensubtitles.org",
                    "webservice.fanart.tv"
                ]
        except Exception as e:
            print(f"读取配置文件错误: {str(e)}")
            print("使用默认域名列表")
            domains = [
                "136.com",
                "qq.com",
                # "api.opensubtitles.org",
                # "webservice.fanart.tv"
            ]

        return domains

        """示例函数"""
    except Exception as e:
        add2log(f"未处理的异常: {str(e)}")
        if DebugModeErr: add2log(f"异常位置: {get_error_location(e)}")
        func_error = 1  # 表示异常退出
    finally:
        funcExitCode = max(func_error, funcExitCode)  # 传递最大错误码
        if DebugModeErr: add2log(f"模块 {sys._getframe().f_code.co_name}() 结束时间戳")


# end load_domains_from_ini


"""================ 自动设置缺省项 ================"""


def get_program_name(): return InfoProgramName or os.path.splitext(os.path.basename(sys.argv[0]))[0] or "Untitled_App"


def get_author(): return InfoAuthor or "Default Programer"


def get_start_date(): return InfoStartDate or datetime.datetime.now().strftime('%Y-%m-%d')


def get_program_ver(): return InfoProgramVer or f"v{datetime.datetime.now().strftime('%Y%m%d')}"


"""================ 消息错误反馈 ================"""


def get_error_location(e):
    if not DebugModeErr: return
    import traceback
    try:
        tb = traceback.extract_tb(e.__traceback__)[-1]
        return f"在 {os.path.basename(tb.filename)} 文件,第 {tb.lineno} 行的 {tb.name}() 模块"
    except:
        return "位置获取失败"


# end get_error_location

def DebugModeInfo():
    import platform

    add2log(f"=" * 18 + " 运行环境信息 " + "=" * 18)
    add2log(f"Python版本: {sys.version}")
    add2log(f"解释器路径: {sys.executable}")
    add2log(f"操作系统: {platform.system()} {platform.release()}")
    add2log(f"系统架构: {platform.architecture()[0]}")
    add2log(f"工作目录: {os.getcwd()}")
    add2log(f"当前时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    add2log("=" * 50)


# end DebugModeInfo


"""================ 模板化日志程序 ================"""


def add2log(content):
    if not NeedTheLog: return
    log_file = f"{get_program_name()}.log"
    log_entry = "\n" if content == "\n" else f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {content}\n"
    try:
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(log_entry)

    except Exception as e:
        print(f"日志写入失败: {str(e)}\n日志内容: {log_entry}")
        if DebugModeErr: print(f"异常位置: {get_error_location(e)}")


# end add2log

"""================ 实际执行起点 ================"""
if __name__ == "__main__":
    try:

        """执行点↓在这里"""
        PgmExitCode = main()
        """执行点↑在这里"""

        PgmExitCode = max(PgmExitCode, funcExitCode)
        status = "正常" if PgmExitCode == 0 else "带异常"
        print("=" * 50)
        print(f"程序【{status}】完成\n")
        add2log(f"执行结束，完成代码为：{PgmExitCode}：({status})")
        if funcExitCode == -1 and DebugModeErr: add2log(f"所有辅助函数未执行")
    except Exception as e:
        add2log(f"顶层系统异常: {str(e)}")
        if DebugModeErr: add2log(f"异常位置: {get_error_location(e)}")
        PgmExitCode = 2
    finally:
        add2log("=" * 50)
        add2log("\n")
        input("按任意键结束……")
        sys.exit(PgmExitCode)
# endif
