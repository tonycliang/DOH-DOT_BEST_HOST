#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""纯交互模式 Ping 延迟测试工具 (简洁版)"""

"""================= 引入模块区 ================="""
import re
import time
import ping3
from typing import Tuple, List

"""================ 定义程序信息 ================"""
# 全局默认值
DEFAULT_TIMEOUT = 1000  # 默认超时时间(秒)
DEFAULT_PING_TIMES = 4  # 默认 ping 次数
USER_MODE = False

"""================= 主程序入口 ================="""


def main():  # 主程序

    """主函数 - 纯交互模式"""
    global USER_MODE
    USER_MODE = True
    settings_ini = False
    user_print("=" * 50)
    user_print("Ping 延迟测试工具")
    user_print("=" * 50)

    # 设置测试参数
    timeout = DEFAULT_TIMEOUT
    ping_times = DEFAULT_PING_TIMES
    # 尝试从ini取配置

    try:
        user_print("尝试读取ini文件")
        timeout_ini, ping_times_ini, ip_ini = read_settings_ini()
        if all([timeout_ini, ping_times_ini, ip_ini]):
            timeout = timeout_ini
            ping_times = ping_times_ini
            IP_address = ip_ini
            settings_ini = True
    except:
        pass
    # settings_ini = False
    if settings_ini:
        user_print("按ini文件批量测试：")
        for ip in IP_address:
            # user_print(f"测试的ip：{ip}")
            single_line_test(ip, timeout, ping_times)

        # 人工测试循环
    while not settings_ini:
        ip = input("\n请输入要测试的 IP 地址(输入 q 退出): ").strip()

        if ip.lower() in ['q', 'quit', 'exit', 'bye']:
            user_print("\n程序已退出")
            break

        if not is_valid_ip(ip):
            user_print("错误: 无效的 IP 地址格式")
            continue
        single_line_test(ip, timeout, ping_times)


"""================= 主计算函数 ================="""


def ping_ip(ip: str, timeout: float = DEFAULT_TIMEOUT, ping_times: int = DEFAULT_PING_TIMES) \
        -> Tuple[int, float, float, float, float]:
    """使用 ping3 库 Ping 指定的 IP 地址并返回结果
        返回:
        Tuple[int, float, float, float, float]: 包含以下五个元素的元组:
            [0] success_count (int): 成功的 Ping 次数
            [1] avg_delay (float): 成功的 Ping 请求的平均延迟（毫秒）
            [2] success_rate (float): 成功率（成功次数/总测试次数）
            [3] min_delay (float): 成功的 Ping 请求的最小延迟（毫秒）
            [4] max_delay (float): 成功的 Ping 请求的最大延迟（毫秒）"""
    # 存储延迟结果
    delays = []
    timeout = timeout / 1000  # 单位协调：ms--->秒
    # 执行多次 ping 测试
    for _ in range(ping_times):
        try:
            # 执行 ping 测试
            delay = ping3.ping(ip, timeout=timeout, unit='ms')

            if delay is not None and delay > 0:
                delays.append(delay)

            # 添加短暂延迟，避免过于频繁
            time.sleep(0.1)
        except Exception:
            # 忽略错误，继续测试
            continue

    # 计算统计结果
    success_count = len(delays)

    if success_count > 0:
        total_delay = sum(delays)
        avg_delay = total_delay / success_count
        min_delay = min(delays)
        max_delay = max(delays)
        success_rate = success_count / ping_times
    else:
        avg_delay = float("inf")
        min_delay = float("inf")
        max_delay = float("inf")
        success_rate = 0.0

    return success_count, avg_delay, success_rate, min_delay, max_delay


"""================= 辅助函数区 ================="""


def single_line_test(ip, timeout, ping_times):
    # 执行测试
    success_count, avg_delay, success_rate, min_delay, max_delay = ping_ip(ip, timeout, ping_times)

    # 单行输出结果
    if success_count > 0:
        user_print(
            f"结果: {ip} - 成功率={success_rate:.2%}, 平均延迟={avg_delay:.2f}ms, 最小延迟={min_delay:.2f}ms, 最大延迟={max_delay:.2f}ms")
    else:
        user_print(f"结果: {ip} - 所有请求超时")


def is_valid_ip(ip: str) -> bool:
    """验证IP地址格式"""
    pattern = r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
    match = re.match(pattern, ip)
    if not match:
        return False

    # 验证每个部分在0-255之间
    for part in match.groups():
        if not 0 <= int(part) <= 255:
            return False

    return True


def read_settings_ini() -> Tuple[int, int, List[str]]:
    """
    读取 settings.ini 配置文件

    返回:
        time_out: 超时时间(毫秒)
        ping_times: ping测试次数
        IP_address: IP地址列表
    """
    # 默认值
    time_out = 1000  # 默认超时时间(毫秒)
    ping_times = 10  # 默认测试次数
    IP_address = []  # 默认空IP列表

    try:
        # 使用 with 语句安全打开文件
        with open('settings.ini', 'r', encoding='utf-8') as f:
            lines = f.readlines()

        current_section = None

        for line in lines:
            line = line.strip()

            # 跳过空行和注释
            if not line or line.startswith(';') or line.startswith('#'):
                continue

            # 检查节头
            if line.startswith('[') and line.endswith(']'):
                current_section = line[1:-1].strip().lower()
                continue

            # 解析超时设置
            if current_section == "time out" and '=' in line:
                key, value = line.split('=', 1)
                if key.strip().lower() == "timeout":
                    try:
                        time_out = int(value.strip())
                    except ValueError:
                        pass

            # 解析测试次数
            elif current_section == "ping times" and '=' in line:
                key, value = line.split('=', 1)
                if key.strip().lower() == "ping_times":
                    try:
                        ping_times = int(value.strip())
                    except ValueError:
                        pass

            # 解析IP地址列表
            elif current_section == "ip address":
                # 直接验证IP地址格式
                if is_valid_ip(line):
                    IP_address.append(line)

    except FileNotFoundError:
        # 文件不存在时使用默认值
        pass
    except Exception as e:
        # 其他错误处理
        user_print(f"配置文件读取错误: {str(e)}", "ERROR")

    return time_out, ping_times, IP_address


def user_print(message, level=None):
    global USER_MODE
    if not USER_MODE:
        return
    if level == "ERROR":
        print(f"[错误] {message}")
    elif level == "WARNING":
        print(f"[警告] {message}")
    else:
        print(message)


"""================ 实际执行起点 ================"""
if __name__ == "__main__":
    main()
