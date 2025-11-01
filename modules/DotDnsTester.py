import base64
import concurrent.futures
import configparser
import ipaddress
# import logging
import os
import random
import socket
import ssl
import struct
import time
from collections import Counter, OrderedDict
from datetime import datetime

import requests

# 全局变量
user_mode = False
dns_servers = []
logger = None
logging_enabled = False


def main():
    global user_mode, dns_servers, logger, logging_enabled
    user_mode = True
    """主函数"""
    # 加载配置
    logging_enabled, dns_servers = load_config()

    user_print("=" * 50)
    user_print("高级 DNS 测试工具 (支持 DoH/DoT)")
    user_print("=" * 50)

    if not dns_servers:
        user_print("错误: 配置文件中没有有效的DNS服务器")
        return

    # 第一次运行时显示完整的 DNS 服务器列表
    user_print("\n配置的DNS服务器:")
    for i, server in enumerate(dns_servers):
        user_print(f"  {i + 1}. {server['type'].upper()}: {server['address']}")

    # 主循环
    first_run = True
    while True:
        # 第一次运行后显示简短提示
        if not first_run:
            user_print("\n配置的DNS服务器: [已配置]")
        first_run = False

        # 获取要查询的域名
        domain = ""
        while domain == "":
            domain = input("\n请输入要查询的域名 (输入 'exit' 退出): ").strip()
            if not domain:
                user_print("错误: 域名不能为空，请重新输入")
            elif domain.lower() == 'exit':
                # global logging_enabled
                if logging_enabled:
                    if input("\n是否分析DNS查询错误? (y/n): ").lower() == 'y':
                        analyze_dns_errors()
                user_print("\n程序已退出")
                return

        user_print(f"\n开始查询域名: {domain}")

        # 执行查询
        all_results = []
        ip_counter = Counter()

        user_print("\n查询结果:")
        user_print("-" * 50)

        start_time = time.time()
        err_ips_message = []

        with concurrent.futures.ThreadPoolExecutor() as executor:
            # 为每个DNS服务器创建查询任务
            futures = {}
            for server in dns_servers:
                futures[executor.submit(resolve_domain, domain, server, logger)] = server

            # 处理完成的任务
            for future in concurrent.futures.as_completed(futures):
                server = futures[future]
                try:
                    ips = future.result()
                    all_results.append({
                        'server': server,
                        'ips': ips
                    })

                    ips, err_ips = filter_public_ips(ips)

                    # 更新IP计数器
                    for ip in ips:
                        ip_counter[ip] += 1
                    # 记录非法IP
                    if err_ips:
                        for ip in err_ips:
                            err_ips_message.append(ip)

                    # 显示结果
                    server_type = server['type'].upper()
                    server_addr = server['address']
                    ips_str = ", ".join(ips) if ips else "无结果"
                    user_print(f"{server_type} ({server_addr}): {ips_str}")
                except Exception as e:
                    user_print(f"查询失败: {str(e)}")

        total_time = time.time() - start_time
        user_print("-" * 50)
        user_print(f"总查询时间: {total_time:.2f}秒")

        # 投票选择最可信的IP
        if not ip_counter:
            user_print("\n所有DNS服务器均未能解析该域名")
            continue

        # 获取得票最多的IP
        most_common = ip_counter.most_common()
        max_votes = most_common[0][1]

        # 选择所有得票数达到最大票数的IP
        trusted_ips = [ip for ip, count in most_common if count == max_votes]

        user_print("\n投票结果:")
        user_print("-" * 50)
        for ip, count in ip_counter.most_common():
            user_print(f"{ip}: {count}票")

        user_print("-" * 50)
        if len(trusted_ips) == 1:
            user_print(f"最可信的IP地址: {trusted_ips[0]}")
        else:
            user_print(f"最可信的IP地址 (并列): {', '.join(trusted_ips)}")
        if len(err_ips_message) > 0:
            for ip in list(set(err_ips_message)):
                user_print(f"已忽略污染IP地址：{ip}")


def load_config(filename='DNSList.ini'):
    """
    加载配置文件，返回日志设置、DNS服务器列表和非法IP列表。

    Args:
        filename (str): 配置文件名。

    Returns:
        tuple: (logging_enabled (bool), dns_servers (list))
    """
    # 默认值
    logging_enabled = False
    dns_servers = []

    # 检查并创建默认配置文件
    if not os.path.exists(filename):
        print(f"配置文件 {filename} 不存在，创建默认文件")
        with open(filename, 'w', encoding='utf-8') as f:
            default_ini_text = """[dns_servers]
server1 = plain, 119.29.29.29
server2 = plain, 114.114.114.114
server3 = plain, 114.114.115.115
server4 = plain, 223.5.5.5
server5 = plain, 223.6.6.6
server6 = plain, 180.76.76.76
server7 = plain, 1.2.4.8
server8 = plain, 202.96.128.166
server9 = plain, 202.96.134.133
server10 = dot, dns.alidns.com
server11 = dot, 1.1.1.1
server12 = dot, 8.8.8.8
server13 = dot, dns.alidns.com
server14 = dot, dot.pub
server15 = dot, dns.google
server16 = dot, dns-family.adguard.com
server17 = doh, https://dns.alidns.com/dns-query
server18 = doh, https://doh.pub/dns-query
server19 = doh, https://cloudflare-dns.com/dns-query
server20 = doh, https://dns.alidns.com/dns-query
server21 = doh, https://223.5.5.5/dns-query
server22 = doh, https://223.6.6.6/dns-query

[general]
logging_enabled = False
"""
            f.write(default_ini_text)

    # 读取配置
    config = configparser.ConfigParser()
    try:
        config.read(filename, encoding='utf-8')
    except Exception as e:
        print(f"读取配置文件 '{filename}' 时出错: {e}")
        # 即使读取失败，也返回默认空列表/值，避免程序崩溃
        return logging_enabled, dns_servers

    # --- 加载 General 设置 ---
    logging_enabled = False
    if 'general' in config:
        try:
            log_setting = config['general'].get('logging_enabled', 'False').lower()
            if log_setting in ['true', '1', 'yes', 'on']:
                logging_enabled = True
            elif log_setting in ['false', '0', 'no', 'off']:
                logging_enabled = False
            else:
                print(f"警告: 无法识别的日志启用标志: '{log_setting}', 使用默认值: False")
        except Exception as e:
            print(f"处理 [general] 部分时出错: {e}")

    # --- 加载 DNS 服务器 ---
    if 'dns_servers' in config:
        for key in config['dns_servers']:
            try:
                server_info = config['dns_servers'][key].split(',')
                if len(server_info) >= 2:
                    server_type = server_info[0].strip().lower()
                    server_address = server_info[1].strip()

                    # 可选端口，默认 DoT 端口 853
                    port = 853
                    if len(server_info) > 2 and server_type == 'dot':
                        try:
                            port = int(server_info[2].strip())
                        except ValueError:
                            print(f"警告: 服务器 '{key}' 的端口无效，使用默认端口 853")

                    dns_servers.append({
                        'type': server_type,
                        'address': server_address,
                        'port': port
                    })
            except Exception as e:
                print(f"解析 DNS 服务器条目 '{key}' 时出错: {e}")

    return logging_enabled, dns_servers


def build_dns_query(domain, record_type="A"):
    """构建标准 DNS 查询报文"""
    # DNS 记录类型映射
    type_map = {"A": 1, "AAAA": 28, "CNAME": 5, "MX": 15}

    # 头部
    query_id = random.randint(0, 65535)
    flags = 0x0100  # 标准查询
    qdcount = 1  # 一个问题
    ancount = 0  # 0个回答
    nscount = 0  # 0个权威记录
    arcount = 0  # 0个附加记录

    header = struct.pack('!HHHHHH', query_id, flags, qdcount, ancount, nscount, arcount)

    # 域名部分
    domain_parts = domain.encode('idna').split(b'.')
    query = b''
    for part in domain_parts:
        query += bytes([len(part)]) + part
    query += b'\x00'  # 结束域名

    # 查询类型和类
    query += struct.pack('!H', type_map.get(record_type, 1))  # QTYPE
    query += b'\x00\x01'  # QCLASS: IN

    return header + query


def resolve_doh(domain, server_url, logger=None):
    """使用 DoH (DNS over HTTPS) 解析域名"""
    try:
        if logger:
            logger.debug(f"开始 DoH 查询: {domain} -> {server_url}")

        # 构建 DNS 查询报文
        dns_query = build_dns_query(domain)

        # Base64URL 编码（移除填充和特殊字符）
        base64_query = base64.urlsafe_b64encode(dns_query).decode('utf-8').rstrip('=')

        # 发送 GET 请求
        params = {'dns': base64_query}
        headers = {
            'Accept': 'application/dns-message',
            'Content-Type': 'application/dns-message'
        }

        response = requests.get(server_url, params=params, headers=headers, timeout=5)

        if response.status_code != 200:
            if logger:
                logger.error(f"DoH 查询失败: {domain} -> {server_url}, 状态码: {response.status_code}")
            return []

        # 验证响应格式
        content_type = response.headers.get('Content-Type', '')
        if 'application/dns-message' not in content_type:
            if logger:
                logger.error(f"无效内容类型: {content_type}")
            return []

        # 解析响应
        return parse_dns_response(response.content, logger)
    except Exception as e:
        if logger:
            logger.error(f"DoH 查询错误: {domain} -> {server_url}, 错误: {str(e)}")
        return []


def parse_dns_response(response, logger=None):
    """解析 DNS 响应，提取所有 A 记录 IP 地址"""
    if len(response) < 12:
        if logger:
            logger.debug("DNS响应太短，无效")
        return []

    ips = []
    pos = 12  # 跳过 DNS 头部 (12字节)

    # 解析问题数量
    qdcount = struct.unpack('!H', response[4:6])[0]

    # 跳过问题部分
    for _ in range(qdcount):
        if pos >= len(response):
            break

        # 处理域名
        while pos < len(response) and response[pos] != 0:
            if response[pos] & 0xC0 == 0xC0:  # 压缩指针
                pos += 2
                break
            else:
                length = response[pos]
                pos += 1
                pos += length
        pos += 1  # 跳过结束符

        # 跳过 QTYPE 和 QCLASS
        if pos + 4 > len(response):
            break
        pos += 4

    # 解析回答数量
    ancount = struct.unpack('!H', response[6:8])[0]

    # 解析回答部分
    for _ in range(ancount):
        if pos >= len(response):
            break

        # 跳过域名
        if response[pos] & 0xC0 == 0xC0:  # 压缩指针
            pos += 2
        else:
            while pos < len(response) and response[pos] != 0:
                if response[pos] & 0xC0 == 0xC0:  # 压缩指针
                    pos += 2
                    break
                else:
                    length = response[pos]
                    pos += 1
                    pos += length
            pos += 1  # 跳过结束符

        # 检查边界
        if pos + 10 > len(response):
            break

        # 获取记录类型和长度
        rtype = struct.unpack('!H', response[pos:pos + 2])[0]
        pos += 2  # 跳过 TYPE
        pos += 2  # 跳过 CLASS
        ttl = struct.unpack('!I', response[pos:pos + 4])[0]
        pos += 4  # 跳过 TTL
        rdlength = struct.unpack('!H', response[pos:pos + 2])[0]
        pos += 2

        # 检查记录长度
        if pos + rdlength > len(response):
            break

        # 如果是 A 记录，提取 IP
        if rtype == 1 and rdlength == 4:  # A record
            ip = socket.inet_ntoa(response[pos:pos + 4])
            ips.append(ip)

        pos += rdlength

    return ips


def resolve_dot(domain, server_address, port=853, logger=None):
    """使用 DoT (DNS over TLS) 解析域名"""
    try:
        if logger:
            logger.debug(f"开始 DoT 查询: {domain} -> {server_address}:{port}")

        # 构建 DNS 查询报文
        dns_query = build_dns_query(domain)

        # 添加长度前缀 (2字节，网络字节序)
        length = struct.pack('!H', len(dns_query))
        request = length + dns_query

        # 创建 TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)

        # 创建 SSL 上下文
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # 不验证证书（简化实现）
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        # 创建安全连接
        secure_sock = context.wrap_socket(sock, server_hostname=server_address)
        secure_sock.connect((server_address, port))

        # 发送查询
        secure_sock.sendall(request)

        # 接收响应长度前缀
        resp_len_data = secure_sock.recv(2)
        if len(resp_len_data) != 2:
            if logger:
                logger.error("接收长度前缀失败")
            return []

        # 获取响应长度
        resp_len = struct.unpack('!H', resp_len_data)[0]

        # 验证长度合理性
        if resp_len < 12 or resp_len > 4096:  # DNS 头部12字节，最大4096字节
            if logger:
                logger.error(f"无效响应长度: {resp_len}")
            return []

        # 接收完整响应
        response = b''
        while len(response) < resp_len:
            chunk = secure_sock.recv(resp_len - len(response))
            if not chunk:
                break
            response += chunk

        if len(response) < resp_len:
            if logger:
                logger.error(f"响应不完整: {len(response)}/{resp_len} 字节")
            return []

        # 解析响应
        return parse_dns_response(response, logger)
    except Exception as e:
        if logger:
            logger.error(f"DoT 查询错误: {domain} -> {server_address}:{port}, 错误: {str(e)}")
        return []
    finally:
        try:
            secure_sock.close()
        except:
            pass


def resolve_plain(domain, server_address, logger=None):
    """使用普通 DNS (UDP) 解析域名"""
    try:
        if logger:
            logger.debug(f"开始普通 DNS 查询: {domain} -> {server_address}")

        # 构建 DNS 查询报文
        dns_query = build_dns_query(domain)

        # 创建 UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)

        # 发送查询
        sock.sendto(dns_query, (server_address, 53))

        # 接收响应
        response, _ = sock.recvfrom(4096)

        # 解析响应
        return parse_dns_response(response, logger)
    except Exception as e:
        if logger:
            logger.error(f"普通 DNS 查询错误: {domain} -> {server_address}, 错误: {str(e)}")
        return []
    finally:
        try:
            sock.close()
        except:
            pass


def resolve_domain(domain, dns_server, logger=None):
    """根据 DNS 服务器类型解析域名"""
    server_type = dns_server['type']
    server_address = dns_server['address']

    if server_type == 'doh':
        return resolve_doh(domain, server_address, logger)
    elif server_type == 'dot':
        return resolve_dot(domain, server_address, dns_server.get('port', 853), logger)
    elif server_type == 'plain':
        return resolve_plain(domain, server_address, logger)
    else:
        if logger:
            logger.error(f"未知的DNS类型: {server_type}")
        return []


def user_print(message, level=None):
    global user_mode
    if not user_mode:
        return
    if level == "ERROR":
        print(f"[错误] {message}")
    elif level == "WARNING":
        print(f"[警告] {message}")
    else:
        print(message)


def DnsIpChecker(domain):
    """
    检查域名在配置的所有DNS服务器上的解析结果

    参数:
        domain: 要查询的域名

    返回:
        dict: 键为DNS服务器标识，值为解析到的IP地址列表
    """
    global dns_servers, logger, logging_enabled

    # 确保配置已加载
    if not dns_servers or not logger:
        logging_enabled, dns_servers = load_config()

    # 确保日志已设置
    # if logger is None:
    #     setup_logging()

    results = {}

    # 执行查询
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {}
        for server in dns_servers:
            futures[executor.submit(resolve_domain, domain, server, logger)] = server

        for future in concurrent.futures.as_completed(futures):
            server = futures[future]
            try:
                ips = future.result()
                # 创建服务器标识
                server_id = f"{server['type'].upper()}:{server['address']}"
                if server['type'] == 'dot':
                    server_id += f":{server.get('port', 853)}"
                results[server_id] = tuple(ips)  # 转换为元组
            except Exception as e:
                server_id = f"{server['type'].upper()}:{server['address']}"
                results[server_id] = tuple()  # 空元组表示失败

    return results


def DnsIpBallot(domain):
    """
    统计域名解析结果的投票情况

    参数:
        domain: 要查询的域名

    返回:
        dict: 键为IP地址，值为投票数
        list: 已污染IP地址
    """
    global dns_servers, logger

    # 确保配置已加载
    # if not dns_servers or not logger:
    logging_enabled, dns_servers = load_config()

    # 确保日志已设置
    # if logger is None:
    #     setup_logging()

    ip_counter = Counter()
    error_ip_list = []
    # error_ip = []
    # 执行查询
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {}
        for server in dns_servers:
            futures[executor.submit(resolve_domain, domain, server, logger)] = server

        for future in concurrent.futures.as_completed(futures):

            try:
                iplist = future.result()

                ips, error_ips = filter_public_ips(iplist)

                for ip in ips:
                    ip_counter[ip] += 1
                if error_ips:
                    for ip in error_ips:
                        error_ip_list.append(ip)

            except:
                pass  # 忽略错误
    # 添加排序：按票数从大到小排序
    # 使用 OrderedDict 保持排序顺序
    sorted_counter = OrderedDict(
        sorted(ip_counter.items(), key=lambda item: item[1], reverse=True)
    )

    # 转换为字典、列表返回
    return dict(sorted_counter), list(set(error_ip_list))


def filter_public_ips(ip_list):
    """使用ipaddress库过滤出公网IP"""
    public_ips = []
    error_ips = []
    for ip_str in ip_list:
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.is_global:  # 这是核心判断
                public_ips.append(str(ip))  # 确保是字符串
            else:
                error_ips.append(str(ip))
        except ValueError:
            # 可以选择记录日志或忽略无效IP
            # print(f"警告: 无效的IP地址 '{ip_str}'，已忽略。")
            continue

    return public_ips, error_ips


def analyze_dns_errors():
    """分析 DNS 查询错误日志"""
    log_file = f"logs/dns_tool_{datetime.now().strftime('%Y%m%d')}.log"

    if not os.path.exists(log_file):
        user_print("没有找到今天的日志文件")
        return

    # 检查日志文件大小
    try:
        file_size = os.path.getsize(log_file)
        if file_size > 10 * 1024 * 1024:  # 大于10MB
            user_print("日志文件过大，跳过分析")
            return
    except:
        pass

    error_stats = {}

    try:
        # 使用错误处理打开日志文件
        with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                if "ERROR" in line:
                    # 提取错误信息
                    parts = line.split(" - ")
                    if len(parts) >= 4:
                        error_msg = parts[3]

                        # 统计错误类型
                        if "timed out" in error_msg:
                            error_type = "超时"
                        elif "unpack requires a buffer of 2 bytes" in error_msg:
                            error_type = "响应解析错误"
                        elif "Connection aborted" in error_msg:
                            error_type = "连接中断"
                        elif "Max retries exceeded" in error_msg:
                            error_type = "最大重试次数超出"
                        else:
                            error_type = "其他错误"

                        # 提取服务器信息
                        server_info = ""
                        if "->" in error_msg:
                            try:
                                server_part = error_msg.split("->")[1].split(",")[0].strip()
                                server_info = server_part
                            except:
                                server_info = "未知服务器"

                        # 更新统计
                        key = f"{error_type} - {server_info}"
                        error_stats[key] = error_stats.get(key, 0) + 1
    except Exception as e:
        user_print(f"分析日志文件时出错: {str(e)}")
        return

    # 输出错误分析
    if error_stats:
        user_print("\nDNS 查询错误分析:")
        user_print("-" * 50)
        for error, count in sorted(error_stats.items()):
            user_print(f"{error}: {count}次")
    else:
        user_print("\n没有发现DNS查询错误")


if __name__ == "__main__":
    main()
