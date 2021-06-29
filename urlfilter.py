import requests
import plink_scanner
from color import *

headers = {
    "Accept": "text/html",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "Connection": "keep-alive",
    "user-agent": plink_scanner.args.ua,
}

proxies = {
    "http": plink_scanner.args.http,
    "https": plink_scanner.args.http
}

def netcheck(url):
    try:
        printRed(url + "正在扫描中---\n")
        if url.endswith("/"):
            url = url[:-1]
        if not url.startswith("http://") and not url.startswith("https://"):
            if ":" in url:
                url = url.split(":")[0]
            attackurl1 = ("http://" + url).strip()
            attackurl2 = ("https://" + url).strip()
            r1 = requests.get(attackurl1, headers=headers, proxies=proxies, timeout=plink_scanner.args.timeout, verify=False)
            r2 = requests.get(attackurl2, headers=headers, proxies=proxies, timeout=plink_scanner.args.timeout, verify=False)
            status_code1 = r1.status_code
            status_code2 = r2.status_code
            if (status_code1==200 or status_code1==403) and (status_code2==200 or status_code2==403):
                return [attackurl1,attackurl2]
            elif status_code1==200 or status_code1==403:
                return attackurl1
            elif status_code2==200 or status_code2==403:
                return attackurl2
            else:
                return
        else:
            if url.count(":") >= 2:
                attackurl1 = ("http://" + url).strip()
                attackurl2 = ("https://" + url).strip()
                r1 = requests.get(attackurl1, headers=headers, proxies=proxies, timeout=plink_scanner.args.timeout,
                                  verify=False)
                r2 = requests.get(attackurl2, headers=headers, proxies=proxies, timeout=plink_scanner.args.timeout,
                                  verify=False)
                status_code1 = r1.status_code
                status_code2 = r2.status_code
                if (status_code1 == 200 or status_code1 == 403) and (status_code2 == 200 or status_code2 == 403):
                    return [attackurl1, attackurl2]
                elif status_code1 == 200 or status_code1 == 403:
                    return attackurl1
                elif status_code2 == 200 or status_code2 == 403:
                    return attackurl2
                else:
                    return
            r1 = requests.get(url, headers=headers, proxies=proxies, timeout=plink_scanner.args.timeout, verify=False)
            if r1.status_code == 200 or r1.status_code == 403:
                return url
            return
    except requests.exceptions.InvalidProxyURL:
        printYellow(url + "请确认输入的proxy-http参数是否正确    参数格式:\ne.g:\n    --proxy-http 127.0.0.0:8080\n    --proxy-http www.test.com:1234")
    except requests.exceptions.ProxyError:
        printYellow(url + "\n----目标proxy-http无法连接, 请检查输入是否有误\n")
    except requests.exceptions.ConnectTimeout:
        printYellow(url + "\n----目标连接超时, 请检查输入是否有误\n")
    except requests.exceptions.MissingSchema:
        printYellow(url + "\n----目标url格式错误\n请尝试重新输入\ne.g:\n    -u http://www.example.com\n    -u https://www.example.com")
    except requests.exceptions.SSLError:
        printYellow(url + "目标SSL错误\n")
    except requests.exceptions.ConnectionError:
        printYellow(url+"目标强迫关闭了一个现有的连接\n")
    except requests.exceptions.ReadTimeout:
        printYellow("服务器未在分配的时间内发送任何数据\n")

