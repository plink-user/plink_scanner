import argparse
from color import *
from scan_target import *
from urlfilter import *
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

filename = __file__.split("/")[-1]
parser = argparse.ArgumentParser(usage="python3 "+filename+" [usage]", add_help=False, description=filename)
parser.add_argument("-u", "--url", dest="url", type=str, help=" target URL (e.g. -u \"http://example.com\")", default="")
parser.add_argument("-f", "--file", dest="file", help="select a target list file (e.g. -f \"list.txt\")", default="")
parser.add_argument("-p", "--port", dest="port", type=str, help="select the range of port to scan (e.g. -p \"1-80,2333\")", default="80,443")
parser.add_argument("-h", "--help", action="help", help="show this help message and exit")
parser.add_argument("--output-text", type=str, dest="O_TEXT", metavar='file', help="result export txt file (e.g. \"result.txt\")")
parser.add_argument("--output-json", type=str, dest="O_JSON", metavar='file', help="result export json file (e.g. \"result.json\")")
parser.add_argument("--output-scan", type=str, dest="O_csv", metavar="file", help="results of the scan are output to the CSV document")
parser.add_argument("--proxy-http", dest="http", type=str, help="http proxy (e.g. --proxy-http 127.0.0.1:8080)", default="")
parser.add_argument("--user-agent", dest="ua", type=str,
                default="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88",
                help="you can customize the user-agent headers")
parser.add_argument("--timeout", dest="timeout", type=int, default=4, help="scan timeout time, default 10s")

example = parser.add_argument_group("examples")
example.add_argument(action='store_false',
                     dest="python3 "+filename+" -u http://example.com\n  "
                          "python3 "+filename+" -u http://example.com --timeout 10\n  "
                          "python3 "+filename+" -u http://example.com:80 --user-agent Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88\n  "
                          "python3 "+filename+" -f list.txt --output-json results.json --output-scan test.csv \n")

args = parser.parse_args()

headers = {
    "Accept": "text/html",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "Connection": "keep-alive",
    "user-agent": args.ua,
}

proxies = {
    "http": args.http,
    "https": args.http
}

if __name__ == "__main__":
    if args.file != "":
        if args.O_csv != "":
            if not args.O_csv.endswith(".csv"):
                args.O_csv = args.O_csv + ".csv"
            with open(args.O_csv, "a") as f:
                f.write("domain, port, service\n")
        listfile = []
        with open(args.file) as f:  # url.txt存放url地址,一个url占一行
            for line in f:
                lines = netcheck(line.strip())  # strip() to remove blankspace or line break
                if lines == None:
                    printYellow(line+"目标访问失败,退出此url的扫描\n")
                    continue
                elif isinstance(lines, list):
                    for line_s in lines:
                        line_s = line_s.replace("http://", "")
                        line_s = line_s.replace("https://", "")
                        listfile.append(line_s)
                else:
                    lines = lines.replace("http://", "")
                    lines = lines.replace("https://", "")
                    listfile.append(lines)
                formatList = list(set(listfile))
                formatList.sort(key=listfile.index)
        for links in formatList:
            if args.O_csv != "":
                with open(args.O_csv, "a") as f:
                    if ":" in links:
                        if links.split(":")[1] not in formatList:
                            a = nmapscan(links, links.split(":")[1], "")[2]
                            for i in a.keys():
                                if ":" in str(a.keys()):
                                    line = line.split(":")[0]
                                f.write(str(line) + ", " + str(i) + ", " + str(a.get(i)) + "\n")
                                printRed(str(links) + ": " + str(i) + ":" + str(a.get(i)) + "成功输出至文档\n")
                    else:
                        a = nmapscan(links, args.port, "")[2]
                        for i in a.keys():
                            if ":" in str(a.keys()):
                                line = line.split(":")[0]
                            f.write(str(line) + ", " + str(i) + ", " + str(a.get(i)) + "\n")
                            printRed(str(links) + ": " + str(i) + ":" + str(a.get(i)) + "成功输出至文档\n")

    elif args.url != "":
        if args.O_csv != "":
            if not args.O_csv.endswith(".csv"):
                args.O_csv = args.O_csv + ".csv"
            with open(args.O_csv, "a") as f:
                f.write("domain, port, service\n")
        listurl = []
        line = netcheck(args.url)
        if line == None:
            printYellow(args.url + "目标访问失败,退出此url的扫描\n")
        else:
            if isinstance(line, list):
                for line_s in line:
                    line_s = line_s.replace("http://", "")
                    line_s = line_s.replace("https://", "")
                    listurl.append(line_s)
            else:
                line = args.url
                line = line.replace("http://", "")
                line = line.replace("https://", "")
                listurl.append(line)
            formatList = list(set(listurl))
            formatList.sort(key=listurl.index)
            for link in formatList:
                if args.O_csv != "":
                    with open(args.O_csv, "a") as f:
                        if ":" in link:
                            if link.split(":")[1] not in formatList:
                                a = nmapscan(link, link.split(":")[1], "")[2]
                                for i in a.keys():
                                    if ":" in str(a.keys()):
                                        link = link.split(":")[0]
                                    f.write(str(link)+", "+ str(i) +", " + str(a.get(i))+"\n")
                                    printRed(str(args.url)+": " + str(i) + ":" + str(a.get(i)) + "成功输出至文档\n")
                        else:
                            a = nmapscan(link, args.port, "")[2]
                            for i in a.keys():
                                if ":" in str(a.keys()):
                                    link = link.split(":")[0]
                                f.write(str(link) + ", " + str(i) + ", " + str(a.get(i)) + "\n")
                                printRed(str(args.url) + ": " + str(i) + ":" + str(a.get(i)) + "成功输出至文档\n")
    else:
        printYellow("请提交请求url数据 \neg:\n    -f 文件名    (提交文件内url,一个url占一行)\n    -u url目标   (直接提交单个url数据)\n")

