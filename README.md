# plink_scanner
> * web漏洞扫描器


## plink_scanner说明
### plink_scanner目前并没有漏洞检测功能，只能检测目标中间件类型
>> plink_scanner通过使用nmap模块进行扫描，所以使用需要先安装nmap扫描，并将其添加到环境变量中
>> 说明:
>>>> plink_scanner通过对传入的url进行过滤，可支持多种url格式
>>>> e.g:
>>>> * `http://www.test.com`
>>>> * `http://www.test.com:2333`
>>>> * `www.test.com`
>>>> * `www.test.com:2333`
>>>> * `127.0.0.1`
>>>> * `127.0.0.1:2333`
>>>> * `http://127.0.0.1`
>>>> * `http://127.0.0.1:2333`

>> plink_scanner通过-p传入参数实现对指定端口扫描，可支持多种传入的格式

>> e.g:
>>>> * -p "1-10,80, 443"
>> 当传入的目标url已经带有端口，例如`127.0.0.1:2333`，则plink_scanner除了默认扫描的80,443端口，还会额外扫描2333端口


## plink_scanner使用说明
* > [usage](https://github.com/plink-user/plink_scanner/usage.md)
* > pip install -r requirements.txt
* > python plink_scanner -f url.txt --timeout=3 --output-scan test.csv

## plink_scanner后续问题
* > plink_scanner目前还处在初开发阶段
* >>> 目前可通过批量扫描目标url实现中间件的识别并将结果输出至CSV文档
* > plink_scanner后续开发方向
* >>> 对获取到的中间件类型进行针对性的poc来进行批量检测
* >>> 使用多线程或者多进程
* >>> 对代码进行整洁化处理
