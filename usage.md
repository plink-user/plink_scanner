# usage
* > -u  /  --url
* >>> 指定单个url进行扫描
* > -f  /  --file
* >>> 对文件内的url进行扫描，每个url占一行
* > -p  /  --port
* >>> 指定目标端口进行扫描，可指定某个范围，灵活使用
* > --output-scan
* >>> 将扫描后的结果进行保存（目前只是简单的数据保存）
* > --proxy-http
* >>> 设置请求目标代理，便于后期的poc扫描，代理格式：--proxy-http 127.0.0.1:8080
* > --user-agent
* >>> 设置请求的user-agent，格式：--user-agent "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88"
* > --timeout
* >>> 设置请求的超时时间
