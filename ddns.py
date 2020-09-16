#!/usr/bin/env python
# coding=utf-8
# DDNS脚本->阿里域名动态解析ipv6地址
import base64
import datetime
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import urllib.parse

# 阿里api请求域名
import requests

requestUrl = "https://alidns.aliyuncs.com/?"
# 阿里RAM ID
accessKeyId = ""
# 阿里RAM KEY
accessKeySecret = ""
# 主域名
domain = "lliiuuhhuuaa.cn"
# 子域名[test],解析后[test.lliiuuhhuuaa.cn],主域名记录要填写”@”
sub = "test"
# RecordId 记录ID,为空时添加记录,不为空时修改记录
recordId = None
# 权重
weight = 1
print("开始执行DDNS脚本...")


# 参数签名
def signParam(params):
    params['AccessKeyId'] = accessKeyId
    params['Format'] = "json"
    params['Version'] = "2015-01-09"
    params['SignatureMethod'] = "HMAC-SHA1"
    params['Timestamp'] = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    params['SignatureVersion'] = "1.0"
    params['SignatureNonce'] = datetime.datetime.now().timestamp()
    param_str = urllib.parse.urlencode(sorted(params.items()))
    sign_str = urllib.parse.quote(param_str)
    sign = urllib.parse.quote(base64.b64encode(
        hmac.new((accessKeySecret + "&").encode(), ("POST&%2F&" + sign_str).encode(), hashlib.sha1).digest()))
    return param_str + "&Signature=" + sign


# 获取本机ipv6地址
def getLocalIpv6():
    getIp = subprocess.Popen("ipconfig", stdout=subprocess.PIPE)
    output = (getIp.stdout.read())
    ipv6_pattern = '(([a-f0-9]{1,4}:){7}[a-f0-9]{1,4})'
    m = re.search(ipv6_pattern, str(output))
    if m is not None:
        return m.group()
    else:
        return None


# 修改脚本中记录ID
def updateFileRecordId(id):
    updating = True
    file_data = ""
    with open(os.path.basename(__file__), "r", encoding="utf-8") as f:
        for line in f:
            if updating and 'recordId =' in line:
                updating = False
                if id is None:
                    line = "recordId = None\n"
                else:
                    line = "recordId = '" + id + "'\n"
            file_data += line
    with open(os.path.basename(__file__), "w", encoding="utf-8") as f:
        f.write(file_data)
    print("更新记录ID为[{}]".format(id))
    return True


# 获取本机v6地址
ipv6 = getLocalIpv6()
if ipv6 is None:
    print("未获取到ipv6地址,请检查是否支持ipv6")
    sys.exit(1)

print("获取到当前ipv6地址:{}".format(ipv6))
# 获取子域名解析设置
print("开始检查子域名是否已存在解析:{}.{}".format(sub, domain))
params = signParam({"Action": "DescribeSubDomainRecords", "SubDomain": sub + "." + domain})
req = requests.post(requestUrl + params)
jsonObj = json.loads(req.content)

# 检查当前是否已经存在解析
existRecordId = False
if jsonObj['TotalCount'] > 0:
    for record in jsonObj['DomainRecords']['Record']:
        if record['Value'] == ipv6:
            if recordId is None:
                updateFileRecordId(record['RecordId'])
            print("已经存在当前主机ipv6解析")
            sys.exit(0)
        if recordId is not None and record['RecordId'] == recordId:
            existRecordId = True

# 更新记录ID为None
if existRecordId is False:
    # 更新记录ID为None
    updateFileRecordId(None)
    recordId = None
# 记录ID为空添加记录,不为空修改记录
if recordId is not None:
    print("存在记录ID[{}],执行修改解析记录".format(recordId))
    params = signParam({"Action": "UpdateDomainRecord", "RecordId": recordId, "RR": sub, "Type": "AAAA", "Value": ipv6})
    req = requests.post(requestUrl + params)
    jsonObj = json.loads(req.content)
    id = jsonObj['RecordId']
    if id is not None:
        print("域名[{}.{}]已成功修改解析到地址[{}],解析ID[{}]".format(sub, domain, ipv6, id))
        sys.exit(0)
else:
    print("不存在记录ID,执行添加解析记录")
    params = signParam({"Action": "AddDomainRecord", "DomainName": domain, "RR": sub, "Type": "AAAA", "Value": ipv6})
    req = requests.post(requestUrl + params)
    jsonObj = json.loads(req.content)
    id = jsonObj['RecordId']
    if id is not None and updateFileRecordId(id):
        print("域名[{}.{}]已成功添加解析到地址[{}],解析ID[{}]".format(sub, domain, ipv6, id))
        sys.exit(0)
