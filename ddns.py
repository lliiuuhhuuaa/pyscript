#!/usr/bin/env python
# coding=utf-8
import base64
import datetime
import hashlib
import hmac
import json
import os
import re
import subprocess
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
# 解析ipv6子域名,域名子域名[test],解析后[test.lliiuuhhuuaa.cn],主域名记录要填写”@”,为空不解析ipv6地址
sub_v6 = "test"
# 解析ipv4子域名,中转子域名[transfer],解析后[transfer.lliiuuhhuuaa.cn]会指向公网ipv4地址，为空不解析ipv4地址,不需要中转填与sub相同的即可
sub_v4 = "transfer"
# RecordId 记录ID,为空时添加记录,不为空时修改记录,v6 ID
record_v6 = '20408622573429760'
# RecordId 记录ID,为空时添加记录,不为空时修改记录,v4 ID
record_v4 = '20408622573429760'

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


# 获取本机ipv4地址
def getLocalIpv4():
    print("开始获取公网ipv4地址...")
    req = requests.get("http://ip.42.pl/raw")
    return req.text


# 修改脚本中记录ID
def updateFileRecordId(key, id):
    updating = True
    file_data = ""
    with open(os.path.basename(__file__), "r", encoding="utf-8") as f:
        for line in f:
            if updating and key in line:
                updating = False
                if id is None:
                    line = key + "None\n"
                else:
                    line = key + "'" + id + "'\n"
            file_data += line
    with open(os.path.basename(__file__), "w", encoding="utf-8") as f:
        f.write(file_data)
    print("更新记录ID为[{}]".format(id))
    return True


# ipv6地址解析
def parsingIpv6():
    print("开始进行ipv6地址解析...")
    # 获取本机v6地址
    ipv6 = getLocalIpv6()
    if ipv6 is None:
        print("未获取到ipv6地址,请检查是否支持ipv6")
        return
    print("获取到当前ipv6地址:{}".format(ipv6))
    # 获取子域名解析设置
    print("开始检查子域名是否已存在解析:{}.{}".format(sub_v6, domain))
    params = signParam({"Action": "DescribeSubDomainRecords", "SubDomain": sub_v6 + "." + domain})
    req = requests.post(requestUrl + params)
    jsonObj = json.loads(req.content)
    # 检查当前是否已经存在解析
    exist_record_id = False
    if "Message" in jsonObj.keys():
        print('请示发生错误:{}'.format(jsonObj['Message']))
        return

    if jsonObj['TotalCount'] > 0:
        for record in jsonObj['DomainRecords']['Record']:
            if record['Value'] == ipv6:
                if record_v6 is None:
                    updateFileRecordId('record_v6 = ', record['RecordId'])
                print("已经存在当前主机ipv6解析")
                return
            if record_v6 is not None and record['RecordId'] == record_v6:
                exist_record_id = True

    # 记录ID为空添加记录,不为空修改记录
    if exist_record_id is True:
        print("存在记录ID[{}],执行修改解析记录".format(record_v6))
        params = signParam(
            {"Action": "UpdateDomainRecord", "RecordId": record_v6, "RR": sub_v6, "Type": "AAAA", "Value": ipv6})
        req = requests.post(requestUrl + params)
        jsonObj = json.loads(req.content)
        id = jsonObj['RecordId']
        if id is not None:
            print("域名[{}.{}]已成功修改解析到地址[{}],解析ID[{}]".format(sub_v6, domain, ipv6, id))
            return
    else:
        print("不存在记录ID,执行添加解析记录")
        params = signParam(
            {"Action": "AddDomainRecord", "DomainName": domain, "RR": sub_v6, "Type": "AAAA", "Value": ipv6})
        req = requests.post(requestUrl + params)
        jsonObj = json.loads(req.content)
        id = jsonObj['RecordId']
        if id is not None and updateFileRecordId('record_v6 = ', id):
            print("域名[{}.{}]已成功添加解析到地址[{}],解析ID[{}]".format(sub_v6, domain, ipv6, id))
            return


# ipv4地址解析
def parsingIpv4():
    print("开始进行ipv4地址解析...")
    # 获取本机v6地址
    ipv4 = getLocalIpv4()
    if ipv4 is None:
        print("未获取到ipv4公网地址,请检查网络连接是否正常")
        return
    print("获取到当前ipv4地址:{}".format(ipv4))

    # 获取子域名解析设置
    print("开始检查子域名是否已存在解析:{}.{}".format(sub_v4, domain))
    params = signParam({"Action": "DescribeSubDomainRecords", "SubDomain": sub_v4 + "." + domain})
    req = requests.post(requestUrl + params)
    jsonObj = json.loads(req.content)

    # 检查当前是否已经存在解析
    exist_record_id = False
    if "Message" in jsonObj.keys():
        print('请示发生错误:{}'.format(jsonObj['Message']))
        return

    if jsonObj['TotalCount'] > 0:
        for record in jsonObj['DomainRecords']['Record']:
            if record['Value'] == ipv4:
                if record_v4 is None:
                    updateFileRecordId('record_v4 = ', record['RecordId'])
                print("已经存在当前主机ipv4解析")
                return
            if record_v4 is not None and record['RecordId'] == record_v4:
                exist_record_id = True

    # 记录ID为空添加记录,不为空修改记录
    if exist_record_id is True:
        print("存在记录ID[{}],执行修改解析记录".format(record_v4))
        params = signParam(
            {"Action": "UpdateDomainRecord", "RecordId": record_v4, "RR": sub_v4, "Type": "A", "Value": ipv4})
        req = requests.post(requestUrl + params)
        jsonObj = json.loads(req.content)
        id = jsonObj['RecordId']
        if id is not None:
            print("域名[{}.{}]已成功修改解析到地址[{}],解析ID[{}]".format(sub_v4, domain, ipv4, id))
            return
    else:
        print("不存在记录ID,执行添加解析记录")
        params = signParam(
            {"Action": "AddDomainRecord", "DomainName": domain, "RR": sub_v4, "Type": "A", "Value": ipv4})
        req = requests.post(requestUrl + params)
        jsonObj = json.loads(req.content)
        id = jsonObj['RecordId']
        if id is not None and updateFileRecordId('record_v4 = ', id):
            print("域名[{}.{}]已成功添加解析到地址[{}],解析ID[{}]".format(sub_v4, domain, ipv4, id))
            return


# 解析ipv6
parsingIpv6()
# 解析ipv4
parsingIpv4()
