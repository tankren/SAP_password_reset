import pyrfc
import string
import secrets
import base64
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.utils import formataddr
from ldap3 import Server, Connection, ALL, NTLM, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, AUTO_BIND_NO_TLS, SUBTREE
import json

    # 生成随机密码
def newpass():    
    letters = string.ascii_letters
    uppercases = string.ascii_uppercase
    digits = string.digits
    special_chars = string.punctuation
    alphabet = uppercases + letters + digits + special_chars
    pwd_length = 15
    while True:
        new_password = ""
        for i in range(pwd_length):
            new_password += "".join(secrets.choice(alphabet))     
        if not new_password[-1] in special_chars and any(c.isupper() for c in new_password) and sum(c.isdigit() for c in new_password) >= 2 :
            break
    return new_password    

def send_mail(username, mailaddress, new_password):
    mail_host = "mailintern.vhit-weifu.com"
    # 邮件发送方邮箱地址
    sender = "no-reply.IDM@vhit-weifu.com"
    # 邮件接受方邮箱地址，注意需要[]包裹，这意味着你可以写多个邮件地址群发
    receivers = mailaddress
    # 设置email信息
    # 邮件内容设置
    email = MIMEMultipart()
    # 邮件主题
    email["Subject"] = f"Identity Management - SAP Password Change"
    # 发送方信息
    email["From"] = formataddr(["VHCN IDM", sender])
    # 接受方信息
    email["To"] = receivers

    if not receivers == "":
        email_content = """\
<html>
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
  <title>SAP密码重置</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
</head>
<body style="margin: 0; padding: 0;">
  <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%">
    <tr>
      <td style="padding: 20px 0 30px 0;">
        <table align="center" border="0" cellpadding="0" cellspacing="0" width="600" style="border-collapse: collapse; border: 1px solid #cccccc;">
          <tr>
            <td align="center" bgcolor="#005691" style="padding: 20px 0 20px 0;">
                <h1 style="color: #ffffff; font-size: 24px; margin: 0;  font-family: Microsoft YaHei;">SAP密码重置成功</h1>
            </td>
          </tr>  
          <tr>
            <td bgcolor="#ffffff" style="padding: 30px 20px 30px 20px;">
              <table border="0" cellpadding="0" cellspacing="0" width="100%" style="border-collapse: collapse;">
                <tr>
                  <td align="center" style="color: #000000; font-family: Microsoft YaHei;">
                    <p style="margin: 0;">您的SAP初始密码如下, 请尽快修改并请妥善保管！</p>
                    <br>
                    <table width="97%" border="0" cellpadding="1" cellspacing="1" class="ChangesTable">
                    <colgroup>
                    <col width="30%">
                    <col width="30%">
                    <col width="40%">
                    </colgroup>
                    <th>SAP System</th><th>User</th><th>Initial Password</th>
                    <tr>
                    <td align="center"> {SAPsystem} </td><td align="center"> {username} </td><td align="center" style="color: red; font-family: Times;"> {new_password} </td>
                    </tr>
                    </table>            
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td bgcolor="#005691" style="padding: 10px 10px;">
                <table border="0" cellpadding="0" cellspacing="0" width="100%" style="border-collapse: collapse;">
                <tr>
                  <td align="center" style="color: #00000; font-family: Microsoft YaHei; font-size: 14px;">
                    <p style="color: #ffffff; margin: 0;">Powered by VHCN ICO</p>
                  </td>
                  <td align="right">
                    <table border="0" cellpadding="0" cellspacing="0" style="border-collapse: collapse;">
                    </table>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
""".format(SAPsystem=SAPsystem, username=username, new_password=new_password)
    else:
        print(f"邮箱不存在...")
        exit()

    email.attach(MIMEText(email_content, "html", "utf-8"))
    try:
        smtpObj = smtplib.SMTP(mail_host, 25)
        # 发送
        smtpObj.sendmail(sender, receivers, email.as_string())
        # 退出
        smtpObj.quit()
        print(f"邮件发送成功...")
    except smtplib.SMTPException as e:
        print(f"{e}")
        
    # SAP连接参数
def unlock_reset(username, mailaddress):    
    new_password=newpass()
    conn_params = {
        "user": "RFC_SAPUM",
        "passwd": base64.b64decode("bjJdYnB3UHlQSzNbM0gj").decode("utf-8"),
        "ashost": f"epsosap{SAPsystem}.vh.lan",
        "sysid": f"{SAPsystem}",
        "sysnr": "00",
        "client": "011",
    }

    # 创建SAP连接
    conn = pyrfc.Connection(**conn_params)

    # Unlock user
    try:
        conn.call("BAPI_USER_UNLOCK", USERNAME=username)
    except Exception as ex:
        conn.close()
        print({"error": ex})

    # 调用BAPI_USER_CHANGE函数修改密码
    password = {"BAPIPWD": new_password}
    passowrdx = {"BAPIPWD": "X"}
    try:
        result = conn.call(
            "BAPI_USER_CHANGE",
            USERNAME=username,
            PASSWORD=password,
            PASSWORDX=passowrdx,
        )
    except Exception as ex:
        conn.close()
        print({"error": ex})

    # 关闭连接
    conn.close()

    # 判断重置密码是否成功
    if result["RETURN"][0]["TYPE"] == "E":
        # 如果重置失败，返回一个包含错误信息的json
        print({"error": result["RETURN"][0]["MESSAGE"]})
        print(f"修改失败! 重新尝试...")
        unlock_reset(username, mailaddress)
    else:
        # 如果重置成功，返回新密码的json
        print(f"修改成功! 发送用户邮件...")
        send_mail(username, mailaddress, new_password)


def main(displayName):
    print("查询用户信息......")
    adserver = Server("WX9ADS01.vh.lan", connect_timeout=5)
    try:
        adconn=Connection(adserver, user='vh\\vhcn', password="P@ssword123", authentication=NTLM, read_only=True, auto_bind=True)
    except Exception as ex:
        print(ex)    

    search_filter = f"(&(displayName=*{displayName}*))"

    try:
        adconn.search('OU=Useraccounts,OU=Wx9,DC=vh,DC=lan', search_filter, attributes=["sAMAccountName", "mail"])
    except Exception as ex:
        print(ex)    

    res=adconn.response_to_json()
    res=json.loads(res)["entries"]
    try:
        res=json.dumps(res[0])
        info=json.loads(res)["attributes"]
        print(f"用户信息：{info}")
        username=info["sAMAccountName"]
        mailaddress=info["mail"]
        print('开始解锁并重置密码......')
        unlock_reset(username, mailaddress)

    except Exception as ex:
        print("用户不存在，请重新输入")
        displayName=input("输入拼音姓名(如REN Chenlong或Chenlong)：")
        main(displayName)

displayName=input("输入拼音姓名(如REN Chenlong或Chenlong)：")
options = ['PVH', 'QVH', 'DVH']
user_input = ''

input_message = "选择需要修改密码的系统:\n"
for index, item in enumerate(options):
    input_message += f'{index+1}) {item}\n'
input_message += '输入选项: '

while user_input.lower() not in map(str, range(1, len(options) + 1)):
    user_input = input(input_message)
print('选择的系统为:' + options[int(user_input) - 1])
SAPsystem=options[int(user_input) - 1]

main(displayName)


