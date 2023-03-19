#!/usr/bin/env python3

import os
import sys
import re
import base64
import pickle
from hashlib import md5
from getpass import getpass

from colorama import init
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import DES3, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad



os.chdir(os.path.dirname(os.path.abspath(__file__)))



def encrypt(message, public_key):
    """
    使用公钥加密消息

    参数：
    message - 待加密的消息，必须是 bytes 类型
    public_key - 公钥对象

    返回值：
    encrypted_message - 加密后的消息，bytes 类型
    """
    # 计算分块大小
    hash_func = SHA256.new()
    hash_size = hash_func.digest_size
    block_size = public_key.size_in_bytes() - 2 * hash_size - 2

    # 分块加密
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=hash_func)
    encrypted_blocks = []
    for i in range(0, len(message), block_size):
        block = message[i:i+block_size]
        encrypted_blocks.append(cipher.encrypt(block))

    # 拼接加密后的块
    encrypted_message = b''.join(encrypted_blocks)
    return encrypted_message

def decrypt(encrypted_message, private_key):
    """
    使用私钥解密消息

    参数：
    encrypted_message - 待解密的消息，必须是 bytes 类型
    private_key - 私钥对象

    返回值：
    decrypted_message - 解密后的消息，bytes 类型
    """
    # 计算分块大小
    hash_func = SHA256.new()
    hash_size = hash_func.digest_size
    block_size = private_key.size_in_bytes()

    # 分块解密
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=hash_func)
    decrypted_blocks = []
    for i in range(0, len(encrypted_message), block_size):
        block = encrypted_message[i:i+block_size]
        decrypted_blocks.append(cipher.decrypt(block))

    # 拼接解密后的块
    decrypted_message = b''.join(decrypted_blocks)
    return decrypted_message






def generate_key_pair(secret="mymasterpassword",key_size=2048):
    """
    生成RSA密钥对并保存到文件中

    参数：
    key_size - 密钥长度，默认为2048

    返回值：
    private_key - 私钥对象
    public_key - 公钥对象
    """
    key = RSA.generate(key_size)

    # 保存私钥到文件
    private_key = key.export_key()
    content = private_key + secret.encode("utf-8")
    with open('private.pem', 'wb') as f:
        f.write(des3_encrypt(secret,content))

    # 保存公钥到文件
    public_key = key.publickey().export_key()
    with open('public.pem', 'wb') as f:
        f.write(public_key)

    return key, key.publickey()






def load_public_key(filename):
    """
    从文件中加载公钥

    参数：
    filename - 公钥文件名

    返回值：
    public_key - 公钥对象
    """
    with open(filename, 'rb') as f:
        public_key = RSA.import_key(f.read())
    return public_key


def des3_encrypt(key, data):
    """
    使用3DES算法加密数据

    参数：
    key - 密钥，字符串类型
    data - 待加密的数据，bytes类型

    返回值：
    encrypted_data - 加密后的数据，bytes类型
    """
    # 对密钥进行MD5哈希，并截取前24个字节作为3DES算法的密钥
    key = md5(key.encode()).digest()[0:24]

    # 创建3DES加密器，采用ECB模式
    cipher = DES3.new(key, DES3.MODE_ECB)

    # 对数据进行填充
    padded_data = pad(data, DES3.block_size)

    # 执行加密操作
    encrypted_data = cipher.encrypt(padded_data)

    # 对加密后的数据进行Base64编码
    return base64.b64encode(encrypted_data)


def des3_decrypt(key, encrypted_data):
    """
    使用3DES算法解密数据

    参数：
    key - 密钥，字符串类型
    encrypted_data - 待解密的数据，bytes类型

    返回值：
    decrypted_data - 解密后的数据，bytes类型
    """
    # 对密钥进行MD5哈希，并截取前24个字节作为3DES算法的密钥
    key = md5(key.encode()).digest()[0:24]

    # 创建3DES解密器，采用ECB模式
    cipher = DES3.new(key, DES3.MODE_ECB)

    # 对加密后的数据进行Base64解码
    encrypted_data = base64.b64decode(encrypted_data)

    # 执行解密操作
    decrypted_data = cipher.decrypt(encrypted_data)

    # 对解密后的数据进行去填充
    return unpad(decrypted_data, DES3.block_size)



def load_private_key(secret,filename):
    """
    从文件中加载私钥

    参数：
    filename - 私钥文件名

    返回值：
    private_key - 私钥对象
    """
    with open(filename, 'rb') as f:
        content = f.read()
        content = des3_decrypt(secret, content)
        content = content[:-len(secret)]
        private_key = RSA.import_key(content)
    return private_key




def all_password():
    """
    打印所有已加密的密码
    """
    global all_list
    for passwd in all_list:
        print(f"\033[31m   [*] {passwd}\033[0m")



def select_password(searchKeyword):
    """
    根据关键字检索加密文件中的密码
    """
    global all_list
    cycleCount = 0
    for passwd in all_list:
        if searchKeyword in passwd:
            print(f"    \033[31m检索到密码： {passwd}\033[0m")
            cycleCount += 1
    if cycleCount == 0:
        print("    \033[32m未检索到您要查询的条目\033[0m")





def add_password(public_key,passwd):
    """
    添加新密码到加密文件中
    """
    global all_list
    all_list.append(passwd)
    save_passwd_book(public_key)



def remove_password(public_key,searchKeyword):
    """
    删除加密文件中的密码
    """
    global all_list
    remove_list = []
    cycleCount = 0

    for passwd in all_list:
        if searchKeyword in passwd:
            print(f"    \033[31m检索到密码： {passwd}\033[0m")
            remove_list.append(passwd)
            cycleCount += 1
    if cycleCount == 0:
        print("    \033[32m未检索到您要删除的密码\033[0m")
    else:
        while True:
            print(f"    \033[31m确定删除以上检索出的{cycleCount}个密码？(y/n)\033[0m",end="")
            flag = input()
            if flag == "y":
                all_list = [x for x in all_list if x not in remove_list]
                save_passwd_book(public_key)
                break
            elif flag == "n":
                break
            else:
                print("    \033[32m请输入正确的参数\033[0m")
                continue
            



def switch(private_key):
    """
    更改主密码
    """
    print("   \033[32m请输入原主密码： \033[m",end="")
    old_passwd = input()
    if secret == old_passwd:
        print("   \033[32m请输入新密码： \033[m",end="")
        new_passwd = getpass("")
        if new_passwd == "":
            print("   \033[31m密码不能为空！\033[m")
            return False
        elif new_passwd == old_passwd:
            print("   \033[31m新密码与原密码一致！\033[m")
            return False
        print("   \033[32m校验新密码： \033[m",end="")
        check_passwd = getpass("")
        if new_passwd == check_passwd:
            private_key = private_key.export_key()
            content = private_key + new_passwd.encode("utf-8")
            with open('private.pem', 'wb') as f:
                f.write(des3_encrypt(new_passwd,content))
        else:
            print("   \033[31m两次输入密码不一致！\033[m")
    else:
        print("   \033[31m主密码错误！\033[m")








def save_passwd_book(public_key):
    global all_list
    with open("passwd_book", "wb") as f:
        f.write(encrypt(pickle.dumps(all_list), public_key))



def load_passwd_book(private_key):
    if os.path.exists("passwd_book"):
        with open("passwd_book", "rb") as f:
            return decrypt(f.read(),private_key)
    else:
        return pickle.dumps([])




def authenticate(filename):
    global secret
    print("\033[32m>>>请输入主密码： \033[m",end="")
    secret = getpass("")
    with open(filename, 'rb') as f:
        content = f.read()
        try:    
            content = des3_decrypt(secret, content)
        except:
            print("    \033[31m密码错误，请重新输入...\033[0m")
            return False
        check_code = content[-len(secret):]
    if check_code.decode("utf-8") == secret:
        return True
    else:
        return False





def show():

    logo = """\033[31m

    ____                               ____                __
   / __ \____ ____________      ______/ / /_  ____  ____  / /__
  / /_/ / __ `/ ___/ ___/ | /| / / __  / __ \/ __ \/ __ \/ //_/
 / ____/ /_/ (__  |__  )| |/ |/ / /_/ / /_/ / /_/ / /_/ / ,<
/_/    \__,_/____/____/ |__/|__/\__,_/_.___/\____/\____/_/|_|           --by  0V0h


    \033[0m"""

    commands = {
        "  select": "查询密码 [searchKeyword]",
        "  all": "打印全部密码",
        "  add": "添加密码 [passwd]",
        "  remove": "删除密码 [searchKeyword]",
        "  exit": "退出",
        "  switch": "更改主密码"
    }

    print(logo)

    for command, description in commands.items():
        print(f"\033[32m{command:<10}{description}\033[m")
    print("\n\n")










#初始化 colorama 模块
init()

show()

if not os.path.exists("private.pem"):
    print("   \033[31m私钥不存在，是否创建密钥对(y/n)\033[0m",end="")
    flag = input()
    if flag == "y":
        generate_key_pair(key_size=2048)
        print("   \033[32m已创建密钥对，\033[0m",end="")
        print("\033[31m默认主密码：mymasterpassword\033[0m")
    else:
        sys.exit()


secret = ""
if not os.path.exists("public.pem"):
    print("    \033[31m公钥不存在，进程无法进行增删改操作...\033[0m")
    sys.exit()

while True:
    if authenticate("private.pem"):
        break

private_key = load_private_key(secret,"private.pem")
public_key = load_public_key("public.pem")

all_list = pickle.loads(load_passwd_book(private_key))
if not all_list:
    print("    \033[32m暂无加密文件，加密内容为空\033[m")





commands = ["select","all","add","remove","exit","switch"]

while True:
    print("\033[32m>>> \033[m",end="")
    cmd = input()
    if cmd == "":
        continue
    count = 0
    for command in commands:
        if command in cmd:
            if command == "exit":
                sys.exit()
            elif command == "all":
                all_password()
            elif command == "switch":
                switch(private_key)
            else:
                match = re.match(fr"{command}\s+(.*)", cmd)
                if match:
                    argument = match.group(1)
                    if argument == "":
                        print("    \033[32m无效命令！\033[0m")
                        continue
                else:
                    print("    \033[32m无效命令！\033[0m")
                    continue
                if command == "select":
                    select_password(argument)
                elif command == "remove":
                    remove_password(public_key,argument)
                elif command == "add":
                    add_password(public_key,argument)
        else:
            count += 1
        if count == 6:
            print("    \033[32m无效命令！\033[0m")
    










