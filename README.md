# PasswordBook

PasswordBook 是用于加密记录密码信息的 Python 小工具，验证主密码通过后即可对密码本的信息进行增删查。

## 安装

安装依赖：```pip install -r requirements.txt```


## 使用

执行命令启动 ```python passwordbook.py```

- 如存在其他密钥文件须删除，仅保留py脚本。

- 在首次运行 PasswordBook 时，需生成密钥对，更新默认主密码。

- 建议将文件目录添加到环境变量中，以便使用。

## 依赖

- colorama
- pycryptodome
