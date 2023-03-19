# PasswordBook

PasswordBook 是一个用于加密记录密码信息的 Python 小工具，验证主密码通过后就可以对密码本里的信息进行增删改查。

## 安装

安装依赖：```pip install -r requirements.txt```


## 使用

执行命令启动 ```python passwordbook.py```

- 在首次运行 PasswordBook 时，需要生成密钥对，更新默认主密码。设置后，您将可以在密码本中查看、添加、删除和修改密码信息。

- 建议将文件目录添加到环境变量中，以便使用。

## 依赖

- colorama
- pycryptodome
