# clashsub-change

项目地址[Commits · wyf1521/clashsub-change](https://github.com/wyf1521/clashsub-change)

git拉取项目之后，请确保有pip和streamlit，没有的话

```
apt update
apt install pip
pip install streamlit
```

以上是ubuntu系统，其余系统同理。



配置文件路径使用nano或者vim修改***/scripts/install_service.sh***，

搜索关键词**Environment**

```
CLASHSUB_STATIC_DIR=/opt/1panel/www/sites/change.padaro.top/index/static
这里是文件写在哪里，我挂载到网站上面，这里请根据文件自行修改
```

```
CLASHSUB_STATIC_URL_PREFIX=/static
使用的url前缀。因为我的网站目录在/opt/1panel/www/sites/change.padaro.top/index，然后文件存放在/static/xxxx.ymal，所以这里填/static
```

```
CLASHSUB_SERVER_HOST=https://change.padaro.top
协议和域名，必须要改成自己的ip，否则无法访问
```

修改好之后赋予执行权限然后运行，直接访问对应的地址，端口为**8501**

```
chmod +x install_service.sh
./install_service.sh
```

自定义端口号：

```
sudo PORT=8600 bash scripts/install_service.sh
```

