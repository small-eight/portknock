# portknock
 port knocking 技术的python验证实现。客户端按照顺序访问指定端口后，服务器防火墙会为该IP地址开放服务端口，可以实现在互联网侧对端口的隐藏。


 例如：192.168.1.1 22 端口默认为关闭状态，当客户机192.168.2.1 依次访问600 700 800 后，22端口将会为192.168.2.1开放，其他用户无法访问该端口。

 ## 注意
port knocking ，有以下几个问题 

1，暴力破解，端口顺序会被暴力破解。 <br>
2，流量监控，如果网络被监控，很容易找出端口顺序。 <br>
3，软件泄露，如果客户端泄露，很容易通过逆向或者行为分析找到访问顺序。 <br>

建议使用SPA技术，[SPA python](https://github.com/small-eight/spa)验证实现
