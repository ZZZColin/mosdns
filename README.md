基于 Go 语言实现的 DNS 转发引擎,fork 自 IrineSistiana/mosdns v5,插件架构与配置格式与上游兼容。

核心新增为 query_log 插件,提供查询追踪能力。配置中只需添加一个实例即可对所有 sequence 插件处理的请求生效,无需接入具体转发链路。关键配置字段如下:

  listen:web 界面监听地址,默认 :9092。
  max_records:内存中保留的最近查询条数,默认 200。
  username / password:可选,任一非空则对 web 界面和接口启用 HTTP Basic Auth,均为空则不启用认证。
  hide_client_ip:布尔值,默认 false,置为 true 时记录中不包含客户端 IP。

服务启动后,浏览器访问监听地址的根路径即为可视化界面,数据接口为 /api/records(JSON 格式),返回每条查询的时间、客户端(如未隐藏)、域名、类型、最终结果与耗时,以及按执行顺序排列的每一步规则匹配情况,并对 fallback、dual_selector 等并发分支做了单独处理,保证并发场景下记录不串行、不丢失。

此外还包括为 forward 插件增加的 SOCKS5 认证支持,以及若干针对连接处理与并发访问的稳定性修复。

许可证与上游一致,采用 GPL-3.0。
