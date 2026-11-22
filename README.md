# PVE NAT 端口转发管理

适用于 Proxmox VE 宿主机的 NAT 端口转发管理脚本：把公网端口映射到内网虚拟机，支持按虚拟机分组显示、备注、开机自动恢复。

```
 ■ 192.168.100.10   VM100 win2022  [1]
     1)  33588 → 3389   TCP+UDP  远程桌面

 ■ 192.168.100.11   VM101 debian  [3]
     2)   8157 → 8157   TCP      Alist
     3)   9119 → 9119   TCP      qBittorrent WebUI
     4)  50022 → 22     TCP      SSH
```

## 一键安装

在 PVE 宿主机上以 root 执行：

```bash
curl -fsSL https://raw.githubusercontent.com/xiaomonk88/pve-nat/main/pve-nat.sh -o /usr/local/sbin/pve-nat && chmod +x /usr/local/sbin/pve-nat && pve-nat
```

安装后随时输入 `pve-nat` 打开菜单。**更新**也是执行同一条命令，已有规则不受影响。

## 功能

| 菜单 | 说明 |
|---|---|
| 1. 查看端口转发 | 按目标 IP 分组，显示 PVE 虚拟机名称和备注 |
| 2. 添加端口转发 | 选择已有虚拟机或输入新 IP；公网端口留空自动随机分配；常用端口自动建议备注 |
| 3. 删除端口转发 | 支持一次删除多条（如 `2 5 8`） |
| 4. 编辑转发 | 修改备注 / 端口 / 目标 / 协议 |
| 5. 刷新虚拟机名称 | 自动识别 IP 对应的 PVE 虚拟机/容器（结果缓存，虚拟机关机也能显示） |
| 6. 查看原始 iptables 规则 | |
| 7. 系统设置 | 公网/内网接口、开启 IP 转发、内网上网（MASQUERADE） |

## 工作方式

- 规则保存在 `/etc/pve-nat/rules.db`（纯文本，一行一条：`公网端口|协议|目标IP|目标端口|备注`），可直接备份或迁移到其他机器
- iptables 规则只写入脚本专用链 `PVE_NAT_DNAT` / `PVE_NAT_FWD` / `PVE_NAT_POST`，不影响 PVE 防火墙、Docker 等其他规则
- 开机由 `pve-nat-restore.service` 执行 `pve-nat --apply` 从数据库重建规则
- 虚拟机名称识别：匹配 LXC / cloud-init 配置中的静态 IP，或通过 ARP 获取 MAC 后匹配虚拟机网卡

## 文件

| 路径 | 说明 |
|---|---|
| `/usr/local/sbin/pve-nat` | 脚本本体 |
| `/etc/pve-nat.conf` | 接口配置 |
| `/etc/pve-nat/rules.db` | 转发规则 |
| `/etc/pve-nat/hosts.db` | 虚拟机名称缓存 |
| `/etc/systemd/system/pve-nat-restore.service` | 开机恢复服务 |

## 从 V7 升级

首次运行会自动迁移 V7 的 `PVE-NAT-*` 规则（同端口的 TCP/UDP 合并为一条），并接管内网 MASQUERADE。V7 的 `/etc/iptables/rules.v4` 会备份为 `rules.v4.v7.bak`。

## 卸载

```bash
systemctl disable --now pve-nat-restore.service
rm -f /etc/systemd/system/pve-nat-restore.service /usr/local/sbin/pve-nat
iptables -t nat -D PREROUTING -j PVE_NAT_DNAT; iptables -t nat -F PVE_NAT_DNAT; iptables -t nat -X PVE_NAT_DNAT
iptables -t nat -D POSTROUTING -j PVE_NAT_POST; iptables -t nat -F PVE_NAT_POST; iptables -t nat -X PVE_NAT_POST
iptables -D FORWARD -j PVE_NAT_FWD; iptables -F PVE_NAT_FWD; iptables -X PVE_NAT_FWD
rm -rf /etc/pve-nat /etc/pve-nat.conf
```
