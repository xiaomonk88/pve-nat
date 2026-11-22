#!/bin/bash
# PVE NAT Port Forward Manager V8
#
# 一键安装:
#   curl -fsSL https://raw.githubusercontent.com/xiaomonk88/pve-nat/main/pve-nat.sh -o /usr/local/sbin/pve-nat && chmod +x /usr/local/sbin/pve-nat && pve-nat
#
# 用法:
#   pve-nat              交互菜单
#   pve-nat --apply      按数据库重建 iptables 规则（开机服务调用）
#
# 数据文件:
#   /etc/pve-nat.conf          接口配置
#   /etc/pve-nat/rules.db      转发规则  公网端口|协议|目标IP|目标端口|备注
#   /etc/pve-nat/hosts.db      虚拟机名缓存 IP|名称（自动识别）

VERSION="V8"
CONFIG="/etc/pve-nat.conf"
DATA_DIR="/etc/pve-nat"
DB="$DATA_DIR/rules.db"
HOSTS="$DATA_DIR/hosts.db"
DB_HEADER="# 公网端口|协议|目标IP|目标端口|备注"
BIN="/usr/local/sbin/pve-nat"
SERVICE_NAME="pve-nat-restore.service"
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME"
OLD_RULE_FILE="/etc/iptables/rules.v4"

CH_DNAT="PVE_NAT_DNAT"   # nat 表   端口映射
CH_POST="PVE_NAT_POST"   # nat 表   内网上网 MASQUERADE（可选）
CH_FWD="PVE_NAT_FWD"     # filter 表 放行转发流量

if [ -t 1 ]; then
    C_R=$'\e[31m'; C_G=$'\e[32m'; C_Y=$'\e[33m'; C_C=$'\e[36m'
    C_D=$'\e[90m'; C_B=$'\e[1m'; C_0=$'\e[0m'
fi

msg_ok(){   echo "${C_G}✔ $*${C_0}"; }
msg_err(){  echo "${C_R}✘ $*${C_0}"; }
msg_warn(){ echo "${C_Y}! $*${C_0}"; }
pause(){ echo; read -rp "按回车返回菜单..." _; }

# ======================= 配置 =======================

load_config(){
    PUBLIC_IF=""; LAN_IF=""; MASQ="no"; LAN_SUBNET=""
    [ -f "$CONFIG" ] && source "$CONFIG"
    local changed=0
    if [ -z "$PUBLIC_IF" ]; then
        PUBLIC_IF=$(ip route | awk '/^default/ {print $5; exit}'); changed=1
    fi
    if [ -z "$LAN_IF" ]; then
        LAN_IF="vmbr1"; changed=1
    fi
    [ "$changed" = 1 ] && save_config
}

save_config(){
cat > "$CONFIG" <<EOF
PUBLIC_IF="$PUBLIC_IF"
LAN_IF="$LAN_IF"
MASQ="$MASQ"
LAN_SUBNET="$LAN_SUBNET"
EOF
}

# ======================= 工具函数 =======================

valid_port(){ [[ "$1" =~ ^[0-9]{1,5}$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }

valid_ip(){
    [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    local o
    for o in "${BASH_REMATCH[@]:1}"; do [ "$((10#$o))" -le 255 ] || return 1; done
}

proto_label(){ case "$1" in tcp) echo "TCP" ;; udp) echo "UDP" ;; *) echo "TCP+UDP" ;; esac; }
protos_of(){   case "$1" in tcp+udp) echo "tcp udp" ;; *) echo "$1" ;; esac; }

clean_note(){
    local s="$1"
    s=${s//|//}
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

suggest_note(){
    case "$1" in
        21) echo "FTP" ;;           22) echo "SSH" ;;
        80) echo "HTTP" ;;          443) echo "HTTPS" ;;
        445) echo "SMB" ;;          1194) echo "OpenVPN" ;;
        3306) echo "MySQL" ;;       3389) echo "远程桌面" ;;
        5432) echo "PostgreSQL" ;;  5900) echo "VNC" ;;
        6379) echo "Redis" ;;       8006) echo "PVE面板" ;;
        25565) echo "Minecraft" ;;  27017) echo "MongoDB" ;;
        51820) echo "WireGuard" ;;
    esac
}

# 宿主机自己是否在监听该端口
host_listening(){ ss -Htuln 2>/dev/null | awk '{print $5}' | grep -qE "[:.]$1\$"; }

# ======================= 规则数据库 =======================

# 读入数组（按 IP、公网端口排序），编号即数组下标
load_rules(){
    R_PUB=(); R_PROTO=(); R_IP=(); R_DPORT=(); R_NOTE=()
    RULE_COUNT=0
    [ -f "$DB" ] || return
    local pub proto ip dport note
    while IFS='|' read -r pub proto ip dport note; do
        [ -z "$pub" ] && continue
        RULE_COUNT=$((RULE_COUNT+1))
        R_PUB[$RULE_COUNT]=$pub
        R_PROTO[$RULE_COUNT]=$proto
        R_IP[$RULE_COUNT]=$ip
        R_DPORT[$RULE_COUNT]=$dport
        R_NOTE[$RULE_COUNT]=$note
    done < <(grep -v '^#' "$DB" | sort -t'|' -k3,3V -k1,1n)
}

# 把数组写回数据库，参数为要跳过（删除）的编号
save_db(){
    local skip=" $* " i
    {
        echo "$DB_HEADER"
        for ((i=1; i<=RULE_COUNT; i++)); do
            [[ "$skip" == *" $i "* ]] && continue
            printf '%s|%s|%s|%s|%s\n' "${R_PUB[$i]}" "${R_PROTO[$i]}" \
                "${R_IP[$i]}" "${R_DPORT[$i]}" "${R_NOTE[$i]}"
        done
    } > "$DB.tmp" && mv -f "$DB.tmp" "$DB"
}

unique_ips(){ [ -f "$DB" ] && grep -v '^#' "$DB" | cut -d'|' -f3 | grep -v '^$' | sort -uV; }

# 公网端口冲突检测（协议有重叠才算冲突），输出冲突的编号
port_conflict(){
    local pub=$1 proto=$2 skip=$3 i
    for ((i=1; i<=RULE_COUNT; i++)); do
        [ "$i" = "$skip" ] && continue
        [ "${R_PUB[$i]}" = "$pub" ] || continue
        if [ "$proto" = "tcp+udp" ] || [ "${R_PROTO[$i]}" = "tcp+udp" ] || [ "${R_PROTO[$i]}" = "$proto" ]; then
            echo "$i"; return 0
        fi
    done
    return 1
}

random_port(){
    local p n
    for ((n=0; n<500; n++)); do
        p=$(shuf -i 20000-60000 -n 1)
        port_conflict "$p" "tcp+udp" >/dev/null && continue
        host_listening "$p" && continue
        echo "$p"; return 0
    done
    return 1
}

# ======================= 虚拟机名称自动识别 =======================

host_name(){ [ -f "$HOSTS" ] && awk -F'|' -v ip="$1" '$1==ip {print $2; exit}' "$HOSTS"; }

host_set(){
    touch "$HOSTS"
    awk -F'|' -v ip="$1" '$1!=ip' "$HOSTS" > "$HOSTS.tmp"
    echo "$1|$2" >> "$HOSTS.tmp"
    mv -f "$HOSTS.tmp" "$HOSTS"
}

# 只取配置主体，去掉快照段
conf_main(){ sed '/^\[/,$d' "$1"; }

conf_label(){
    local f=$1 id name
    id=$(basename "$f" .conf)
    if [[ "$f" == */lxc/* ]]; then
        name=$(conf_main "$f" | awk -F': ' '/^hostname:/ {print $2; exit}')
        echo "CT$id ${name}"
    else
        name=$(conf_main "$f" | awk -F': ' '/^name:/ {print $2; exit}')
        echo "VM$id ${name}"
    fi
}

# 识别 IP 对应的 PVE 虚拟机/容器
#  1) LXC 静态 IP / VM cloud-init ipconfig 中写死的 IP
#  2) 邻居表(ARP) 拿 MAC，再匹配 VM/CT 网卡 MAC
detect_host(){
    local ip=$1 f mac ip_re
    ip_re=${ip//./\\.}
    for f in /etc/pve/lxc/*.conf /etc/pve/qemu-server/*.conf; do
        [ -f "$f" ] || continue
        if conf_main "$f" | grep -qE "^(net|ipconfig)[0-9]+:.*[ ,]ip=${ip_re}/"; then
            conf_label "$f"; return 0
        fi
    done

    mac=$(ip neigh show "$ip" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="lladdr"){print $(i+1); exit}}')
    [ -z "$mac" ] && return 1
    for f in /etc/pve/qemu-server/*.conf /etc/pve/lxc/*.conf; do
        [ -f "$f" ] || continue
        if conf_main "$f" | grep -E '^net[0-9]+:' | grep -qi "$mac"; then
            conf_label "$f"; return 0
        fi
    done
    return 1
}

# 先 ping 一下让邻居表里有 MAC（即使目标禁 ping，ARP 也会完成）
probe_host(){
    local ip=$1 name
    ping -c1 -W1 "$ip" >/dev/null 2>&1
    name=$(detect_host "$ip") && host_set "$ip" "$name" && echo "$name"
}

refresh_hosts(){
    local ips ip name old
    ips=($(unique_ips))
    if [ ${#ips[@]} -eq 0 ]; then
        echo "暂无转发规则"; return
    fi
    echo "正在识别 PVE 虚拟机..."
    for ip in "${ips[@]}"; do ping -c1 -W1 "$ip" >/dev/null 2>&1 & done
    wait
    echo
    for ip in "${ips[@]}"; do
        if name=$(detect_host "$ip"); then
            host_set "$ip" "$name"
            printf "  ${C_G}✔${C_0} %-15s  %s\n" "$ip" "$name"
        else
            old=$(host_name "$ip")
            if [ -n "$old" ]; then
                printf "  ${C_Y}-${C_0} %-15s  %s ${C_D}(当前离线，沿用缓存)${C_0}\n" "$ip" "$old"
            else
                printf "  ${C_R}✘${C_0} %-15s  ${C_D}未识别（虚拟机离线或不在本机）${C_0}\n" "$ip"
            fi
        fi
    done
}

# ======================= iptables =======================

apply_rules(){
    local i p payload_nat="" payload_fwd=""
    load_rules
    for ((i=1; i<=RULE_COUNT; i++)); do
        for p in $(protos_of "${R_PROTO[$i]}"); do
            payload_nat+="-A $CH_DNAT -i $PUBLIC_IF -p $p --dport ${R_PUB[$i]} -m comment --comment pve-nat:${R_PUB[$i]} -j DNAT --to-destination ${R_IP[$i]}:${R_DPORT[$i]}"$'\n'
            payload_fwd+="-A $CH_FWD -i $PUBLIC_IF -o $LAN_IF -p $p -d ${R_IP[$i]} --dport ${R_DPORT[$i]} -m conntrack --ctstate NEW,ESTABLISHED,RELATED -m comment --comment pve-nat:${R_PUB[$i]} -j ACCEPT"$'\n'
        done
    done
    # 回程流量放行（Docker 会把 FORWARD 默认策略改成 DROP，必须显式放行）
    local base_fwd=""
    base_fwd+="-A $CH_FWD -i $LAN_IF -o $PUBLIC_IF -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"$'\n'
    base_fwd+="-A $CH_FWD -i $PUBLIC_IF -o $LAN_IF -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"$'\n'
    # 内网上网：MASQUERADE + 放行内网主动出站
    if [ "$MASQ" = "yes" ] && [ -n "$LAN_SUBNET" ]; then
        payload_nat+="-A $CH_POST -s $LAN_SUBNET -o $PUBLIC_IF -j MASQUERADE"$'\n'
        base_fwd+="-A $CH_FWD -s $LAN_SUBNET -i $LAN_IF -o $PUBLIC_IF -j ACCEPT"$'\n'
    fi
    payload_fwd="$base_fwd$payload_fwd"

    # --noflush 模式下声明自定义链会清空该链，只重建本脚本的链，其他规则不受影响
    if ! iptables-restore --noflush <<EOF
*nat
:$CH_DNAT - [0:0]
:$CH_POST - [0:0]
${payload_nat}COMMIT
*filter
:$CH_FWD - [0:0]
${payload_fwd}COMMIT
EOF
    then
        msg_err "iptables 规则应用失败"
        return 1
    fi

    iptables -t nat -C PREROUTING  -j $CH_DNAT 2>/dev/null || iptables -t nat -I PREROUTING 1 -j $CH_DNAT
    iptables -t nat -C POSTROUTING -j $CH_POST 2>/dev/null || iptables -t nat -I POSTROUTING 1 -j $CH_POST
    iptables        -C FORWARD     -j $CH_FWD  2>/dev/null || iptables -I FORWARD 1 -j $CH_FWD

    # 系统装了 netfilter-persistent 时同步保存，避免开机恢复出旧规则
    if command -v netfilter-persistent >/dev/null 2>&1; then
        mkdir -p /etc/iptables
        iptables-save > "$OLD_RULE_FILE"
    fi
    return 0
}

ensure_service(){
    local self want
    self=$(readlink -f "$0")
    if [ ! -f "$self" ]; then
        # 通过管道运行（bash <(curl ...)）时无法复制自身
        if [ ! -x "$BIN" ]; then
            msg_warn "未能安装到 $BIN，开机自动恢复将不可用，请按 README 的一键安装命令安装"
            return 1
        fi
    elif [ "$self" != "$BIN" ] && ! cmp -s "$self" "$BIN"; then
        install -m 755 "$self" "$BIN"
    fi
    want="[Unit]
Description=PVE NAT Port Forward Restore
After=network-online.target pve-firewall.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$BIN --apply
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target"
    if [ "$(cat "$SERVICE_FILE" 2>/dev/null)" != "$want" ]; then
        echo "$want" > "$SERVICE_FILE"
        systemctl daemon-reload
    fi
    systemctl is-enabled -q "$SERVICE_NAME" 2>/dev/null || systemctl enable -q "$SERVICE_NAME" 2>/dev/null
}

# ======================= V7 迁移 =======================

migrate_v7(){
    [ -f "$DB" ] && return 1
    echo "$DB_HEADER" > "$DB"

    local old r proto pub dest key ip dport masq_rule src
    old=$(iptables -t nat -S PREROUTING 2>/dev/null | grep -- 'PVE-NAT-')
    if [ -n "$old" ]; then
        echo "检测到 V7 规则，正在迁移..."
        local -A M=()
        local -a ORDER=()
        while read -r r; do
            proto=$(awk '{for(i=1;i<=NF;i++) if($i=="-p") print $(i+1)}' <<< "$r")
            pub=$(awk '{for(i=1;i<=NF;i++) if($i=="--dport") print $(i+1)}' <<< "$r")
            dest=$(awk '{for(i=1;i<=NF;i++) if($i=="--to-destination") print $(i+1)}' <<< "$r")
            [ -z "$pub" ] || [ -z "$dest" ] && continue
            key="$pub|${dest%:*}|${dest##*:}"
            if [ -z "${M[$key]}" ]; then
                ORDER+=("$key"); M[$key]=$proto
            elif [ "${M[$key]}" != "$proto" ]; then
                M[$key]="tcp+udp"
            fi
        done <<< "$old"
        for key in "${ORDER[@]}"; do
            IFS='|' read -r pub ip dport <<< "$key"
            echo "$pub|${M[$key]}|$ip|$dport|" >> "$DB"
        done
    fi

    # V7 靠 iptables-restore 恢复整表来持久化内网上网规则（MASQUERADE + FORWARD 放行），
    # V8 不再恢复整表，所以检测到内网 MASQUERADE 就接管，避免重启后虚拟机断网。
    # 即使 interfaces 里也配置了，规则重复一份也无害。
    masq_rule=$(lan_masq_rule)
    if [ -n "$masq_rule" ]; then
        src=$(awk '{for(i=1;i<=NF;i++) if($i=="-s") print $(i+1)}' <<< "$masq_rule")
        [ -z "$src" ] && src=$(lan_subnet_detect)
        if [ -n "$src" ]; then
            MASQ="yes"; LAN_SUBNET="$src"; save_config
            echo "已接管内网上网规则（MASQUERADE + 转发放行）: $src"
        fi
    fi

    if ! apply_rules; then
        rm -f "$DB"
        msg_err "迁移失败，V7 规则保持原样未改动"
        return 2
    fi

    # 新规则已生效（链在最前面），再删除 V7 的旧规则
    iptables -t nat -S PREROUTING | grep -- 'PVE-NAT-' | while read -r r; do
        iptables -t nat ${r/-A /-D }
    done
    iptables -S FORWARD | grep -- 'PVE-NAT-' | while read -r r; do
        iptables ${r/-A /-D }
    done

    if [ -f "$OLD_RULE_FILE" ] && ! command -v netfilter-persistent >/dev/null 2>&1; then
        mv -f "$OLD_RULE_FILE" "$OLD_RULE_FILE.v7.bak"
        echo "旧规则文件已备份为 $OLD_RULE_FILE.v7.bak"
    fi
    load_rules
    if [ -n "$old" ]; then
        msg_ok "迁移完成，共 $RULE_COUNT 条转发"
    else
        msg_ok "初始化完成"
    fi
    return 0
}

# ======================= 菜单功能 =======================

show_list(){
    load_rules
    echo
    if [ "$RULE_COUNT" -eq 0 ]; then
        echo "  暂无端口转发"
        return
    fi

    local -A CNT=()
    local i ip cur="" name note
    for ((i=1; i<=RULE_COUNT; i++)); do CNT[${R_IP[$i]}]=$(( ${CNT[${R_IP[$i]}]:-0} + 1 )); done

    for ((i=1; i<=RULE_COUNT; i++)); do
        ip=${R_IP[$i]}
        if [ "$ip" != "$cur" ]; then
            cur=$ip
            name=$(host_name "$ip")
            [ -z "$name" ] && name="${C_D}(未识别)${C_0}"
            [ "$i" -gt 1 ] && echo
            printf " ${C_G}■ %-15s${C_0}  ${C_B}%s${C_0}  ${C_D}[%d]${C_0}\n" "$ip" "$name" "${CNT[$ip]}"
        fi
        note=${R_NOTE[$i]}
        [ -z "$note" ] && note="${C_D}(未备注)${C_0}"
        printf "   %3d)  ${C_C}%5s${C_0} → %-5s  %-7s  ${C_Y}%s${C_0}\n" \
            "$i" "${R_PUB[$i]}" "${R_DPORT[$i]}" "$(proto_label "${R_PROTO[$i]}")" "$note"
    done
}

ask_proto(){
    local def=${1:-tcp} defn v
    case "$def" in tcp) defn=1 ;; udp) defn=2 ;; *) defn=3 ;; esac
    read -rp "协议 [1 TCP / 2 UDP / 3 TCP+UDP，默认 $defn]: " v
    case "${v:-$defn}" in
        1) PROTO="tcp" ;; 2) PROTO="udp" ;; 3) PROTO="tcp+udp" ;;
        *) return 1 ;;
    esac
}

# 手动输入的公网端口被宿主机占用时提醒
confirm_host_port(){
    host_listening "$1" || return 0
    msg_warn "宿主机正在监听 $1 端口，转发后公网将无法访问宿主机上的该服务"
    local ok; read -rp "仍然继续? [y/N]: " ok
    [[ "$ok" =~ ^[Yy]$ ]]
}

add_forward(){
    load_rules
    local ips ip sel i dport pub note def c name
    ips=($(unique_ips))

    echo
    if [ ${#ips[@]} -gt 0 ]; then
        echo "选择目标虚拟机:"
        for i in "${!ips[@]}"; do
            printf "  %2d) %-15s  %s\n" $((i+1)) "${ips[$i]}" "$(host_name "${ips[$i]}")"
        done
        echo "   n) 输入新 IP"
        read -rp "请选择（也可直接输入 IP）: " sel
        if [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le ${#ips[@]} ]; then
            ip=${ips[$((sel-1))]}
        elif valid_ip "$sel"; then
            ip=$sel
        elif [[ "$sel" =~ ^[nN]$ ]]; then
            read -rp "目标IP: " ip
        else
            msg_err "无效选择"; return
        fi
    else
        read -rp "目标IP: " ip
    fi
    valid_ip "$ip" || { msg_err "IP 格式错误"; return; }

    read -rp "目标端口: " dport
    valid_port "$dport" || { msg_err "端口错误（1-65535）"; return; }

    ask_proto tcp || { msg_err "无效协议"; return; }

    read -rp "公网端口 [回车随机分配]: " pub
    if [ -z "$pub" ]; then
        pub=$(random_port) || { msg_err "未找到空闲端口"; return; }
        echo "  已分配公网端口: ${C_C}$pub${C_0}"
    else
        valid_port "$pub" || { msg_err "端口错误（1-65535）"; return; }
        if c=$(port_conflict "$pub" "$PROTO"); then
            msg_err "公网端口 $pub 已被占用: ${R_IP[$c]}:${R_DPORT[$c]} ${R_NOTE[$c]}"; return
        fi
        confirm_host_port "$pub" || return
    fi

    def=$(suggest_note "$dport")
    if [ -n "$def" ]; then
        read -rp "备注 [$def]: " note
        note=${note:-$def}
    else
        read -rp "备注: " note
    fi
    note=$(clean_note "$note")

    RULE_COUNT=$((RULE_COUNT+1))
    R_PUB[$RULE_COUNT]=$pub; R_PROTO[$RULE_COUNT]=$PROTO; R_IP[$RULE_COUNT]=$ip
    R_DPORT[$RULE_COUNT]=$dport; R_NOTE[$RULE_COUNT]=$note
    save_db
    apply_rules || return

    echo
    msg_ok "已添加  $pub → $ip:$dport  $(proto_label "$PROTO")  $note"

    if [ -z "$(host_name "$ip")" ]; then
        name=$(probe_host "$ip") && echo "  识别虚拟机: $name"
    fi
}

# 读取编号，输出到 SEL_NUMS
read_nums(){
    local prompt=$1 multi=$2 input n
    SEL_NUMS=()
    read -rp "$prompt" input
    [ -z "$input" ] && return 1
    for n in $input; do
        if ! [[ "$n" =~ ^[0-9]+$ ]] || [ "$n" -lt 1 ] || [ "$n" -gt "$RULE_COUNT" ]; then
            msg_err "编号 $n 不存在"; return 1
        fi
        SEL_NUMS+=("$n")
    done
    if [ "$multi" != "multi" ] && [ ${#SEL_NUMS[@]} -gt 1 ]; then
        msg_err "只能输入一个编号"; return 1
    fi
}

delete_forward(){
    show_list
    [ "$RULE_COUNT" -eq 0 ] && return
    echo
    read_nums "输入要删除的编号（多个用空格分隔）: " multi || return

    local n ok
    echo
    echo "将删除:"
    for n in "${SEL_NUMS[@]}"; do
        printf "  %5s → %s:%s  %s  %s\n" "${R_PUB[$n]}" "${R_IP[$n]}" "${R_DPORT[$n]}" \
            "$(proto_label "${R_PROTO[$n]}")" "${R_NOTE[$n]}"
    done
    read -rp "确认 [y/N]: " ok
    [[ "$ok" =~ ^[Yy]$ ]] || return

    save_db "${SEL_NUMS[@]}"
    apply_rules && msg_ok "已删除 ${#SEL_NUMS[@]} 条转发"
}

edit_forward(){
    show_list
    [ "$RULE_COUNT" -eq 0 ] && return
    echo
    read_nums "输入要编辑的编号: " || return

    local n=${SEL_NUMS[0]} v c
    local ip=${R_IP[$n]} dport=${R_DPORT[$n]} pub=${R_PUB[$n]} note=${R_NOTE[$n]}

    echo
    echo "直接回车保留原值"
    read -rp "目标IP [$ip]: " v
    if [ -n "$v" ]; then valid_ip "$v" || { msg_err "IP 格式错误"; return; }; ip=$v; fi

    read -rp "目标端口 [$dport]: " v
    if [ -n "$v" ]; then valid_port "$v" || { msg_err "端口错误"; return; }; dport=$v; fi

    ask_proto "${R_PROTO[$n]}" || { msg_err "无效协议"; return; }

    read -rp "公网端口 [$pub]: " v
    if [ -n "$v" ]; then valid_port "$v" || { msg_err "端口错误"; return; }; fi
    if c=$(port_conflict "${v:-$pub}" "$PROTO" "$n"); then
        msg_err "公网端口 ${v:-$pub} 已被占用: ${R_IP[$c]}:${R_DPORT[$c]} ${R_NOTE[$c]}"; return
    fi
    if [ -n "$v" ] && [ "$v" != "$pub" ]; then
        confirm_host_port "$v" || return
        pub=$v
    fi

    read -rp "备注 [${note:-无}]（输入 - 清空）: " v
    if [ "$v" = "-" ]; then note=""; elif [ -n "$v" ]; then note=$(clean_note "$v"); fi

    R_IP[$n]=$ip; R_DPORT[$n]=$dport; R_PROTO[$n]=$PROTO; R_PUB[$n]=$pub; R_NOTE[$n]=$note
    save_db
    apply_rules || return
    msg_ok "已修改  $pub → $ip:$dport  $(proto_label "$PROTO")  $note"

    [ -z "$(host_name "$ip")" ] && probe_host "$ip" >/dev/null
}

show_raw(){
    echo "${C_B}== nat / $CH_DNAT（端口映射）==${C_0}"
    iptables -t nat -L $CH_DNAT -n -v --line-numbers
    echo
    echo "${C_B}== filter / $CH_FWD（转发放行）==${C_0}"
    iptables -L $CH_FWD -n -v --line-numbers
    echo
    echo "${C_B}== nat / POSTROUTING ==${C_0}"
    iptables -t nat -L POSTROUTING -n -v --line-numbers
    echo
    echo "${C_B}== nat / $CH_POST ==${C_0}"
    iptables -t nat -L $CH_POST -n -v --line-numbers
}

lan_subnet_detect(){
    ip -4 route show dev "$LAN_IF" proto kernel scope link 2>/dev/null | awk '{print $1; exit}'
}

# 查找 POSTROUTING 中针对内网网段的 MASQUERADE（忽略 Docker 等其他网段的规则）
lan_masq_rule(){
    local sub; sub=$(lan_subnet_detect)
    iptables -t nat -S POSTROUTING 2>/dev/null | grep -- '-j MASQUERADE' | \
        awk -v s="$sub" -v o="$PUBLIC_IF" '{
            src=""; out=""; neg=0
            for(i=1;i<=NF;i++){
                if($i=="-s") src=$(i+1)
                if($i=="-o"){ out=$(i+1); if($(i-1)=="!") neg=1 }
            }
            if ((s!="" && src==s) || (src=="" && out==o && !neg)) { print; exit }
        }'
}

settings(){
    local c v fwd masq_ext masq_txt sub
    while true; do
        fwd=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
        masq_ext=$(lan_masq_rule)
        if [ "$MASQ" = "yes" ]; then
            masq_txt="${C_G}由本脚本管理${C_0}（$LAN_SUBNET）"
        elif [ -n "$masq_ext" ]; then
            masq_txt="${C_Y}外部规则${C_0}（重启后可能丢失，建议交给本脚本管理）"
        else
            masq_txt="${C_R}未配置${C_0}（虚拟机无法上网）"
        fi

        clear
        echo "================================"
        echo " 系统设置"
        echo "================================"
        echo " 1. 公网接口: $PUBLIC_IF"
        echo " 2. 内网接口: $LAN_IF"
        if [ "$fwd" = "1" ]; then
            echo " 3. IP 转发:  ${C_G}已开启${C_0}"
        else
            echo " 3. IP 转发:  ${C_R}未开启${C_0}（端口转发不会生效）"
        fi
        echo " 4. 内网上网（MASQUERADE + 转发放行）: $masq_txt"
        echo " 0. 返回"
        echo
        read -rp "请选择: " c
        case "$c" in
            1|2)
                local cur; [ "$c" = 1 ] && cur=$PUBLIC_IF || cur=$LAN_IF
                ip -br link | awk '{printf "  %-12s %s\n", $1, $2}'
                read -rp "新接口名 [$cur]: " v
                if [ -n "$v" ] && [ "$v" != "$cur" ]; then
                    if ! ip link show "$v" >/dev/null 2>&1; then
                        msg_err "接口 $v 不存在"; pause; continue
                    fi
                    [ "$c" = 1 ] && PUBLIC_IF=$v || LAN_IF=$v
                    save_config
                    apply_rules && msg_ok "已更新并重建规则"
                    pause
                fi
                ;;
            3)
                if [ "$fwd" = "1" ]; then
                    echo "IP 转发已开启"
                else
                    sysctl -qw net.ipv4.ip_forward=1
                    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-pve-nat.conf
                    msg_ok "已开启并持久化（/etc/sysctl.d/99-pve-nat.conf）"
                fi
                pause
                ;;
            4)
                if [ "$MASQ" = "yes" ]; then
                    msg_warn "关闭后若没有其他规则兜底，虚拟机将无法上网"
                    read -rp "关闭本脚本管理的内网上网规则? [y/N]: " v
                    if [[ "$v" =~ ^[Yy]$ ]]; then
                        MASQ="no"; save_config; apply_rules && msg_ok "已关闭"
                    fi
                else
                    [ -n "$masq_ext" ] && echo "当前外部规则: $masq_ext"
                    sub=$(lan_subnet_detect)
                    read -rp "内网网段 [$sub]: " v
                    sub=${v:-$sub}
                    if [ -z "$sub" ]; then
                        msg_err "无法确定内网网段"
                    else
                        MASQ="yes"; LAN_SUBNET=$sub; save_config
                        apply_rules && msg_ok "已开启 MASQUERADE: $sub → $PUBLIC_IF"
                    fi
                fi
                pause
                ;;
            0|q|"") return ;;
        esac
    done
}

# ======================= 入口 =======================

if [ "$(id -u)" -ne 0 ]; then
    echo "请使用 root 运行"; exit 1
fi
for cmd in iptables iptables-restore ip ss shuf; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "缺少命令: $cmd"; exit 1; }
done

mkdir -p "$DATA_DIR"
load_config

if [ "$1" = "--apply" ]; then
    [ -f "$DB" ] || echo "$DB_HEADER" > "$DB"
    apply_rules
    exit $?
fi

migrate_v7; rc=$?
if [ "$rc" -eq 2 ]; then
    exit 1
elif [ "$rc" -eq 0 ]; then
    ensure_service
    echo
    refresh_hosts
    pause
else
    ensure_service
    apply_rules >/dev/null
fi

while true; do
    load_rules
    host_count=$(unique_ips | grep -c .)
    clear
    echo "========================================"
    echo " PVE NAT 端口转发管理 $VERSION"
    echo "========================================"
    echo " 公网接口: $PUBLIC_IF    内网接口: $LAN_IF"
    echo " ${host_count} 台虚拟机 / ${RULE_COUNT} 条转发"
    [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" = "1" ] || \
        msg_warn "IP 转发未开启，端口转发不会生效（菜单 7 → 3 开启）"
    echo
    echo " 1. 查看端口转发"
    echo " 2. 添加端口转发"
    echo " 3. 删除端口转发"
    echo " 4. 编辑转发（备注 / 端口 / 目标）"
    echo " 5. 刷新虚拟机名称（自动识别）"
    echo " 6. 查看原始 iptables 规则"
    echo " 7. 系统设置"
    echo " 0. 退出"
    echo
    read -rp "请选择: " C

    case "$C" in
        1) show_list; pause ;;
        2) add_forward; pause ;;
        3) delete_forward; pause ;;
        4) edit_forward; pause ;;
        5) refresh_hosts; pause ;;
        6) show_raw; pause ;;
        7) settings ;;
        0|q) exit 0 ;;
    esac
done
