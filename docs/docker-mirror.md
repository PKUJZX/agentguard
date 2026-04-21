# 配置 Docker 镜像加速（国内用户必看）

> 症状：`./scripts/demo.sh` 报错 `failed to resolve reference "docker.io/library/postgres:16-alpine": dial tcp …: i/o timeout`。
>
> 原因：国内直连 Docker Hub 几乎必然超时；老的公共镜像源（`dockerproxy.com`、`mirror.baidubce.com`、`docker.m.daocloud.io` 等）在 2024 年陆续关停。下面给出**当前仍可用的**镜像源清单与配置方式。

## 1. 编辑 Docker daemon 配置

```bash
sudo mkdir -p /etc/docker
sudo tee /etc/docker/daemon.json > /dev/null <<'EOF'
{
    "registry-mirrors": [
        "https://docker.1ms.run",
        "https://docker.xuanyuan.me",
        "https://hub.rat.dev",
        "https://docker.1panel.live",
        "https://proxy.1panel.live",
        "https://docker.nju.edu.cn",
        "https://docker.mirrors.sjtug.sjtu.edu.cn"
    ]
}
EOF
```

## 2. 重启 Docker 守护进程

**Linux (systemd)**：

```bash
sudo systemctl daemon-reload
sudo systemctl restart docker
```

**WSL2**（你当前是 `LAPTOP-EKQGUIGU`，看起来是 WSL）：

```bash
# 在 Windows PowerShell 里（以管理员身份）：
#   wsl --shutdown
# 然后重新打开 WSL 终端，或者：
sudo service docker restart
```

## 3. 验证镜像源已生效

```bash
docker info | grep -A5 "Registry Mirrors"
# 应看到上面配置的几个地址
```

## 4. 拉一张小镜像确认网络通畅

```bash
docker pull hello-world
# 成功后：
docker run --rm hello-world
```

## 5. 重跑 AgentGuard demo

```bash
cd ~/agentguard
./scripts/demo.sh
```

---

## 如果以上镜像源全部失败

镜像源会不定期下线，可以通过下面的**一次性预拉取**方案绕过：

```bash
# 一次性拉齐所需镜像（用你能通的任意代理/加速器）
docker pull redis:7-alpine
docker pull postgres:16-alpine
docker pull python:3.11-slim

# 然后就可以 build 和 up 了
cd ~/agentguard
docker compose up --build -d
```

或者，如果你本机有代理：

```bash
# 在当前终端临时使用代理
export HTTP_PROXY=http://127.0.0.1:7890
export HTTPS_PROXY=http://127.0.0.1:7890
docker compose up --build -d
```

> 如果需要让 Docker daemon 自己走代理，请参考官方文档 [Configure the Docker daemon to use a proxy server](https://docs.docker.com/config/daemon/systemd/#httphttps-proxy)。

## 备用公共镜像列表（2025 年 4 月仍在运行）

| 地址 | 维护方 | 备注 |
|------|--------|------|
| `https://docker.1ms.run` | 1ms.run | 稳定、速度快 |
| `https://docker.xuanyuan.me` | 轩辕 | |
| `https://hub.rat.dev` | rat.dev | |
| `https://docker.1panel.live` | 1Panel | |
| `https://proxy.1panel.live` | 1Panel | |
| `https://docker.nju.edu.cn` | 南京大学 | 需校内 or 教育网 |
| `https://docker.mirrors.sjtug.sjtu.edu.cn` | 上交大 | 校内优先 |

下线/已失效（请勿再使用）：

- ❌ `https://dockerproxy.com`（2024-06 下线）
- ❌ `https://mirror.baidubce.com`（官方已停运）
- ❌ `https://docker.m.daocloud.io`（2024 下架公开镜像）
- ❌ `https://registry.docker-cn.com`（早已停服）
