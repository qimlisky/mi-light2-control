# MiIO C++ 实现

两个文件方案有略微差异
### 本项目参考了python-miio项目

# 比较
## 1. AES 输出缓冲区大小计算

```cpp
// v1: 用 BCryptEncrypt(nullptr, 0) 查询所需大小
ULONG cbCipher = 0;
BCryptEncrypt(hKey, nullptr, 0, nullptr, nullptr, 0, nullptr, 0, &cbCipher, BCRYPT_BLOCK_PADDING);
std::vector<uint8_t> cipher(cbCipher);
BCryptEncrypt(hKey, ..., cipher.data(), cbCipher, &cbCipher, BCRYPT_BLOCK_PADDING);

// v2: 手动计算 PKCS7 填充后的大小
ULONG cbC = ((ULONG)plain.size() / 16 + 1) * 16;
std::vector<uint8_t> c(cbC);
BCryptEncrypt(hKey, ..., c.data(), cbC, &cbO, BCRYPT_BLOCK_PADDING);
c.resize(cbO);
```

**差异：** v1 多一次系统调用；v2 直接按块大小预计算，更简洁。

---

## 2. 时间戳来源

```cpp
// v1: 每次发包取系统时间
uint32_t ts = (uint32_t)time(nullptr);

// v2: 从握手响应中提取，之后每条命令 +1
s.ts = ((uint32_t)resp[12]<<24) | ... | (uint32_t)resp[15];  // 握手时
++s.ts;  // 每次 send_cmd 后递增
```

**差异：** v2 的时间戳与设备同步，避免设备因时间差过大丢弃报文。

---

## 3. 握手时机

```cpp
// v1: 构造函数中握手一次
LampController() {
    miio_handshake(sock, addr, device_id);  // 仅一次
}

// v2: 每条命令前重新握手
do_handshake(s);       // 获取最新 device_id + 时间戳
auto resp = cmd_get(s);
```

**差异：** v1 握手一次后复用；v2 每次重新握手确保 session 有效。

---

## 4. 报文头时间戳写入

```cpp
// v1: memcpy 直接拷贝（小端序，与协议大端序不符）
uint32_t ts = (uint32_t)time(nullptr);
memcpy(header + 8, &ts, 4);        // 实际写入小端序

// v2: 手动按大端序逐字节写入
hdr[12] = (ts >> 24) & 0xFF;       // 高字节在前
hdr[13] = (ts >> 16) & 0xFF;
hdr[14] = (ts >> 8)  & 0xFF;
hdr[15] = ts & 0xFF;
```

**差异：** v1 在小端机器上会写错字节序，v2 正确。

---

## 5. JSON 命令格式

```cpp
// v1: 无 did 字段
"{\"id\":1,\"method\":\"get_properties\",\"params\":[{\"siid\":2,\"piid\":1}]}"

// v2: 包含 did 字段（米家 App 中的设备 ID）
"{\"id\":1,\"method\":\"get_properties\",\"params\":["
  "{\"did\":\"847276450\",\"siid\":2,\"piid\":1}]}";
```

**差异：** 部分设备要求 JSON 中包含 `did`，否则命令无效。

---

## 6. 错误处理

```cpp
// v1: 不检查返回值，静默失败
BCryptOpenAlgorithmProvider(&hAlg, ...);     // 忽略错误
sendto(sock, ...);                           // 忽略错误

// v2: CHECK_NT 宏 + 异常
#define CHECK_NT(expr, msg) \
    do { NTSTATUS _s=(expr); if(!BCRYPT_SUCCESS(_s)){ \
        throw std::runtime_error(...); } } while(0)
CHECK_NT(BCryptOpenAlgorithmProvider(...), "aes open");
```

**差异：** v1 错误时静默继续，产生难以排查的问题；v2 立即报错。

---

## 7. 代码结构

```cpp
// v1: 类封装
class LampController {
    SOCKET sock;
    std::vector<uint8_t> key;
    uint32_t device_id;
    void status();
    void set_power(bool on);
};

// v2: 结构体 + 自由函数
struct Session { SOCKET sock; uint32_t dev_id, ts; ... };
void do_handshake(Session& s);
std::string send_cmd(Session& s, const std::string& json);
std::string cmd_get(Session& s);
std::string cmd_set(Session& s, int piid, const std::string& val);
```

**差异：** v2 更扁平，函数职责更清晰，便于调试。

---

## 8. 调试支持

```cpp
// v1: 无调试输出

// v2: DEBUG 宏控制
#define DEBUG 1
#if DEBUG
    std::cout << "[TX] " << json << "\n";
    std::cout << "[RX] " << dec << "\n";
    std::cout << "[HS] dev_id=" << s.dev_id << " ts=" << s.ts << "\n";
#endif
```

---

## 总结

| 问题 | v1 | v2 |
|------|----|----|
| 时间戳字节序 | 小端（错误） | 大端（正确） |
| 时间戳来源 | 系统时间 | 握手响应 + 递增 |
| 握手频率 | 一次 | 每命令前 |
| JSON did | 缺失 | 包含 |
| BCrypt 错误 | 静默忽略 | 抛异常 |
| 调试输出 | 无 | 有 |
| AES 缓冲区 | 系统调用查询 | 手动计算 |
