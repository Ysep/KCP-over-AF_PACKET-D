# KCP (ikcp) 依赖

## 来源
- 仓库: https://github.com/skywind3000/kcp
- 作者: skywind3000 (KCP 协议发明者)
- 许可证: MIT License
- 版本: 原始版本（集成到项目中编译）

## 说明
KCP-over-AF_PACKET-D 使用 KCP 协议作为可靠传输层。源码 (ikcp.c/ikcp.h) 放置在 `src/` 目录下直接参与编译。

此 vendor 目录保留 KCP 源码副本，用于：
1. 明确标注第三方依赖
2. 便于版本升级时 diff 对比
3. 满足 GPL/MIT 许可证合规要求

## 修改记录
- vsprintf → vsnprintf（缓冲区溢出修复）
- 无其他修改
