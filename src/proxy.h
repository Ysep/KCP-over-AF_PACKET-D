/*
 * proxy.h - 代理模块
 *
 * 负责本地 TCP/UDP 端口的监听、连接和数据桥接。
 * 支持正向代理（监听本地→转发到远端）和反向代理（从 AF_PACKET 接收→连接本地服务）。
 */

#ifndef PROXY_H
#define PROXY_H

#include "types.h"

/* ============================================================================
 * 函数声明
 * ============================================================================ */

/*
 * 初始化代理子系统
 * @param ctx 全局上下文
 * @return    成功返回 0，失败返回 -1
 */
int proxy_init(global_ctx_t *ctx);

/*
 * 关闭代理子系统
 * @param ctx 全局上下文
 */
void proxy_shutdown(global_ctx_t *ctx);

/*
 * 为通道创建监听套接字并注册到 epoll
 * @param ctx 全局上下文
 * @param ch  通道
 * @return    成功返回 0，失败返回 -1
 */
int proxy_start_listen(global_ctx_t *ctx, channel_t *ch);

/*
 * 接受监听套接字上的新连接（TCP）
 * @param ctx 全局上下文
 * @param ch  通道
 * @return    成功返回新连接的 fd，失败返回 -1
 */
int proxy_accept(global_ctx_t *ctx, channel_t *ch);

/*
 * 连接到远端服务（反向代理模式）
 * @param ch 通道
 * @return   成功返回连接的 fd，失败返回 -1
 */
int proxy_connect_remote(channel_t *ch);

/*
 * 处理本地套接字的可读事件（应用→KCP方向）
 * @param ctx 全局上下文
 * @param ch  通道
 * @return    成功返回处理的字节数，失败返回 -1
 */
int proxy_handle_local_read(global_ctx_t *ctx, channel_t *ch);

/*
 * 处理本地套接字的可写事件（KCP→应用方向）
 * @param ch 通道
 * @return   成功返回写入的字节数，-1 表示错误，0 表示写阻塞
 */
int proxy_handle_local_write(channel_t *ch);

/*
 * 从 KCP 接收缓冲区刷新数据到本地套接字
 * @param ch 通道
 * @return   成功返回 0，失败返回 -1
 */
int proxy_flush_to_local(channel_t *ch);

/*
 * 从通道接收数据并写入 KCP（KCP→应用方向完成后的反向路径）
 * @param ch   通道
 * @param data 数据
 * @param len  数据长度
 * @return     成功返回写入的字节数，失败返回 -1
 */
int proxy_write_to_local(channel_t *ch, const uint8_t *data, int len);

/*
 * 关闭通道的本地连接
 * @param ch 通道
 */
void proxy_close_local(channel_t *ch);

/*
 * 获取通道本地套接字的 epoll 事件掩码
 * @param ch 通道
 * @return   epoll 事件掩码（用于更新注册）
 */
uint32_t proxy_get_events(channel_t *ch);

/*
 * 处理 epoll 事件分发到代理
 * @param ctx    全局上下文
 * @param fd     触发事件的文件描述符
 * @param events 事件掩码
 * @return       成功返回 0，失败返回 -1
 */
int proxy_handle_event(global_ctx_t *ctx, int fd, uint32_t events);

/*
 * 添加 fd 到 epoll（辅助函数）
 * @param ctx 全局上下文
 * @param fd  文件描述符
 * @param ptr 关联数据指针
 * @return    成功返回 0，失败返回 -1
 */
int proxy_epoll_add(global_ctx_t *ctx, int fd, void *ptr);

/*
 * 从 epoll 移除 fd（辅助函数）
 * @param ctx 全局上下文
 * @param fd  文件描述符
 * @return    成功返回 0，失败返回 -1
 */
int proxy_epoll_del(global_ctx_t *ctx, int fd);

#endif /* PROXY_H */
