
#pragma once

#include "boost/beast/http/empty_body.hpp"
#include <memory_resource>
#include <optional>
#include <stdexcept>
#include <string>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/filesystem.hpp>

namespace proxy
{
	namespace net = boost::asio;
	using tcp = net::ip::tcp;
	using tcp_acceptor = tcp::acceptor;

	using tcp = net::ip::tcp;               // from <boost/asio/ip/tcp.hpp>
	using udp = net::ip::udp;               // from <boost/asio/ip/udp.hpp>

	namespace beast = boost::beast;			// from <boost/beast.hpp>
	namespace http = beast::http;           // from <boost/beast/http.hpp>

	namespace fs = boost::filesystem;

	using pmr_alloc_t = std::pmr::polymorphic_allocator<char>;
	using pmr_fields = http::basic_fields<pmr_alloc_t>;

	using string_body = http::basic_string_body<char, std::char_traits<char>, pmr_alloc_t>;
	using span_body = http::span_body<const char>;

	// using string_body = http::string_body;
	using dynamic_body = http::basic_dynamic_body<boost::beast::basic_multi_buffer<pmr_alloc_t>>;
	using buffer_body = http::buffer_body;

	using dynamic_request = http::request<dynamic_body, pmr_fields>;
	using string_request = http::request<string_body, pmr_fields>;

	using string_response = http::response<string_body, pmr_fields>;
	using buffer_response = http::response<buffer_body, pmr_fields>;
	using custom_body_response = http::response<http::empty_body, pmr_fields>;
	using span_response = http::response<span_body, pmr_fields>;

	using request_parser = http::request_parser<string_request::body_type, pmr_alloc_t>;
	using response_parser = http::response_parser<string_response::body_type, pmr_alloc_t>;

	using response_serializer = http::response_serializer<buffer_response::body_type, pmr_fields>;
	using string_response_serializer = http::response_serializer<string_response::body_type, pmr_fields>;
	using span_response_serializer = http::response_serializer<span_body, pmr_fields>;
	using custom_body_response_serializer = http::response_serializer<http::empty_body, pmr_fields>;

	// http_ranges 用于保存 http range 请求头的解析结果.
	// 例如: bytes=0-100,200-300,400-500
	// 解析后的结果为: { {0, 100}, {200, 300}, {400, 500} }
	// 例如: bytes=0-100,200-300,400-500,600
	// 解析后的结果为: { {0, 100}, {200, 300}, {400, 500}, {600, -1} }
	// 如果解析失败, 则返回空数组.
	using http_ranges = std::vector<std::pair<int64_t, int64_t>>;


    class proxy_session_base;
    class proxy_session;
    class proxy_server_base;
    class proxy_server;


	//////////////////////////////////////////////////////////////////////////

	// udp_session_expired_time 用于指定 udp session 的默认过期时间, 单位为秒.
	inline constexpr int udp_session_expired_time = 60;

	// tcp_session_expired_time 用于指定 tcp session 的默认过期时间, 单位为秒.
	inline constexpr int tcp_session_expired_time = 60;

	// nosie_injection_max_len 用于指定噪声注入的最大长度, 单位为字节.
	inline constexpr uint16_t nosie_injection_max_len = 0x0fff;

	// global_known_proto 用于指定全局已知的协议, 用于噪声注入时避免生成已知的协议头.
	inline const std::set<uint8_t> global_known_proto =
		{
			0x04, // socks4
			0x05, // socks5
			0x47, // 'G'
			0x50, // 'P'
			0x43, // 'C'
			0x16, // ssl
		};

	//////////////////////////////////////////////////////////////////////////

	// proxy server 参数选项, 用于指定 proxy server 的各种参数.
	struct proxy_server_option
	{
		// proxy server 侦听端口.
		// 可同时侦听在多个 endpoint 上
		// 其中 bool 表示是在 endpoint 是 v6 地址的情况下否是 v6only.
		std::vector<std::tuple<tcp::endpoint, bool>> listens_;

		// 授权信息.
		// auth_users 的第1个元素为用户名, 第2个元素为密码.
		// auth_users_ 为空时, 表示不需要认证.
		// auth_users_ 可以是多个用户, 例如:
		// { {"user1", "passwd1"}, {"user2", "passwd2"} };
		using auth_users = std::tuple<std::string, std::string>;
		std::vector<auth_users> auth_users_;

		// 指定用户限速设置.
		// 其中表示：用户名对应的速率.
		std::unordered_map<std::string, int> users_rate_limit_;

		// allow_regions/deny_regions 用于指定允许/拒绝的地区, 例如:
		// allow_regions_ = { "中国", "香港", "台湾" };
		// deny_regions_ = { "美国", "日本" };
		// allow_regions/deny_regions 为空时, 表示不限制地区.
		// 必须在设置了 ipip 数据库文件后才能生效.
		std::unordered_set<std::string> allow_regions_;
		std::unordered_set<std::string> deny_regions_;

		// ipip 数据库文件, 用于指定 ipip 数据库文件, 用于地区限制.
		// ipip 数据库文件可以从: https://www.ipip.net 下载.
		std::string ipip_db_;

		// 多层代理, 当前服务器级连下一个服务器, 对于 client 而言是无感的,
		// 这是当前服务器通过 proxy_pass_ 指定的下一个代理服务器, 为 client
		// 实现多层代理.
		//
		// 例如 proxy_pass_ 可以是:
		// socks5://user:passwd@proxy.server.com:1080
		// 或:
		// https://user:passwd@proxy.server.com:1080
		//
		// 当 proxy_pass_ 是 socks5 代理时, 默认使用 hostname 模式, 即 dns
		// 解析在远程执行.
		//
		// 在配置了 proxy_protocol (haproxy)协议时, proxy_pass_ 通常为
		// 下一个 proxy_protocol 或直接目标服务器(目标服务器需要支持
		// proxy_protocol).
		std::string proxy_pass_;

		// 多层代理模式中, 与下一个代理服务器(next_proxy_)是否使用tls加密(ssl).
		// 该参数只能当 next_proxy_ 是 socks 代理时才有作用, 如果 next_proxy_
		// 是 http proxy，则由 url 指定的 protocol 决定是否使用 ssl.
		bool proxy_pass_use_ssl_{ false };

		// 启用 proxy protocol (haproxy)协议.
		// 当前服务将会在连接到 proxy_pass_ 成功后，首先传递 proxy protocol
		// 以告之 proxy_pass_ 来源 IP/PORT 以及目标 IP/PORT.
		// 注意：此选项当前未实现.
		// bool haproxy_{ false };

		// 指定当前proxy server向外发起连接时, 绑定到哪个本地地址, 在多网卡
		// 的服务器上, 可以指定此参数, 默认为空, 表示不指定, 由系统自动选择.
		std::string local_ip_;

		// 启用 TCP 端口重用(仅Linux kernel version 3.9以上支持).
		bool reuse_port_{ false };

		// 是否启用 Happy Eyeballs 连接算法, 默认为使用.
		bool happyeyeballs_{ true };

		// 用于指定是否仅使用 ipv4 地址发起连接, 默认为 false, 即同时使用
		// ipv4 和 ipv6 地址.
		bool connect_v4_only_{ false };

		// 用于指定是否仅使用 ipv6 地址发起连接, 默认为 false, 即同时使用
		// ipv4 和 ipv6 地址.
		bool connect_v6_only_{ false };

		// 是否作为透明代理服务器(仅linux).
		bool transparent_{ false };

		// so_mark 用于指定发起连接时的 so_mark, 仅在 transparent_ 为 true.
		std::optional<uint32_t> so_mark_;

		// udp 超时时间, 用于指定 udp 连接的超时时间, 单位为秒.
		int udp_timeout_{ udp_session_expired_time };

		// tcp 超时时间, 用于指定 tcp 连接的超时时间, 单位为秒.
		int tcp_timeout_{ tcp_session_expired_time };

		// tcp 连接速率控制, bytes/second.
		int tcp_rate_limit_{ -1 };

		// 作为服务器时, 指定ssl证书目录, 自动搜索子目录, 每一个目录保存一个域
		// 名对应的所有证书文件, 如果证书是加密的, 则需要指定 password.txt 用
		// 于存储加密的密码.
		// 另外每个目录应该指定当前域名, 对应相应的证书文件, 域名存储在 domain.txt
		// 文件当中, 如果目录下没有 domain.txt 文件, 则表示这将用于默认证书, 当
		// 匹配不到证书时则使用默认证书.
		std::string ssl_cert_path_;

		// 作为客户端时, 指定ssl证书目录(通常是保存 ca 证书的目录), 如果不指定则
		// 默认使用 https://curl.se/docs/caextract.html 中的 ca 证书文件作
		// 为默认的 ca 证书.
		std::string ssl_cacert_path_;

		// 用于上游代理服务器具有多域名证书下指定具体域名, 即通过此指定 SNI 参数.
		std::string proxy_ssl_name_;

		// 指定允许的加密算法.
		std::string ssl_ciphers_;

		// 优先使用server端加密算法.
		bool ssl_prefer_server_ciphers_;

		// http doc 目录, 用于伪装成web站点, 如果此字段为空, 则表示不启
		// 用此功能, 遇到 http/https 文件请求时则返回错误信息.
		std::string doc_directory_;

		// autoindex 功能, 类似 nginx 中的 autoindex.
		// 打开将会显示目录下的文件列表, 此功能作用在启用 doc_directory_
		// 的时候, 对 doc_directory_ 目录下的文件列表信息是否使用列表展
		// 示.
		bool autoindex_;

		// 用于指定是否启用 http basic auth 认证, 默认为 false,
		// 即不启用, 如果启用, 则需要设置 auth_users_ 参数.
		bool htpasswd_{ false };

		// 禁用 http 服务, 客户端无法通过明文的 http 协议与之通信, 包括
		// ssl 加密的 https 以及不加密的 http 服务, 同时也包括 http(s)
		// proxy 也会被禁用.
		// 在有些时候, 为了安全考虑, 可以禁用 http 服务避免服务器上的信息
		// 意外访问, 或不想启用 http(s) 服务.
		bool disable_http_{ false };

		// 禁用 socks proxy 服务, 服务端不提供 socks4/5 代理服务, 包括
		// 加密的 socks4/5 以及不加密的 socks4/5.
		bool disable_socks_{ false };

		// 禁止非安全连接, 即禁止 http/socks 明文连接, 只允许 https/socks5
		// 加密连接.
		bool disable_insecure_{ false };

		// 禁止 udp 服务, 服务端不提供 udp 代理服务.
		bool disable_udp_{ false };

		// 启用噪声注入以干扰流量分析, 从而达到数据安全的目的.
		// 此功能必须在 server/client 两端同时启用才有效, 此功能表示在启
		// 用 ssl 协议时, 在 ssl 握手后双方互相发送一段随机长度的随机数据
		// 以干扰流量分析.
		// 在双方接收到对方的随机数据后, 将对整个随机数据进行 hash 计算, 得
		// 到的结果将会作为后续数据的加密密钥, 从而达到加密通信的目的.
		// 加密算法仅仅是简单的异或运算, 但是由于密钥是随机的, 因此即使是
		// 同样的明文, 也会得到不同的密文, 从而达到加密通信的目的.
		// 密钥在一轮(密钥长度)使用完后, 将会通过 hash(hash) 重新计算得到
		// 新的密钥, 用于下一轮的加密通信.
		// hash 算法采用快速的 xxhash, 但是由于 xxhash 本身的特性. 因此
		// 密钥长度不能太长, 否则会影响性能, 所在固定密钥长度为 16 字节.
		// 此功能可以有效的防止流量分析, 但是会增加一定的流量消耗以及延迟,
		// 此选项默认不启用, 除非有确定证据证明代理流量被分析或干扰, 此时可
		// 以启用此选项.
		bool scramble_{ false };

		// 设置发送噪声的最大长度.
		// 最大设置为 64k, 最小设置为 16, 默认为 4096.
		uint16_t noise_length_{ nosie_injection_max_len };
	};
	struct unknow_mime_ext : public std::runtime_error { using std::runtime_error::runtime_error; };
	std::string_view mime_type_for_file_ext(std::string_view ext);
}

inline bool operator == (const std::string& a, const std::pmr::string& b)
{
	return std::string_view(a) == std::string_view(b);
}

inline bool operator == (const std::pmr::string& a, const std::string& b)
{
	return std::string_view(a) == std::string_view(b);
}

