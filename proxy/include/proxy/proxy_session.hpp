
#pragma once

#include "proxy/proxy_fwd.hpp"
#include "proxy/proxy_stream.hpp"

#include <memory>
#include <vector>
#include <string>
#include <string_view>
#include <boost/asio/ssl.hpp>
#include <boost/variant2.hpp>

namespace proxy
{
    using util::proxy_tcp_socket;
    using util::variant_stream_type;
    using util::ssl_stream;

	//////////////////////////////////////////////////////////////////////////
	// proxy session 虚基类.
	class proxy_session_base {
	public:
		virtual ~proxy_session_base() {}
		virtual void start() = 0;
		virtual void close() = 0;
		virtual void set_tproxy_remote(const net::ip::tcp::endpoint&) = 0;
		virtual size_t connection_id() = 0;
	};

    //////////////////////////////////////////////////////////////////////////
    // proxy_session 用于处理代理服务器的连接, 一个 proxy_session 对应一个
	// 客户端连接, 用于处理客户端的请求, 并将请求转发到目标服务器.
	class proxy_session
		: public proxy_session_base
		, public std::enable_shared_from_this<proxy_session>
	{
		proxy_session(const proxy_session&) = delete;
		proxy_session& operator=(const proxy_session&) = delete;

		struct http_context
		{
			pmr_alloc_t alloc;
			// 在 http 请求时, 保存正则表达式命中时匹配的结果列表.
			std::pmr::vector<std::string_view> command_;

			// 保存 http 客户端的请求信息.
			string_request& request_;

			// 保存 http 客户端请求的原始目标.
			std::string_view target_;

			// 保存 http 客户端请求目标的具体路径, 即: doc 目录 + target_ 组成的路径.
			std::pmr::string target_path_;
		};

		// net_tcp_socket 用于将 stream 转换为 tcp::socket 对象.
		template <typename Stream>
		tcp::socket& net_tcp_socket(Stream& socket)
		{
			return static_cast<tcp::socket&>(socket.lowest_layer());
		}

		std::tuple<std::string, fs::path> file_last_wirte_time(const fs::path& file);
		std::pmr::string path_cat(std::string_view doc, std::string_view target, pmr_alloc_t alloc);

		std::pmr::string make_target_path(std::string_view target, pmr_alloc_t alloc);
		std::pmr::string make_real_target_path(std::string_view target, pmr_alloc_t alloc);

	public:
		proxy_session(net::any_io_executor executor, variant_stream_type&& socket, size_t id,
					  std::weak_ptr<proxy_server_base> server, bool tproxy = false);

		~proxy_session();

		enum {
			PROXY_AUTH_SUCCESS = 0,
			PROXY_AUTH_FAILED,
			PROXY_AUTH_NONE,
			PROXY_AUTH_ILLEGAL,
		};
	public:
		virtual void start() override;

		virtual void close() override;

		virtual void set_tproxy_remote(const net::ip::tcp::endpoint& tproxy_remote) override;

		virtual size_t connection_id() override;

	private:
		net::awaitable<void> tick();

		template<typename S1, typename S2>
		net::awaitable<void> transfer(S1& from, S2& to, size_t& bytes_transferred);
		net::awaitable<void> transparent_proxy();

		net::awaitable<bool> noise_handshake(tcp::socket& socket, std::vector<uint8_t>& inkey,
											 std::vector<uint8_t>& outkey);

		// 协议侦测协程.
		net::awaitable<void> proto_detect(bool handshake_before = true);

		net::awaitable<void> start_proxy();

		net::awaitable<void> socks_connect_v5();

		net::awaitable<void> forward_udp();

		net::awaitable<void> socks_connect_v4();

		net::awaitable<bool> http_proxy_get();

		net::awaitable<bool> http_proxy_connect();

		int http_authorization(std::string_view pa);
		net::awaitable<bool> socks_auth();

		template <typename Stream, typename Endpoint>
		bool check_condition(const boost::system::error_code&, Stream& stream, Endpoint&) const;

		net::awaitable<bool> connect_bridge_proxy(tcp::socket& remote_socket, std::string target_host,
												  uint16_t target_port, boost::system::error_code& ec);

		net::awaitable<bool> start_connect_host(std::string target_host, uint16_t target_port,
												boost::system::error_code& ec, bool resolve = false);

		// is_crytpo_stream 判断当前连接是否为加密连接.
		inline bool is_crytpo_stream() const
		{
			return boost::variant2::holds_alternative<ssl_stream>(m_remote_socket);
		}

		net::awaitable<void> normal_web_server(string_request& req, pmr_alloc_t alloc);

		net::awaitable<void> on_http_json(const http_context& hctx);

		net::awaitable<void> on_http_dir(const http_context& hctx);

		net::awaitable<void> on_http_get(const http_context& hctx);

		std::pmr::vector<std::pmr::string> format_path_list(std::string_view path, boost::system::error_code& ec, pmr_alloc_t alloc);
		std::pmr::string server_date_string(pmr_alloc_t alloc = pmr_alloc_t{});

		net::awaitable<void> default_http_route(
			const string_request& request, std::string response, http::status status);

		net::awaitable<void> location_http_route(const string_request& request, const std::string& path);

		net::awaitable<void> forbidden_http_route(const string_request& request);

		net::awaitable<void> unauthorized_http_route(const string_request& request);

		inline void user_rate_limit_config(const std::string& user)
		{
			// 在这里使用用户指定的速率设置替换全局速率配置.
			auto found = m_option.users_rate_limit_.find(user);
			if (found != m_option.users_rate_limit_.end())
			{
				auto& rate = *found;
				m_option.tcp_rate_limit_ = rate.second;
			}
		}

		inline void stream_rate_limit(variant_stream_type& stream, int rate)
		{
			boost::variant2::visit([rate](auto& s) mutable
				{
					using ValueType = std::decay_t<decltype(s)>;
					using NextLayerType = util::proxy_tcp_socket::next_layer_type;

					if constexpr (std::same_as<NextLayerType, util::tcp_socket>)
					{
						if constexpr (std::same_as<util::proxy_tcp_socket, ValueType>)
						{
							auto& next_layer = s.next_layer();
							next_layer.rate_limit(rate);
						}
						else if constexpr (std::same_as<util::ssl_stream, ValueType>)
						{
							auto& next_layer = s.next_layer().next_layer();
							next_layer.rate_limit(rate);
						}
					}
				}, stream);
		}

		void stream_expires_never(variant_stream_type& stream);

		void stream_expires_after(variant_stream_type& stream, net::steady_timer::duration expiry_time);

		void stream_expires_at(variant_stream_type& stream, net::steady_timer::time_point expiry_time);

	private:
		// m_executor 保存当前 io_context 的 executor.
		net::any_io_executor m_executor;

		// m_local_socket 本地 socket, 即客户端连接的 socket.
		variant_stream_type m_local_socket;

		// m_remote_socket 远程 socket, 即连接远程代理服务端或远程服务的 socket.
		variant_stream_type m_remote_socket;

		// 用于 socsks5 代理中的 udp 通信.
		udp::socket m_udp_socket;

		// m_bind_interface 用于向外发起连接时, 指定的 bind 地址.
		std::optional<net::ip::address> m_bind_interface;

		// m_local_udp_address 用于保存 udp 通信时, 本地的地址.
		net::ip::address m_local_udp_address;

		// m_timer 用于定时检查 udp 会话是否过期, 由于 udp 通信是无连接的, 如果 2 端长时间
		// 没有数据通信, 则可能会话已经失效, 此时应该关闭 udp socket 以及相关资源.
		net::steady_timer m_timer;

		// m_timeout udp 会话超时时间, 默认 60 秒.
		int m_udp_timeout{ udp_session_expired_time };

		// m_connection_id 当前连接的 id, 用于日志输出.
		size_t m_connection_id;

		// m_tproxy 是否是 tproxy 模式.
		bool m_tproxy{ false };

		// m_tproxy_remote tproxy 模式下, 客户端期望请求远程地址.
		net::ip::tcp::endpoint m_tproxy_remote;

		// m_local_buffer 本地缓冲区, 用于接收客户端的数据的 buffer.
		net::streambuf m_local_buffer{};

		// m_inin_key 用于身份为服务端时, 解密接收到的数据的 key.
		std::vector<uint8_t> m_inin_key;
		// m_inout_key 用于身份为服务端时, 加密发送的数据的 key.
		std::vector<uint8_t> m_inout_key;

		// m_proxy_server 当前代理服务器对象的弱引用.
		std::weak_ptr<proxy_server_base> m_proxy_server;

		// m_option 当前代理服务器的配置选项.
		proxy_server_option m_option;

		// m_bridge_proxy 作为中继桥接的时候, 下游代理服务器的地址.
		std::unique_ptr<boost::urls::url_view> m_bridge_proxy;

		// m_outin_key 用于身份为客户端时, 与下游代理服务器加密通信时, 解密接收到
		// 下游代理服务器数据的 key.
		std::vector<uint8_t> m_outin_key;
		// m_outout_key 用于身份为客户端时, 与下游代理服务器加密通信时, 加密给下
		// 游代理服务器发送的数据的 key.
		std::vector<uint8_t> m_outout_key;

		// 用于使用 ssl 加密通信与下游代理服务器通信时的 ssl context.
		net::ssl::context m_ssl_cli_context{ net::ssl::context::sslv23_client };

		// 当前 session 是否被中止的状态.
		bool m_abort{ false };
	};
}