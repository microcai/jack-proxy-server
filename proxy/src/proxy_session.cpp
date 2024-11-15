

#include "proxy/libproxy_pch.hpp"

#include "proxy/proxy_session.hpp"
#include "proxy/proxy_server.hpp"
#include "proxy/default_cert.hpp"
#include "proxy/async_connect.hpp"
#include "proxy/logging.hpp"
#include "proxy/socks_enums.hpp"
#include "proxy/socks_client.hpp"
#include "proxy/scramble.hpp"
#include "proxy/use_awaitable.hpp"
#include "proxy/proxy_stream.hpp"

#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/beast/core/detail/base64.hpp>
#include <boost/url.hpp>

#include <fmt/xchar.h>
#include <fmt/format.h>

#ifdef __linux__
#include <sys/sendfile.h>
#endif

using namespace boost::asio::experimental::awaitable_operators;
namespace urls = boost::urls;			// form <boost/url.hpp>

namespace proxy
{
	using namespace util;
	//////////////////////////////////////////////////////////////////////////

	static const char fake_400_content_fmt[] =
R"x*x*x(HTTP/1.1 400 Bad Request
Server: nginx/1.20.2
Date: {}
Content-Type: text/html
Content-Length: 165
Connection: close

<html>
<head><title>400 Bad Request</title></head>
<body bgcolor="white">
<center><h1>400 Bad Request</h1></center>
<hr><center>nginx/1.20.2</center>
</body>
</html>)x*x*x";

	static const char fake_407_content_fmt[] =
R"x*x*x(HTTP/1.1 407 Proxy Authentication Required
Server: nginx/1.20.2
Date: {}
Connection: close
Proxy-Authenticate: Basic realm="proxy"
Proxy-Connection: close
Content-Length: 0

)x*x*x";

	//////////////////////////////////////////////////////////////////////////
	// 检测 host 是否是域名或主机名, 如果是域名则返回 true, 否则返回 false.
	static bool detect_hostname(const std::string& host) noexcept
	{
		boost::system::error_code ec;
		net::ip::address::from_string(host, ec);
		if (ec)
			return true;
		return false;
	}

	// http 认证错误代码对应的错误信息.
	static std::string pauth_error_message(int code) noexcept
	{
		switch (code)
		{
		case proxy_session::PROXY_AUTH_SUCCESS:
			return "auth success";
		case proxy_session::PROXY_AUTH_FAILED:
			return "auth failed";
		case proxy_session::PROXY_AUTH_NONE:
			return "auth none";
		case proxy_session::PROXY_AUTH_ILLEGAL:
			return "auth illegal";
		default:
			return "auth unknown";
		}
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	std::pmr::string proxy_session::path_cat(std::string_view doc, std::string_view target, pmr_alloc_t alloc)
	{
		size_t start_pos = 0;
		for (auto& c : target)
		{
			if (!(c == '/' || c == '\\'))
			{
				break;
			}

			start_pos++;
		}

		std::string_view sv;
		std::pmr::string slash{"/", alloc};

		if (start_pos < target.size())
		{
			sv = target.substr(start_pos);
		}
#ifdef WIN32
		slash = "\\";
		if (doc.back() == '/' || doc.back() == '\\')
		{
			slash = "";
		}
		auto filename = std::pmr::string(doc, alloc) + slash + std::pmr::string(sv, alloc);
		return filename;
#else
		if (doc.back() == '/')
		{
			slash = "";
		}
		return std::pmr::string(doc, alloc) + slash + std::pmr::string(sv, alloc);
#endif // WIN32
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	proxy_session::proxy_session(net::any_io_executor executor, variant_stream_type&& socket, size_t id, std::weak_ptr<proxy_server_base> server, bool tproxy)
		: m_executor(executor)
		, m_local_socket(std::move(socket))
		, m_remote_socket(init_proxy_stream(executor))
		, m_udp_socket(executor), m_timer(executor)
		, m_connection_id(id)
		, m_tproxy(tproxy)
		, m_proxy_server(server)
	{
	}

	proxy_session::~proxy_session()
	{
		auto server = m_proxy_server.lock();
		if (!server)
		{
			return;
		}

		// 从 server 中移除当前 session.
		server->remove_session(m_connection_id);

		// 打印当前 session 数量.
		auto num = server->num_session();

		XLOG_DBG << "connection id: " << m_connection_id << ", terminated, " << num << " active connections remaining.";
	}

	void proxy_session::start()
	{
		auto server = m_proxy_server.lock();
		if (!server)
		{
			return;
		}

		// 保存 server 的参数选项.
		m_option = server->option();

		// 设置 udp 超时时间.
		m_udp_timeout = m_option.udp_timeout_;

		// 将 local_ip 转换为 ip::address 对象, 用于后面向外发起连接时
		// 绑定到指定的本地地址.
		boost::system::error_code ec;
		m_bind_interface = net::ip::address::from_string(m_option.local_ip_, ec);
		if (ec)
		{
			// bind 地址有问题, 忽略bind参数.
			m_bind_interface.reset();
		}

		// 如果指定了 proxy_pass_ 参数, 则解析它, 这说明它是一个
		// 多层代理, 本服务器将会连接到下一个代理服务器.
		// 所有数据将会通过本服务器转发到由 proxy_pass_ 指定的下一
		// 个代理服务器.
		if (!m_option.proxy_pass_.empty())
		{
			try
			{
				m_bridge_proxy = std::make_unique<urls::url_view>(m_option.proxy_pass_);
			}
			catch (const std::exception& e)
			{
				XLOG_ERR << "connection id: " << m_connection_id
						 << ", params next_proxy error: " << m_option.proxy_pass_ << ", exception: " << e.what();

				return;
			}
		}

		// 保持 self 对象指针, 以防止在协程完成后 this 被销毁.
		auto self = this->shared_from_this();

		// 如果是透明代理, 则启动透明代理协程.
		if (m_tproxy)
		{
			net::co_spawn(m_executor, [this, self, server]() -> net::awaitable<void>
			{
				co_await transparent_proxy();
				co_return;
			}, net::detached);

			return;
		}

		// 启动协议侦测协程.
		net::co_spawn(m_executor, [this, self, server]() -> net::awaitable<void>
		{
			co_await proto_detect();
			co_return;
		}, net::detached);
	}

	void proxy_session::close()
	{
		if (m_abort)
		{
			return;
		}

		m_abort = true;

		boost::system::error_code ignore_ec;

		// 关闭所有 socket.
		m_local_socket.close(ignore_ec);
		m_remote_socket.close(ignore_ec);

		m_udp_socket.close(ignore_ec);

		// 取消所有定时器.
		m_timer.cancel(ignore_ec);
	}

	void proxy_session::set_tproxy_remote(const net::ip::tcp::endpoint& tproxy_remote)
	{
		m_tproxy_remote = tproxy_remote;
	}

	size_t proxy_session::connection_id()
	{
		return m_connection_id;
	}

	net::awaitable<void> proxy_session::tick()
	{
		[[maybe_unused]] auto self = shared_from_this();
		boost::system::error_code ec;

		while (!m_abort)
		{
			m_timer.expires_from_now(std::chrono::seconds(1));
			co_await m_timer.async_wait(net_awaitable[ec]);
			if (ec)
			{
				XLOG_WARN << "connection id: " << m_connection_id << ", ec: " << ec.message();
				break;
			}

			if (--m_udp_timeout <= 0)
			{
				XLOG_DBG << "connection id: " << m_connection_id << ", udp socket expired";
				m_udp_socket.close(ec);
				break;
			}
		}

		XLOG_DBG << "connection id: " << m_connection_id << ", udp expired timer quit";

		co_return;
	}

	template<typename S1, typename S2>
	net::awaitable<void> proxy_session::transfer(S1& from, S2& to, size_t& bytes_transferred)
	{
		std::vector<char> data(1024 * 1024, 0);
		boost::system::error_code ec;
		bytes_transferred = 0;

		stream_rate_limit(from, m_option.tcp_rate_limit_);
		stream_rate_limit(to, m_option.tcp_rate_limit_);

		for (; !m_abort;)
		{
			stream_expires_after(from, std::chrono::seconds(m_option.tcp_timeout_));

			auto bytes = co_await from.async_read_some(
				net::buffer(data), net_awaitable[ec]);
			if (ec || m_abort)
			{
				if (bytes > 0)
					co_await net::async_write(to,
						net::buffer(data, bytes), net_awaitable[ec]);

				to.shutdown(net::socket_base::shutdown_send, ec);
				co_return;
			}

			stream_expires_after(to, std::chrono::seconds(m_option.tcp_timeout_));

			co_await net::async_write(to,
				net::buffer(data, bytes), net_awaitable[ec]);
			if (ec || m_abort)
			{
				from.shutdown(net::socket_base::shutdown_receive, ec);
				co_return;
			}

			bytes_transferred += bytes;
		}
	}

	net::awaitable<void> proxy_session::transparent_proxy()
	{
		auto executor = co_await net::this_coro::executor;

		tcp::socket& remote_socket = net_tcp_socket(m_remote_socket);

#if defined(__linux__)
		if (m_option.so_mark_)
		{
			auto sockfd = remote_socket.native_handle();
			uint32_t mark = m_option.so_mark_.value();

			if (::setsockopt(sockfd, SOL_SOCKET, SO_MARK, &mark, sizeof(uint32_t)) < 0)
			{
				XLOG_FWARN("connection id: {}, setsockopt({}, SO_MARK: {}", m_connection_id, sockfd, strerror(errno));
			}
		}
#endif

		boost::system::error_code ec;

		bool ret = co_await connect_bridge_proxy(remote_socket, m_tproxy_remote.address().to_string(),
												 m_tproxy_remote.port(), ec);

		if (!ret)
		{
			co_return;
		}

		size_t l2r_transferred = 0;
		size_t r2l_transferred = 0;

		co_await (transfer(m_local_socket, m_remote_socket, l2r_transferred) &&
				  transfer(m_remote_socket, m_local_socket, r2l_transferred));

		XLOG_DBG << "connection id: " << m_connection_id << ", transfer completed"
				 << ", local to remote: " << l2r_transferred << ", remote to local: " << r2l_transferred;

		co_return;
	}

	net::awaitable<bool> proxy_session::noise_handshake(tcp::socket& socket, std::vector<uint8_t>& inkey,
														std::vector<uint8_t>& outkey)
	{
		boost::system::error_code error;

		// 工作流程:
		// 1. 生成一段随机长度的随机数据(最大长度由配置文件中的参数 noise_length 指定), 用于发送给对方.
		// 2. 根据这些随机数据计算发送数据的 key, 这个 key 将会用于后续的代理时数据的加密.
		// 3. 发送随机数据.
		// 4. 对方在接收到随机数据后, 同样会发送噪声随机数据(包含随机数长度本身, 在前16字节中的最后一位,
		//    组成一个 16 位的整数表示长度).
		// 5. 计算接收随机数据的 key 用于后续的接收到的数据的解密.

		// 生成要发送的噪声数据.
		int noise_length = m_option.noise_length_;

		if (noise_length < 16 || (noise_length > std::numeric_limits<uint16_t>::max() / 2))
		{
			noise_length = nosie_injection_max_len;
		}

		std::vector<uint8_t> noise = generate_noise(static_cast<uint16_t>(noise_length), global_known_proto);

		// 计算数据发送 key.
		outkey = compute_key(noise);

		XLOG_DBG << "connection id: " << m_connection_id << ", send noise, length: " << noise.size();

		// 发送 noise 消息.
		co_await net::async_write(socket, net::buffer(noise), net_awaitable[error]);
		if (error)
		{
			XLOG_WARN << "connection id: " << m_connection_id << ", noise write error: " << error.message();

			co_return false;
		}

		noise.resize(16);

		// 接收对方发过来的 noise 回应消息.
		co_await net::async_read(socket, net::buffer(noise, 16), net_awaitable[error]);

		if (error)
		{
			XLOG_WARN << "connection id: " << m_connection_id << ", noise read header error: " << error.message();

			co_return false;
		}

		noise_length = extract_noise_length(noise);

		// 计算要接收的剩余数据大小.
		int remainder = static_cast<int>(noise_length) - 16;
		if (remainder < 0 || remainder >= std::numeric_limits<uint16_t>::max())
		{
			XLOG_DBG << "connection id: " << m_connection_id << ", noise length: " << noise_length
					 << ", is invalid, noise size: " << noise.size();

			co_return false;
		}

		noise.resize(noise_length);
		co_await net::async_read(socket, net::buffer(noise.data() + 16, remainder), net_awaitable[error]);

		if (error)
		{
			XLOG_WARN << "connection id: " << m_connection_id << ", noise read body error: " << error.message();

			co_return false;
		}

		XLOG_DBG << "connection id: " << m_connection_id << ", recv noise, length: " << noise.size();

		// 计算接收数据key.
		inkey = compute_key(noise);

		co_return true;
	}

	net::awaitable<void> proxy_session::proto_detect(bool handshake_before)
	{
		// 如果 server 对象已经撤销, 说明服务已经关闭则直接退出这个 session 连接不再
		// 进行任何处理.
		auto server = m_proxy_server.lock();
		if (!server)
		{
			co_return;
		}

		auto self = shared_from_this();

		// 从 m_local_socket 中获取 tcp::socket 对象的引用.
		auto& socket = boost::variant2::get<proxy_tcp_socket>(m_local_socket);

		boost::system::error_code error;

		// 等待 read 事件以确保下面 recv 偷看数据时能有数据.
		co_await socket.async_wait(net::socket_base::wait_read, net_awaitable[error]);
		if (error)
		{
			XLOG_WARN << "connection id: " << m_connection_id << ", socket.async_wait error: " << error.message();
			co_return;
		}

		auto scramble_setup = [this](auto& sock) mutable
		{
			if (!m_option.scramble_)
			{
				return;
			}

			if (m_inin_key.empty() || m_inout_key.empty())
			{
				return;
			}

			using Stream = std::decay_t<decltype(sock)>;
			using ProxySocket = util::proxy_tcp_socket;

			if constexpr (std::same_as<Stream, tcp::socket>)
			{
				return;
			}

			if constexpr (std::same_as<Stream, ProxySocket>)
			{
				sock.set_scramble_key(m_inout_key);
				sock.set_unscramble_key(m_inin_key);
			}
		};

		// handshake_before 在调用 proto_detect 时第1次为 true, 第2次调用 proto_detect
		// 时 handshake_before 为 false, 此时就表示已经完成了 scramble 握手并协
		// 商好了 scramble 加解密用的 key, 则此时应该为 socket 配置好加解密用的 key.

		if (!handshake_before)
		{
			// 为 socket 设置 scramble key.
			scramble_setup(socket);
		}

		// 检查协议.
		auto fd = socket.native_handle();
		uint8_t detect[5] = {0};

#if defined(WIN32) || defined(__APPLE__)
		auto ret = recv(fd, (char*)detect, sizeof(detect), MSG_PEEK);
#else
		auto ret = recv(fd, (void*)detect, sizeof(detect), MSG_PEEK | MSG_NOSIGNAL | MSG_DONTWAIT);
#endif
		if (ret <= 0)
		{
			XLOG_WARN << "connection id: " << m_connection_id << ", peek message return: " << ret;
			co_return;
		}

		// detect 中的数据只有下面几种情况, 它是 http/socks4/5/ssl 协议固定的头
		// 几个字节, 如若不是, 在启用 scramble 的情况下, 则是 scramble 协议头
		// 此时应该进入 scramble 协商密钥, 协商密钥之后则重新进入 proto_detect
		// 以检测在 scramble 加密后的真实协议头.
		// 如果没启用 scramble, 接受到 http/socks4/5/ssl 协议固定的头之外的数据
		// 则视为未知协议退出.

		// scramble_peek 用于解密 peek 数据.
		auto scramble_peek = [this](auto& sock, std::span<uint8_t> detect) mutable
		{
			if (!m_option.scramble_)
			{
				return;
			}

			if (m_inin_key.empty() || m_inout_key.empty())
			{
				return;
			}

			using Stream = std::decay_t<decltype(sock)>;
			using ProxySocket = util::proxy_tcp_socket;

			if constexpr (std::same_as<Stream, tcp::socket>)
			{
				return;
			}

			if constexpr (std::same_as<Stream, ProxySocket>)
			{
				auto& unscramble = sock.unscramble();
				unscramble.peek_data(detect);
			}
		};

		if (!handshake_before)
		{
			// peek 方式解密混淆的数据, 用于检测加密混淆的数据的代理协议. 在双方启用
			// scramble 的情况下, 上面 recv 接收到的数据则会为 scramble 加密后的
			// 数据, 要像未启用 scramble 时那样探测协议, 就必须将上面 recv 中
			// peek 得到的数据：detect 临时解密(因为 proxy_stream 的加密为流式加
			// 密, 非临时解密则会对整个数据流产生错误解密), 从而得到具体的协议字节
			// 用于后面探测逻辑.
			scramble_peek(socket, detect);
		}

		// 保存第一个字节用于协议类型甄别.
		const uint8_t proto_byte = detect[0];

		// 非安全连接检查.
		if (m_option.disable_insecure_)
		{
			bool noise_proto = false;

			// 如果启用了 scramble, 则也认为是安全连接.
			if ((proto_byte != 0x05 && proto_byte != 0x04 && proto_byte != 0x47 && proto_byte != 0x50 &&
				 proto_byte != 0x43) ||
				!handshake_before)
			{
				noise_proto = true;
			}

			if (detect[0] != 0x16 && !noise_proto)
			{
				XLOG_DBG << "connection id: " << m_connection_id << ", insecure protocol disabled";
				co_return;
			}
		}

		// plain socks4/5 protocol.
		if (detect[0] == 0x05 || detect[0] == 0x04)
		{
			if (m_option.disable_socks_)
			{
				XLOG_DBG << "connection id: " << m_connection_id << ", socks protocol disabled";
				co_return;
			}

			XLOG_DBG << "connection id: " << m_connection_id << ", plain socks4/5 protocol";

			// 开始启动代理协议.
			co_await start_proxy();
		}
		else if (detect[0] == 0x16) // http/socks proxy with ssl crypto protocol.
		{
			XLOG_DBG << "connection id: " << m_connection_id << ", ssl protocol";

			auto& srv_ssl_context = server->ssl_context();

			// instantiate socks stream with ssl context.
			auto ssl_socks_stream = init_proxy_stream(std::move(socket), srv_ssl_context);

			// get origin ssl stream type.
			ssl_stream& ssl_socket = boost::variant2::get<ssl_stream>(ssl_socks_stream);

			// do async ssl handshake.
			co_await ssl_socket.async_handshake(net::ssl::stream_base::server, net_awaitable[error]);

			if (error)
			{
				XLOG_DBG << "connection id: " << m_connection_id
						 << ", ssl server protocol handshake error: " << error.message();
				co_return;
			}

			// 使用 ssl_socks_stream 替换 m_local_socket.
			m_local_socket = std::move(ssl_socks_stream);

			// 开始启动代理协议.
			co_await start_proxy();
		} // plain http protocol.
		else if (detect[0] == 0x47 || // 'G'
				 detect[0] == 0x50 || // 'P'
				 detect[0] == 0x43)   // 'C'
		{
			if (m_option.disable_http_)
			{
				XLOG_DBG << "connection id: " << m_connection_id << ", http protocol disabled";
				co_return;
			}

			XLOG_DBG << "connection id: " << m_connection_id << ", plain http protocol";

			// 开始启动代理协议.
			co_await start_proxy();
		}
		else if (handshake_before && m_option.scramble_)
		{
			// 进入噪声握手协议, 即: 返回一段噪声给客户端, 并等待客户端返回噪声.
			XLOG_DBG << "connection id: " << m_connection_id << ", noise protocol";

			if (!co_await noise_handshake(net_tcp_socket(socket), m_inin_key, m_inout_key))
			{
				co_return;
			}

			// 在完成 noise 握手后, 重新检测被混淆之前的代理协议.
			co_await proto_detect(false);
		}
		else
		{
			XLOG_DBG << "connection id: " << m_connection_id << ", unknown protocol";
		}

		co_return;
	}

	net::awaitable<void> proxy_session::start_proxy()
	{
		// read
		//  +----+----------+----------+
		//  |VER | NMETHODS | METHODS  |
		//  +----+----------+----------+
		//  | 1  |    1     | 1 to 255 |
		//  +----+----------+----------+
		//  [               ]
		// or
		//  +----+----+----+----+----+----+----+----+----+----+....+----+
		//  | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
		//  +----+----+----+----+----+----+----+----+----+----+....+----+
		//    1    1      2        4                  variable       1
		//  [         ]
		// 读取[]里的部分.

		boost::system::error_code ec;

		[[maybe_unused]] auto bytes =
			co_await net::async_read(m_local_socket, m_local_buffer, net::transfer_exactly(2), net_awaitable[ec]);
		if (ec)
		{
			XLOG_ERR << "connection id: " << m_connection_id << ", read socks version: " << ec.message();
			co_return;
		}
		BOOST_ASSERT(bytes == 2);

		auto p = net::buffer_cast<const char*>(m_local_buffer.data());
		int socks_version = read<uint8_t>(p);

		if (socks_version == SOCKS_VERSION_5)
		{
			if (m_option.disable_socks_)
			{
				XLOG_DBG << "connection id: " << m_connection_id << ", socks5 protocol disabled";
				co_return;
			}

			XLOG_DBG << "connection id: " << m_connection_id << ", socks version: " << socks_version;

			co_await socks_connect_v5();
			co_return;
		}
		if (socks_version == SOCKS_VERSION_4)
		{
			if (m_option.disable_socks_)
			{
				XLOG_DBG << "connection id: " << m_connection_id << ", socks4 protocol disabled";
				co_return;
			}

			XLOG_DBG << "connection id: " << m_connection_id << ", socks version: " << socks_version;

			co_await socks_connect_v4();
			co_return;
		}
		if (socks_version == 'G' || socks_version == 'P')
		{
			if (m_option.disable_http_)
			{
				XLOG_DBG << "connection id: " << m_connection_id << ", http protocol disabled";
				co_return;
			}

			auto ret = co_await http_proxy_get();
			if (!ret)
			{
				auto fake_page = fmt::vformat(fake_400_content_fmt, fmt::make_format_args(server_date_string()));

				co_await net::async_write(m_local_socket, net::buffer(fake_page), net::transfer_all(),  net_awaitable[ec]);
			}
		}
		else if (socks_version == 'C')
		{
			if (m_option.disable_http_)
			{
				XLOG_DBG << "connection id: " << m_connection_id << ", http protocol disabled";
				co_return;
			}

			auto ret = co_await http_proxy_connect();
			if (!ret)
			{
				auto fake_page = fmt::vformat(fake_400_content_fmt, fmt::make_format_args(server_date_string()));

				co_await net::async_write(m_local_socket, net::buffer(fake_page), net::transfer_all(), net_awaitable[ec]);
			}
		}

		co_return;
	}

	net::awaitable<void> proxy_session::socks_connect_v5()
	{
		auto p = net::buffer_cast<const char*>(m_local_buffer.data());

		auto socks_version = read<int8_t>(p);
		BOOST_ASSERT(socks_version == SOCKS_VERSION_5);
		int nmethods = read<int8_t>(p);
		if (nmethods <= 0 || nmethods > 255)
		{
			XLOG_ERR << "connection id: " << m_connection_id << ", unsupported method : " << nmethods;
			co_return;
		}

		//  +----+----------+----------+
		//  |VER | NMETHODS | METHODS  |
		//  +----+----------+----------+
		//  | 1  |    1     | 1 to 255 |
		//  +----+----------+----------+
		//                  [          ]
		m_local_buffer.consume(m_local_buffer.size());
		boost::system::error_code ec;
		auto bytes = co_await net::async_read(m_local_socket, m_local_buffer, net::transfer_exactly(nmethods),
											  net_awaitable[ec]);
		if (ec)
		{
			XLOG_ERR << "connection id: " << m_connection_id << ", read socks methods: " << ec.message();
			co_return;
		}

		// 服务端是否需要认证.
		auto auth_required = !m_option.auth_users_.empty();

		// 循环读取客户端支持的代理方式.
		p = net::buffer_cast<const char*>(m_local_buffer.data());

		int method = SOCKS5_AUTH_UNACCEPTABLE;
		while (bytes != 0)
		{
			int m = read<int8_t>(p);

			if (auth_required)
			{
				if (m == SOCKS5_AUTH)
				{
					method = m;
					break;
				}
			}
			else
			{
				if (m == SOCKS5_AUTH_NONE || m == SOCKS5_AUTH)
				{
					method = m;
					break;
				}
			}

			bytes--;
		}

		net::streambuf wbuf;

		// 回复客户端, server所选择的代理方式.
		auto wp = net::buffer_cast<char*>(wbuf.prepare(1024));
		write<uint8_t>(socks_version, wp);
		write<uint8_t>((uint8_t)method, wp);

		wbuf.commit(2);

		//  +----+--------+
		//  |VER | METHOD |
		//  +----+--------+
		//  | 1  |   1    |
		//  +----+--------+
		//  [             ]
		bytes = co_await net::async_write(m_local_socket, wbuf, net::transfer_exactly(2), net_awaitable[ec]);
		if (ec)
		{
			XLOG_WARN << "connection id: " << m_connection_id << ", write server method error : " << ec.message();
			co_return;
		}

		if (method == SOCKS5_AUTH_UNACCEPTABLE)
		{
			XLOG_WARN << "connection id: " << m_connection_id << ", no acceptable methods for server";
			co_return;
		}

		// 认证模式, 则进入认证子协程.
		if (method == SOCKS5_AUTH)
		{
			auto ret = co_await socks_auth();
			if (!ret)
			{
				co_return;
			}
		}

		//  +----+-----+-------+------+----------+----------+
		//  |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
		//  +----+-----+-------+------+----------+----------+
		//  | 1  |  1  | X'00' |  1   | Variable |    2     |
		//  +----+-----+-------+------+----------+----------+
		//  [                          ]
		m_local_buffer.consume(m_local_buffer.size());
		bytes = co_await net::async_read(m_local_socket, m_local_buffer, net::transfer_exactly(5), net_awaitable[ec]);
		if (ec)
		{
			XLOG_WARN << "connection id: " << m_connection_id << ", read client request error: " << ec.message();
			co_return;
		}

		p = net::buffer_cast<const char*>(m_local_buffer.data());
		auto ver = read<int8_t>(p);
		if (ver != SOCKS_VERSION_5)
		{
			XLOG_WARN << "connection id: " << m_connection_id << ", socks requests, invalid protocol: " << ver;
			co_return;
		}

		int command = read<int8_t>(p); // CONNECT/BIND/UDP
		read<int8_t>(p);               // reserved.
		int atyp = read<int8_t>(p);    // atyp.

		//  +----+-----+-------+------+----------+----------+
		//  |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
		//  +----+-----+-------+------+----------+----------+
		//  | 1  |  1  | X'00' |  1   | Variable |    2     |
		//  +----+-----+-------+------+----------+----------+
		//                              [                   ]
		int length = 0;

		// 消费掉前4个字节, 保存第1个字节.
		m_local_buffer.consume(4);

		if (atyp == SOCKS5_ATYP_IPV4)
		{
			length = 5; // 6 - 1
		}
		else if (atyp == SOCKS5_ATYP_DOMAINNAME)
		{
			length = read<uint8_t>(p) + 2;
			m_local_buffer.consume(1);
		}
		else if (atyp == SOCKS5_ATYP_IPV6)
		{
			length = 17; // 18 - 1
		}

		bytes =
			co_await net::async_read(m_local_socket, m_local_buffer, net::transfer_exactly(length), net_awaitable[ec]);
		if (ec)
		{
			XLOG_WARN << "connection id: " << m_connection_id
					  << ", read client request dst.addr error: " << ec.message();
			co_return;
		}

		tcp::endpoint dst_endpoint;
		std::string domain;
		uint16_t port = 0;

		auto executor = co_await net::this_coro::executor;

		p = net::buffer_cast<const char*>(m_local_buffer.data());
		if (atyp == SOCKS5_ATYP_IPV4)
		{
			dst_endpoint.address(net::ip::address_v4(read<uint32_t>(p)));
			dst_endpoint.port(read<uint16_t>(p));

			domain = dst_endpoint.address().to_string();
			port = dst_endpoint.port();

			XLOG_DBG << "connection id: " << m_connection_id << ", " << m_local_socket.remote_endpoint()
					 << " to ipv4: " << dst_endpoint;
		}
		else if (atyp == SOCKS5_ATYP_DOMAINNAME)
		{
			for (size_t i = 0; i < bytes - 2; i++)
			{
				domain.push_back(read<int8_t>(p));
			}
			port = read<uint16_t>(p);

			XLOG_DBG << "connection id: " << m_connection_id << ", " << m_local_socket.remote_endpoint()
					 << " to domain: " << domain << ":" << port;
		}
		else if (atyp == SOCKS5_ATYP_IPV6)
		{
			net::ip::address_v6::bytes_type addr;
			for (auto i = addr.begin(); i != addr.end(); ++i)
			{
				*i = read<int8_t>(p);
			}

			dst_endpoint.address(net::ip::address_v6(addr));
			dst_endpoint.port(read<uint16_t>(p));

			domain = dst_endpoint.address().to_string();
			port = dst_endpoint.port();

			XLOG_DBG << "connection id: " << m_connection_id << ", " << m_local_socket.remote_endpoint()
					 << " to ipv6: " << dst_endpoint;
		}

		if (command == SOCKS_CMD_CONNECT)
		{
			// 连接目标主机.
			co_await start_connect_host(domain, port, ec, atyp == SOCKS5_ATYP_DOMAINNAME);
		}
		else if (command == SOCKS5_CMD_UDP)
		{
			do
			{
				if (m_option.disable_udp_)
				{
					XLOG_DBG << "connection id: " << m_connection_id << ", udp protocol disabled";
					ec = net::error::connection_refused;
					break;
				}

				if (atyp == SOCKS5_ATYP_DOMAINNAME)
				{
					tcp::resolver resolver{executor};

					auto targets = co_await resolver.async_resolve(domain, std::to_string(port), net_awaitable[ec]);
					if (ec)
					{
						break;
					}

					for (const auto& target : targets)
					{
						dst_endpoint = target.endpoint();
						break;
					}
				}

				// 创建UDP端口.
				auto protocol = dst_endpoint.address().is_v4() ? udp::v4() : udp::v6();
				m_udp_socket.open(protocol, ec);
				if (ec)
				{
					break;
				}

				m_udp_socket.bind(udp::endpoint(protocol, dst_endpoint.port()), ec);
				if (ec)
				{
					break;
				}

				auto remote_endp = m_local_socket.remote_endpoint();

				// 所有发向 udp socket 的数据, 都将转发到 m_local_udp_address
				// 除非地址是 m_local_udp_address 本身除外.
				m_local_udp_address = remote_endp.address();

				// 开启udp socket数据接收, 并计时, 如果在一定时间内没有接收到数据包
				// 则关闭 udp socket 等相关资源.
				net::co_spawn(executor, tick(), net::detached);

				net::co_spawn(executor, forward_udp(), net::detached);

				wbuf.consume(wbuf.size());
				auto wp = net::buffer_cast<char*>(wbuf.prepare(64 + domain.size()));

				write<uint8_t>(SOCKS_VERSION_5, wp); // VER
				write<uint8_t>(0, wp);               // REP
				write<uint8_t>(0x00, wp);            // RSV

				auto local_endp = m_udp_socket.local_endpoint(ec);
				if (ec)
				{
					break;
				}

				XLOG_DBG << "connection id: " << m_connection_id
						 << ", local udp address: " << m_local_udp_address.to_string()
						 << ", udp socket: " << local_endp;

				if (local_endp.address().is_v4())
				{
					auto uaddr = local_endp.address().to_v4().to_uint();

					write<uint8_t>(SOCKS5_ATYP_IPV4, wp);
					write<uint32_t>(uaddr, wp);
					write<uint16_t>(local_endp.port(), wp);
				}
				else if (local_endp.address().is_v6())
				{
					write<uint8_t>(SOCKS5_ATYP_IPV6, wp);
					auto data = local_endp.address().to_v6().to_bytes();
					for (auto c : data)
					{
						write<uint8_t>(c, wp);
					}
					write<uint16_t>(local_endp.port(), wp);
				}

				auto len = wp - net::buffer_cast<const char*>(wbuf.data());
				wbuf.commit(len);
				bytes = co_await net::async_write(m_local_socket, wbuf, net::transfer_exactly(len), net_awaitable[ec]);
				if (ec)
				{
					XLOG_WARN << "connection id: " << m_connection_id
							  << ", write server response error: " << ec.message();
					co_return;
				}

				co_return;
			}
			while (0);
		}

		// 连接成功或失败.
		{
			int8_t error_code = SOCKS5_SUCCEEDED;

			if (ec == net::error::connection_refused)
			{
				error_code = SOCKS5_CONNECTION_REFUSED;
			}
			else if (ec == net::error::network_unreachable)
			{
				error_code = SOCKS5_NETWORK_UNREACHABLE;
			}
			else if (ec == net::error::host_unreachable)
			{
				error_code = SOCKS5_HOST_UNREACHABLE;
			}
			else if (ec)
			{
				error_code = SOCKS5_GENERAL_SOCKS_SERVER_FAILURE;
			}

			//  +----+-----+-------+------+----------+----------+
			//  |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
			//  +----+-----+-------+------+----------+----------+
			//  | 1  |  1  | X'00' |  1   | Variable |    2     |
			//  +----+-----+-------+------+----------+----------+
			//  [                                               ]

			wbuf.consume(wbuf.size());
			auto wp = net::buffer_cast<char*>(wbuf.prepare(64 + domain.size()));

			write<uint8_t>(SOCKS_VERSION_5, wp); // VER
			write<uint8_t>(error_code, wp);      // REP
			write<uint8_t>(0x00, wp);            // RSV

			if (dst_endpoint.address().is_v4())
			{
				auto uaddr = dst_endpoint.address().to_v4().to_uint();

				write<uint8_t>(SOCKS5_ATYP_IPV4, wp);
				write<uint32_t>(uaddr, wp);
				write<uint16_t>(dst_endpoint.port(), wp);
			}
			else if (dst_endpoint.address().is_v6())
			{
				write<uint8_t>(SOCKS5_ATYP_IPV6, wp);
				auto data = dst_endpoint.address().to_v6().to_bytes();
				for (auto c : data)
				{
					write<uint8_t>(c, wp);
				}
				write<uint16_t>(dst_endpoint.port(), wp);
			}
			else if (!domain.empty())
			{
				write<uint8_t>(SOCKS5_ATYP_DOMAINNAME, wp);
				write<uint8_t>(static_cast<int8_t>(domain.size()), wp);
				std::copy(domain.begin(), domain.end(), wp);
				wp += domain.size();
				write<uint16_t>(port, wp);
			}
			else
			{
				write<uint8_t>(0x1, wp);
				write<uint32_t>(0, wp);
				write<uint16_t>(0, wp);
			}

			auto len = wp - net::buffer_cast<const char*>(wbuf.data());
			wbuf.commit(len);
			bytes = co_await net::async_write(m_local_socket, wbuf, net::transfer_exactly(len), net_awaitable[ec]);
			if (ec)
			{
				XLOG_WARN << "connection id: " << m_connection_id << ", write server response error: " << ec.message();
				co_return;
			}

			if (error_code != SOCKS5_SUCCEEDED)
			{
				co_return;
			}
		}

		XLOG_DBG << "connection id: " << m_connection_id << ", connected start transfer";

		// 发起数据传输协程.
		if (command == SOCKS_CMD_CONNECT)
		{
			size_t l2r_transferred = 0;
			size_t r2l_transferred = 0;

			co_await (transfer(m_local_socket, m_remote_socket, l2r_transferred) &&
					  transfer(m_remote_socket, m_local_socket, r2l_transferred));

			XLOG_DBG << "connection id: " << m_connection_id << ", transfer completed"
					 << ", local to remote: " << l2r_transferred << ", remote to local: " << r2l_transferred;
		}
		else
		{
			XLOG_WARN << "connection id: " << m_connection_id << ", SOCKS_CMD_BIND and SOCKS5_CMD_UDP is unsupported";
		}

		co_return;
	}

	net::awaitable<void> proxy_session::forward_udp()
	{
		[[maybe_unused]] auto self = shared_from_this();
		auto executor = co_await net::this_coro::executor;

		boost::system::error_code ec;

		udp::endpoint remote_endp;
		udp::endpoint local_endp;

		char read_buffer[4096];
		size_t send_total = 0;
		size_t recv_total = 0;

		const char* rbuf = &read_buffer[96];
		char* wbuf = &read_buffer[96];

		while (!m_abort)
		{
			// 重置 udp 超时时间.
			m_udp_timeout = m_option.udp_timeout_;

			auto bytes =
				co_await m_udp_socket.async_receive_from(net::buffer(wbuf, 4000), remote_endp, net_awaitable[ec]);
			if (ec)
			{
				break;
			}

			auto rp = rbuf;

			// 如果数据包来自 socks 客户端, 则解析数据包并将数据转发给目标主机.
			if (remote_endp.address() == m_local_udp_address)
			{
				local_endp = remote_endp;

				//  +----+------+------+----------+-----------+----------+
				//  |RSV | FRAG | ATYP | DST.ADDR | DST.PORT  |   DATA   |
				//  +----+------+------+----------+-----------+----------+
				//  | 2  |  1   |  1   | Variable |    2      | Variable |
				//  +----+------+------+----------+-----------+----------+

				// 去掉包头转发至远程主机.
				read<uint16_t>(rp);            // rsv
				auto frag = read<uint8_t>(rp); // frag

				// 不支持udp分片.
				if (frag != 0)
				{
					continue;
				}

				auto atyp = read<uint8_t>(rp);

				if (atyp == SOCKS5_ATYP_IPV4)
				{
					remote_endp.address(net::ip::address_v4(read<uint32_t>(rp)));
					remote_endp.port(read<uint16_t>(rp));
				}
				else if (atyp == SOCKS5_ATYP_DOMAINNAME)
				{
					auto length = read<uint8_t>(rp);
					std::string domain;

					for (size_t i = 0; i < length; i++)
					{
						domain.push_back(read<int8_t>(rp));
					}
					auto port = read<uint16_t>(rp);

					udp::resolver resolver{executor};

					auto targets = co_await resolver.async_resolve(domain, std::to_string(port), net_awaitable[ec]);
					if (ec)
					{
						break;
					}

					for (const auto& target : targets)
					{
						remote_endp = target.endpoint();
						break;
					}
				}
				else if (atyp == SOCKS5_ATYP_IPV6)
				{
					net::ip::address_v6::bytes_type addr;
					for (auto i = addr.begin(); i != addr.end(); ++i)
					{
						*i = read<int8_t>(rp);
					}

					remote_endp.address(net::ip::address_v6(addr));
					remote_endp.port(read<uint16_t>(rp));
				}

				auto head_size = rp - rbuf;
				auto udp_size = bytes - head_size;

				send_total++;

				co_await m_udp_socket.async_send_to(net::buffer(rp, udp_size), remote_endp, net_awaitable[ec]);
			}
			else // 如果数据包来自远程主机, 则解析数据包并将数据转发给 socks 客户端.
			{
				// 6 + 4 表示 socks5 udp 头部长度, 6 是 (RSV + FRAG + ATYP + DST.PORT)
				// 这部分的固定长度, 4 是 DST.ADDR 的长度.
				auto head_size = 6 + (remote_endp.address().is_v6() ? 16 : 4);
				auto udp_size = bytes + head_size;

				// 在数据包前面添加 socks5 udp 头部, 然后转发给 socks 客户端.
				auto wp = wbuf - head_size;

				write<uint16_t>(0x0, wp); // rsv
				write<uint8_t>(0x0, wp);  // frag

				if (remote_endp.address().is_v4())
				{
					auto uaddr = remote_endp.address().to_v4().to_uint();
					write<uint8_t>(SOCKS5_ATYP_IPV4, wp); // atyp

					write<uint32_t>(uaddr, wp);
					write<uint16_t>(remote_endp.port(), wp);
				}
				if (remote_endp.address().is_v6())
				{
					write<uint8_t>(SOCKS5_ATYP_IPV6, wp); // atyp

					auto data = remote_endp.address().to_v6().to_bytes();
					for (auto c : data)
					{
						write<uint8_t>(c, wp);
					}
					write<uint16_t>(remote_endp.port(), wp);
				}

				recv_total++;

				// 更新 wbuf 指针到 udp header 位置.
				wbuf = wbuf - head_size;

				co_await m_udp_socket.async_send_to(net::buffer(wbuf, udp_size), local_endp, net_awaitable[ec]);
			}
		}

		XLOG_DBG << "connection id: " << m_connection_id << ", recv total: " << recv_total
				 << ", send total: " << send_total << ", forward_udp quit";

		co_return;
	}

	net::awaitable<void> proxy_session::socks_connect_v4()
	{
		auto self = shared_from_this();
		auto p = net::buffer_cast<const char*>(m_local_buffer.data());

		[[maybe_unused]] auto socks_version = read<int8_t>(p);
		BOOST_ASSERT(socks_version == SOCKS_VERSION_4);
		auto command = read<int8_t>(p);

		//  +----+----+----+----+----+----+----+----+----+----+....+----+
		//  | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
		//  +----+----+----+----+----+----+----+----+----+----+....+----+
		//  | 1  | 1  |    2    |         4         | variable     | 1  |
		//  +----+----+----+----+----+----+----+----+----+----+....+----+
		//            [                             ]
		m_local_buffer.consume(m_local_buffer.size());
		boost::system::error_code ec;
		auto bytes =
			co_await net::async_read(m_local_socket, m_local_buffer, net::transfer_exactly(6), net_awaitable[ec]);
		if (ec)
		{
			XLOG_WARN << "connection id: " << m_connection_id << ", read socks4 dst: " << ec.message();
			co_return;
		}

		tcp::endpoint dst_endpoint;
		p = net::buffer_cast<const char*>(m_local_buffer.data());

		auto port = read<uint16_t>(p);
		dst_endpoint.port(port);
		dst_endpoint.address(net::ip::address_v4(read<uint32_t>(p)));

		bool socks4a = false;
		auto tmp = dst_endpoint.address().to_v4().to_uint() ^ 0x000000ff;
		if (0xff > tmp)
		{
			socks4a = true;
		}

		//  +----+----+----+----+----+----+----+----+----+----+....+----+
		//  | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
		//  +----+----+----+----+----+----+----+----+----+----+....+----+
		//  | 1  | 1  |    2    |         4         | variable     | 1  |
		//  +----+----+----+----+----+----+----+----+----+----+....+----+
		//                                          [                   ]
		m_local_buffer.consume(m_local_buffer.size());
		bytes = co_await net::async_read_until(m_local_socket, m_local_buffer, '\0', net_awaitable[ec]);
		if (ec)
		{
			XLOG_WARN << "connection id: " << m_connection_id << ", read socks4 userid: " << ec.message();
			co_return;
		}

		std::string userid;
		if (bytes > 1)
		{
			userid.resize(bytes - 1);
			m_local_buffer.sgetn(&userid[0], bytes - 1);
		}
		m_local_buffer.consume(1); // consume `null`

		std::string hostname;
		if (socks4a)
		{
			bytes = co_await net::async_read_until(m_local_socket, m_local_buffer, '\0', net_awaitable[ec]);
			if (ec)
			{
				XLOG_WARN << "connection id: " << m_connection_id << ", read socks4a hostname: " << ec.message();
				co_return;
			}

			if (bytes > 1)
			{
				hostname.resize(bytes - 1);
				m_local_buffer.sgetn(&hostname[0], bytes - 1);
			}
		}

		XLOG_DBG << "connection id: " << m_connection_id << ", use " << (socks4a ? "domain: " : "ip: ")
				 << (socks4a ? hostname : dst_endpoint.address().to_string());

		// 用户认证逻辑.
		bool verify_passed = m_option.auth_users_.empty();

		for (auto [user, pwd] : m_option.auth_users_)
		{
			if (user == userid)
			{
				verify_passed = true;
				user_rate_limit_config(user);
				break;
			}
		}

		if (verify_passed)
		{
			XLOG_DBG << "connection id: " << m_connection_id << ", auth passed";
		}
		else
		{
			XLOG_WARN << "connection id: " << m_connection_id << ", auth no pass";
		}

		if (!verify_passed)
		{
			//  +----+----+----+----+----+----+----+----+
			//  | VN | CD | DSTPORT |      DSTIP        |
			//  +----+----+----+----+----+----+----+----+
			//  | 1  | 1  |    2    |         4         |
			//  +----+----+----+----+----+----+----+----+
			//  [                                       ]

			net::streambuf wbuf;
			auto wp = net::buffer_cast<char*>(wbuf.prepare(16));

			write<uint8_t>(0, wp);
			write<uint8_t>(SOCKS4_REQUEST_REJECTED_USER_NO_ALLOW, wp);

			write<uint16_t>(dst_endpoint.port(), wp);
			write<uint32_t>(dst_endpoint.address().to_v4().to_ulong(), wp);

			wbuf.commit(8);
			bytes = co_await net::async_write(m_local_socket, wbuf, net::transfer_exactly(8), net_awaitable[ec]);
			if (ec)
			{
				XLOG_WARN << "connection id: " << m_connection_id << ", write socks4 no allow: " << ec.message();
				co_return;
			}

			XLOG_WARN << "connection id: " << m_connection_id << ", socks4 " << userid << " auth fail";
			co_return;
		}

		int error_code = SOCKS4_REQUEST_GRANTED;
		if (command == SOCKS_CMD_CONNECT)
		{
			if (socks4a)
			{
				co_await start_connect_host(hostname, port, ec, true);
			}
			else
			{
				co_await start_connect_host(dst_endpoint.address().to_string(), port, ec);
			}
			if (ec)
			{
				XLOG_FWARN("connection id: {},"
						   " connect to target {}:{} error: {}",
						   m_connection_id, dst_endpoint.address().to_string(), port, ec.message());
				error_code = SOCKS4_CANNOT_CONNECT_TARGET_SERVER;
			}
		}
		else
		{
			error_code = SOCKS4_REQUEST_REJECTED_OR_FAILED;
			XLOG_FWARN("connection id: {},"
					   " unsupported command for socks4",
					   m_connection_id);
		}

		//  +----+----+----+----+----+----+----+----+
		//  | VN | CD | DSTPORT |      DSTIP        |
		//  +----+----+----+----+----+----+----+----+
		//  | 1  | 1  |    2    |         4         |
		//  +----+----+----+----+----+----+----+----+
		//  [                                       ]

		net::streambuf wbuf;
		auto wp = net::buffer_cast<char*>(wbuf.prepare(16));

		write<uint8_t>(0, wp);
		write<uint8_t>((uint8_t)error_code, wp);

		// 返回IP:PORT.
		write<uint16_t>(dst_endpoint.port(), wp);
		write<uint32_t>(dst_endpoint.address().to_v4().to_ulong(), wp);

		wbuf.commit(8);
		bytes = co_await net::async_write(m_local_socket, wbuf, net::transfer_exactly(8), net_awaitable[ec]);
		if (ec)
		{
			XLOG_WARN << "connection id: " << m_connection_id << ", write socks4 response: " << ec.message();
			co_return;
		}

		if (error_code != SOCKS4_REQUEST_GRANTED)
		{
			co_return;
		}

		size_t l2r_transferred = 0;
		size_t r2l_transferred = 0;

		co_await (transfer(m_local_socket, m_remote_socket, l2r_transferred) &&
				  transfer(m_remote_socket, m_local_socket, r2l_transferred));

		XLOG_DBG << "connection id: " << m_connection_id << ", transfer completed"
				 << ", local to remote: " << l2r_transferred << ", remote to local: " << r2l_transferred;
		co_return;
	}


	net::awaitable<bool> proxy_session::http_proxy_get()
	{
		boost::system::error_code ec;
		bool keep_alive = false;
		bool first = true;

		while (!m_abort)
		{
			std::array<std::byte, 4096> pre_alloc_buf;
			std::pmr::monotonic_buffer_resource mbr(pre_alloc_buf.data(), pre_alloc_buf.size());
			pmr_alloc_t alloc(&mbr);
			std::optional<request_parser> parser;
			parser.emplace(std::piecewise_construct, std::make_tuple(alloc), std::make_tuple(alloc));

			parser->body_limit(1024 * 1024 * 10);
			if (!first)
			{
				m_local_buffer.consume(m_local_buffer.size());
			}

			// 读取 http 请求头.
			co_await http::async_read(m_local_socket, m_local_buffer, *parser, net_awaitable[ec]);
			if (ec)
			{
				XLOG_WARN << "connection id: " << m_connection_id << (keep_alive ? ", keepalive" : "")
						  << ", http_proxy_get request async_read: " << ec.message();

				co_return !first;
			}

			auto req = parser->release();
			auto mth = std::pmr::string(req.method_string(), alloc);
			std::string_view target_view = req.target();
			std::string_view pa = req[http::field::proxy_authorization];

			keep_alive = req.keep_alive();

			XLOG_DBG << "connection id: " << m_connection_id << ", method: " << mth << ", target: " << target_view
					 << (pa.empty() ? "" : ", proxy_authorization: ") << ( pa.empty()? std::string_view() : pa );

			// 判定是否为 GET url 代理模式.
			bool get_url_proxy = false;
			if (boost::istarts_with(req.target(), "https://") || boost::istarts_with(req.target(), "http://"))
			{
				get_url_proxy = true;
			}

			// http 代理认证, 如果请求的 rarget 不是 http url 或认证
			// 失败, 则按正常 web 请求处理.
			auto auth = http_authorization(pa);
			if (auth != PROXY_AUTH_SUCCESS || !get_url_proxy)
			{
				auto expect_url = urls::parse_absolute_uri(req.target());

				if (!expect_url.has_error())
				{
					XLOG_WARN << "connection id: " << m_connection_id << ", proxy err: " << pauth_error_message(auth);

					co_return !first;
				}

				// 如果 doc 目录为空, 则不允许访问目录
				// 这里直接返回错误页面.
				if (m_option.doc_directory_.empty())
				{
					co_return !first;
				}

				// htpasswd 表示需要用户认证.
				if (m_option.htpasswd_)
				{
					// 处理 http 认证, 如果客户没有传递认证信息, 则返回 401.
					// 如果用户认证信息没有设置, 则直接返回 401.
					auto auth = req[http::field::authorization];
					if (auth.empty() || m_option.auth_users_.empty())
					{
						XLOG_WARN << "connection id: " << m_connection_id
								  << ", auth error: " << (auth.empty() ? "no auth" : "no user");

						co_await unauthorized_http_route(req);
						co_return true;
					}

					auto auth_result = http_authorization(auth);
					if (auth_result != PROXY_AUTH_SUCCESS)
					{
						XLOG_WARN << "connection id: " << m_connection_id
								  << ", auth error: " << pauth_error_message(auth_result);

						co_await unauthorized_http_route(req);
						co_return true;
					}
				}

				// 如果不允许目录索引, 检查请求的是否为文件, 如果是具体文件则按文
				// 件请求处理, 否则返回 403.
				if (!m_option.autoindex_)
				{
					auto path = make_real_target_path(req.target(), alloc);

					if (!fs::is_directory(std::string_view{path}, ec))
					{
						co_await normal_web_server(req, alloc);
						co_return true;
					}

					// 如果不允许目录索引, 则直接返回 403 forbidden.
					co_await forbidden_http_route(req);

					co_return true;
				}

				// 按正常 http 目录请求来处理.
				co_await normal_web_server(req, alloc);
				co_return true;
			}

			const auto authority_pos = target_view.find_first_of("//") + 2;

			std::string host;

			const auto scheme_id = urls::string_to_scheme(target_view.substr(0, authority_pos - 3));
			uint16_t port = urls::default_port(scheme_id);

			auto host_pos = authority_pos;
			auto host_end = std::string::npos;

			auto port_start = std::string::npos;

			for (auto pos = authority_pos; pos < target_view.size(); pos++)
			{
				const auto& c = target_view[pos];
				if (c == '@')
				{
					host_pos = pos + 1;

					host_end = std::string::npos;
					port_start = std::string::npos;
				}
				else if (c == ':')
				{
					host_end = pos;
					port_start = pos + 1;
				}
				else if (c == '/' || (pos + 1 == target_view.size()))
				{
					if (host_end == std::string::npos)
					{
						host_end = pos;
					}
					host = target_view.substr(host_pos, host_end - host_pos);

					if (port_start != std::string::npos)
					{
						port = (uint16_t)std::strtol(target_view.substr(port_start, pos - port_start).data(), nullptr, 10);
					}

					break;
				}
			}

			if (!m_remote_socket.is_open())
			{
				// 连接到目标主机.
				co_await start_connect_host(host, port ? port : 80, ec, true);
				if (ec)
				{
					XLOG_FWARN("connection id: {},"
							   " connect to target {}:{} error: {}",
							   m_connection_id, host, port, ec.message());

					co_return !first;
				}
			}

			// 处理代理请求头.
			const auto path_pos = target_view.find_first_of("/", authority_pos);
			if (path_pos == std::string_view::npos)
			{
				req.target("/");
			}
			else
			{
				req.target(std::string(target_view.substr(path_pos)));
			}

			req.set(http::field::host, host);

			if (req.find(http::field::connection) == req.end() && req.find(http::field::proxy_connection) != req.end())
			{
				req.set(http::field::connection, req[http::field::proxy_connection]);
			}

			req.erase(http::field::proxy_authorization);
			req.erase(http::field::proxy_connection);

			co_await http::async_write(m_remote_socket, req, net_awaitable[ec]);
			if (ec)
			{
				XLOG_WARN << "connection id: " << m_connection_id
						  << ", http_proxy_get request async_write: " << ec.message();
				co_return !first;
			}

			m_local_buffer.consume(m_local_buffer.size());
			beast::flat_buffer buf;

			response_parser _parser{std::piecewise_construct, std::make_tuple(alloc), std::make_tuple(alloc)};
			_parser.body_limit(1024 * 1024 * 10);

			auto bytes = co_await http::async_read(m_remote_socket, buf, _parser, net_awaitable[ec]);
			if (ec)
			{
				XLOG_WARN << "connection id: " << m_connection_id
						  << ", http_proxy_get response async_read: " << ec.message();
				co_return !first;
			}

			co_await http::async_write(m_local_socket, _parser.release(), net_awaitable[ec]);
			if (ec)
			{
				XLOG_WARN << "connection id: " << m_connection_id
						  << ", http_proxy_get response async_write: " << ec.message();
				co_return !first;
			}

			XLOG_DBG << "connection id: " << m_connection_id << ", transfer completed"
					 << ", remote to local: " << bytes;

			first = false;
			if (!keep_alive)
			{
				break;
			}
		}

		co_return true;
	}

	net::awaitable<bool> proxy_session::http_proxy_connect()
	{
		http::request<http::string_body> req;
		boost::system::error_code ec;

		// 读取 http 请求头.
		co_await http::async_read(m_local_socket, m_local_buffer, req, net_awaitable[ec]);
		if (ec)
		{
			XLOG_ERR << "connection id: " << m_connection_id << ", http_proxy_connect async_read: " << ec.message();

			co_return false;
		}

		auto mth = std::string(req.method_string());
		auto target_view = std::string(req.target());
		auto pa = std::string(req[http::field::proxy_authorization]);

		XLOG_DBG << "connection id: " << m_connection_id << ", method: " << mth << ", target: " << target_view
				 << (pa.empty() ? std::string() : ", proxy_authorization: " + pa);

		// http 代理认证.
		auto auth = http_authorization(pa);
		if (auth != PROXY_AUTH_SUCCESS)
		{
			XLOG_WARN << "connection id: " << m_connection_id << ", proxy err: " << pauth_error_message(auth);

			auto fake_page = fmt::vformat(fake_407_content_fmt, fmt::make_format_args(server_date_string()));

			co_await net::async_write(m_local_socket, net::buffer(fake_page), net::transfer_all(), net_awaitable[ec]);

			co_return true;
		}

		auto pos = target_view.find(':');
		if (pos == std::string::npos)
		{
			XLOG_ERR << "connection id: " << m_connection_id << ", illegal target: " << target_view;
			co_return false;
		}

		std::string host(target_view.substr(0, pos));
		std::string port(target_view.substr(pos + 1));

		co_await start_connect_host(host, static_cast<uint16_t>(std::atol(port.c_str())), ec, true);
		if (ec)
		{
			XLOG_FWARN("connection id: {},"
					   " connect to target {}:{} error: {}",
					   m_connection_id, host, port, ec.message());
			co_return false;
		}

		http::response<http::empty_body> res{http::status::ok, req.version()};
		res.reason("Connection established");

		co_await http::async_write(m_local_socket, res, net_awaitable[ec]);
		if (ec)
		{
			XLOG_FWARN("connection id: {},"
					   " async write response {}:{} error: {}",
					   m_connection_id, host, port, ec.message());
			co_return false;
		}

		size_t l2r_transferred = 0;
		size_t r2l_transferred = 0;

		co_await (transfer(m_local_socket, m_remote_socket, l2r_transferred) &&
				  transfer(m_remote_socket, m_local_socket, r2l_transferred));

		XLOG_DBG << "connection id: " << m_connection_id << ", transfer completed"
				 << ", local to remote: " << l2r_transferred << ", remote to local: " << r2l_transferred;

		co_return true;
	}

	int proxy_session::http_authorization(std::string_view pa)
	{
		if (m_option.auth_users_.empty())
		{
			return PROXY_AUTH_SUCCESS;
		}

		if (pa.empty())
		{
			return PROXY_AUTH_NONE;
		}

		auto pos = pa.find(' ');
		if (pos == std::string::npos)
		{
			return PROXY_AUTH_ILLEGAL;
		}

		auto type = pa.substr(0, pos);
		auto auth = pa.substr(pos + 1);

		if (type != "Basic")
		{
			return PROXY_AUTH_ILLEGAL;
		}

		char buff[1024];
		std::pmr::monotonic_buffer_resource mbr(buff, sizeof buff);
		pmr_alloc_t alloc(&mbr);

		std::pmr::string userinfo(beast::detail::base64::decoded_size(auth.size()), 0, alloc);
		auto [len, _] = beast::detail::base64::decode((char*)userinfo.data(), auth.data(), auth.size());
		userinfo.resize(len);

		pos = userinfo.find(':');

		std::pmr::string uname{userinfo.substr(0, pos), alloc};
		std::pmr::string passwd{userinfo.substr(pos + 1), alloc};

		bool verify_passed = m_option.auth_users_.empty();

		for (auto [user, pwd] : m_option.auth_users_)
		{
			if (uname == user && passwd == pwd)
			{
				verify_passed = true;
				user_rate_limit_config(user);
				break;
			}
		}

		auto endp = m_local_socket.remote_endpoint();
		auto client = endp.address().to_string();
		client += ":" + std::to_string(endp.port());

		if (!verify_passed)
		{
			return PROXY_AUTH_FAILED;
		}

		return PROXY_AUTH_SUCCESS;
	}

	net::awaitable<bool> proxy_session::socks_auth()
	{
		//  +----+------+----------+------+----------+
		//  |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
		//  +----+------+----------+------+----------+
		//  | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
		//  +----+------+----------+------+----------+
		//  [           ]

		boost::system::error_code ec;
		m_local_buffer.consume(m_local_buffer.size());
		auto bytes =
			co_await net::async_read(m_local_socket, m_local_buffer, net::transfer_exactly(2), net_awaitable[ec]);
		if (ec)
		{
			XLOG_WARN << "connection id: " << m_connection_id
					  << ", read client username/passwd error: " << ec.message();
			co_return false;
		}

		auto p = net::buffer_cast<const char*>(m_local_buffer.data());
		int auth_version = read<int8_t>(p);
		if (auth_version != 1)
		{
			XLOG_WARN << "connection id: " << m_connection_id << ", socks negotiation, unsupported socks5 protocol";
			co_return false;
		}
		int name_length = read<uint8_t>(p);
		if (name_length <= 0 || name_length > 255)
		{
			XLOG_WARN << "connection id: " << m_connection_id << ", socks negotiation, invalid name length";
			co_return false;
		}
		name_length += 1;

		//  +----+------+----------+------+----------+
		//  |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
		//  +----+------+----------+------+----------+
		//  | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
		//  +----+------+----------+------+----------+
		//              [                 ]
		m_local_buffer.consume(m_local_buffer.size());
		bytes = co_await net::async_read(m_local_socket, m_local_buffer, net::transfer_exactly(name_length),
										 net_awaitable[ec]);
		if (ec)
		{
			XLOG_WARN << "connection id: " << m_connection_id << ", read client username error: " << ec.message();
			co_return false;
		}

		std::string uname;

		p = net::buffer_cast<const char*>(m_local_buffer.data());
		for (size_t i = 0; i < bytes - 1; i++)
		{
			uname.push_back(read<int8_t>(p));
		}

		int passwd_len = read<uint8_t>(p);
		if (passwd_len <= 0 || passwd_len > 255)
		{
			XLOG_WARN << "connection id: " << m_connection_id << ", socks negotiation, invalid passwd length";
			co_return false;
		}

		//  +----+------+----------+------+----------+
		//  |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
		//  +----+------+----------+------+----------+
		//  | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
		//  +----+------+----------+------+----------+
		//                                [          ]
		m_local_buffer.consume(m_local_buffer.size());
		bytes = co_await net::async_read(m_local_socket, m_local_buffer, net::transfer_exactly(passwd_len),
										 net_awaitable[ec]);
		if (ec)
		{
			XLOG_WARN << "connection id: " << m_connection_id << ", read client passwd error: " << ec.message();
			co_return false;
		}

		std::string passwd;

		p = net::buffer_cast<const char*>(m_local_buffer.data());
		for (size_t i = 0; i < bytes; i++)
		{
			passwd.push_back(read<int8_t>(p));
		}

		// SOCKS5验证用户和密码.
		auto endp = m_local_socket.remote_endpoint();
		auto client = endp.address().to_string();
		client += ":" + std::to_string(endp.port());

		// 用户认证逻辑.
		bool verify_passed = m_option.auth_users_.empty();

		for (auto [user, pwd] : m_option.auth_users_)
		{
			if (uname == user && passwd == pwd)
			{
				verify_passed = true;
				user_rate_limit_config(user);
				break;
			}
		}

		XLOG_DBG << "connection id: " << m_connection_id << ", auth: " << uname << ", passwd: " << passwd
				 << ", client: " << client;

		net::streambuf wbuf;
		auto wp = net::buffer_cast<char*>(wbuf.prepare(16));
		write<uint8_t>(0x01, wp); // version 只能是1.
		if (verify_passed)
		{
			write<uint8_t>(0x00, wp); // 认证通过返回0x00, 其它值为失败.
		}
		else
		{
			write<uint8_t>(0x01, wp); // 认证返回0x01为失败.
		}

		// 返回认证状态.
		//  +----+--------+
		//  |VER | STATUS |
		//  +----+--------+
		//  | 1  |   1    |
		//  +----+--------+
		wbuf.commit(2);
		co_await net::async_write(m_local_socket, wbuf, net::transfer_exactly(2), net_awaitable[ec]);
		if (ec)
		{
			XLOG_WARN << "connection id: " << m_connection_id << ", server write status error: " << ec.message();
			co_return false;
		}

		co_return verify_passed;
	}

	template <typename Stream, typename Endpoint>
	bool proxy_session::check_condition(const boost::system::error_code&, Stream& stream, Endpoint&) const
	{
		if (!m_bind_interface)
			return true;

		tcp::endpoint bind_endpoint(*m_bind_interface, 0);
		boost::system::error_code err;

		stream.open(bind_endpoint.protocol(), err);
		if (err)
			return false;

		stream.bind(bind_endpoint, err);
		if (err)
			return false;

		return true;
	}

	net::awaitable<bool> proxy_session::connect_bridge_proxy(tcp::socket& remote_socket, std::string target_host,
															 uint16_t target_port, boost::system::error_code& ec)
	{
		auto executor = co_await net::this_coro::executor;

		tcp::resolver resolver{executor};

		auto proxy_host = std::string(m_bridge_proxy->host());
		std::string proxy_port;
		if (m_bridge_proxy->port_number() == 0)
		{
			proxy_port = std::to_string(urls::default_port(m_bridge_proxy->scheme_id()));
		}
		else
		{
			proxy_port = std::to_string(m_bridge_proxy->port_number());
		}
		if (proxy_port.empty())
		{
			proxy_port = m_bridge_proxy->scheme();
		}

		XLOG_DBG << "connection id: " << m_connection_id << ", connect to next proxy: " << proxy_host << ":"
				 << proxy_port;

		tcp::resolver::results_type targets;

		if (!detect_hostname(proxy_host))
		{
			net::ip::tcp::endpoint endp(net::ip::address::from_string(proxy_host),
										m_bridge_proxy->port_number()
											? m_bridge_proxy->port_number()
											: urls::default_port(m_bridge_proxy->scheme_id()));

			targets = tcp::resolver::results_type::create(endp, proxy_host, m_bridge_proxy->scheme());
		}
		else
		{
			targets = co_await resolver.async_resolve(proxy_host, proxy_port, net_awaitable[ec]);

			if (ec)
			{
				XLOG_FWARN("connection id: {},"
						   " resolver to next proxy {}:{} error: {}",
						   m_connection_id, std::string(m_bridge_proxy->host()), std::string(m_bridge_proxy->port()),
						   ec.message());

				co_return false;
			}
		}

		if (m_option.happyeyeballs_)
		{
			co_await asio_util::async_connect(remote_socket, targets, [this](const auto& ec, auto& stream, auto& endp)
			{ return check_condition(ec, stream, endp); }, net_awaitable[ec]);
		}
		else
		{
			for (auto endpoint : targets)
			{
				ec = boost::asio::error::host_not_found;

				if (m_option.connect_v4_only_)
				{
					if (endpoint.endpoint().address().is_v6())
					{
						continue;
					}
				}
				else if (m_option.connect_v6_only_)
				{
					if (endpoint.endpoint().address().is_v4())
					{
						continue;
					}
				}

				boost::system::error_code ignore_ec;
				remote_socket.close(ignore_ec);

				if (m_bind_interface)
				{
					tcp::endpoint bind_endpoint(*m_bind_interface, 0);

					remote_socket.open(bind_endpoint.protocol(), ec);
					if (ec)
					{
						break;
					}

					remote_socket.bind(bind_endpoint, ec);
					if (ec)
					{
						break;
					}
				}

				co_await remote_socket.async_connect(endpoint, net_awaitable[ec]);
				if (!ec)
				{
					break;
				}
			}
		}

		if (ec)
		{
			XLOG_FWARN("connection id: {},"
					   " connect to next proxy {}:{} error: {}",
					   m_connection_id, std::string(m_bridge_proxy->host()), std::string(m_bridge_proxy->port()),
					   ec.message());

			co_return false;
		}

		XLOG_DBG << "connection id: " << m_connection_id << ", connect to next proxy: " << proxy_host << ":"
				 << proxy_port << " success";

		// 如果启用了 noise, 则在向上游代理服务器发起 tcp 连接成功后, 发送 noise
		// 数据以及接收 noise 数据.
		if (m_option.scramble_)
		{
			if (!co_await noise_handshake(remote_socket, m_outin_key, m_outout_key))
			{
				co_return false;
			}

			XLOG_DBG << "connection id: " << m_connection_id << ", with upstream noise completed";
		}

		// 使用ssl加密与下一级代理通信.
		if (m_option.proxy_pass_use_ssl_)
		{
			// 设置 ssl cert 证书目录.
			if (fs::exists(m_option.ssl_cacert_path_))
			{
				m_ssl_cli_context.add_verify_path(m_option.ssl_cacert_path_, ec);
				if (ec)
				{
					XLOG_FWARN("connection id: {}, "
							   "load cert path: {}, "
							   "error: {}",
							   m_connection_id, m_option.ssl_cacert_path_, ec.message());

					co_return false;
				}
			}
		}

		auto scheme = m_bridge_proxy->scheme();

		auto instantiate_stream = [this, &scheme, &proxy_host, &remote_socket,
								   &ec]() mutable -> net::awaitable<variant_stream_type>
		{
			ec = {};

			XLOG_DBG << "connection id: " << m_connection_id << ", connect to next proxy: " << proxy_host
					 << " instantiate stream";

			if (m_option.proxy_pass_use_ssl_ || scheme == "https")
			{
				m_ssl_cli_context.set_verify_mode(net::ssl::verify_peer);
				auto cert = default_root_certificates();
				m_ssl_cli_context.add_certificate_authority(net::buffer(cert.data(), cert.size()), ec);
				if (ec)
				{
					XLOG_FWARN("connection id: {},"
							   " add_certificate_authority error: {}",
							   m_connection_id, ec.message());
				}

				m_ssl_cli_context.use_tmp_dh(net::buffer(default_dh_param()), ec);

				m_ssl_cli_context.set_verify_callback(net::ssl::rfc2818_verification(proxy_host), ec);
				if (ec)
				{
					XLOG_FWARN("connection id: {},"
							   " set_verify_callback error: {}",
							   m_connection_id, ec.message());
				}

				// 生成 ssl socket 对象.
				auto sock_stream = init_proxy_stream(std::move(remote_socket), m_ssl_cli_context);

				// get origin ssl stream type.
				ssl_stream& ssl_socket = boost::variant2::get<ssl_stream>(sock_stream);

				if (m_option.scramble_)
				{
					auto& next_layer = ssl_socket.next_layer();

					using NextLayerType = std::decay_t<decltype(next_layer)>;

					if constexpr (!std::same_as<tcp::socket, NextLayerType>)
					{
						next_layer.set_scramble_key(m_outout_key);

						next_layer.set_unscramble_key(m_outin_key);
					}
				}

				std::string sni = m_option.proxy_ssl_name_.empty() ? proxy_host : m_option.proxy_ssl_name_;

				// Set SNI Hostname.
				if (!SSL_set_tlsext_host_name(ssl_socket.native_handle(), sni.c_str()))
				{
					XLOG_FWARN("connection id: {},"
							   " SSL_set_tlsext_host_name error: {}",
							   m_connection_id, ::ERR_get_error());
				}

				XLOG_DBG << "connection id: " << m_connection_id << ", do async ssl handshake...";

				// do async handshake.
				co_await ssl_socket.async_handshake(net::ssl::stream_base::client, net_awaitable[ec]);
				if (ec)
				{
					XLOG_FWARN("connection id: {},"
							   " ssl client protocol handshake error: {}",
							   m_connection_id, ec.message());
				}

				XLOG_FDBG("connection id: {}, ssl handshake: {}", m_connection_id, proxy_host);

				co_return sock_stream;
			}

			auto sock_stream = init_proxy_stream(std::move(remote_socket));

			auto& sock = boost::variant2::get<proxy_tcp_socket>(sock_stream);

			if (m_option.scramble_)
			{
				using NextLayerType = std::decay_t<decltype(sock)>;

				if constexpr (!std::same_as<tcp::socket, NextLayerType>)
				{
					sock.set_scramble_key(m_outout_key);

					sock.set_unscramble_key(m_outin_key);
				}
			}

			co_return sock_stream;
		};

		m_remote_socket = std::move(co_await instantiate_stream());

		XLOG_DBG << "connection id: " << m_connection_id << ", connect to next proxy: " << proxy_host << ":"
				 << proxy_port << " start upstream handshake with " << std::string(scheme);

		if (scheme.starts_with("socks"))
		{
			socks_client_option opt;

			opt.target_host = target_host;
			opt.target_port = target_port;
			opt.proxy_hostname = true;
			opt.username = std::string(m_bridge_proxy->user());
			opt.password = std::string(m_bridge_proxy->password());

			if (scheme == "socks4")
			{
				opt.version = socks4_version;
			}
			else if (scheme == "socks4a")
			{
				opt.version = socks4a_version;
			}

			co_await async_socks_handshake(m_remote_socket, opt, net_awaitable[ec]);
		}
		else if (scheme.starts_with("http"))
		{
			http_proxy_client_option opt;

			opt.target_host = target_host;
			opt.target_port = target_port;
			opt.username = std::string(m_bridge_proxy->user());
			opt.password = std::string(m_bridge_proxy->password());

			co_await async_http_proxy_handshake(m_remote_socket, opt, net_awaitable[ec]);
		}

		if (ec)
		{
			XLOG_FWARN("connection id: {}"
					   ", {} connect to next host {}:{} error: {}",
					   m_connection_id, std::string(scheme), target_host, target_port, ec.message());

			co_return false;
		}

		co_return true;
	}

	net::awaitable<bool> proxy_session::start_connect_host(std::string target_host, uint16_t target_port,
														   boost::system::error_code& ec, bool resolve)
	{
		auto executor = co_await net::this_coro::executor;

		tcp::socket& remote_socket = net_tcp_socket(m_remote_socket);

		if (m_bridge_proxy)
		{
			auto ret = co_await connect_bridge_proxy(remote_socket, target_host, target_port, ec);

			co_return ret;
		}
		else
		{
			net::ip::basic_resolver_results<tcp> targets;
			if (resolve)
			{
				tcp::resolver resolver{executor};

				targets = co_await resolver.async_resolve(target_host, std::to_string(target_port), net_awaitable[ec]);
				if (ec)
				{
					XLOG_WARN << "connection id: " << m_connection_id << ", resolve: " << target_host
							  << ", error: " << ec.message();

					co_return false;
				}
			}
			else
			{
				tcp::endpoint dst_endpoint;

				dst_endpoint.address(net::ip::address::from_string(target_host));
				dst_endpoint.port(target_port);

				targets = net::ip::basic_resolver_results<tcp>::create(dst_endpoint, "", "");
			}

			if (m_option.happyeyeballs_)
			{
				co_await asio_util::async_connect(remote_socket, targets,
												  [this](const auto& ec, auto& stream, auto& endp)
				{ return check_condition(ec, stream, endp); }, net_awaitable[ec]);
			}
			else
			{
				for (auto endpoint : targets)
				{
					ec = boost::asio::error::host_not_found;

					if (m_option.connect_v4_only_)
					{
						if (endpoint.endpoint().address().is_v6())
						{
							continue;
						}
					}
					else if (m_option.connect_v6_only_)
					{
						if (endpoint.endpoint().address().is_v4())
						{
							continue;
						}
					}

					boost::system::error_code ignore_ec;
					remote_socket.close(ignore_ec);

					if (m_bind_interface)
					{
						tcp::endpoint bind_endpoint(*m_bind_interface, 0);

						remote_socket.open(bind_endpoint.protocol(), ec);
						if (ec)
						{
							break;
						}

						remote_socket.bind(bind_endpoint, ec);
						if (ec)
						{
							break;
						}
					}

					co_await remote_socket.async_connect(endpoint, net_awaitable[ec]);
					if (!ec)
					{
						break;
					}
				}
			}

			if (ec)
			{
				XLOG_FWARN("connection id: {}, connect to target {}:{} error: {}", m_connection_id, target_host,
						   target_port, ec.message());

				co_return false;
			}

			m_remote_socket = init_proxy_stream(std::move(remote_socket));
		}

		co_return true;
	}

} // namespace proxy
