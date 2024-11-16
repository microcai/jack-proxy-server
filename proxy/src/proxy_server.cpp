

#include "proxy/libproxy_pch.hpp"

#include "proxy/proxy_session.hpp"
#include "proxy/proxy_server.hpp"
#include "proxy/strutil.hpp"
#include "proxy/fileop.hpp"
#include "proxy/logging.hpp"
#include "proxy/use_awaitable.hpp"
#include "proxy/proxy_stream.hpp"

#include <boost/asio.hpp>

#include <boost/regex.hpp>

#include <fmt/xchar.h>
#include <fmt/format.h>

namespace proxy
{
	//////////////////////////////////////////////////////////////////////////

	// 检测 host 是否是域名或主机名, 如果是域名则返回 true, 否则返回 false.
	inline bool detect_hostname(const std::string& host) noexcept
	{
		boost::system::error_code ec;
		net::ip::address::from_string(host, ec);
		if (ec)
			return true;
		return false;
	}

	////////////////////////////////////////////////////////////////////////////////////
	// proxy_server 实现
	////////////////////////////////////////////////////////////////////////////////////
	proxy_server::proxy_server(net::any_io_executor executor, proxy_server_option opt)
		: m_executor(executor), m_option(std::move(opt))
	{
		init_ssl_context();

		boost::nowide::nowide_filesystem();

		boost::system::error_code ec;

		if (fs::exists(m_option.ipip_db_, ec))
		{
			m_ipip = std::make_unique<ipip_datx>();
			if (!m_ipip->load(m_option.ipip_db_))
			{
				m_ipip.reset();
			}
		}

		init_acceptor();
	}

	pem_file proxy_server::determine_pem_type(const std::string& filepath) noexcept
	{
		pem_file result{filepath, pem_type::none};

		boost::nowide::ifstream file(filepath);
		if (!file.is_open())
		{
			return result;
		}

		if (fs::path(filepath).filename() == "password.txt" || fs::path(filepath).filename() == "passwd.txt" ||
			fs::path(filepath).filename() == "passwd" || fs::path(filepath).filename() == "password" ||
			fs::path(filepath).filename() == "passphrase" || fs::path(filepath).filename() == "passphrase.txt")
		{
			result.type_ = pem_type::pwd;
			return result;
		}

		if (fs::path(filepath).filename() == "domain.txt" || fs::path(filepath).filename() == "domain" ||
			fs::path(filepath).filename() == "servername" || fs::path(filepath).filename() == "servername.txt")
		{
			result.type_ = pem_type::domain;
			return result;
		}

		proxy::pem_type type = pem_type::none;
		std::string line;

		boost::regex re(R"(-----BEGIN\s.*\s?PRIVATE\sKEY-----)");
		boost::smatch what;

		while (std::getline(file, line))
		{
			if (line.find("-----BEGIN CERTIFICATE-----") != std::string::npos)
			{
				type = pem_type::cert;
				result.chains_++;
				continue;
			}
			else if (line.find("DH PARAMETERS-----") != std::string::npos)
			{
				type = pem_type::dhparam;
				break;
			}
			else if (boost::regex_search(line, what, re))
			{
				type = pem_type::key;
				break;
			}
		}
		result.type_ = type;

		return result;
	}

	void proxy_server::find_cert(const fs::path& directory) noexcept
	{
		if (!fs::exists(directory) || !fs::is_directory(directory))
		{
			XLOG_WARN << "Path is not a directory or doesn't exist: " << directory;
			return;
		}

		certificate_file file;

		// 域名在路径中，如：/etc/letsencrypt/live/www.jackarain.org/
		boost::regex re(R"(([^\/|\\]+?\.[a-zA-Z]{2,})(?=\/?$))");
		boost::smatch what;
		if (boost::regex_search(directory.string(), what, re))
		{
			file.domain_ = std::string(what[1]);
			strutil::trim(file.domain_);
		}

		for (const auto& entry : fs::directory_iterator(directory))
		{
			if (entry.is_directory())
			{
				find_cert(entry.path());
				continue;
			}

			if (entry.is_regular_file())
			{
				// 读取文件, 并判断文件类型.
				auto type = determine_pem_type(entry.path().string());
				switch (type.type_)
				{
				case pem_type::cert:
					if (type.chains_ > file.cert_.chains_)
					{
						file.cert_ = type;
					}
					break;
				case pem_type::key:
					file.key_ = type;
					break;
				case pem_type::dhparam:
					file.dhparam_ = type;
					break;
				case pem_type::pwd:
					file.pwd_ = type;
					break;
				case pem_type::domain:
					fileop::read(entry.path(), file.domain_);
					strutil::trim(file.domain_);
					break;
				default:
					break;
				}
			}
		}

		// 如果找到了证书文件, 创建一个证书文件对象.
		if (file.cert_.type_ != pem_type::none && file.key_.type_ != pem_type::none)
		{
			// 创建 ssl context 对象.
			file.ssl_context_.emplace(net::ssl::context::sslv23);

			auto& ssl_ctx = file.ssl_context_.value();

			// 设置 ssl context 选项.
			ssl_ctx.set_options(net::ssl::context::default_workarounds | net::ssl::context::no_sslv2 |
								net::ssl::context::no_sslv3 | net::ssl::context::no_tlsv1 |
								net::ssl::context::no_tlsv1_1 | net::ssl::context::single_dh_use);

			// 如果设置了 ssl_prefer_server_ciphers_ 则设置 SSL_OP_CIPHER_SERVER_PREFERENCE.
			if (m_option.ssl_prefer_server_ciphers_)
			{
				ssl_ctx.set_options(SSL_OP_CIPHER_SERVER_PREFERENCE);
			}

			// 默认的 ssl ciphers.
			const std::string ssl_ciphers = "HIGH:!aNULL:!MD5:!3DES";
			if (m_option.ssl_ciphers_.empty())
			{
				m_option.ssl_ciphers_ = ssl_ciphers;
			}

			// 设置 ssl ciphers.
			SSL_CTX_set_cipher_list(ssl_ctx.native_handle(), m_option.ssl_ciphers_.c_str());

			// 设置证书文件.
			boost::system::error_code ec;
			ssl_ctx.use_certificate_chain_file(file.cert_.filepath_.string(), ec);
			if (ec)
			{
				XLOG_WARN << "use_certificate_chain_file: " << file.cert_.filepath_ << ", error: " << ec.message();
				return;
			}

			// 设置 password 文件, 如果存在的话.
			if (file.pwd_.type_ != pem_type::none && fs::exists(file.pwd_.filepath_))
			{
				auto pwd = file.pwd_.filepath_;

				ssl_ctx.set_password_callback([pwd]([[maybe_unused]] auto... args)
				{
					std::string password;
					fileop::read(pwd, password);
					return password;
				});
			}

			// 设置私钥文件.
			ssl_ctx.use_private_key_file(file.key_.filepath_.string(), net::ssl::context::pem, ec);
			if (ec)
			{
				XLOG_WARN << "use_private_key_file: " << file.key_.filepath_ << ", error: " << ec.message();
				return;
			}

			// 设置 dhparam 文件, 如果存在的话.
			if (file.dhparam_.type_ != pem_type::none && fs::exists(file.dhparam_.filepath_))
			{
				ssl_ctx.use_tmp_dh_file(file.dhparam_.filepath_.string(), ec);
				if (ec)
				{
					XLOG_WARN << "use_tmp_dh_file: " << file.dhparam_.filepath_ << ", error: " << ec.message();
					return;
				}
			}

			X509 *x509_cert = SSL_CTX_get0_certificate(ssl_ctx.native_handle());

			const auto expire_date = X509_get_notAfter(x509_cert);
			tm expire_date_tm;
			ASN1_TIME_to_tm(expire_date, &expire_date_tm);
			file.expire_date = boost::posix_time::ptime_from_tm(expire_date_tm);

			std::unique_ptr<GENERAL_NAMES, decltype(&GENERAL_NAMES_free)> general_names{
				static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(x509_cert, NID_subject_alt_name, 0, 0)),
				&GENERAL_NAMES_free
			};

			for (int i = 0; i < sk_GENERAL_NAME_num(general_names.get()); ++i)
			{
				GENERAL_NAME* gen = sk_GENERAL_NAME_value(general_names.get(), i);
				if (gen->type == GEN_DNS)
				{
					const  ASN1_IA5STRING* domain = gen->d.dNSName;

					if (domain->type == V_ASN1_IA5STRING && domain->data && domain->length)
					{
						file.alt_names.emplace_back(reinterpret_cast<const char*>(domain->data), domain->length);
					}
				}
			}

			char cert_cname[256] = { 0 };
			X509_NAME_get_text_by_NID(X509_get_subject_name(x509_cert), NID_commonName, cert_cname, sizeof cert_cname);
			file.domain_ = cert_cname;

			// 保存到 m_certificates 中.
			m_certificates.emplace_back(std::move(file));
		}
	}

	void proxy_server::init_acceptor() noexcept
	{
		auto& endps = m_option.listens_;

		for (const auto& [endp, v6only] : endps)
		{
			tcp_acceptor acceptor(m_executor);
			boost::system::error_code ec;

			acceptor.open(endp.protocol(), ec);
			if (ec)
			{
				XLOG_WARN << "acceptor open: " << endp << ", error: " << ec.message();
				continue;
			}

			acceptor.set_option(net::socket_base::reuse_address(true), ec);
			if (ec)
			{
				XLOG_WARN << "acceptor set_option with reuse_address: " << ec.message();
			}

			if (m_option.reuse_port_)
			{
#ifdef ENABLE_REUSEPORT
				using net::detail::socket_option::boolean;
				using reuse_port = boolean<SOL_SOCKET, SO_REUSEPORT>;

				acceptor.set_option(reuse_port(true), ec);
				if (ec)
				{
					XLOG_WARN << "acceptor set_option with SO_REUSEPORT: " << ec.message();
				}
#endif
			}

			if (v6only)
			{
				acceptor.set_option(net::ip::v6_only(true), ec);
				if (ec)
				{
					XLOG_ERR << "TCP server accept "
							 << "set v6_only failed: " << ec.message();
					continue;
				}
			}

			acceptor.bind(endp, ec);
			if (ec)
			{
				XLOG_ERR << "acceptor bind: " << endp << ", error: " << ec.message();
				continue;
			}

			acceptor.listen(net::socket_base::max_listen_connections, ec);
			if (ec)
			{
				XLOG_ERR << "acceptor listen: " << endp << ", error: " << ec.message();
				continue;
			}

			m_tcp_acceptors.emplace_back(std::move(acceptor));
		}
	}

	void proxy_server::init_ssl_context() noexcept
	{
		if (m_option.ssl_cert_path_.empty())
		{
			return;
		}

		find_cert(m_option.ssl_cert_path_);

		for (const auto& ctx : m_certificates)
		{
			XLOG_DBG << "domain: '" << ctx.domain_ << "', cert: '" << ctx.cert_.filepath_.string() << "', key: '"
					 << ctx.key_.filepath_.string() << "', dhparam: '" << ctx.dhparam_.filepath_.string() << "', pwd: '"
					 << ctx.pwd_.filepath_.string() << "'";
		}

		auto sni_callback_c =  [](SSL *ssl, int *ad, void *arg) -> int
		{
			proxy_server* self = (proxy_server*)arg;
			return self->sni_callback(ssl, ad);
		};

		SSL_CTX_set_tlsext_servername_callback(
			m_ssl_srv_context.native_handle(),
			(int (*)(SSL *, int *, void *))sni_callback_c
		);
		SSL_CTX_set_tlsext_servername_arg(m_ssl_srv_context.native_handle(), this);
	}

	bool rfc2818_verification_match_pattern(const char* pattern, std::size_t pattern_length, const char* host)
	{
		using namespace std; // For tolower.

		const char* p = pattern;
		const char* p_end = p + pattern_length;
		const char* h = host;

		while (p != p_end && *h)
		{
			if (*p == '*')
			{
				++p;
				while (*h && *h != '.')
				{
					if (rfc2818_verification_match_pattern(p, p_end - p, h++))
					{
						return true;
					}
				}
			}
			else if (tolower(*p) == tolower(*h))
			{
				++p;
				++h;
			}
			else
			{
				return false;
			}
		}

		return p == p_end && !*h;
	}

	int proxy_server::sni_callback(SSL* ssl, int* ad) noexcept
	{
		const char* servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
		if (servername)
		{
			certificate_file* default_ctx = nullptr;

			for (auto& ctx : m_certificates)
			{
				if (ctx.ssl_context_.has_value())
				{
					if (rfc2818_verification_match_pattern(ctx.domain_.c_str(), ctx.domain_.length(), servername))
					{
						SSL_set_SSL_CTX(ssl, ctx.ssl_context_->native_handle());
						return SSL_TLSEXT_ERR_OK;
					}

					for (auto& alt_name : ctx.alt_names)
					{
						if (rfc2818_verification_match_pattern(alt_name.c_str(), alt_name.length(), servername))
						{
							SSL_set_SSL_CTX(ssl, ctx.ssl_context_->native_handle());
							return SSL_TLSEXT_ERR_OK;
						}
					}
				}

				if (ctx.domain_.empty())
				{
					default_ctx = &ctx;
				}
			}

			if (default_ctx)
			{
				SSL_set_SSL_CTX(ssl, default_ctx->ssl_context_->native_handle());
				return SSL_TLSEXT_ERR_OK;
			}
		}
		return SSL_TLSEXT_ERR_OK;
	}


	void proxy_server::start() noexcept
	{
		// 如果作为透明代理.
		if (m_option.transparent_)
		{
#if defined(__linux__)

#if !defined(IP_TRANSPARENT)
#define IP_TRANSPARENT 19
#endif
#if !defined(IPV6_TRANSPARENT)
#define IPV6_TRANSPARENT 75
#endif

#if defined(IP_TRANSPARENT) && defined(IPV6_TRANSPARENT)
			// 设置 acceptor 为透明代理模式.
			using transparent = net::detail::socket_option::boolean<IPPROTO_IP, IP_TRANSPARENT>;
			using transparent6 = net::detail::socket_option::boolean<IPPROTO_IPV6, IPV6_TRANSPARENT>;

			for (auto& acceptor : m_tcp_acceptors)
			{
				boost::system::error_code error;

				acceptor.set_option(transparent(true), error);
				acceptor.set_option(transparent6(true), error);
			}
#endif

#else
			XLOG_WARN << "transparent proxy only support linux";
#endif
			// 获取所有本机 ip 地址.
			net::co_spawn(m_executor, get_local_address(), net::detached);
		}

		// 同时启动32个连接协程为每个 acceptor 用于为 proxy client 提供服务.
		for (auto& acceptor : m_tcp_acceptors)
		{
			for (int i = 0; i < 32; i++)
			{
				net::co_spawn(m_executor, start_proxy_listen(acceptor), net::detached);
			}
		}
	}

	void proxy_server::close() noexcept
	{
		boost::system::error_code ignore_ec;
		m_abort = true;

		for (auto& acceptor : m_tcp_acceptors)
		{
			acceptor.close(ignore_ec);
		}

		for (auto& [id, c] : m_clients)
		{
			if (auto client = c.lock())
			{
				client->close();
			}
		}
	}

	net::awaitable<void> proxy_server::start_proxy_listen(tcp_acceptor& acceptor) noexcept
	{
		boost::system::error_code error;
		net::socket_base::keep_alive keep_alive_opt(true);
		net::ip::tcp::no_delay no_delay_opt(true);
		net::ip::tcp::no_delay delay_opt(false);

		auto self = shared_from_this();

		while (!m_abort)
		{
			proxy_tcp_socket socket(m_executor);

			co_await acceptor.async_accept(socket.lowest_layer(), net_awaitable[error]);
			if (error)
			{
				if (!m_abort)
				{
					XLOG_ERR << "start_proxy_listen"
								", async_accept: "
							 << error.message();
				}
				co_return;
			}

			static std::atomic_size_t id{1};
			size_t connection_id = id++;

			auto endp = socket.remote_endpoint(error);
			auto client = endp.address().to_string();
			client += ":" + std::to_string(endp.port());

			std::vector<std::string> local_info;

			if (m_ipip)
			{
				auto [ret, isp] = m_ipip->lookup(endp.address());
				if (!ret.empty())
				{
					for (auto& c : ret)
					{
						client += " " + c;
					}

					local_info = ret;
				}

				if (!isp.empty())
				{
					client += " " + isp;
				}
			}

			XLOG_DBG << "connection id: " << connection_id << ", start client incoming: " << client;

			if (!region_filter(local_info))
			{
				XLOG_WARN << "connection id: " << connection_id << ", region filter: " << client;

				continue;
			}

			socket.set_option(keep_alive_opt, error);

			// 是否启用透明代理.
#if defined(__linux__)
			if (m_option.transparent_)
			{
				if (co_await start_transparent_proxy(socket, connection_id))
				{
					continue;
				}
			}
#endif

			// 在启用 scramble 时, 刻意开启 Nagle's algorithm 以尽量保证数据包
			// 被重组, 尽最大可能避免观察者通过观察 ip 数据包大小的规律来分析 tcp
			// 数据发送调用, 从而增加噪声加扰的强度.
			if (m_option.scramble_)
			{
				socket.set_option(delay_opt, error);
			}
			else
			{
				socket.set_option(no_delay_opt, error);
			}

			// 创建 proxy_session 对象.
			auto new_session =
				std::make_shared<proxy_session>(m_executor, init_proxy_stream(std::move(socket)), connection_id, self);

			// 保存 proxy_session 对象到 m_clients 中.
			m_clients[connection_id] = new_session;

			// 启动 proxy_session 对象.
			new_session->start();
		}

		XLOG_WARN << "start_proxy_listen exit ...";
		co_return;
	}

	net::awaitable<bool> proxy_server::start_transparent_proxy(util::proxy_tcp_socket& socket, size_t connection_id) noexcept
	{
#ifndef SO_ORIGINAL_DST
#	define SO_ORIGINAL_DST 80
#endif
		auto sockfd = socket.native_handle();

		sockaddr_storage addr;
		socklen_t addrlen = sizeof(addr);

		int protocol = socket.lowest_layer().local_endpoint().protocol() == net::ip::tcp::v6() ? IPPROTO_IPV6 : IPPROTO_IP;

		if (::getsockopt(sockfd, protocol, SO_ORIGINAL_DST, (char*)&addr, &addrlen) < 0)
		{
			XLOG_FWARN("connection id: {}, getsockopt: {}, SO_ORIGINAL_DST: {}", connection_id, (int)sockfd,
					   strerror(errno));
			co_return false;
		}

		net::ip::tcp::endpoint remote_endp;

		if (addr.ss_family == AF_INET6)
		{
			auto addr6 = reinterpret_cast<sockaddr_in6*>(&addr);
			auto port = ntohs(addr6->sin6_port);

			net::ip::address_v6::bytes_type bt;

			std::copy(std::begin(addr6->sin6_addr.s6_addr), std::end(addr6->sin6_addr.s6_addr), std::begin(bt));

			remote_endp.address(net::ip::make_address_v6(bt));
			remote_endp.port(port);
		}
		else
		{
			auto addr4 = reinterpret_cast<sockaddr_in*>(&addr);
			auto port = ntohs(addr4->sin_port);

			remote_endp.address(net::ip::address_v4(htonl(addr4->sin_addr.s_addr)));
			remote_endp.port(port);
		}

		// 创建透明代理, 开始连接通过代理服务器连接与当前客户端通信.
		auto it = std::find_if(m_local_addrs.begin(), m_local_addrs.end(), [&](const auto& addr)
		{
			if (addr == remote_endp.address())
			{
				return true;
			}
			return false;
		});

		if (it == m_local_addrs.end())
		{
			XLOG_DBG << "connection id: " << connection_id << ", is tproxy, remote: " << remote_endp;

			auto self = shared_from_this();

			// 创建 proxy_session 对象用于 tproxy.
			auto new_session = std::make_shared<proxy_session>(m_executor, init_proxy_stream(std::move(socket)),
															   connection_id, self, true);

			// 保存 proxy_session 对象到 m_clients 中.
			m_clients[connection_id] = new_session;

			// 设置 tproxy 的 remote 到 session 对象.
			new_session->set_tproxy_remote(remote_endp);
			// 启动 proxy_session 对象.
			new_session->start();

			co_return true;
		}

		// 执行到这里, 表示客户端直接请求本代理服务, 则按普通代理服务请求处理.
		co_return false;
	}

	net::awaitable<void> proxy_server::get_local_address() noexcept
	{
		boost::system::error_code ec;

		auto hostname = net::ip::host_name(ec);
		if (ec)
		{
			XLOG_WARN << "get_local_address, host_name: " << ec.message();

			co_return;
		}

		if (!detect_hostname(hostname))
		{
			m_local_addrs.insert(net::ip::make_address(hostname, ec));
			co_return;
		}

		tcp::resolver resolver(m_executor);
		tcp::resolver::query query(hostname, "");

		auto it = co_await resolver.async_resolve(query, net_awaitable[ec]);
		if (ec)
		{
			XLOG_WARN << "get_local_address, async_resolve: " << ec.message();

			co_return;
		}

		while (it != tcp::resolver::iterator())
		{
			tcp::endpoint ep = *it++;
			m_local_addrs.insert(ep.address());
		}
	}

	bool proxy_server::region_filter(const std::vector<std::string>& local_info) const noexcept
	{
		auto& deny_region = m_option.deny_regions_;
		auto& allow_region = m_option.allow_regions_;

		std::optional<bool> allow;

		if (m_ipip && (!allow_region.empty() || !deny_region.empty()))
		{
			for (auto& region : allow_region)
			{
				for (auto& l : local_info)
				{
					if (l == region)
					{
						allow.emplace(true);
						break;
					}
					allow.emplace(false);
				}

				if (allow && *allow)
				{
					break;
				}
			}

			if (!allow)
			{
				for (auto& region : deny_region)
				{
					for (auto& l : local_info)
					{
						if (l == region)
						{
							allow.emplace(false);
							break;
						}
						allow.emplace(true);
					}

					if (allow && !*allow)
					{
						break;
					}
				}
			}
		}

		if (!allow)
		{
			return true;
		}

		return *allow;
	}

} // namespace proxy
