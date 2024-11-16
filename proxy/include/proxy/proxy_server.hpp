//
// proxy_server.hpp
// ~~~~~~~~~~~~~~~~
//
// Copyright (c) 2019 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include <cstddef>
#include <memory>
#include <optional>
#include <cstdint>
#include <cstdint>
#include <string>
#include <type_traits>
#include <vector>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <memory_resource>

#include <boost/asio.hpp>

#ifdef _MSC_VER
# pragma warning(push)
# pragma warning(disable: 4702)
#endif // _MSC_VER

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>

#ifdef _MSC_VER
# pragma warning(pop)
#endif

#include <boost/url/url_view.hpp>

#include <boost/nowide/convert.hpp>
#include <boost/nowide/filesystem.hpp>
#include <boost/nowide/fstream.hpp>

#ifdef _MSC_VER
# pragma warning(push)
# pragma warning(disable: 4819)
#endif

#include <boost/json.hpp>

#ifdef _MSC_VER
# pragma warning(pop)
#endif

#include <boost/algorithm/string.hpp>

#include "proxy/ipip.hpp"
#include "proxy/http_proxy_client.hpp"
#include "proxy/proxy_fwd.hpp"
#include "proxy/proxy_stream.hpp"
#include "proxy/variant_stream.hpp"

namespace proxy {

	//////////////////////////////////////////////////////////////////////////

	enum class pem_type
	{
		none,		// none.
		domain,		// domain file.
		cert,		// certificate file.
		key,  		// certificate key file.
		pwd,		// certificate password file.
		dhparam		// dh param file.
	};

	struct pem_file
	{
		fs::path filepath_;
		pem_type type_ { pem_type::none };
		int chains_{ 0 };
	};

	struct certificate_file
	{
		pem_file cert_;
		pem_file key_;
		pem_file pwd_;
		pem_file dhparam_;

		std::string domain_;
		std::vector<std::string> alt_names;
		boost::posix_time::ptime expire_date;

		std::optional<net::ssl::context> ssl_context_;
	};


	//////////////////////////////////////////////////////////////////////////

	// proxy server 虚基类, 任何 proxy server 的实现, 必须基于这个基类.
	// 这样 proxy_session 才能通过虚基类指针访问 proxy server 的具体实
	// 现以及虚函数方法.
	class proxy_server_base {
	public:
		virtual ~proxy_server_base() {}
		virtual void remove_session(size_t id) = 0;
		virtual size_t num_session() = 0;
		virtual const proxy_server_option& option() = 0;
		virtual net::ssl::context& ssl_context() = 0;
	};

	//////////////////////////////////////////////////////////////////////////

	class proxy_server
		: public proxy_server_base
		, public std::enable_shared_from_this<proxy_server>
	{
		proxy_server(const proxy_server&) = delete;
		proxy_server& operator=(const proxy_server&) = delete;

		proxy_server(net::any_io_executor executor, proxy_server_option opt);

	public:
		inline static std::shared_ptr<proxy_server>
		make(net::any_io_executor executor, proxy_server_option opt)
		{
			return std::shared_ptr<proxy_server>(new
				proxy_server(executor, opt));
		}

		virtual ~proxy_server() = default;

		pem_file determine_pem_type(const std::string& filepath) noexcept;

		void find_cert(const fs::path& directory) noexcept;

		void init_acceptor() noexcept;

		void init_ssl_context() noexcept;

		int sni_callback(SSL* ssl, int* ad) noexcept;

	public:
		void start() noexcept;

		void close() noexcept;

	private:
		virtual void remove_session(size_t id) override
		{
			m_clients.erase(id);
		}

		virtual size_t num_session() override
		{
			return m_clients.size();
		}

		virtual const proxy_server_option& option() override
		{
			return m_option;
		}

		virtual net::ssl::context& ssl_context() override
		{
			return m_ssl_srv_context;
		}

	private:
		// start_proxy_listen 启动一个协程, 用于监听 proxy client 的连接.
		// 当有新的连接到来时, 会创建一个 proxy_session 对象, 并启动 proxy_session
		// 的对象.
		net::awaitable<void> start_proxy_listen(tcp_acceptor& acceptor) noexcept;

		net::awaitable<bool> start_transparent_proxy(util::proxy_tcp_socket& socket, size_t connection_id) noexcept;

		net::awaitable<void> get_local_address() noexcept;

		bool region_filter(const std::vector<std::string>& local_info) const noexcept;

	private:
		// m_executor 保存当前 io_context 的 executor.
		net::any_io_executor m_executor;

		// m_tcp_acceptors 用于侦听客户端 tcp 连接请求.
		std::vector<tcp_acceptor> m_tcp_acceptors;

		// m_option 保存当前服务器各选项配置.
		proxy_server_option m_option;

		// 当前机器的所有 ip 地址.
		std::set<net::ip::address> m_local_addrs;

		// ipip 用于获取 ip 地址的地理位置信息.
		std::unique_ptr<ipip> m_ipip;

		using proxy_session_weak_ptr =
			std::weak_ptr<proxy_session>;

		// 当前客户端连接列表.
		std::unordered_map<size_t, proxy_session_weak_ptr> m_clients;

		// 当前服务端作为 ssl 服务时的 ssl context.
		net::ssl::context m_ssl_srv_context{ net::ssl::context::tls_server };

		// m_certificates 保存当前服务端的证书信息.
		std::vector<certificate_file> m_certificates;

		// 当前服务是否中止标志.
		bool m_abort{ false };
	};

}
