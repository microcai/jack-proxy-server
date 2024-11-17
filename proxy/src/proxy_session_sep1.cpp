

#include "boost/asio/file_base.hpp"
#include "proxy/libproxy_pch.hpp"

#include "proxy/proxy_fwd.hpp"
#include "proxy/proxy_session.hpp"
#include "proxy/strutil.hpp"
#include "proxy/logging.hpp"
#include "proxy/use_awaitable.hpp"

#include <array>
#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/hana.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <boost/url.hpp>
#include <boost/json.hpp>

#include <fmt/xchar.h>
#include <fmt/format.h>
#include <string_view>

#include "ctre.hpp"

#ifdef __linux__
#include <sys/sendfile.h>
#endif

using namespace boost::asio::experimental::awaitable_operators;
namespace urls = boost::urls;			// form <boost/url.hpp>

namespace proxy
{
	using namespace util;
	//////////////////////////////////////////////////////////////////////////

	static const char version_string[] =
R"x*x*x(nginx/1.20.2)x*x*x";

	static const char fake_302_content[] =
R"x*x*x(<html>
<head><title>301 Moved Permanently</title></head>
<body>
<center><h1>301 Moved Permanently</h1></center>
<hr><center>nginx/1.20.2</center>
</body>
</html>
)x*x*x";

	static const char fake_400_content[] =
R"x*x*x(<html>
<head><title>400 Bad Request</title></head>
<body bgcolor="white">
<center><h1>400 Bad Request</h1></center>
<hr><center>nginx/1.20.2</center>
</body>
</html>)x*x*x";

	static const char fake_401_content[] =
R"x*x*x(<html>
<head><title>401 Authorization Required</title></head>
<body>
<center><h1>401 Authorization Required</h1></center>
<hr><center>nginx/1.20.2</center>
</body>
</html>)x*x*x";

	static const char fake_403_content[] =
R"x*x*x(<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx/1.20.2</center>
</body>
</html>
)x*x*x";

	static const char fake_404_content_fmt[] =
R"x*x*x(HTTP/1.1 404 Not Found
Server: nginx/1.20.2
Date: {}
Content-Type: text/html
Content-Length: 145
Connection: close

<html><head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr>
<center>nginx/1.20.2</center>
</body>
</html>)x*x*x";

	static const char fake_404_content[] =
R"x*x*x(<html><head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr>
<center>nginx/1.20.2</center>
</body>
</html>)x*x*x";

	static const char fake_416_content[] =
R"x*x*x(<html>
<head><title>416 Requested Range Not Satisfiable</title></head>
<body>
<center><h1>416 Requested Range Not Satisfiable</h1></center>
<hr><center>nginx/1.20.2</center>
</body>
</html>
)x*x*x";

	static const char fake_502_content[] =
R"xx(<html>
<head><title>502 Bad Gateway</title></head>
<body>
<center><h1>502 Bad Gateway</h1></center>
<hr><center>nginx/1.26.2</center>
</body>
</html>)xx";

	static constexpr auto head_fmt =
		R"(<html><head><meta charset="UTF-8"><title>Index of {}</title></head><body bgcolor="white"><h1>Index of {}</h1><hr><div><table><tbody>)";
	static constexpr auto tail_fmt =
		"</tbody></table></div><hr></body></html>";
	static constexpr auto body_fmt =
		// "<a href=\"{}\">{}</a>{} {}       {}\r\n";
		"<tr><td class=\"link\"><a href=\"{}\">{}</a></td><td class=\"size\">{}</td><td class=\"date\">{}</td></tr>\r\n";

	//////////////////////////////////////////////////////////////////////////
	// parser_http_ranges 用于解析 http range 请求头.
	static http_ranges parser_http_ranges(std::string_view range_line) noexcept
	{
		http_ranges results;

		if (!range_line.empty())
		{
			// 去掉前后空白.
			range_line = strutil::remove_spaces(range_line);

			// range 必须以 bytes= 开头, 否则返回空数组.
			if (auto regex_match_result = ctre::match<"bytes=([0-9,\\- ]+)">(range_line))
			{
				std::string_view range = regex_match_result.get<1>();

				std::array<std::byte, 64> pre_alloc_buf;
				std::pmr::monotonic_buffer_resource mbr(pre_alloc_buf.data(), pre_alloc_buf.size());
				std::pmr::polymorphic_allocator<char> alloc(&mbr);

				std::pmr::vector<std::string_view> ranges{alloc};

				// 获取其中所有 range 字符串.
				strutil::split(range, ",", std::back_inserter(ranges));
				for (const auto& str : ranges)
				{
					if (auto range_match = ctre::match<"(-?[0-9 ]+)(-([0-9 ]*))?">(str))
					{
						auto first = range_match.get<1>().to_number<int64_t>();

						if (first < 0)
						{
							results.emplace_back(-1, -first);
						}
						else
						{
							if (range_match.get<3>().to_view().empty())
							{
								results.emplace_back(first, -1);
							}
							else
							{
								auto second = range_match.get<3>().to_number<long long>();

								results.emplace_back(first, second);
							}
						}
					}
				}
			}
		}

		return results;
	}

	static std::string file_hash(const fs::path& p, boost::system::error_code& ec)
	{
		ec = {};

		boost::nowide::ifstream file(p.string(), std::ios::binary);
		if (!file)
		{
			ec = boost::system::error_code(errno, boost::system::generic_category());
			return {};
		}

		boost::uuids::detail::sha1 sha1;
		const auto buf_size = 1024 * 1024 * 4;
		std::unique_ptr<char, decltype(&std::free)> bufs((char*)std::malloc(buf_size), &std::free);


		while (file.read(bufs.get(), buf_size) || file.gcount())
			sha1.process_bytes(bufs.get(), file.gcount());

		boost::uuids::detail::sha1::digest_type hash;
		sha1.get_digest(hash);

		std::stringstream ss;
		for (auto const& c : hash)
			ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(c);

		return ss.str();
	}

	template <typename CompletionToken>
	auto async_hash_file(const fs::path& path, CompletionToken&& token)
	{
		return net::async_initiate<CompletionToken, void (boost::system::error_code, std::string)>(
			[path](auto&& handler) mutable
			{
				std::thread([path, handler = std::move(handler)]() mutable
					{
						boost::system::error_code ec;

						auto hash = file_hash(path, ec);

						auto executor = net::get_associated_executor(handler);
						net::post(
							executor
							, [ec = std::move(ec), hash = std::move(hash), handler = std::move(handler)]() mutable
							{
								handler(ec, hash);
							}
						);
					}
				).detach();
			}
			, token
		);
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	template <CTRE_REGEX_INPUT_TYPE exp, auto func>
	struct route_op
	{
		boost::asio::awaitable<bool> operator()(auto* _proxy_session, auto target, auto& http_ctx, auto alloc) const
		{
			if (auto result = ctre::match<exp>( target ) )
			{
				boost::hana::for_each(std::make_index_sequence<result.count()>(), [&](auto element)
				{
					// 将 正则匹配到的 () 子串，给依次 push 到 http_ctx.command_ 这个容器里.
					http_ctx.command_.push_back(result.template get<element>());
				});
				co_await (_proxy_session->*func)(http_ctx);
				co_return true;
			}
			co_return false;
		}
	};

	template <auto... RouteOPs>
	boost::asio::awaitable<void> routes(proxy_session* _proxy_session, auto& target, auto& http_ctx, auto alloc)
	{
		// 依次等待 route_op 执行，因为是 || 所以如果一个成功了，剩下的就不等了.
		( (co_await RouteOPs(_proxy_session, target, http_ctx, alloc)) || ...);
	}

	net::awaitable<void> proxy_session::normal_web_server(string_request& req, pmr_alloc_t alloc)
	{
		boost::system::error_code ec;

		bool keep_alive = false;
		bool has_read_header = true;

		for (; !m_abort;)
		{
			std::optional<request_parser> parser;
			if (!has_read_header)
			{
				// normal_web_server 调用是从 http_proxy_get
				// 跳转过来的, 该函数已经读取了请求头, 所以第1次不需
				// 要再次读取请求头, 即 has_read_header 为 true.
				// 当 keepalive 时，需要读取请求头, 此时 has_read_header
				// 为 false, 则在此读取和解析后续的 http 请求头.
				parser.emplace(std::piecewise_construct, std::make_tuple(alloc), std::make_tuple(alloc));
				parser->body_limit(1024 * 512); // 512k
				m_local_buffer.consume(m_local_buffer.size());

				co_await http::async_read_header(m_local_socket, m_local_buffer, *parser, net_awaitable[ec]);
				if (ec)
				{
					XLOG_DBG << "connection id: " << m_connection_id << (keep_alive ? ", keepalive" : "")
							 << ", web async_read_header: " << ec.message();
					co_return;
				}

				req = parser->release();
			}

			if (req[http::field::expect] == "100-continue")
			{
				http::response<http::empty_body> res;
				res.version(11);
				res.result(http::status::method_not_allowed);

				co_await http::async_write(m_local_socket, res, net_awaitable[ec]);
				if (ec)
				{
					XLOG_DBG << "connection id: " << m_connection_id << ", web expect async_write: " << ec.message();
				}
				co_return;
			}

			has_read_header = false;
			keep_alive = req.keep_alive();

			if (beast::websocket::is_upgrade(req))
			{
				std::pmr::string fake_page{alloc};

				fmt::vformat_to(std::back_inserter(fake_page), fake_404_content_fmt, fmt::make_format_args(server_date_string(alloc)));

				co_await net::async_write(m_local_socket, net::buffer(fake_page), net::transfer_all(),
										  net_awaitable[ec]);

				co_return;
			}

			std::pmr::string target{req.target(), alloc};
			std::string_view target_pv{target};
			boost::match_results<
				std::pmr::string::const_iterator,
				std::pmr::polymorphic_allocator<boost::sub_match<std::pmr::string::const_iterator>>
			> what{alloc};

			http_context http_ctx{
				alloc,
				std::pmr::vector<std::string_view>{alloc},
				req,
				req.target(),
				{ make_real_target_path(req.target(), alloc), alloc }
            };

			co_await routes<
				route_op<R"regex((.*)/)regex", &proxy_session::on_http_dir>{},
				route_op<R"regex((.*)\?q=json(&(.*))?)regex", &proxy_session::on_http_json>{},
				route_op<R"regex(^(?!.*\/$).*$)regex", &proxy_session::on_http_get>{}
			>(this, target_pv, http_ctx, alloc);

			if (!keep_alive)
			{
				break;
			}
			continue;
		}

		co_await m_local_socket.lowest_layer().async_wait(net::socket_base::wait_read, net_awaitable[ec]);

		co_return;
	}

	net::awaitable<void> proxy_session::on_http_json(const http_context& hctx)
	{
		boost::system::error_code ec;
		auto& request = hctx.request_;

		auto target = make_real_target_path(hctx.command_[1], hctx.alloc);

		std::array<std::byte, 4096> pre_alloc_buf;
		std::pmr::monotonic_buffer_resource mbr(pre_alloc_buf.data(), pre_alloc_buf.size());
		std::pmr::polymorphic_allocator<char> alloc(&mbr);

		fs::directory_iterator end;
		fs::directory_iterator it(std::string_view{target}, ec);
		if (ec)
		{
			string_response res{
				std::piecewise_construct,
				std::make_tuple(alloc),
				std::make_tuple(http::status::found, request.version(), alloc)
			};
			res.set(http::field::server, version_string);
			res.set(http::field::date, server_date_string(alloc));
			res.set(http::field::location, "/");
			res.keep_alive(request.keep_alive());
			res.prepare_payload();

			string_response_serializer sr(res);
			co_await http::async_write(m_local_socket, sr, net_awaitable[ec]);
			if (ec)
			{
				XLOG_WARN << "connection id: " << m_connection_id << ", http_dir write location err: " << ec.message();
			}

			co_return;
		}

		bool hash = false;

		urls::params_view qp(hctx.command_[3]);
		if (qp.find("hash") != qp.end())
		{
			hash = true;
		}

		boost::json::array path_list;

		for (; it != end && !m_abort; it++)
		{
			const auto& item = it->path();
			boost::json::object obj;

			auto [ftime, unc_path] = file_last_wirte_time(item);
			obj["last_write_time"] = ftime;

			if (fs::is_directory(unc_path.empty() ? item : unc_path, ec))
			{
				obj["filename"] = item.filename().string();
				obj["is_dir"] = true;
			}
			else
			{
				obj["filename"] = item.filename().string();
				obj["is_dir"] = false;
				if (unc_path.empty())
				{
					unc_path = item;
				}
				auto sz = fs::file_size(unc_path, ec);
				if (ec)
				{
					sz = 0;
				}
				obj["filesize"] = sz;
				if (hash)
				{
					auto ret = co_await async_hash_file(unc_path, net_awaitable[ec]);
					if (ec)
					{
						ret = "";
					}
					obj["hash"] = ret;
				}
			}

			path_list.push_back(obj);
		}

		auto body = boost::json::serialize(path_list);

		span_response res{
			std::piecewise_construct,
			std::make_tuple(boost::span<const char, boost::dynamic_extent>{body.data(), body.size()}),
			std::make_tuple(http::status::ok, request.version(), alloc)
		};
		res.set(http::field::server, version_string);
		res.set(http::field::date, server_date_string(alloc));
		res.set(http::field::content_type, "application/json");
		res.keep_alive(request.keep_alive());
		res.prepare_payload();

		span_response_serializer sr(res);
		co_await http::async_write(m_local_socket, sr, net_awaitable[ec]);
		if (ec)
		{
			XLOG_WARN << "connection id: " << m_connection_id << ", http dir write body err: " << ec.message();
		}

		co_return;
	}

	net::awaitable<void> proxy_session::on_http_dir(const http_context& hctx)
	{
		using namespace std::literals;

		boost::system::error_code ec;
		auto& request = hctx.request_;

		std::array<std::byte, 16384> pre_alloc_buf;
		std::pmr::monotonic_buffer_resource mbr(pre_alloc_buf.data(), pre_alloc_buf.size());
		std::pmr::polymorphic_allocator<char> alloc(&mbr);

		// 查找目录下是否存在 index.html 或 index.htm 文件, 如果存在则返回该文件.
		// 否则返回目录下的文件列表.
		auto index_html = fs::path(std::string_view{hctx.target_path_}) / "index.html";
		fs::exists(index_html, ec) ? index_html = index_html : index_html = fs::path(std::string_view{hctx.target_path_}) / "index.htm";

		if (fs::exists(index_html, ec))
		{
			boost::nowide::ifstream file(index_html.string(), std::ios::binary);
			if (file)
			{
				std::pmr::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>(),
										 alloc);

				span_response res{
					std::piecewise_construct,
					std::make_tuple(boost::span<const char, boost::dynamic_extent>{content.data(), content.size() }),
					std::make_tuple(http::status::ok, request.version(), alloc)
				};
				res.set(http::field::server, version_string);
				res.set(http::field::date, server_date_string(alloc));
				res.set(http::field::content_type, "text/html; charset=utf-8");
				res.keep_alive(request.keep_alive());
				res.prepare_payload();

				span_response_serializer sr(res);
				co_await http::async_write(m_local_socket, sr, net_awaitable[ec]);
				if (ec)
				{
					XLOG_WARN << "connection id: " << m_connection_id << ", http dir write index err: " << ec.message();
				}

				co_return;
			}
		}

		auto path_list = format_path_list(std::string_view{hctx.target_path_}, ec, alloc);

		assert(path_list.get_allocator() == alloc);

		if (ec)
		{
			string_response res{
				std::piecewise_construct,
				std::make_tuple(alloc),
				std::make_tuple(http::status::found, request.version(), alloc)
			};

			res.set(http::field::server, version_string);
			res.set(http::field::date, server_date_string(alloc));
			res.set(http::field::location, "/");
			res.keep_alive(request.keep_alive());
			res.prepare_payload();

			string_response_serializer sr(res);
			co_await http::async_write(m_local_socket, sr, net_awaitable[ec]);
			if (ec)
			{
				XLOG_WARN << "connection id: " << m_connection_id << ", http_dir write location err: " << ec.message();
			}

			co_return;
		}

		auto target_path = make_target_path(hctx.target_, hctx.alloc);
		std::pmr::string autoindex_page{alloc};
		autoindex_page.reserve(4096);

		fmt::format_to(std::back_inserter(autoindex_page), head_fmt, target_path, target_path);
		fmt::format_to(std::back_inserter(autoindex_page), body_fmt, "../", "../", "", "");

		for (const auto& s : path_list)
		{
			autoindex_page += s;
		}

		autoindex_page += tail_fmt;

		span_response res{
			std::piecewise_construct,
			std::make_tuple(boost::span<const char, boost::dynamic_extent>{autoindex_page.data(), autoindex_page.size() }),
			std::make_tuple(http::status::ok, request.version(), alloc)
		};

		res.set(http::field::server, version_string);
		res.set(http::field::date, server_date_string(alloc));
		res.keep_alive(request.keep_alive());
		res.prepare_payload();

		span_response_serializer sr(res);
		co_await http::async_write(m_local_socket, sr, net_awaitable[ec]);
		if (ec)
		{
			XLOG_WARN << "connection id: " << m_connection_id << ", http dir write body err: " << ec.message();
		}

		co_return;
	}

	net::awaitable<void> proxy_session::on_http_get(const http_context& hctx)
	{
		boost::system::error_code ec;

		const auto& request = hctx.request_;
		fs::path path = std::string_view{hctx.target_path_};

		if (!fs::exists(path, ec))
		{
			XLOG_WARN << "connection id: " << m_connection_id << ", http " << hctx.target_ << " file not exists";

			std::pmr::string fake_page{hctx.alloc};

			span_response res{
				std::piecewise_construct,
				std::make_tuple(boost::span<const char, boost::dynamic_extent>{fake_404_content, sizeof fake_404_content - 1}),
				std::make_tuple(http::status::not_found, request.version(), hctx.alloc)
			};
			res.set(http::field::server, version_string);
			res.set(http::field::date, server_date_string(hctx.alloc));
			res.keep_alive(request.keep_alive());
			res.prepare_payload();

			span_response_serializer sr(res);

			co_await http::async_write(m_local_socket, sr, net_awaitable[ec]);

			co_return;
		}

		if (fs::is_directory(path, ec))
		{
			XLOG_DBG << "connection id: " << m_connection_id << ", http " << hctx.target_ << " is directory";

			std::pmr::string url = {"http://", hctx.alloc};
			if (is_crytpo_stream())
			{
				url = "https://";
			}
			url += request[http::field::host];
			urls::url u(url);
			std::pmr::string target{hctx.target_ , hctx.alloc};
			target += "/";
			u.set_path(target);

			co_await location_http_route(request, u.buffer());

			co_return;
		}

		size_t content_length = fs::file_size(path, ec);
		if (ec)
		{
			XLOG_WARN << "connection id: " << m_connection_id << ", http " << hctx.target_
					  << " file size error: " << ec.message();

			co_await default_http_route(request, fake_400_content, http::status::bad_request);

			co_return;
		}
#if defined (BOOST_ASIO_HAS_FILE)
#	if defined(_WIN32)
		net::stream_file file(co_await net::this_coro::executor);
		file.assign(::CreateFileW(path.wstring().c_str(), GENERIC_READ, FILE_SHARE_READ, 0,
          	OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED|FILE_FLAG_SEQUENTIAL_SCAN, 0), ec);
#	else
		net::stream_file file(co_await net::this_coro::executor, path.string(), net::stream_file::read_only);
#	endif
#else // BOOST_ASIO_HAS_FILE
		boost::nowide::fstream file(path.string(), std::ios_base::binary | std::ios_base::in);
#endif //BOOST_ASIO_HAS_FILE

		std::pmr::string user_agent { hctx.alloc };
		if (request.count(http::field::user_agent))
		{
			user_agent = request[http::field::user_agent];
		}

		std::pmr::string referer { hctx.alloc };
		if (request.count(http::field::referer))
		{
			referer = request[http::field::referer];
		}

		XLOG_DBG << "connection id: " << m_connection_id << ", http file: " << hctx.target_
				 << ", size: " << content_length
				 << (request.count("Range") ? ", range: " + std::pmr::string(request["Range"], hctx.alloc) : std::pmr::string(hctx.alloc))
				 << (!user_agent.empty() ? ", user_agent: " + user_agent : std::pmr::string(hctx.alloc))
				 << (!referer.empty() ? ", referer: " + referer : std::pmr::string(hctx.alloc));

		http::status st = http::status::ok;
		auto range = parser_http_ranges(request["Range"]);
		std::string_view content_type;
		std::array<char, 512> file_head_content;
		bool check_file_header_to_get_mime_type = false;

		try
		{
			auto ext = strutil::to_lower(fs::path(path).extension().string());
			content_type = mime_type_for_file_ext(ext);
		}
		catch (proxy::unknow_mime_ext)
		{
			check_file_header_to_get_mime_type = true;
		}
		if (check_file_header_to_get_mime_type)
		{
#if defined (BOOST_ASIO_HAS_FILE)
			auto file_head_content_read_size = co_await file.async_read_some(net::buffer(file_head_content), net_awaitable[ec]);
			file.seek(0, boost::asio::file_base::seek_set);
#else
			auto file_head_content_read_size = fileop::read(file, std::span<char>(file_head_content.data(), file_head_content.size()));
			file.seekg(0, std::ios_base::beg);
#endif
			// check mime for unknow ext
			if ( xlogger::logger_aux__::utf8_check_is_valid(std::string_view{file_head_content.data(), file_head_content_read_size}) )
			{
				content_type = std::string_view{"text/plain; charset=utf-8"};
			}
			else
			{
				content_type = std::string_view{"application/octet-stream"};
			}
		}

		// 只支持一个 range 的请求, 不支持多个 range 的请求.
		if (range.size() == 1)
		{
			st = http::status::partial_content;
			auto& r = range.front();

			// 起始位置为 -1, 表示从文件末尾开始读取, 例如 Range: -500
			// 则表示读取文件末尾的 500 字节.
			if (r.first == -1)
			{
				// 如果第二个参数也为 -1, 则表示请求有问题, 返回 416.
				if (r.second < 0)
				{
					co_await default_http_route(request, fake_416_content, http::status::range_not_satisfiable);
					co_return;
				}
				else if (r.second >= 0)
				{
					// 计算起始位置和结束位置, 例如 Range: -5
					// 则表示读取文件末尾的 5 字节.
					// content_length - r.second 表示起始位置.
					// content_length - 1 表示结束位置.
					// 例如文件长度为 10 字节, 则起始位置为 5,
					// 结束位置为 9(数据总长度为[0-9]), 一共 5 字节.
					r.first = content_length - r.second;
					r.second = content_length - 1;
				}
			}
			else if (r.second == -1)
			{
				// 起始位置为正数, 表示从文件头开始读取, 例如 Range: 500
				// 则表示读取文件头的 500 字节.
				if (r.first < 0)
				{
					co_await default_http_route(request, fake_416_content, http::status::range_not_satisfiable);
					co_return;
				}
				else
				{
					r.second = content_length - 1;

					if (r.first == content_length)
					{
						std::pmr::string content_range{hctx.alloc};
						fmt::format_to(std::back_inserter(content_range), "bytes */{}", r.second, r.second, content_length);
						
						span_response res{
							std::piecewise_construct,
							std::make_tuple(boost::span<const char, boost::dynamic_extent>{fake_416_content, sizeof (fake_416_content) - 1}),
							std::make_tuple(http::status::range_not_satisfiable, request.version(), hctx.alloc)
						};

						res.set(http::field::server, version_string);
						res.set(http::field::date, server_date_string(hctx.alloc));
						res.set(http::field::content_type, "text/html; charset=UTF-8");
						res.set(http::field::content_range, content_range);

						res.keep_alive(hctx.request_.keep_alive());
						res.prepare_payload();

						span_response_serializer sr(res);
						co_await http::async_write(m_local_socket, sr, net_awaitable[ec]);
						co_return;
					}
				}
			}
#if defined (BOOST_ASIO_HAS_FILE)
			file.seek(r.first, net::stream_file::seek_set);
#else
			file.seekg(r.first, std::ios_base::beg);
#endif
		}

		if (ec)
		{
			XLOG_WARN << "connection id: " << m_connection_id << ", open target: " << path << " failed: " << ec.message();
			// FILE OPEN FAILED
			// 返回 502
			st = http::status::internal_server_error;

			span_response res{
				std::piecewise_construct,
				std::make_tuple(boost::span<const char, boost::dynamic_extent>{fake_502_content, sizeof (fake_502_content) - 1}),
				std::make_tuple(http::status::found, request.version(), hctx.alloc)
			};

			res.set(http::field::server, version_string);
			res.set(http::field::date, server_date_string(hctx.alloc));
			res.set(http::field::content_type, "text/html; charset=UTF-8");

			res.keep_alive(true);
			res.prepare_payload();

			span_response_serializer sr(res);
			co_await http::async_write(m_local_socket, sr, net_awaitable[ec]);
			if (ec)
			{
				XLOG_WARN << "connection id: " << m_connection_id << ", send 502 err: " << ec.message();
			}

			co_return;
		}

		custom_body_response res{
			std::piecewise_construct,
			std::make_tuple(),
			std::make_tuple(st, request.version(), hctx.alloc)
		};

		res.set(http::field::server, version_string);
		res.set(http::field::date, server_date_string(hctx.alloc));

		res.set(http::field::content_type, content_type);

		if (st == http::status::ok)
		{
			res.set(http::field::accept_ranges, "bytes");
		}

		if (st == http::status::partial_content)
		{
			const auto& r = range.front();

			if (r.second < r.first && r.second >= 0)
			{
				co_await default_http_route(request, fake_416_content, http::status::range_not_satisfiable);
				co_return;
			}

			std::pmr::string content_range{hctx.alloc};
			fmt::format_to(std::back_inserter(content_range), "bytes {}-{}/{}", r.first, r.second, content_length);

			content_length = r.second - r.first + 1;
			res.set(http::field::content_range, content_range);
		}

		res.keep_alive(hctx.request_.keep_alive());
		res.content_length(content_length);

		custom_body_response_serializer sr(res);

		co_await http::async_write_header(m_local_socket, sr, net_awaitable[ec]);
		if (ec)
		{
			XLOG_WARN << "connection id: " << m_connection_id << ", http async_write_header: " << ec.message();

			co_return;
		}

		auto buf_size = 64 * 1024;
		if (m_option.tcp_rate_limit_ > 0 && m_option.tcp_rate_limit_ < buf_size)
		{
			buf_size = m_option.tcp_rate_limit_;
		}

		std::unique_ptr<char, decltype(&std::free)> bufs((char*)std::malloc(buf_size), &std::free);
		char* buf = bufs.get();
		std::streamsize total = 0;

		stream_rate_limit(m_local_socket, m_option.tcp_rate_limit_);

		do
		{
			auto remain_to_read = std::min<std::streamsize>(buf_size, content_length - total);
#if defined (BOOST_ASIO_HAS_FILE)
			auto bytes_transferred = co_await file.async_read_some(net::buffer(buf, remain_to_read), net_awaitable[ec]);
#else
			auto bytes_transferred = fileop::read(file, std::span<char>(buf, remain_to_read));

#endif
			if (bytes_transferred == 0 || total >= (std::streamsize)content_length)
			{
				break;
			}

			bytes_transferred = std::min<std::streamsize>(bytes_transferred, content_length - total);

			stream_expires_after(m_local_socket, std::chrono::seconds(m_option.tcp_timeout_));

			co_await net::async_write(m_local_socket, net::buffer(buf, bytes_transferred), net::transfer_all(), net_awaitable[ec]);
			total += bytes_transferred;
			if (ec)
			{
				XLOG_WARN << "connection id: " << m_connection_id << ", http async_write: " << ec.message()
						  << ", already write: " << total;
				co_return;
			}
		}
		while (total < content_length);

		XLOG_DBG << "connection id: " << m_connection_id << ", http request: " << hctx.target_ << ", completed";

		co_return;
	}


	net::awaitable<void> proxy_session::default_http_route(const string_request& request, std::string response, http::status status)
	{
		boost::system::error_code ec;

		std::array<std::byte, 4096> pre_alloc_buf;
		std::pmr::monotonic_buffer_resource mbr(pre_alloc_buf.data(), pre_alloc_buf.size());
		pmr_alloc_t alloc(&mbr);

		string_response res{std::piecewise_construct, std::make_tuple(alloc),
							std::make_tuple(status, request.version(), alloc)};

		res.set(http::field::server, version_string);
		res.set(http::field::date, server_date_string(alloc));
		res.set(http::field::content_type, "text/html");

		res.keep_alive(true);
		res.body() = response;
		res.prepare_payload();

		string_response_serializer sr(res);
		co_await http::async_write(m_local_socket, sr, net_awaitable[ec]);
		if (ec)
		{
			XLOG_WARN << "connection id: " << m_connection_id << ", default http route err: " << ec.message();
		}

		co_return;
	}

	net::awaitable<void> proxy_session::location_http_route(const string_request& request, const std::string& path)
	{
		boost::system::error_code ec;

		std::array<std::byte, 4096> pre_alloc_buf;
		std::pmr::monotonic_buffer_resource mbr(pre_alloc_buf.data(), pre_alloc_buf.size());
		pmr_alloc_t alloc(&mbr);

		span_response res{
			std::piecewise_construct,
			std::make_tuple(boost::span<const char, boost::dynamic_extent>{fake_302_content, sizeof (fake_302_content) - 1}),
			std::make_tuple(http::status::found, request.version(), alloc)
		};

		res.set(http::field::server, version_string);
		res.set(http::field::date, server_date_string(alloc));
		res.set(http::field::content_type, "text/html; charset=UTF-8");
		res.set(http::field::location, path);

		res.keep_alive(true);
		res.prepare_payload();

		span_response_serializer sr(res);
		co_await http::async_write(m_local_socket, sr, net_awaitable[ec]);
		if (ec)
		{
			XLOG_WARN << "connection id: " << m_connection_id << ", location http route err: " << ec.message();
		}

		co_return;
	}

	net::awaitable<void> proxy_session::forbidden_http_route(const string_request& request)
	{
		boost::system::error_code ec;

		std::array<std::byte, 4096> pre_alloc_buf;
		std::pmr::monotonic_buffer_resource mbr(pre_alloc_buf.data(), pre_alloc_buf.size());
		pmr_alloc_t alloc(&mbr);

		span_response res{
			std::piecewise_construct,
			std::make_tuple(boost::span<const char, boost::dynamic_extent>{fake_403_content, sizeof(fake_403_content) - 1}),
			std::make_tuple(http::status::forbidden, request.version(), alloc)
		};

		res.set(http::field::server, version_string);
		res.set(http::field::date, server_date_string(alloc));
		res.set(http::field::content_type, "text/html; charset=UTF-8");

		res.keep_alive(true);
		res.prepare_payload();

		span_response_serializer sr(res);
		co_await http::async_write(m_local_socket, sr, net_awaitable[ec]);
		if (ec)
		{
			XLOG_WARN << "connection id: " << m_connection_id << ", forbidden http route err: " << ec.message();
		}

		co_return;
	}

	net::awaitable<void> proxy_session::unauthorized_http_route(const string_request& request)
	{
		boost::system::error_code ec;

		std::array<std::byte, 4096> pre_alloc_buf;
		std::pmr::monotonic_buffer_resource mbr(pre_alloc_buf.data(), pre_alloc_buf.size());
		pmr_alloc_t alloc(&mbr);

		span_response res{
			std::piecewise_construct,
			std::make_tuple(boost::span<const char, boost::dynamic_extent>{fake_401_content, sizeof (fake_401_content) - 1}),
			std::make_tuple(http::status::unauthorized, request.version(), alloc)
		};

		res.set(http::field::server, version_string);
		res.set(http::field::date, server_date_string(alloc));
		res.set(http::field::content_type, "text/html; charset=UTF-8");
		res.set(http::field::www_authenticate, "Basic realm=\"proxy\"");

		res.keep_alive(true);
		res.prepare_payload();

		span_response_serializer sr(res);
		co_await http::async_write(m_local_socket, sr, net_awaitable[ec]);
		if (ec)
		{
			XLOG_WARN << "connection id: " << m_connection_id << ", unauthorized http route err: " << ec.message();
		}

		co_return;
	}


} // namespace proxy
