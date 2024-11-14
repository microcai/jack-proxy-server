

#include "proxy/libproxy_pch.hpp"

#include "proxy/proxy_session.hpp"
#include "proxy/strutil.hpp"
#include "proxy/logging.hpp"

#include <boost/asio.hpp>

#include <boost/url.hpp>

#include <fmt/xchar.h>
#include <fmt/format.h>

namespace urls = boost::urls;			// form <boost/url.hpp>

namespace proxy
{
	using namespace util;
	//////////////////////////////////////////////////////////////////////////
	static constexpr auto body_fmt =
		// "<a href=\"{}\">{}</a>{} {}       {}\r\n";
		"<tr><td class=\"link\"><a href=\"{}\">{}</a></td><td class=\"size\">{}</td><td class=\"date\">{}</td></tr>\r\n";

	//////////////////////////////////////////////////////////////////////////

	static std::string make_unc_path(std::string_view path)
	{
		std::string ret { path };

#ifdef WIN32
		if (ret.size() > MAX_PATH)
		{
			boost::replace_all(ret, "/", "\\");
			return "\\\\?\\" + ret;
		}
#endif

		return ret;
	}

	//////////////////////////////////////////////////////////////////////////

	std::tuple<std::string, fs::path> proxy_session::file_last_wirte_time(const fs::path& file)
	{
		static auto loc_time = [](auto t) -> struct tm*
		{
			using time_type = std::decay_t<decltype(t)>;
			if constexpr (std::is_same_v<time_type, std::filesystem::file_time_type>)
			{
				auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
					t - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now());
				auto time = std::chrono::system_clock::to_time_t(sctp);
				return std::localtime(&time);
			}
			else if constexpr (std::is_same_v<time_type, std::time_t>)
			{
				return std::localtime(&t);
			}
			else
			{
				static_assert(!std::is_same_v<time_type, time_type>, "time type required!");
			}
		};

		boost::system::error_code ec;
		std::string time_string;
		fs::path unc_path;

		auto ftime = fs::last_write_time(file, ec);
		if (ec)
		{
#ifdef WIN32
			if (file.string().size() > MAX_PATH)
			{
				unc_path = make_unc_path(file.string());
				ftime = fs::last_write_time(unc_path, ec);
			}
#endif
		}

		if (!ec)
		{
			auto tm = loc_time(ftime);

			char tmbuf[64] = {0};
			std::strftime(tmbuf, sizeof(tmbuf), "%m-%d-%Y %H:%M", tm);

			time_string = tmbuf;
		}

		return {time_string, unc_path};
	}

	std::pmr::string proxy_session::make_target_path(std::string_view target, pmr_alloc_t alloc)
	{
		std::pmr::string url { "http://example.com", alloc };
		if (target.starts_with("/"))
		{
			url += target;
		}
		else
		{
			url += "/";
			url += target;
		}

		auto result = urls::parse_uri(url);
		if (result.has_error())
		{
			return std::pmr::string(target, alloc);
		}

		return std::pmr::string{result->path(), alloc};
	}

	std::pmr::string proxy_session::make_real_target_path(std::string_view target, pmr_alloc_t alloc)
	{
		auto target_path = make_target_path(target, alloc);
		auto doc_path = m_option.doc_directory_;

		auto ret = path_cat(doc_path, target_path, alloc);

#ifdef WIN32
		std::string ret_str = make_unc_path(ret);
		return std::pmr::string{ret_str.begin(), ret_str.end(), alloc};
#else
		return ret;
#endif
	}

	std::pmr::vector<std::pmr::string> proxy_session::format_path_list(std::string_view path, boost::system::error_code& ec, pmr_alloc_t alloc)
	{
		fs::directory_iterator end;
		fs::directory_iterator it(path, ec);
		if (ec)
		{
			XLOG_DBG << "connection id: " << m_connection_id << ", format_path_list read dir: " << path
					 << ", error: " << ec.message();
			return std::pmr::vector<std::pmr::string>{alloc};
		}

		std::pmr::vector<std::pmr::string> path_list{alloc};
		std::pmr::vector<std::pmr::string> file_list{alloc};

		for (; it != end && !m_abort; it++)
		{
			const auto& item = it->path();

			auto [time_string, unc_path] = file_last_wirte_time(item);

			std::pmr::string rpath{alloc};

			if (fs::is_directory(unc_path.empty() ? item : unc_path, ec))
			{
				rpath = item.filename().string();
				rpath += "/";

				auto show_path = rpath;
				if (show_path.size() > 50)
				{
					show_path = show_path.substr(0, 47);
					show_path += "..&gt;";
				}
				std::pmr::string str(alloc);
				fmt::format_to(std::back_inserter(str), body_fmt, rpath, show_path, time_string, "-");

				path_list.push_back(std::move(str));
			}
			else
			{
				rpath = item.filename().string();
				std::string filesize;
				if (unc_path.empty())
				{
					unc_path = item;
				}
				auto sz = static_cast<float>(fs::file_size(unc_path, ec));
				if (ec)
				{
					sz = 0;
				}
				filesize = strutil::add_suffix(sz);
				auto show_path = rpath;
				if (show_path.size() > 50)
				{
					show_path = show_path.substr(0, 47);
					show_path += "..&gt;";
				}
				std::pmr::string str(alloc);
				fmt::format_to(std::back_inserter(str), body_fmt, rpath, show_path, time_string, filesize);

				file_list.push_back(std::move(str));
			}
		}

		ec = {};

		for (auto& item : file_list)
		{
			path_list.push_back(std::move(item));
		}

		return path_list;
	}

	void proxy_session::stream_expires_never(variant_stream_type& stream)
	{
		boost::variant2::visit([](auto& s) mutable
		{
			using ValueType = std::decay_t<decltype(s)>;
			using NextLayerType = util::proxy_tcp_socket::next_layer_type;

			if constexpr (std::same_as<NextLayerType, util::tcp_socket>)
			{
				if constexpr (std::same_as<util::proxy_tcp_socket, ValueType>)
				{
					auto& next_layer = s.next_layer();
					next_layer.expires_never();
				}
				else if constexpr (std::same_as<util::ssl_stream, ValueType>)
				{
					auto& next_layer = s.next_layer().next_layer();
					next_layer.expires_never();
				}
			}
		}, stream);
	}

	void proxy_session::stream_expires_after(variant_stream_type& stream, net::steady_timer::duration expiry_time)
	{
		if (expiry_time.count() < 0)
		{
			return;
		}

		boost::variant2::visit([expiry_time](auto& s) mutable
		{
			using ValueType = std::decay_t<decltype(s)>;
			using NextLayerType = util::proxy_tcp_socket::next_layer_type;

			if constexpr (std::same_as<NextLayerType, util::tcp_socket>)
			{
				if constexpr (std::same_as<util::proxy_tcp_socket, ValueType>)
				{
					auto& next_layer = s.next_layer();
					next_layer.expires_after(expiry_time);
				}
				else if constexpr (std::same_as<util::ssl_stream, ValueType>)
				{
					auto& next_layer = s.next_layer().next_layer();
					next_layer.expires_after(expiry_time);
				}
			}
		}, stream);
	}

	void proxy_session::stream_expires_at(variant_stream_type& stream, net::steady_timer::time_point expiry_time)
	{
		boost::variant2::visit([expiry_time](auto& s) mutable
		{
			using ValueType = std::decay_t<decltype(s)>;
			using NextLayerType = util::proxy_tcp_socket::next_layer_type;

			if constexpr (std::same_as<NextLayerType, util::tcp_socket>)
			{
				if constexpr (std::same_as<util::proxy_tcp_socket, ValueType>)
				{
					auto& next_layer = s.next_layer();
					next_layer.expires_at(expiry_time);
				}
				else if constexpr (std::same_as<util::ssl_stream, ValueType>)
				{
					auto& next_layer = s.next_layer().next_layer();
					next_layer.expires_at(expiry_time);
				}
			}
		}, stream);
	}

	std::pmr::string proxy_session::server_date_string(pmr_alloc_t alloc)
	{
		auto time = std::time(nullptr);
		auto gmt = gmtime((const time_t*)&time);

		std::pmr::string str(64, '\0', alloc);
		auto ret = strftime((char*)str.data(), 64, "%a, %d %b %Y %H:%M:%S GMT", gmt);
		str.resize(ret);

		return str;
	}

} // namespace proxy
