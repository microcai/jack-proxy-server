
#pragma once

#include <memory>
#include <functional>
#include <boost/asio.hpp>
#include <boost/asio/experimental/channel.hpp>
#include "proxy/use_awaitable.hpp"

namespace proxy
{
    namespace
    {
        template<typename T>
        concept has_expires_after = requires(T t, boost::asio::steady_timer::duration d)
        {
            t.expires_after(d);
        };

    }

    template<typename SourceStream, typename SinkStream>
    boost::asio::awaitable<std::streamsize> splice_impl(SourceStream& src_stream, SinkStream& dest_stream, std::streamsize total_splice_bytes, auto timeout)
    {
        using namespace boost::asio::experimental::awaitable_operators;

        constexpr auto buf_size = 64 * 1024;
        std::array<std::byte, buf_size> m_buf[2];

        std::streamsize total_readed = 0;
        std::streamsize total_writed = 0;
        boost::system::error_code ec;

        int cur_read_buf = 0, next_read_buf = 1;
        std::streamsize this_reading_size = ( total_splice_bytes == -1) ? buf_size : std::min<std::streamsize>(buf_size, total_splice_bytes - total_readed);

        auto read_size = co_await src_stream.async_read_some(
            boost::asio::buffer(m_buf[cur_read_buf].data(), this_reading_size), boost::asio::use_awaitable);
        total_readed += read_size;

        for (;!ec;)
        {
            // 计算本次应该读取字节数, m_total_bytes == -1 表示全部发送，直到 读取到 EOF
            this_reading_size = (total_splice_bytes == -1) ? buf_size : std::min<std::streamsize>(buf_size, total_splice_bytes - total_readed);

            if (this_reading_size > 0)
            {
                if constexpr (has_expires_after<SourceStream>)
                    src_stream.expires_after(timeout);
                if constexpr (has_expires_after<SinkStream>)
                    dest_stream.expires_after(timeout);

                auto [write_bytes, read_bytes] = co_await (
                    boost::asio::async_write(
                        dest_stream,
                        boost::asio::buffer(m_buf[cur_read_buf].data(), read_size),
                        boost::asio::transfer_all(),
                        boost::asio::use_awaitable
                    )
                    &&
                    src_stream.async_read_some(
                        boost::asio::buffer(m_buf[next_read_buf].data(), this_reading_size),
                        net_awaitable[ec]
                    )
                );

                total_readed += read_bytes;
                total_writed += write_bytes;

                if (read_bytes == 0)
                {
                    break;
                }
                read_size = read_bytes;
                std::swap(cur_read_buf, next_read_buf);
            }
            else
            {
                if constexpr (has_expires_after<SinkStream>)
                    dest_stream.expires_after(timeout);
                total_writed += co_await boost::asio::async_write(
                    dest_stream, boost::asio::buffer(m_buf[cur_read_buf].data(), read_size), boost::asio::use_awaitable);
                break;
            }
        }

        co_return total_writed;
    }

    template<typename SourceStream, typename SinkStream, typename Timeout, typename CompletionToken>
    auto async_splice(SourceStream& src, SinkStream& dst, std::streamsize bytes_to_send, Timeout timeout, CompletionToken&& token)
    {
        return boost::asio::co_spawn(src.get_executor(), splice_impl(src, dst, bytes_to_send, timeout), std::forward<CompletionToken>(token));
    }


}
