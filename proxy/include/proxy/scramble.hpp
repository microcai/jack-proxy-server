//
// scramble.hpp
// ~~~~~~~~~~~~
//
// Copyright (c) 2023 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#pragma once

#include <cstdint>
#include <vector>
#include <set>
#include <span>


namespace proxy {

	// 用于制造噪声数据, 具体而言, 就是通过生成随机长度的随机数据, 并将长度信息通过
	// 编码到随机数据前几个字节的最后一位, 以提高数据的隐匿性.
	// 分析者即使通过阅读此源码得知数据的编码方法, 也很难将正常数据与通过此方式得到
	// 的数据快速甄别.
	std::vector<uint8_t> generate_noise(uint16_t max_len = 0x7FFF, std::set<uint8_t> bfilter = {});

	// 从噪声数据中恢复噪声数据的长度信息.
	inline int extract_noise_length(const std::vector<uint8_t>& data)
	{
		if (data.size() < 16)
			return -1;

		uint16_t length = 0;

		for (int i = 0; i < 16; ++i)
			length |= ((data[i] & 1) << i);

		return length;
	}

	// 用于通过计算噪声数据的 xx128hash 得到一个随机的 key.
	std::vector<uint8_t> compute_key(std::span<uint8_t> data);

	// 用于对数据进行混淆, 通过 key 与数据进行异或运算, 以达到混淆数据的目的.
	class scramble_stream
	{
		scramble_stream(const scramble_stream&) = delete;
		scramble_stream& operator=(const scramble_stream&) = delete;

	public:
		scramble_stream() = default;
		~scramble_stream() = default;

		scramble_stream(scramble_stream&& other) noexcept;

		scramble_stream& operator=(scramble_stream&& other) noexcept;

	public:
		inline bool is_valid() const noexcept
		{
			return !m_key.empty();
		}

		inline void reset() noexcept
		{
			m_key.clear();
			m_pos = 0;
		}

		inline void reset(std::span<uint8_t> data) noexcept
		{
			m_key = compute_key(data);
			m_pos = 0;
		}

		inline void set_key(const std::vector<uint8_t>& key) noexcept
		{
			m_key = key;
		}

		// 将数据 data 加解密, 但不改变 scramble_stream 类的状态.
		void peek_data(std::span<uint8_t> data) const noexcept;

		std::vector<uint8_t> scramble(std::span<uint8_t> data) noexcept;

		virtual void scramble(uint8_t* data, size_t size) noexcept;

	private:
		std::vector<uint8_t> m_key;
		size_t m_pos = 0;
	};
}
