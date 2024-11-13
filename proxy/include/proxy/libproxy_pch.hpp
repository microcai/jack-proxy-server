
#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <condition_variable>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <chrono>
#include <deque>
#include <exception>
#include <span>
#include <filesystem>
#include <functional>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <memory_resource>
#include <mutex>
#include <optional>
#include <random>
#include <regex>
#include <set>
#include <span>
#include <sstream>
#include <streambuf>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>
#include <version>

#if defined(__cpp_lib_format)
# include <format>
#endif

#include <boost/assert.hpp>

#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/beast.hpp>
#include <boost/beast/core/detail/base64.hpp>

#include <boost/date_time/posix_time/posix_time.hpp>

#include <boost/url.hpp>
#include <boost/regex.hpp>

#include <boost/nowide/convert.hpp>
#include <boost/nowide/filesystem.hpp>
#include <boost/nowide/fstream.hpp>

#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <boost/algorithm/string.hpp>

#include <fmt/xchar.h>
#include <fmt/format.h>

#include <boost/hana.hpp>

#include <boost/smart_ptr/local_shared_ptr.hpp>
#include <boost/smart_ptr/make_local_shared.hpp>
#include <boost/smart_ptr/weak_ptr.hpp>

#include <boost/system/error_code.hpp>

#include <boost/variant2.hpp>
