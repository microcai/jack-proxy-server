
#include "proxy/proxy_fwd.hpp"

static const std::map<std::string_view, std::string_view> global_mimes =
{
    { ".html", "text/html; charset=utf-8" },
    { ".htm", "text/html; charset=utf-8" },
    { ".js", "application/javascript" },
    { ".h", "text/javascript" },
    { ".hpp", "text/javascript" },
    { ".cpp", "text/javascript" },
    { ".cxx", "text/javascript" },
    { ".cc", "text/javascript" },
    { ".c", "text/javascript" },
    { ".json", "application/json" },
    { ".css", "text/css" },
    { ".txt", "text/plain; charset=utf-8" },
    { ".md", "text/plain; charset=utf-8" },
    { ".log", "text/plain; charset=utf-8" },
    { ".xml", "text/xml" },
    { ".ico", "image/x-icon" },
    { ".ttf", "application/x-font-ttf" },
    { ".eot", "application/vnd.ms-fontobject" },
    { ".woff", "application/x-font-woff" },
    { ".pdf", "application/pdf" },
    { ".png", "image/png" },
    { ".jpg", "image/jpg" },
    { ".jpeg", "image/jpg" },
    { ".gif", "image/gif" },
    { ".webp", "image/webp" },
    { ".svg", "image/svg+xml" },
    { ".wav", "audio/x-wav" },
    { ".ogg", "video/ogg" },
    { ".m4a", "audio/mp4" },
    { ".mp3", "audio/mpeg" },
    { ".mp4", "video/mp4" },
    { ".flv", "video/x-flv" },
    { ".f4v", "video/x-f4v" },
    { ".ts", "video/MP2T" },
    { ".mov", "video/quicktime" },
    { ".avi", "video/x-msvideo" },
    { ".wmv", "video/x-ms-wmv" },
    { ".3gp", "video/3gpp" },
    { ".mkv", "video/x-matroska" },
    { ".7z", "application/x-7z-compressed" },
    { ".ppt", "application/vnd.ms-powerpoint" },
    { ".zip", "application/zip" },
    { ".xz", "application/x-xz" },
    { ".xml", "application/xml" },
    { ".webm", "video/webm" },
    { ".weba", "audio/webm" },
    { ".m3u8", "application/vnd.apple.mpegurl" },
};

std::string_view proxy::mime_type_for_file_ext(std::string_view ext)
{
    if (global_mimes.count(ext))
    {
        return global_mimes.at(ext);
    }

    return "application/octet-stream";
}
