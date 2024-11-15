
#include <cstdlib>

void * operator new(decltype(sizeof(0)) size) noexcept(false)
{
    return std::malloc(size);
}

void operator delete(void* ptr)
{
    std::free(ptr);
}