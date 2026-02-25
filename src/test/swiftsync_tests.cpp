#include <swiftsync.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>

namespace {
const uint32_t MAX_OUTPUTS{111115};
} // namespace

BOOST_AUTO_TEST_SUITE(swiftsync_tests);

BOOST_AUTO_TEST_CASE(compress_decompress)
{
    std::vector<uint32_t> indices{};
    indices.reserve(MAX_OUTPUTS);
    for (uint32_t i{}; i < MAX_OUTPUTS; ++i) {
        // Randomly filter some indices, otherwise the representation would be trivial.
        if ((i % 7 != 0) && (i % 13 != 0) && ((i + 5) % 3 != 0)) {
            indices.push_back(i);
        }
    }
    auto ef = swiftsync::EliasFano::Compress(indices);
    auto decompress = ef.Decompress();
    BOOST_CHECK_EQUAL_COLLECTIONS(indices.begin(), indices.end(), decompress.begin(), decompress.end());
}

BOOST_AUTO_TEST_SUITE_END();
