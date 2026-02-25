#include <streams.h>
#include <swiftsync.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>

namespace {
const uint32_t MAX_OUTPUTS{111115};
} // namespace

BOOST_AUTO_TEST_SUITE(swiftsync_tests);

BOOST_AUTO_TEST_CASE(compress_decompress_elias_fano)
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

BOOST_AUTO_TEST_CASE(serialize_elias_fano)
{
    std::vector<uint32_t> indices{};
    indices.reserve(10000);
    for (uint32_t i{}; i < 10000; ++i) {
        // Randomly filter some indices, otherwise the representation would be trivial.
        if ((i % 21 != 0) && (i % 17 != 0) && ((i + 7) % 5 != 0)) {
            indices.push_back(i);
        }
    }
    auto want = swiftsync::EliasFano::Compress(indices);
    DataStream stream{};
    stream << want;
    BOOST_CHECK(stream.size() > 0);
    swiftsync::EliasFano got;
    stream >> got;
    auto want_result = want.Decompress();
    auto got_result = got.Decompress();
    BOOST_CHECK_EQUAL(got_result.size(), want_result.size());
    BOOST_CHECK_EQUAL_COLLECTIONS(got_result.begin(), got_result.end(), want_result.begin(), want_result.end());
    std::vector<uint32_t> none{};
    auto empty = swiftsync::EliasFano::Compress(none);
    stream << empty;
    BOOST_CHECK(stream.size() == 1);
    swiftsync::EliasFano maybe_empty;
    stream >> maybe_empty;
    auto actual_empty = want.Decompress();
    auto expected_empty = got.Decompress();
    BOOST_CHECK_EQUAL(actual_empty.size(), expected_empty.size());
    BOOST_CHECK_EQUAL_COLLECTIONS(actual_empty.begin(), actual_empty.end(), expected_empty.begin(), expected_empty.end());
}

BOOST_AUTO_TEST_SUITE_END();
