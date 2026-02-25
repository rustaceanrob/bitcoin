#include <swiftsync.h>
using namespace swiftsync;

HintsfileWriter::HintsfileWriter(AutoFile& file) : m_file(file.release())
{
    m_file << FILE_MAGIC;
    m_file << FILE_VERSION;
}

bool HintsfileWriter::WriteStopHeight(uint32_t stop)
{
    m_file << stop;
    return m_file.Commit();
}

bool HintsfileWriter::WriteHints(const EliasFano& ef)
{
    m_file << ef;
    return m_file.Commit();
}
