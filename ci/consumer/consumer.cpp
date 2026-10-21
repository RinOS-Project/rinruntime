#include <rinruntime/rinruntime.hpp>

#include "consumer_frame_copy.h"

int main()
{
    static_assert(sizeof(RinRuntimeFrameCopyV1) == 80);
    return rinruntime_ci_frame_copy();
}
