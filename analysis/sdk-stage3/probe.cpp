#include "dng_exceptions.h"
#include "dng_host.h"
#include "dng_ifd.h"
#include "dng_image.h"
#include "dng_info.h"
#include "dng_linearization_info.h"
#include "dng_negative.h"
#include "dng_mosaic_info.h"
#include "dng_pixel_buffer.h"
#include "dng_stream.h"
#include "dng_tag_types.h"
#include "dng_tag_values.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <vector>

static void require(bool ok, const char *message) {
    if (!ok) throw std::runtime_error(message);
}

static void dump(const dng_image &image, const char *path, const char *stage,
                 uint32 planes, const char *reference = nullptr) {
    const dng_rect area = image.Bounds();
    require(image.Planes() == planes && image.PixelType() == ttShort, "unexpected image format");
    std::vector<uint16> words(size_t(area.W()) * area.H() * planes);
    dng_pixel_buffer buffer(area, 0, planes, ttShort, pcInterleaved, words.data());
    image.Get(buffer);
    if (reference) {
        std::unique_ptr<FILE, decltype(&std::fclose)> input(std::fopen(reference, "rb"), std::fclose);
        require(input != nullptr, "cannot open pinned earlier-stage reference");
        uint16 row[6304];
        for (int32 y = 0; y < area.H(); ++y) {
            size_t width = area.W();
            require(width <= 6304 && std::fread(row, sizeof(uint16), width, input.get()) == width &&
                    std::memcmp(row, words.data() + size_t(y) * width, width * sizeof(uint16)) == 0,
                    "earlier-stage bytes differ before Stage 3");
        }
        require(std::fgetc(input.get()) == EOF && !std::ferror(input.get()),
                "earlier-stage reference length mismatch");
    }
    auto limits = std::minmax_element(words.begin(), words.end());
    std::printf("%s bounds=[%d,%d,%d,%d] planes=%u pixelType=%u samples=%llu min=%u max=%u zero=%llu max_count=%llu\n",
                stage, area.t, area.l, area.b, area.r, image.Planes(), image.PixelType(),
                static_cast<unsigned long long>(words.size()), unsigned(*limits.first), unsigned(*limits.second),
                static_cast<unsigned long long>(std::count(words.begin(), words.end(), uint16(0))),
                static_cast<unsigned long long>(std::count(words.begin(), words.end(), uint16(65535))));
    FILE *out = std::fopen(path, "wbx");
    require(out != nullptr, "cannot create exclusive stage dump");
    const size_t written = std::fwrite(words.data(), sizeof(uint16), words.size(), out);
    const int status = std::fclose(out);
    require(written == words.size() && status == 0, "stage dump failed");
}

int main(int argc, char **argv) {
    if (argc != 7) return 2;
    try {
        FILE *in = std::fopen(argv[1], "rb");
        require(in != nullptr, "cannot open DNG");
        std::vector<uint8> bytes(31652773);
        const size_t count = std::fread(bytes.data(), 1, bytes.size(), in);
        const int read_error = std::ferror(in);
        std::fclose(in);
        require(!read_error && count == 31652772, "DNG read size mismatch");

        dng_host host;
        require(!host.ForPreview() && !host.ForFastSaveToDNG() && !host.WantsPreserveStage2() &&
                host.MinimumSize() == 0 && host.PreferredSize() == 0 && host.MaximumSize() == 0 &&
                host.CropFactor() == 1.0, "unexpected default host settings");
        dng_stream stream(bytes.data(), static_cast<uint32>(count));
        dng_info info;
        info.Parse(host, stream);
        info.PostParse(host);
        require(info.IsValidDNG(), "invalid DNG");
        require(info.fMainIndex >= 0 && info.fEnhancedIndex == -1 &&
                info.fMaskIndex == -1 && info.fDepthIndex == -1 && info.fSemanticMaskIndices.empty(),
                "unexpected enhanced or auxiliary IFD");
        const dng_ifd &ifd = *info.fIFD[info.fMainIndex];
        const dng_rect active = ifd.fActiveArea;
        require(ifd.PixelType() == ttShort && ifd.fSamplesPerPixel == 1 &&
                ifd.fWhiteLevel[0] == 16315 && ifd.fBlackLevelRepeatRows == 2 &&
                ifd.fBlackLevelRepeatCols == 2 && ifd.fLinearizationTableCount == 0 &&
                ifd.fBlackLevelDeltaHCount == 0 && ifd.fBlackLevelDeltaVCount == 0 &&
                ifd.fBlackLevel[0][0][0] == 64 && ifd.fBlackLevel[0][1][0] == 64 &&
                ifd.fBlackLevel[1][0][0] == 64 && ifd.fBlackLevel[1][1][0] == 64 &&
                active == dng_rect(34, 26, 4194, 6250), "unexpected parsed raw IFD");
        AutoPtr<dng_negative> negative(host.Make_dng_negative());
        negative->Parse(host, stream, info);
        negative->PostParse(host, stream, info);
        negative->ReadStage1Image(host, stream, info);
        negative->ValidateRawImageDigest(host);
        require(negative->Stage1Image() && negative->Stage1Image()->Bounds() == dng_rect(0, 0, 4224, 6304),
                "unexpected Stage 1");
        std::printf("SDK=%s xmp=%d baseline_libjpeg=%d sdk_avx=%d\n",
                    kDNGSDK_GetInfoVersion, qDNGUseXMP, qDNGUseLibJPEG, qDNGAVXSupport);
        std::printf("parsed_active=[%d,%d,%d,%d] white=%.0f black=%.0f black_preservation=%d\n",
                    active.t, active.l, active.b, active.r, ifd.fWhiteLevel[0], ifd.fBlackLevel[0][0][0],
                    negative->SupportsPreservedBlackLevels(host));
        const dng_rect crop = negative->DefaultCropArea();
        require(crop == dng_rect(24, 28, 4152, 6220), "unexpected active-relative default crop");
        std::printf("default_crop_active_relative=[%d,%d,%d,%d]\n", crop.t, crop.l, crop.b, crop.r);
        dump(*negative->Stage1Image(), argv[2], "stage1", 1, argv[5]);
        negative->SynchronizeMetadata();
        negative->BuildStage2Image(host);
        require(negative->Stage2Image() && negative->Stage2Image()->Bounds() == dng_rect(0, 0, 4160, 6224) &&
                negative->Stage3BlackLevel() == 0, "unexpected Stage 2");
        dump(*negative->Stage2Image(), argv[3], "stage2", 1, argv[6]);
        const dng_mosaic_info *mosaic = negative->GetMosaicInfo();
        require(mosaic && mosaic->IsColorFilterArray() && mosaic->fCFALayout == 1 &&
                mosaic->fColorPlanes == 3 && mosaic->fCFAPatternSize == dng_point(2, 2) &&
                mosaic->fCFAPlaneColor[0] == 0 && mosaic->fCFAPlaneColor[1] == 1 &&
                mosaic->fCFAPlaneColor[2] == 2 && mosaic->fCFAPattern[0][0] == 0 &&
                mosaic->fCFAPattern[0][1] == 1 && mosaic->fCFAPattern[1][0] == 1 &&
                mosaic->fCFAPattern[1][1] == 2 && ifd.fOpcodeList3Count == 0,
                "unexpected CFA pattern or OpcodeList3");
        std::printf("before_stage3 reference_stage1_stage2=equal mosaic_layout=%u pattern=0,1,1,2 plane_colors=0,1,2 green_split=%u opcode3_count=%u\n",
                    mosaic->fCFALayout, mosaic->fBayerGreenSplit, ifd.fOpcodeList3Count);
        std::fflush(stdout);
        negative->BuildStage3Image(host, -1);
        require(negative->Stage3Image() && !negative->Stage2Image() &&
                negative->Stage3Image()->Bounds() == dng_rect(0, 0, 4160, 6224) &&
                negative->DefaultCropArea() == crop && negative->DefaultFinalWidth() == 6192 &&
                negative->DefaultFinalHeight() == 4128 && !negative->IsPreview() &&
                negative->RawToFullScaleH() == 1.0 && negative->RawToFullScaleV() == 1.0 &&
                negative->Stage3BlackLevel() == 0 && negative->Stage3Gain() == 1.0,
                "unexpected Stage 3 dimensions or state");
        std::printf("after_stage3 src_plane_argument=-1 minimum_size=0 preferred_size=0 maximum_size=0 preview=0 crop_factor=1 raw_to_full=1,1 stage2_preserved=0 black=0 gain=1 default_final=6192,4128\n");
        dump(*negative->Stage3Image(), argv[4], "stage3", 3);
        return 0;
    } catch (const dng_exception &error) {
        std::fprintf(stderr, "SDK error: %d\n", int(error.ErrorCode()));
    } catch (const std::exception &error) {
        std::fprintf(stderr, "%s\n", error.what());
    }
    return 1;
}
