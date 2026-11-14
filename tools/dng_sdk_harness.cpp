// Cross-check harness for tools/check_dcp_against_sdk.py.
// Runs the Adobe DNG SDK reference routines RefBaselineHueSatMap and RefBaselineRGBTone
// (dng_reference.cpp) on a LookTable and a tone curve.  Contains no Adobe code; it is compiled
// against a DNG SDK source folder that the user supplies.
// Input (binary, little endian): u32 hue,sat,val,encoding,curvePoints,count; float table[hue*sat*val*3];
// float curve[curvePoints*2]; float rgb[count*3] (linear ProPhoto).  Output: float rgb[count*3] after
// RefBaselineHueSatMap and RefBaselineRGBTone.
#include "dng_reference.h"
#include "dng_hue_sat_map.h"
#include "dng_1d_table.h"
#include "dng_1d_function.h"
#include "dng_tone_curve.h"
#include "dng_spline.h"
#include "dng_color_space.h"
#include "dng_memory.h"
#include "dng_auto_ptr.h"
#include <cstdio>
#include <vector>
int main (int argc, char **argv)
	{
	FILE *in = fopen (argv [1], "rb"); FILE *out = fopen (argv [2], "wb");
	uint32 h [6]; fread (h, 4, 6, in);
	uint32 hue = h [0], sat = h [1], val = h [2], encoding = h [3], points = h [4], count = h [5];
	std::vector<float> table (hue * sat * val * 3), curve (points * 2), rgb (count * 3);
	fread (table.data (), 4, table.size (), in); fread (curve.data (), 4, curve.size (), in); fread (rgb.data (), 4, rgb.size (), in);
	dng_hue_sat_map map; map.SetDivisions (hue, sat, val);
	size_t k = 0;
	for (uint32 v = 0; v < val; v++) for (uint32 hh = 0; hh < hue; hh++) for (uint32 s = 0; s < sat; s++)
		{
		dng_hue_sat_map::HSBModify m; m.fHueShift = table [k]; m.fSatScale = table [k + 1]; m.fValScale = table [k + 2]; k += 3;
		map.SetDelta (hh, s, v, m);
		}
	AutoPtr<dng_1d_table> enc, dec;
	if (encoding == 1)
		{
		enc.Reset (new dng_1d_table); dec.Reset (new dng_1d_table);
		const dng_1d_function &f = dng_function_GammaEncode_sRGB::Get ();
		enc->Initialize (gDefaultDNGMemoryAllocator, f, false);
		const dng_1d_inverse inv (f);
		dec->Initialize (gDefaultDNGMemoryAllocator, inv, false);
		}
	dng_tone_curve tc; tc.fCoord.resize (points);
	for (uint32 i = 0; i < points; i++) { tc.fCoord [i].h = curve [2 * i]; tc.fCoord [i].v = curve [2 * i + 1]; }
	dng_spline_solver solver; tc.Solve (solver);
	dng_1d_table tone; tone.Initialize (gDefaultDNGMemoryAllocator, solver, false);
	std::vector<float> r (count), g (count), b (count);
	for (uint32 i = 0; i < count; i++) { r [i] = rgb [3 * i]; g [i] = rgb [3 * i + 1]; b [i] = rgb [3 * i + 2]; }
	RefBaselineHueSatMap (r.data (), g.data (), b.data (), r.data (), g.data (), b.data (), count, map, enc.Get (), dec.Get (), false);
	RefBaselineRGBTone (r.data (), g.data (), b.data (), r.data (), g.data (), b.data (), count, tone);
	for (uint32 i = 0; i < count; i++) { float o [3] = {r [i], g [i], b [i]}; fwrite (o, 4, 3, out); }
	fclose (out); return 0;
	}
