// ------------------------------------------------------------------------------------------------
/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *
 *      ___        ___           ___           ___           ___           ___           ___
 *     /\__\      /\  \         /\__\         /\__\         /\__\         /\__\         /\  \
 *    /:/ _/_     \:\  \       /::|  |       /::|  |       /:/ _/_       /:/ _/_        \:\  \
 *   /:/ /\__\     \:\  \     /:/:|  |      /:/:|  |      /:/ /\  \     /:/ /\__\        \:\  \
 *  /:/ /:/  / ___  \:\  \   /:/|:|  |__   /:/|:|  |__   /:/ /::\  \   /:/ /:/ _/_   _____\:\  \
 * /:/_/:/  / /\  \  \:\__\ /:/ |:| /\__\ /:/ |:| /\__\ /:/__\/\:\__\ /:/_/:/ /\__\ /::::::::\__\
 * \:\/:/  /  \:\  \ /:/  / \/__|:|/:/  / \/__|:|/:/  / \:\  \ /:/  / \:\/:/ /:/  / \:\~~\~~\/__/
 *  \::/__/    \:\  /:/  /      |:/:/  /      |:/:/  /   \:\  /:/  /   \::/_/:/  /   \:\  \
 *   \:\  \     \:\/:/  /       |::/  /       |::/  /     \:\/:/  /     \:\/:/  /     \:\  \
 *    \:\__\     \::/  /        |:/  /        |:/  /       \::/  /       \::/  /       \:\__\
 *     \/__/      \/__/         |/__/         |/__/         \/__/         \/__/         \/__/
 *
 * FuzzGen - Automatic Fuzzer Generation
 * Version: v3.1
 *
 * Target Library: external/libopus
 * Build Options: analysis=deep; arch=x64; permute=yes; failure=yes; 
 *                coalesce=yes; progressive=no; max-depth=4; seed=random;
 *                min-buflen=32; max-buflen=4096;
 *
 * Issues: 
 *   > Header file for function 'opus_select_arch' not found/is invalid. Function is discarded.
 *
 *
 * ~~~ THIS FILE HAS BEEN GENERATED AUTOMATICALLY BY *FUZZGEN* AT: 30-09-2019 00:35:53 PDT ~~~
 *
 */
// ------------------------------------------------------------------------------------------------
#include <cstdint>
#include <iostream>
#include <cstdlib>
#include <cassert>
#include <math.h>

/* headers for library includes */
#include "opus.h"
#include "opus_multistream.h"
#include "opus_private.h"


using namespace std;

// ------------------------------------------------------------------------------------------------
/* calculate the number of bytes needed to hold a factorial */
#define NBYTES_FOR_FACTORIAL(n) ((((uint64_t)ceil( log2(FACTORIAL[n]) ) + 7) & (uint64_t)~7) >> 3)

/* The first 20 factorials (to avoid calculations) */
const uint64_t FACTORIAL[] = {
    1,                  // 0!
    1,                  // 1!
    2,                  // 2!
    6,                  // 3!
    24,                 // 4!
    120,                // 5!
    720,                // 6!
    5040,               // 7!
    40320,              // 8!
    362880,             // 9!
    3628800,            // 10!
    39916800,           // 11!
    479001600,          // 12!
    6227020800,         // 13!
    87178291200,        // 14!
    1307674368000,      // 15!
    20922789888000,     // 16!
    355687428096000,    // 17!
    6402373705728000,   // 18!
    121645100408832000, // 19!
    2432902008176640000 // 20!
};


/* predefined sets */
const int32_t v_SUc[] = {0, 1};
const int64_t v_LQb[] = {-32768, -11553, -9721, -7725, -7142, -6887, -6824, -6539, -6474, -5580, -5468, -4964, -4210, -3944, -3155, -2553, -1304, -1073, -256, -1, 0, 4, 7, 26, 32, 100, 128, 150, 228, 255, 256, 343, 1792, 1799, 3254, 3641, 4285, 4352, 5431, 5632, 7558, 7874, 9741, 10204, 10459, 10500, 11601, 11741, 12480, 12600, 13385, 13463, 13670, 13872, 16384, 25600, 32767};
const int64_t v_IUV[] = {-9526, -9510, 25600};
const int64_t v_LFw[] = {-9510, -9494};
const int64_t v_Qam[] = {-9510, -9479};
const int64_t v_wnL[] = {-9510, -256, 0, 4, 32, 128, 148, 255, 1799, 4352, 5632};
const int64_t v_EYN[] = {-11553, -7725, -7142, -6887, -6824, -6539, -6474, -5580, -5468, -4964, -4210, -3155, -1304, -1073, -256, -1, 0, 26, 226, 343, 3254, 3641, 5431, 7558, 9741, 10204, 10459, 11601, 11741, 12480, 12482, 12600, 13385, 13463, 13670, 13872};
const int64_t v_VqT[] = {-128, -127, -126, -125, -124, -123, -122, -121, -120, -119, -118, -117, -116, -115, -114, -113, -112, -111, -110, -109, -108, -107, -106, -105, -104, -103, -102, -101, -100, -99, -98, -97, -96, -95, -94, -93, -92, -91, -90, -89, -88, -87, -86, -85, -84, -83, -82, -81, -80, -79, -78, -77, -76, -75, -74, -73, -72, -71, -70, -69, -68, -67, -66, -65, -64, -63, -62, -61, -60, -59, -58, -57, -56, -55, -54, -53, -52, -51, -50, -49, -48, -47, -46, -45, -44, -43, -42, -41, -40, -39, -38, -37, -36, -35, -34, -33, -32, -31, -30, -29, -28, -27, -26, -25, -24, -23, -22, -21, -20, -19, -18, -17, -16, -15, -14, -13, -12, -11, -10, -9, -8, -7, -6, -5, -4, -3, -2, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127};
const int64_t v_NHw[] = {-128, -127, -126, -125, -124, -123, -122, -121, -120, -119, -118, -117, -116, -115, -114, -113, -112, -111, -110, -109, -108, -107, -106, -105, -104, -103, -102, -101, -100, -99, -98, -97, -96, -95, -94, -93, -92, -91, -90, -89, -88, -87, -86, -85, -84, -83, -82, -81, -80, -79, -78, -77, -76, -75, -74, -73, -72, -71, -70, -69, -68, -67, -66, -65, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127};
const int64_t v_kOF[] = {-32763, -32752, -32562, -32521, -32513, -32497, -31990, -31487, -31479, -31464, -31168, -31008, -30745, -30723, -30259, -30213, -30018, -29905, -29699, -29665, -29487, -29137, -28942, -28927, -28915, -28726, -28410, -27906, -27666, -27397, -27396, -27373, -26926, -26138, -26118, -25903, -25880, -25863, -25855, -25821, -25607, -25594, -25337, -25089, -25055, -24826, -24798, -24598, -24529, -24350, -24308, -23815, -23813, -23776, -23321, -23101, -23089, -22802, -22579, -22516, -22493, -22426, -22294, -22271, -22270, -22080, -21998, -21763, -21544, -21496, -21252, -21221, -20992, -20984, -20758, -20735, -20474, -20240, -19771, -19716, -19709, -19703, -19220, -18944, -18719, -18690, -18678, -18421, -18190, -17711, -17674, -17406, -17387, -17167, -17106, -16898, -16888, -16643, -16642, -16638, -16627, -16505, -16476, -16443, -16417, -16384, -16374, -16237, -16218, -16206, -16194, -16179, -16175, -16161, -16146, -16136, -16124, -16015, -15931, -15903, -15868, -15615, -15590, -15553, -15350, -15170, -15130, -15074, -15056, -14977, -14907, -14905, -14897, -14871, -14863, -14854, -14632, -14612, -14579, -14395, -14367, -14330, -14023, -13849, -13842, -13824, -13805, -13792, -13759, -13478, -13472, -13094, -13072, -13071, -12844, -12840, -12830, -12805, -12631, -12535, -12523, -12420, -12360, -12349, -12275, -12007, -11965, -11825, -11794, -11779, -11727, -11634, -11541, -11447, -11292, -11135, -11029, -10820, -10777, -10769, -10755, -10523, -10299, -10220, -10215, -10183, -10095, -9986, -9889, -9770, -9678, -9579, -9500, -9477, -9197, -8998, -8731, -8730, -8694, -8594, -8436, -8308, -8041, -7993, -7948, -7933, -7870, -7844, -7745, -7705, -7701, -7686, -7605, -7569, -7537, -7497, -7372, -7276, -7175, -7173, -7128, -7088, -7072, -6925, -6910, -6896, -6862, -6857, -6738, -6720, -6701, -6682, -6656, -6645, -6644, -6612, -6601, -6421, -6414, -6401, -6397, -6386, -6381, -6343, -6341, -6272, -6271, -6211, -6208, -6158, -6149, -6144, -6130, -6051, -6049, -6019, -5719, -5696, -5660, -5646, -5606, -5592, -5555, -5541, -5434, -5401, -5287, -5280, -5258, -5233, -5219, -5218, -5207, -5183, -5164, -5112, -5081, -4958, -4933, -4916, -4912, -4877, -4632, -4608, -4596, -4585, -4581, -4577, -4558, -4495, -4458, -4442, -4440, -4428, -4410, -4374, -4357, -4355, -4291, -4206, -4173, -4152, -4149, -4100, -4086, -4070, -3969, -3904, -3883, -3860, -3841, -3816, -3767, -3755, -3747, -3736, -3664, -3639, -3600, -3598, -3529, -3464, -3447, -3425, -3382, -3359, -3292, -3287, -3278, -3254, -3133, -3103, -3079, -3048, -2977, -2851, -2839, -2821, -2751, -2737, -2722, -2664, -2661, -2392, -2317, -2287, -2197, -2173, -2167, -2161, -2107, -2070, -2063, -1928, -1874, -1842, -1800, -1774, -1748, -1711, -1666, -1579, -1552, -1419, -1403, -1363, -1316, -1304, -1293, -1247, -1233, -1209, -1199, -1196, -1187, -1170, -1169, -1163, -1147, -1083, -1073, -1042, -1033, -1025, -994, -930, -923, -866, -836, -830, -769, -767, -751, -718, -717, -641, -613, -608, -562, -535, -523, -521, -519, -517, -491, -433, -390, -386, -330, -304, -259, -250, -237, -189, -173, -130, -129, -121, -99, -74, -32, -20, -18, -9, -1, 0, 1, 13, 28, 57, 64, 128, 148, 156, 179, 188, 197, 202, 224, 234, 238, 240, 256, 294, 310, 327, 369, 455, 486, 491, 516, 523, 593, 619, 634, 661, 675, 697, 706, 780, 921, 942, 1019, 1105, 1213, 1223, 1309, 1355, 1455, 1554, 1558, 1598, 1604, 1648, 1649, 1718, 1726, 1758, 1775, 1863, 1926, 1945, 2068, 2106, 2150, 2218, 2278, 2292, 2301, 2317, 2325, 2326, 2375, 2443, 2476, 2573, 2576, 2597, 2604, 2629, 2681, 2703, 2746, 2765, 2804, 2806, 2818, 2856, 2862, 2922, 2964, 2966, 3023, 3026, 3102, 3115, 3153, 3158, 3174, 3197, 3285, 3314, 3317, 3345, 3349, 3362, 3367, 3421, 3430, 3434, 3435, 3454, 3492, 3514, 3568, 3575, 3631, 3632, 3641, 3654, 3660, 3674, 3695, 3760, 3840, 3879, 3881, 3917, 3964, 4011, 4041, 4096, 4120, 4153, 4236, 4250, 4288, 4293, 4403, 4474, 4556, 4600, 4609, 4700, 4826, 4864, 4878, 4884, 4888, 4901, 4906, 4920, 4922, 5027, 5058, 5132, 5133, 5148, 5162, 5278, 5372, 5431, 5530, 5540, 5541, 5573, 5617, 5632, 5883, 6132, 6146, 6255, 6301, 6373, 6380, 6417, 6434, 6653, 6687, 6847, 6865, 6940, 6946, 6950, 7168, 7204, 7335, 7398, 7423, 7444, 7543, 7710, 7721, 7774, 7877, 7905, 8062, 8147, 8192, 8362, 8419, 8439, 8448, 8461, 8549, 8622, 8661, 8743, 8815, 8901, 8907, 9098, 9099, 9343, 9375, 9459, 9468, 9502, 9753, 9792, 9850, 9925, 9977, 10004, 10185, 10192, 10204, 10225, 10274, 10388, 10467, 10478, 10553, 10680, 10689, 10709, 10954, 10986, 11253, 11281, 11314, 11596, 11733, 11790, 11955, 12012, 12040, 12193, 12228, 12288, 12299, 12485, 12528, 12551, 12557, 12838, 12890, 12992, 13038, 13041, 13051, 13052, 13064, 13066, 13215, 13248, 13307, 13520, 13639, 13773, 13790, 13816, 13854, 14061, 14081, 14086, 14088, 14090, 14105, 14330, 14335, 14544, 14553, 14580, 14598, 14605, 14607, 14608, 14843, 15050, 15075, 15083, 15119, 15934, 15984, 16143, 16384, 16504, 16557, 16649, 16871, 16888, 16907, 17173, 17392, 17408, 18313, 18368, 18398, 18404, 18425, 18433, 18690, 18707, 19154, 19453, 19659, 19745, 20275, 20453, 20697, 20717, 20745, 20967, 20974, 20991, 21398, 22011, 22211, 22773, 22798, 22833, 23060, 23142, 23282, 23557, 23563, 23827, 23840, 24020, 24049, 24066, 24255, 24346, 24353, 24361, 24583, 24587, 24589, 24672, 25859, 25866, 26074, 26121, 26136, 26323, 26328, 27387, 27628, 27635, 28137, 28188, 28303, 28417, 28642, 28647, 28648, 28911, 29144, 29178, 29182, 29958, 30188, 30449, 30750, 30953, 30973, 31205, 31471, 31472, 31772, 31965, 32231, 32255, 32262, 32448, 32452, 32486, 32488, 32499, 32507, 32512, 32705, 32767};
const int64_t v_hBS[] = {-32768, -32763, -32752, -32562, -32521, -32513, -31503, -31464, -31227, -31008, -30745, -30461, -30418, -30018, -29905, -29716, -29665, -29202, -28915, -28726, -28420, -28410, -27413, -27396, -27386, -26427, -26385, -26138, -26118, -25880, -25821, -25594, -25337, -25073, -25055, -24819, -24798, -24379, -24350, -24308, -23776, -23539, -23321, -22802, -22271, -22270, -22080, -22021, -21998, -21763, -21221, -20758, -20474, -20240, -19968, -19709, -19703, -19472, -19220, -18719, -18678, -18491, -18186, -17711, -17624, -17406, -17106, -16647, -16642, -16417, -16384, -16136, -16124, -15931, -15074, -14938, -14917, -14907, -14897, -14891, -14854, -14853, -14848, -14579, -14330, -13849, -13792, -13546, -13539, -13472, -13365, -13072, -12830, -12616, -12523, -12349, -12275, -11965, -11727, -11634, -11541, -11530, -11292, -11070, -11029, -10820, -10811, -10777, -10769, -9986, -9808, -9678, -9477, -8961, -8731, -8694, -8594, -7948, -7945, -7725, -7705, -7701, -7686, -7631, -7457, -7409, -7142, -6887, -6857, -6824, -6717, -6644, -6539, -6474, -6414, -6397, -6386, -6381, -6343, -6341, -6272, -6130, -6051, -6049, -5839, -5696, -5660, -5646, -5580, -5482, -5449, -5401, -5258, -5183, -5112, -4964, -4608, -4607, -4585, -4581, -4440, -4410, -4374, -4357, -4247, -4210, -4173, -4152, -4086, -4082, -4011, -3944, -3867, -3860, -3637, -3606, -3598, -3359, -3287, -3254, -3133, -3079, -2851, -2821, -2316, -2070, -1912, -1853, -1774, -1742, -1304, -1293, -1199, -1163, -1083, -1073, -868, -792, -571, -330, -250, -129, -74, -58, -23, -11, -1, 0, 28, 64, 148, 156, 188, 205, 237, 239, 256, 294, 310, 486, 491, 593, 780, 921, 1213, 1554, 1558, 1598, 1604, 1791, 2106, 2278, 2292, 2443, 2604, 2614, 2681, 2804, 2966, 3055, 3064, 3102, 3197, 3254, 3343, 3345, 3492, 3641, 3689, 4041, 4082, 4250, 4285, 4619, 4826, 4866, 4888, 4906, 5059, 5133, 5278, 5530, 5541, 5573, 5597, 5630, 5632, 6255, 6380, 6653, 6657, 6687, 6732, 6940, 7168, 7188, 7204, 7444, 7710, 7721, 7883, 7922, 8179, 8192, 8422, 8461, 8549, 8661, 8743, 8815, 8901, 8909, 8926, 8947, 9086, 9375, 9502, 10004, 10204, 10225, 10231, 10274, 10450, 10459, 10467, 10478, 10500, 10553, 10689, 10986, 11601, 11741, 11955, 12012, 12193, 12228, 12299, 12480, 12482, 12528, 12542, 12600, 12838, 12890, 12998, 13038, 13041, 13064, 13385, 13463, 13670, 13799, 13872, 14088, 14090, 14093, 14330, 14335, 14580, 14598, 14605, 14843, 15083, 15119, 15934, 15984, 16907, 17392, 17408, 17863, 18164, 18368, 18404, 18425, 18707, 19453, 19458, 19728, 19745, 19987, 20224, 20671, 20717, 20991, 22524, 22798, 22986, 23282, 23557, 23563, 23827, 23840, 24049, 24066, 24346, 24361, 24583, 25866, 26121, 26323, 26328, 27328, 27387, 27627, 27628, 27635, 27756, 27863, 28188, 28417, 28642, 28647, 28648, 28911, 28928, 29144, 29182, 30188, 30202, 30449, 30750, 30953, 30973, 31205, 31965, 32231, 32262, 32285, 32452, 32464, 32488, 32507, 32767};
const int64_t v_zIV[] = {0, 5140};
const int64_t v_uCU[] = {-32768, -31056, -29793, -25913, -25600, -25472, -25444, -24832, -24705, -24698, -24678, -24673, -24656, -24633, -22272, -20480, -20256, -20243, -20240, -20230, -20213, -18192, -14433, -12033, -7973, -7968, -7960, -7948, -5920, -5359, -4609, -4096, -4088, -3852, -3072, -2903, -2896, -2888, -2873, -2817, -2796, -1281, -1025, -256, -246, -234, -176, -1, 0, 1, 7, 11, 13, 16, 32, 80, 116, 128, 156, 159, 208, 224, 244, 255, 256, 516, 1792, 2292, 2640, 2816, 2870, 2896, 3061, 4096, 4352, 5120, 5140, 5200, 5364, 5652, 6912, 7156, 8351, 13963, 16609, 20456, 20480, 20496, 20656, 20715, 29872, 32671};
const int64_t v_VPl[] = {-32768, 0, 32767};
const int64_t v_DkZ[] = {0, 32767};


/* global variables */
uint8_t *perm;
uint8_t data_ueg[4096];
uint8_t *dep_85;
int32_t dep_270;
uint32_t dep_264;
int32_t *dep_191;
OpusMSEncoder* dep_190;
OpusRepacketizer* dep_231;
int32_t *dep_1120;
int32_t *dep_494;
OpusEncoder* dep_1118;
uint32_t dep_86;
int32_t dep_273;
int32_t *dep_271;
OpusDecoder* dep_262;
uint8_t mapping_iNm[256];
uint8_t *dep_442;
int32_t *dep_464;
OpusMSEncoder* dep_449;
OpusDecoder* dep_75;
uint8_t data_eqQ[48][1500];
int32_t len_ZDS[48];
uint32_t dep_236;
OpusDecoder* dep_1119;
int32_t *dep_84;
uint8_t data_Bgc[32000];
uint8_t *dep_232;
int16_t pcm_Cnt[1920];
uint8_t data_FIa[3828];
uint8_t *dep_1116;
uint32_t dep_1117;
int64_t *dep_74;
int16_t pcm_NCR[8192];
int16_t *dep_76;
int32_t dep_83;
int16_t pcm_GBk[8192];
int16_t *dep_456;
uint32_t dep_473;
int16_t pcm_iAi[11520];
uint8_t data_PTx[4096];
OpusEncoder **dep_465;
char **dep_272;
OpusDecoder* dep_527;
int16_t pcm_XwM[320];
uint8_t data_TtD[2460];
uint8_t *dep_192;
OpusMSDecoder* dep_451;
uint8_t data_zbC[4096];
int16_t pcm_FSn[8192];
uint8_t data_VkV[1276];
uint8_t *dep_267;
int16_t pcm_Czz[1920];
int16_t *dep_269;
OpusMSDecoder* dep_452;
OpusDecoder* dep_453;
int16_t pcm_VXw[160];
int16_t pcm_kTG[8192];
int16_t *dep_454;
uint8_t data_KVC[1757];
uint8_t *dep_458;
int16_t pcm_Hth[160];
float pcm_GYp[1920];
uint32_t dep_287;
int32_t dep_298;
uint8_t mapping_PsK[256];
uint8_t *dep_291;
int32_t *dep_297;
OpusMSDecoder* dep_285;
int16_t pcm_qom[160];
int16_t pcm_dGR[8192];
int16_t *dep_455;
uint32_t dep_481;
uint32_t dep_493;
int16_t pcm_pZH[160];
uint8_t frames_quV_0[48];
uint8_t *frames_quV_1[48];
int16_t size_Xxq[48];
char **dep_286;
OpusDecoder **dep_300;
int16_t pcm_CtX[40];
OpusDecoder **dep_301;
uint8_t mapping_lSX[255];
int32_t *dep_197;
OpusMSEncoder* dep_196;
int32_t Fs_xEM[5];
int32_t *dep_417;
int32_t channels_tTn[2];
int32_t *dep_418;
OpusDecoder* dep_396;
int32_t application_gWt[3];
OpusEncoder* dep_395;
int32_t request_tgR[11];
int32_t request_lfV[4];
int32_t application_CZB[3];
int32_t application_lOG[3];
int32_t request_WPE[11];
uint8_t data_ZZW[1276];
uint8_t *dep_290;
int16_t pcm_dEb[1920];
int16_t *dep_293;
int32_t request_YrX[6];
int32_t request_ZoU[4];
int32_t application_xai[3];
int32_t request_ZwM[4];
int32_t channels_OJa[2];
float pcm_jIq[1920];
int32_t application_SFJ[3];
int32_t channels_nII[2];
uint8_t data_mTk[1276];
uint8_t *dep_306;
uint8_t frames_Amj_0[48];
uint8_t *frames_Amj_1[48];
uint8_t **dep_310;
int32_t *dep_434;
int16_t size_awg[48];
int16_t *dep_311;
uint32_t dep_313;
int16_t pcm_ceA[5100];
uint8_t data_IJq[627300];
int16_t pcm_UTi[8192];
uint8_t data_Gln[1757];
uint8_t *dep_389;
uint32_t dep_390;
int32_t dep_304;
int16_t pcm_omw[8192];
uint8_t mapping_rbd[192];
int32_t *dep_200;
OpusMSEncoder* dep_199;
int16_t pcm_lLE[3840];
uint8_t data_unj[472320];
uint8_t mapping_WEq[3];
int32_t *dep_203;
OpusMSEncoder* dep_202;
int32_t dep_332;
uint32_t dep_327;
int32_t dep_335;
int32_t *dep_333;
OpusEncoder* dep_326;
int16_t pcm_Nln[2880];
uint8_t data_IAG[7380];
uint8_t *dep_204;
int16_t pcm_YrA[4320];
int32_t dep_107;
int32_t dep_103;
int32_t *dep_93;
OpusEncoder* dep_208;
int32_t *dep_104;
int16_t pcm_PWN[960];
uint8_t data_wWg[2000];
uint8_t *dep_211;
uint32_t dep_210;
int16_t pcm_vGp[2880];
int32_t *dep_158;
OpusDecoder* dep_99;
int16_t pcm_YoN[2880];
OpusEncoder* dep_212;
char **dep_151;
uint8_t data_jap_0[4096][2][4096];
uint8_t *data_jap_1[4096][2];
uint8_t **dep_105;
uint32_t dep_101;
int16_t pcm_sXe[960];
uint8_t data_XeV[2000];
uint8_t *dep_215;
uint32_t dep_214;
int16_t pcm_Fhw[480];
int32_t request_tQL[2];
int32_t dep_166;
OpusEncoder* dep_216;
int16_t pcm_JSz[8192];
int16_t *dep_122;
int16_t pcm_thA[160];
uint8_t data_AJX[1000];
uint8_t *dep_219;
uint32_t dep_218;
int16_t pcm_iJy[960];
int16_t pcm_hxO[1920];
uint8_t data_xjZ[1276];
uint8_t *dep_329;
float pcm_MYS[1920];
uint32_t dep_338;
OpusRepacketizer *dep_341;
uint8_t data_OcY[4096];
uint8_t *dep_342;
uint32_t dep_336;
uint8_t data_WgH[4096];
uint8_t *dep_343;
int32_t dep_348;
int32_t dep_352;


size_t buflen = 32; /* adaptable buffer length */
size_t nbufs = 8279; /* total number of buffers */
size_t ninp  = 18446744073709362189; /* total number of other input bytes */


/* function declarations (used by function pointers), if any */


// ------------------------------------------------------------------------------------------------
//
// Find the k-th permutation (in lexicographic order) in a sequence of n numbers,
// without calculating the k-1 permutations first. This is done in O(n^2) time.
//
// Function returns an array[n] that contains the indices of the k-th permutation.
//
static uint8_t *kperm(uint8_t n, uint64_t k) {
    uint64_t d = 0, factorial = FACTORIAL[n];
    uint8_t  c = 0, i, pool[32];
    uint8_t  *perm = new uint8_t[32];


    /* Because we're using 64-bit numbers, the larger factorial that can fit in, is 20! */
    assert( n <= 20 );

    for (i=0; i<n; ++i) pool[i] = i;                // initialize pool

    k = (k % factorial) + 1;                        // to get the correct results, 1 <= k <= n!
    factorial /= n;                                 // start from (n-1)!


    for (i=0; i<n-1; factorial/=(n-1 - i++)) {      // for all (but last) elements
        /* find d, r such that: k = d(n!) + r, subject to: d >= 0 and 0 < r <= n! */
        /* (classic division doesn't work here, so we use iterative subtractions) */

        for (d=0; k>(d+1)*factorial; ++d);          // k < n! so loop runs in O(n)
        k -= d * factorial;                         // calculate r

        perm[c++] = pool[d];

        for (uint8_t j=d; j<n-1; ++j) {             // remove d-th element from pool
            pool[j] = pool[j+1];
        }
        pool[n-1] = 0;                              // optional
    }

    perm[c++] = pool[0];                            // last element is trivial

    return perm;
}


// ------------------------------------------------------------------------------------------------
//
// The interface for "eating" bytes from the random input. 
//
// When a corpus is used and codec libraries are fuzzed, eating from the input needs special
// care. The beginning of the random input it's very likely to a valid frame or a buffer that
// can achieve a deep coverage. By using the first bytes for path selection and for variable
// fuzzing, we essentially destroy the frame.
//
// To fix this problem we split the input in two parts. When a buffer is being fuzzed, we eat
// bytes from the beginning of the input. Otherwise we eat from the end. Hence, we preserve the
// corpus and the frames that they may contain.
//
class EatData {
public:
    /* class constructor (no need for destructor) */
    EatData(const uint8_t *data, size_t size, size_t ninp) :
            data(data), size(size), delimiter(size-1 > ninp ? size-1 - ninp : 0), 
            bwctr(size-1), fwctr(0) { }

    /* eat (backwards) an integer between 1 and 8 bytes (for other input) */
    uint64_t eatIntBw(uint8_t k) {
        uint64_t num = 0;


        assert(k > 0 && k < 9);                     // make sure that size is valid

        if (bwctr - k < delimiter) {                // ensure that there're enough data

            cout << "eatIntBw(): All input has been eaten. This is a FuzzGen bug!\n";
            cout << "size = " << size << ", delimiter = " << delimiter
                 << ", bwctr = " << bwctr << ", k = " << (int)k << "\n";

            exit(-1);                               // abort

        }

        for (uint8_t i=0; i<k; ++i) {               // build the number (in big endian)
            num |= (uint64_t)data[bwctr - i] << (i << 3);
        }

        bwctr -= k;                                 // update counter
        return num;
    }


    /* eat (forward) an integer between 1 and 8 bytes (for buffers) */
    uint64_t eatIntFw(uint8_t k) {
        uint64_t num = 0;

        
        assert(k > 0 && k < 9);                     // make sure that size is valid

        if (fwctr + k > delimiter) {                // ensure that there're enough data

            cout << "eatIntFw(): All input has been eaten. This is a FuzzGen bug!\n";
            cout << "size = " << size << ", delimiter = " << delimiter
                 << ", fwctr = " << fwctr << ", k = " << (int)k << "\n";        

            exit(-1);                               // abort
        }

        for (uint8_t i=0; i<k; ++i) {               // build the number (in big endian)
            num |= (uint64_t)data[fwctr + i] << (i << 3);
        }

        fwctr += k;                                 // update counter
        return num;
    }


    /* abbervations for common sizes */
    inline uint8_t  eat1() { return (uint8_t) eatIntBw(1); }
    inline uint16_t eat2() { return (uint16_t)eatIntBw(2); }
    inline uint32_t eat4() { return (uint32_t)eatIntBw(4); }
    inline uint64_t eat8() { return eatIntBw(8); }


    /* abbervations for common sizes */
    inline uint8_t  buf_eat1() { return (uint8_t) eatIntFw(1); }
    inline uint16_t buf_eat2() { return (uint16_t)eatIntFw(2); }
    inline uint32_t buf_eat4() { return (uint32_t)eatIntFw(4); }
    inline uint64_t buf_eat8() { return eatIntFw(8); }


    /* eat a buffer of arbitrary size (DEPRECATED) */
    inline const uint8_t *eatBuf(uint32_t k) {
        const uint8_t *buf = &data[bwctr];

        if (bwctr - k < delimiter) {                // ensure that there're enough data  

            cout << "eatBuf(): All input has been eaten. This is a FuzzGen bug!\n";

            exit(-1);                               // abort
        }

        bwctr -= k;                                 // update counter
        return buf;
    }


private:
    const uint8_t *data;                            // random data
    size_t        size;                             // and its size
    size_t        delimiter;                        // delimiter (between buffer and other data)
    uint32_t      bwctr, fwctr;                     // backward and forward counters
};


// ------------------------------------------------------------------------------------------------
//
// LibFuzzer's initialization routine.
//
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void) argc;
    (void) argv;

    cout << "[*] This fuzzer has been created by *FuzzGen*\n";

    return 0;
}


// ------------------------------------------------------------------------------------------------
//
// LibFuzzer's main processing routine.
//
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* min size needed for Eat() to work properly */
    if (size < 75501 || size > 33722381) return 0;

    /* all variables contain 3 random letters, so E cannot redefined */
    EatData E(data, size, ninp);

    buflen = (size - ninp) / nbufs - 1;             // find length of each buffer


    /* * * function pool #0 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(5, E.eatIntBw( NBYTES_FOR_FACTORIAL(5) ));
    
        // initializing argument 'data_ueg'
        for (uint64_t i_0=0; i_0<buflen; ++i_0) {
            data_ueg[i_0] = E.buf_eat1();
        }

        // Dependence family #85 Definition
        dep_85 = (uint8_t *)data_ueg;

        // initializing argument 'channels_bbD'
        int32_t channels_bbD_0 = 0;

        // Dependence family #270 Definition
        dep_270 = (int32_t )channels_bbD_0;

        // initializing argument 'streams_bQU'
        int32_t streams_bQU_0 = 0 /* WO */;
        int32_t *streams_bQU_1 = &streams_bQU_0;

        // initializing argument 'coupled_streams_ogg'
        int32_t coupled_streams_ogg_0 = 0 /* WO */;
        int32_t *coupled_streams_ogg_1 = &coupled_streams_ogg_0;

        // initializing argument 'mapping_xvu'
        uint8_t mapping_xvu_0 = 0 /* WO */;
        uint8_t *mapping_xvu_1 = &mapping_xvu_0;

        // initializing argument 'error_SZN'
        int32_t error_SZN_0 = E.eat4();
        int32_t *error_SZN_1 = &error_SZN_0;

        // Dependence family #191 Definition
        dep_191 = (int32_t *)error_SZN_1;

        // initializing argument 'error_HPW'
        int32_t error_HPW_0 = 0 /* WO */;
        int32_t *error_HPW_1 = &error_HPW_0;

        // Dependence family #1120 Definition
        dep_1120 = (int32_t *)error_HPW_1;
        // initializing argument 'error_kqq'
        int32_t error_kqq_0 = 0 /* WO */;
        int32_t *error_kqq_1 = &error_kqq_0;

        // Dependence family #494 Definition
        dep_494 = (int32_t *)error_kqq_1;
        auto s_BoA[] = {dep_1120, dep_494};


        for (int i=0; i<5; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_packet_get_bandwidth(dep_85); /* vertex #3 */
            }

            else if (perm[i] == 1) {
                dep_264 = opus_decoder_get_size(dep_270); /* vertex #0 */
            }

            else if (perm[i] == 2) {
                dep_190 = opus_multistream_surround_encoder_create(16000, 1, 1, streams_bQU_1, coupled_streams_ogg_1, mapping_xvu_1, 2048, dep_191); /* vertex #0 */
            }

            else if (perm[i] == 3) {
                dep_231 = opus_repacketizer_create(); /* vertex #0 */
            }

            else if (perm[i] == 4) {
                dep_1118 = opus_encoder_create(48000, 2, 2049, s_BoA[E.eat1() % 2]);
                dep_448 = dep_1118; /* vertex #0 */
            }

        }
    //}



    /* * * function pool #1 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(6, E.eatIntBw( NBYTES_FOR_FACTORIAL(6) ));
    
        // initializing argument 'Fs_Nbu'
        int32_t Fs_Nbu_0 = -8000;

        // Dependence family #273 Definition
        dep_273 = (int32_t )Fs_Nbu_0;
        // initializing argument 'error_maQ'
        int32_t error_maQ_0 = 0;
        int32_t *error_maQ_1 = &error_maQ_0;

        // Dependence family #271 Definition
        dep_271 = (int32_t *)error_maQ_1;

        // initializing argument 'mapping_iNm'
        for (uint64_t i_0=0; i_0<256; ++i_0) {
            mapping_iNm[i_0] = 1;
        }

        // Dependence family #442 Definition
        dep_442 = (uint8_t *)&mapping_iNm;
        // initializing argument 'error_OBV'
        int32_t *error_OBV_0 = dep_447;

        // Dependence family #464 Definition
        dep_464 = (int32_t *)error_OBV_0;


        for (int i=0; i<6; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_86 = opus_packet_get_nb_channels(dep_85); /* vertex #4 */
            }

            else if (perm[i] == 1) {
                dep_262 = opus_decoder_create(dep_273, dep_270, dep_271); /* vertex #1 */
            }

            else if (perm[i] == 2) {
                opus_multistream_encoder_ctl(dep_190, 4024, 3002); /* vertex #1 */
            }

            else if (perm[i] == 3) {
                opus_repacketizer_init(dep_231); /* vertex #1 */
            }

            else if (perm[i] == 4) {
                dep_449 = opus_multistream_encoder_create(8000, 2, 2, 0, (const uint8_t *)dep_442, -5, dep_464); /* vertex #1 */
            }

            else if (perm[i] == 5) {
                opus_encoder_ctl(dep_1118, 4002, 64000); /* vertex #1 */
            }

        }
    //}



    /* * * function pool #2 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(6, E.eatIntBw( NBYTES_FOR_FACTORIAL(6) ));
    
        // initializing argument 'error_HRu'
        int32_t error_HRu_0 = 0 /* WO */;
        int32_t *error_HRu_1 = &error_HRu_0;


        // initializing argument 'error_cLq'


        // initializing argument 'data_eqQ'
        for (uint64_t i_0=0; i_0<48; ++i_0) {
            for (uint64_t i_1=0; i_1<1500; ++i_1) {
                data_eqQ[i_0][i_1] = E.eat1();
            }
        }

        // initializing argument 'len_ZDS'
        for (uint64_t i_0=0; i_0<48; ++i_0) {
            len_ZDS[i_0] = 0 /* DEAD */;
        }



        for (int i=0; i<6; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_75 = opus_decoder_create(E.eat4(), dep_86, error_HRu_1); /* vertex #5 */
            }

            else if (perm[i] == 1) {
                dep_262 = opus_decoder_create(dep_273, dep_270, NULL); /* vertex #2 */
            }

            else if (perm[i] == 2) {
                opus_multistream_encoder_ctl(dep_190, 4006, 0); /* vertex #2 */
            }

            else if (perm[i] == 3) {
                dep_236 = opus_repacketizer_cat(dep_231, (const uint8_t *)&data_eqQ, (int32_t *)*&len_ZDS); /* vertex #2 */
            }

            else if (perm[i] == 4) {
                dep_449 = opus_multistream_encoder_create(8000, 0, 1, 0, (const uint8_t *)dep_442, 2048, dep_464); /* vertex #2 */
            }

            else if (perm[i] == 5) {
                dep_1119 = opus_decoder_create(48000, 2, dep_1120); /* vertex #2 */
            }

        }
    //}



    /* * * function pool #3 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(7, E.eatIntBw( NBYTES_FOR_FACTORIAL(7) ));
    
        auto s_gpn[] = {dep_450, dep_75};
        // initializing argument 'request_RvZ'
        int32_t request_RvZ_0 = 0 /* WO */;
        int32_t *request_RvZ_1 = &request_RvZ_0;

        // Dependence family #84 Definition
        dep_84 = (int32_t *)request_RvZ_1;
        auto s_Qbx[] = {dep_494, dep_84};

        // initializing argument 'data_Bgc'
        for (uint64_t i_0=0; i_0<32000; ++i_0) {
            data_Bgc[i_0] = 0 /* DEAD */;
        }

        // Dependence family #232 Definition
        dep_232 = (uint8_t *)&data_Bgc;

        // initializing argument 'pcm_Cnt'
        for (uint64_t i_0=0; i_0<1920; ++i_0) {
            pcm_Cnt[i_0] = 0 /* DEAD */;
        }

        // initializing argument 'data_FIa'
        for (uint64_t i_0=0; i_0<3828; ++i_0) {
            data_FIa[i_0] = 0 /* WO */;
        }

        // Dependence family #1116 Definition
        dep_1116 = (uint8_t *)&data_FIa;


        for (int i=0; i<7; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decoder_ctl(s_gpn[E.eat1() % 2], 4031, s_Qbx[E.eat1() % 2]); /* vertex #45 */
            }

            else if (perm[i] == 1) {
                opus_decoder_get_size(2); /* vertex #3 */
            }

            else if (perm[i] == 2) {
                opus_multistream_encoder_ctl(dep_190, 4020, 0); /* vertex #3 */
            }

            else if (perm[i] == 3) {
                dep_236 = opus_repacketizer_out(dep_231, (uint8_t *)dep_232, 32000); /* vertex #3 */
            }

            else if (perm[i] == 4) {
                opus_repacketizer_get_nb_frames(dep_231); /* vertex #4 */
            }

            else if (perm[i] == 5) {
                dep_449 = opus_multistream_encoder_create(44100, 2, 2, 0, (const uint8_t *)dep_442, 2048, dep_464); /* vertex #3 */
            }

            else if (perm[i] == 6) {
                dep_1117 = opus_encode(dep_1118, (const int16_t *)&pcm_Cnt, 960, (uint8_t *)dep_1116, 3828); /* vertex #3 */
            }

        }
    //}



    /* * * function pool #4 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(7, E.eatIntBw( NBYTES_FOR_FACTORIAL(7) ));
    
        // initializing argument 'data_nhz'

        // initializing argument 'len_Xew'
        int64_t len_Xew_0 = buflen;
        int64_t *len_Xew_1 = &len_Xew_0;

        // Dependence family #74 Definition
        dep_74 = (int64_t *)len_Xew_1;
        // initializing argument 'pcm_NCR'
        for (uint64_t i_0=0; i_0<buflen; ++i_0) {
            pcm_NCR[i_0] = E.buf_eat2();
        }

        // Dependence family #76 Definition
        dep_76 = (int16_t *)pcm_NCR;
        // initializing argument 'decode_fec_Hsn'
        int32_t decode_fec_Hsn_0 = v_SUc[E.eat1() % 2];

        // Dependence family #83 Definition
        dep_83 = (int32_t )decode_fec_Hsn_0;

        // initializing argument 'pcm_GBk'
        for (uint64_t i_0=0; i_0<buflen; ++i_0) {
            pcm_GBk[i_0] = E.buf_eat2();
        }

        // Dependence family #456 Definition
        dep_456 = (int16_t *)pcm_GBk;

        // initializing argument 'pcm_iAi'
        for (uint64_t i_0=0; i_0<11520; ++i_0) {
            pcm_iAi[i_0] = 0 /* WO */;
        }



        for (int i=0; i<7; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decode(dep_75, NULL, *dep_74, dep_76, *dep_84, dep_83); /* vertex #6 */
            }

            else if (perm[i] == 1) {
                opus_decoder_init(dep_262, dep_273, dep_270); /* vertex #4 */
            }

            else if (perm[i] == 2) {
                opus_multistream_encoder_ctl(dep_190, 4042, 1); /* vertex #4 */
            }

            else if (perm[i] == 3) {
                dep_236 = opus_repacketizer_out_range(dep_231, 0, E.eat4(), (uint8_t *)dep_232, 32000); /* vertex #5 */
            }

            else if (perm[i] == 4) {
                dep_449 = opus_multistream_encoder_create(8000, 2, 2, 3, (const uint8_t *)dep_442, 2048, dep_464); /* vertex #4 */
            }

            else if (perm[i] == 5) {
                dep_473 = opus_decode((OpusDecoder **)*dep_453, (uint8_t *)dep_458, *dep_494, dep_456, (int32_t *)*dep_494, E.eat4()); /* vertex #46 */
            }

            else if (perm[i] == 6) {
                opus_decode(dep_1119, (uint8_t *)dep_1116, dep_1117, (int16_t *)&pcm_iAi, 5760, 0); /* vertex #4 */
            }

        }
    //}



    /* * * function pool #5 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(6, E.eatIntBw( NBYTES_FOR_FACTORIAL(6) ));
    
        // initializing argument 'data_PTx'
        for (uint64_t i_0=0; i_0<buflen; ++i_0) {
            data_PTx[i_0] = E.buf_eat1();
        }



        for (int i=0; i<6; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decode(dep_75, data_PTx, *dep_74, dep_76, 5760, dep_83); /* vertex #1 */
            }

            else if (perm[i] == 1) {
                dep_262 = opus_decoder_create(48000, 2, dep_271); /* vertex #5 */
            }

            else if (perm[i] == 2) {
                opus_multistream_encoder_ctl(dep_190, 4046, 0); /* vertex #5 */
            }

            else if (perm[i] == 3) {
                dep_449 = opus_multistream_encoder_create(8000, 2, -1, 0, (const uint8_t *)dep_442, 2048, dep_464); /* vertex #5 */
            }

            else if (perm[i] == 4) {
                dep_473 = opus_decode((OpusDecoder **)*dep_453, (uint8_t *)dep_458, E.eat4(), dep_456, 5760, E.eat4()); /* vertex #47 */
            }

            else if (perm[i] == 5) {
                opus_encoder_destroy(dep_1118); /* vertex #5 */
            }

        }
    //}



    /* * * function pool #6 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(4, E.eatIntBw( NBYTES_FOR_FACTORIAL(4) ));
    
        // initializing argument 'request_Sfs'



        for (int i=0; i<4; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decoder_ctl(dep_262, 4031, NULL); /* vertex #6 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4016, 0); /* vertex #6 */
            }

            else if (perm[i] == 2) {
                dep_449 = opus_multistream_encoder_create(8000, 256, 2, 0, (const uint8_t *)dep_442, 2048, dep_464); /* vertex #6 */
            }

            else if (perm[i] == 3) {
                opus_decoder_destroy(dep_1119); /* vertex #6 */
            }

        }
    //}



    /* * * function pool #7 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'request_MUy'



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decoder_ctl(dep_262, 4031, NULL); /* vertex #7 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4010, 0); /* vertex #7 */
            }

            else if (perm[i] == 2) {
                dep_449 = opus_multistream_encoder_create(8000, 2, 2, 0, (const uint8_t *)dep_442, 2049, dep_494); /* vertex #7 */
            }

        }
    //}



    /* * * function pool #8 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decoder_ctl(dep_262, -5); /* vertex #8 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4004, 1101); /* vertex #8 */
            }

            else if (perm[i] == 2) {
                opus_multistream_encoder_ctl(dep_449, 4003, dep_494); /* vertex #8 */
            }

        }
    //}



    /* * * function pool #9 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'request_duj'



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decoder_ctl(dep_262, 4009, NULL); /* vertex #9 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4008, -1000); /* vertex #9 */
            }

            else if (perm[i] == 2) {
                opus_multistream_encoder_ctl(dep_449, 4037, dep_494); /* vertex #9 */
            }

        }
    //}



    /* * * function pool #10 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'request_ioT'
        OpusEncoder request_ioT_0;



        for (uint64_t i_0=0; i_0<100; ++i_0) {
        }



        OpusEncoder *request_ioT_1 = &request_ioT_0;
        OpusEncoder **request_ioT_2 = &request_ioT_1;

        // Dependence family #465 Definition
        dep_465 = (OpusEncoder **)request_ioT_2;


        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decoder_ctl(dep_262, 4009, &dep_264); /* vertex #10 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4036, 8); /* vertex #10 */
            }

            else if (perm[i] == 2) {
                opus_multistream_encoder_ctl(dep_449, 5120, 1, dep_465); /* vertex #10 */
            }

        }
    //}



    /* * * function pool #11 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'request_xnW'



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decoder_ctl(dep_262, 4029, NULL); /* vertex #11 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4012, 0); /* vertex #11 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(*dep_465, 4037, dep_494); /* vertex #11 */
            }

        }
    //}



    /* * * function pool #12 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decoder_ctl(dep_262, 4029, &dep_264); /* vertex #12 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4014, 0); /* vertex #12 */
            }

            else if (perm[i] == 2) {
                opus_multistream_encoder_ctl(dep_449, 5120, 2, dep_465); /* vertex #12 */
            }

        }
    //}



    /* * * function pool #13 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'request_Ggd'

        // Dependence family #272 Definition
        dep_272 = (char **)NULL;

        // initializing argument 'error_JbC'
        int32_t error_JbC_0 = 0 /* WO */;
        int32_t *error_JbC_1 = &error_JbC_0;

        auto s_wjw[] = {error_JbC_1, dep_494};


        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decoder_ctl(dep_262, 4033, *dep_272); /* vertex #13 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4002, -1000); /* vertex #13 */
            }

            else if (perm[i] == 2) {
                dep_527 = opus_decoder_create(48000, 2, s_wjw[E.eat1() % 2]);
                dep_450 = dep_527; /* vertex #0 */
            }

        }
    //}



    /* * * function pool #14 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(4, E.eatIntBw( NBYTES_FOR_FACTORIAL(4) ));
    
        // initializing argument 'pcm_XwM'
        for (uint64_t i_0=0; i_0<320; ++i_0) {
            pcm_XwM[i_0] = v_LQb[E.eat1() % 57];
        }

        // initializing argument 'data_TtD'
        for (uint64_t i_0=0; i_0<2460; ++i_0) {
            data_TtD[i_0] = 0 /* WO */;
        }

        // Dependence family #192 Definition
        dep_192 = (uint8_t *)&data_TtD;

        // initializing argument 'data_zbC'
        for (uint64_t i_0=0; i_0<buflen; ++i_0) {
            data_zbC[i_0] = -1;
        }

        // initializing argument 'pcm_FSn'
        for (uint64_t i_0=0; i_0<buflen; ++i_0) {
            pcm_FSn[i_0] = E.buf_eat2();
        }



        for (int i=0; i<4; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decoder_ctl(dep_262, 4033, &dep_264); /* vertex #14 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encode(dep_190, (const int16_t *)&pcm_XwM, 320, (uint8_t *)dep_192, 2460); /* vertex #14 */
            }

            else if (perm[i] == 2) {
                dep_451 = opus_multistream_decoder_create(48000, 2, 2, 0, (const uint8_t *)dep_442, dep_494); /* vertex #14 */
            }

            else if (perm[i] == 3) {
                opus_decode(dep_527, data_zbC, 16909318, pcm_FSn, 5760, 0); /* vertex #1 */
            }

        }
    //}



    /* * * function pool #15 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(4, E.eatIntBw( NBYTES_FOR_FACTORIAL(4) ));
    
        // initializing argument 'data_VkV'
        for (uint64_t i_0=0; i_0<1276; ++i_0) {
            data_VkV[i_0] = -4;
        }

        // Dependence family #267 Definition
        dep_267 = (uint8_t *)&data_VkV;
        // initializing argument 'pcm_Czz'
        for (uint64_t i_0=0; i_0<1920; ++i_0) {
            pcm_Czz[i_0] = 0 /* WO */;
        }

        // Dependence family #269 Definition
        dep_269 = (int16_t *)&pcm_Czz;


        for (int i=0; i<4; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decode(dep_262, (const uint8_t *)dep_267, 3, (int16_t *)dep_269, 960, 0); /* vertex #15 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4024, 3002); /* vertex #15 */
            }

            else if (perm[i] == 2) {
                dep_452 = opus_multistream_decoder_create(48000, 3, 2, 0, (const uint8_t *)dep_442, dep_494); /* vertex #15 */
            }

            else if (perm[i] == 3) {
                opus_decoder_destroy(dep_527); /* vertex #2 */
            }

        }
    //}



    /* * * function pool #16 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decoder_ctl(dep_262, 4033, &dep_264); /* vertex #16 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4006, 0); /* vertex #16 */
            }

            else if (perm[i] == 2) {
                opus_decoder_get_size(2); /* vertex #16 */
            }

        }
    //}



    /* * * function pool #17 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decode(dep_262, (const uint8_t *)dep_267, 1, (int16_t *)dep_269, 960, 0); /* vertex #17 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4020, 1); /* vertex #17 */
            }

            else if (perm[i] == 2) {
                opus_decoder_get_size(2); /* vertex #90 */
            }

        }
    //}



    /* * * function pool #18 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decoder_ctl(dep_262, 4033, &dep_264); /* vertex #18 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4042, 1); /* vertex #18 */
            }

            else if (perm[i] == 2) {
                dep_453 = opus_decoder_create(48000, 1, dep_494); /* vertex #91 */
            }

        }
    //}



    /* * * function pool #19 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'request_Jmj'



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decoder_ctl(dep_262, 4039, NULL); /* vertex #19 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4046, 0); /* vertex #19 */
            }

            else if (perm[i] == 2) {
                dep_453 = opus_decoder_create(24000, 2, dep_494); /* vertex #92 */
            }

        }
    //}



    /* * * function pool #20 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decoder_ctl(dep_262, 4039, &dep_264); /* vertex #20 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4016, 1); /* vertex #20 */
            }

            else if (perm[i] == 2) {
                dep_453 = opus_decoder_create(24000, 1, dep_494); /* vertex #93 */
            }

        }
    //}



    /* * * function pool #21 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decoder_ctl(dep_262, 4045, &dep_264); /* vertex #21 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4010, 10); /* vertex #21 */
            }

            else if (perm[i] == 2) {
                dep_453 = opus_decoder_create(16000, 2, dep_494); /* vertex #94 */
            }

        }
    //}



    /* * * function pool #22 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decoder_ctl(dep_262, 4045, *dep_272); /* vertex #22 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4004, 1105); /* vertex #22 */
            }

            else if (perm[i] == 2) {
                dep_453 = opus_decoder_create(16000, 1, dep_494); /* vertex #95 */
            }

        }
    //}



    /* * * function pool #23 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decoder_ctl(dep_262, 4034, -32769); /* vertex #23 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4008, 1105); /* vertex #23 */
            }

            else if (perm[i] == 2) {
                dep_453 = opus_decoder_create(12000, 2, dep_494); /* vertex #96 */
            }

        }
    //}



    /* * * function pool #24 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decoder_ctl(dep_262, 4034, 32768); /* vertex #24 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4036, 18); /* vertex #24 */
            }

            else if (perm[i] == 2) {
                dep_453 = opus_decoder_create(12000, 1, dep_494); /* vertex #97 */
            }

        }
    //}



    /* * * function pool #25 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decoder_ctl(dep_262, 4034, -15); /* vertex #25 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4012, 1); /* vertex #25 */
            }

            else if (perm[i] == 2) {
                dep_453 = opus_decoder_create(8000, 2, dep_494); /* vertex #98 */
            }

        }
    //}



    /* * * function pool #26 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decoder_ctl(dep_262, 4045, &dep_264); /* vertex #26 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4014, 90); /* vertex #26 */
            }

            else if (perm[i] == 2) {
                dep_453 = opus_decoder_create(8000, 1, dep_494); /* vertex #99 */
            }

        }
    //}



    /* * * function pool #27 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decoder_get_size(2); /* vertex #27 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4002, 280130); /* vertex #27 */
            }

            else if (perm[i] == 2) {
                opus_encoder_get_size(2); /* vertex #17 */
            }

        }
    //}



    /* * * function pool #28 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'pcm_VXw'
        for (uint64_t i_0=0; i_0<160; ++i_0) {
            pcm_VXw[i_0] = v_IUV[E.eat1() % 3];
        }



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decoder_get_size(2); /* vertex #50 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encode(dep_190, (const int16_t *)&pcm_VXw, 160, (uint8_t *)dep_192, 2460); /* vertex #28 */
            }

            else if (perm[i] == 2) {
                opus_encoder_get_size(2); /* vertex #100 */
            }

        }
    //}



    /* * * function pool #29 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decoder_ctl(dep_262, 4028); /* vertex #51 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4024, 3002); /* vertex #29 */
            }

            else if (perm[i] == 2) {
                opus_encoder_get_size(2); /* vertex #101 */
            }

        }
    //}



    /* * * function pool #30 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decoder_get_size(2); /* vertex #28 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4006, 0); /* vertex #30 */
            }

            else if (perm[i] == 2) {
                opus_encoder_destroy(dep_448); /* vertex #102 */
            }

        }
    //}



    /* * * function pool #31 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decoder_get_nb_samples(dep_262, (const uint8_t *)dep_267, 1); /* vertex #29 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4020, 1); /* vertex #31 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_448, 4008, -1000); /* vertex #18 */
            }

        }
    //}



    /* * * function pool #32 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_packet_get_nb_samples((const uint8_t *)dep_267, 1, 48000); /* vertex #30 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4042, 1); /* vertex #32 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_448, 11002, -2); /* vertex #19 */
            }

        }
    //}



    /* * * function pool #33 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'pcm_kTG'
        for (uint64_t i_0=0; i_0<buflen; ++i_0) {
            pcm_kTG[i_0] = E.buf_eat2();
        }

        // Dependence family #454 Definition
        dep_454 = (int16_t *)pcm_kTG;
        // initializing argument 'data_KVC'
        for (uint64_t i_0=0; i_0<1757; ++i_0) {
            data_KVC[i_0] = 0 /* WO */;
        }

        // Dependence family #458 Definition
        dep_458 = (uint8_t *)&data_KVC;


        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_packet_get_nb_samples((const uint8_t *)dep_267, 1, 96000); /* vertex #31 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4046, 0); /* vertex #33 */
            }

            else if (perm[i] == 2) {
                opus_encode(dep_448, dep_454, 500, (uint8_t *)dep_458, 1500); /* vertex #20 */
            }

        }
    //}



    /* * * function pool #34 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_packet_get_nb_samples((const uint8_t *)dep_267, 1, 32000); /* vertex #32 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4016, 1); /* vertex #34 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_448, 4006, *dep_494); /* vertex #21 */
            }

        }
    //}



    /* * * function pool #35 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_packet_get_nb_samples((const uint8_t *)dep_267, 1, 8000); /* vertex #33 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4010, 10); /* vertex #35 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_448, 4020, *dep_494); /* vertex #22 */
            }

        }
    //}



    /* * * function pool #36 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_packet_get_nb_samples((const uint8_t *)dep_267, 1, 24000); /* vertex #34 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4004, 1105); /* vertex #36 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_448, 4020, *dep_494); /* vertex #23 */
            }

        }
    //}



    /* * * function pool #37 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_packet_get_nb_samples((const uint8_t *)dep_267, 0, 24000); /* vertex #35 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4008, 1105); /* vertex #37 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_448, 4012, *dep_494); /* vertex #24 */
            }

        }
    //}



    /* * * function pool #38 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(4, E.eatIntBw( NBYTES_FOR_FACTORIAL(4) ));
    

        for (int i=0; i<4; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_packet_get_nb_samples((const uint8_t *)dep_267, 2, 48000); /* vertex #36 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4036, 18); /* vertex #38 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_448, 4028); /* vertex #25 */
            }

            else if (perm[i] == 3) {
                opus_encoder_ctl(dep_448, 11002, -1000); /* vertex #48 */
            }

        }
    //}



    /* * * function pool #39 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(4, E.eatIntBw( NBYTES_FOR_FACTORIAL(4) ));
    

        for (int i=0; i<4; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decoder_get_nb_samples(dep_262, (const uint8_t *)dep_267, 2); /* vertex #37 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4012, 1); /* vertex #39 */
            }

            else if (perm[i] == 2) {
                opus_decoder_ctl(dep_450, 4028); /* vertex #26 */
            }

            else if (perm[i] == 3) {
                opus_encoder_ctl(dep_448, 4022, -1000); /* vertex #49 */
            }

        }
    //}



    /* * * function pool #40 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(4, E.eatIntBw( NBYTES_FOR_FACTORIAL(4) ));
    

        for (int i=0; i<4; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_packet_get_nb_frames((const uint8_t *)dep_267, 0); /* vertex #38 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4014, 90); /* vertex #40 */
            }

            else if (perm[i] == 2) {
                opus_decoder_ctl((OpusDecoder **)*dep_453, 4028); /* vertex #27 */
            }

            else if (perm[i] == 3) {
                opus_encoder_ctl(dep_448, 4012, 0); /* vertex #50 */
            }

        }
    //}



    /* * * function pool #41 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(4, E.eatIntBw( NBYTES_FOR_FACTORIAL(4) ));
    

        for (int i=0; i<4; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_packet_get_nb_frames(dep_267, 1); /* vertex #39 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4002, 280130); /* vertex #41 */
            }

            else if (perm[i] == 2) {
                opus_decoder_ctl((OpusDecoder **)*dep_453, 4028); /* vertex #28 */
            }

            else if (perm[i] == 3) {
                opus_encoder_ctl(dep_448, 4016, 0); /* vertex #51 */
            }

        }
    //}



    /* * * function pool #42 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(4, E.eatIntBw( NBYTES_FOR_FACTORIAL(4) ));
    
        // initializing argument 'pcm_Hth'
        for (uint64_t i_0=0; i_0<160; ++i_0) {
            pcm_Hth[i_0] = v_LFw[E.eat1() % 2];
        }



        for (int i=0; i<4; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_packet_get_nb_frames(dep_267, 2); /* vertex #40 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encode(dep_190, (const int16_t *)&pcm_Hth, 160, (uint8_t *)dep_192, 2460); /* vertex #42 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_448, 4010, *dep_494); /* vertex #29 */
            }

            else if (perm[i] == 3) {
                opus_multistream_encoder_ctl(dep_449, 4006, *dep_494); /* vertex #52 */
            }

        }
    //}



    /* * * function pool #43 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(4, E.eatIntBw( NBYTES_FOR_FACTORIAL(4) ));
    

        for (int i=0; i<4; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_packet_get_bandwidth(dep_267); /* vertex #41 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4024, 3002); /* vertex #43 */
            }

            else if (perm[i] == 2) {
                opus_decoder_ctl(dep_450, 4028); /* vertex #30 */
            }

            else if (perm[i] == 3) {
                opus_multistream_encoder_ctl(dep_449, 4020, *dep_494); /* vertex #53 */
            }

        }
    //}



    /* * * function pool #44 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(4, E.eatIntBw( NBYTES_FOR_FACTORIAL(4) ));
    

        for (int i=0; i<4; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_packet_get_samples_per_frame(dep_267, 0); /* vertex #42 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4006, 0); /* vertex #44 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_448, 4012, *dep_494); /* vertex #31 */
            }

            else if (perm[i] == 3) {
                opus_multistream_encoder_ctl(dep_449, 4020, *dep_494); /* vertex #54 */
            }

        }
    //}



    /* * * function pool #45 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(4, E.eatIntBw( NBYTES_FOR_FACTORIAL(4) ));
    
        // initializing argument 'a_pPa'



        for (int i=0; i<4; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decode(dep_262, dep_267, 51, (int16_t *)dep_269, 960, 0); /* vertex #43 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4020, 1); /* vertex #45 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_448, 11002, ); /* vertex #32 */
            }

            else if (perm[i] == 3) {
                opus_multistream_encoder_ctl(dep_449, 4012, *dep_494); /* vertex #55 */
            }

        }
    //}



    /* * * function pool #46 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(4, E.eatIntBw( NBYTES_FOR_FACTORIAL(4) ));
    
        // initializing argument 'a_isx'


        // initializing argument 'a_swS'



        for (int i=0; i<4; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decode(dep_262, dep_267, -1, (int16_t *)dep_269, 960, 0); /* vertex #44 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4042, 1); /* vertex #46 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_448, 4016, ); /* vertex #33 */
            }

            else if (perm[i] == 3) {
                opus_multistream_encoder_ctl(dep_449, 4012, ); /* vertex #56 */
            }

        }
    //}



    /* * * function pool #47 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(4, E.eatIntBw( NBYTES_FOR_FACTORIAL(4) ));
    
        // initializing argument 'a_SzT'



        for (int i=0; i<4; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decode(dep_262, dep_267, 3, (int16_t *)dep_269, 60, 0); /* vertex #45 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4046, 0); /* vertex #47 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_448, 4002, *dep_494); /* vertex #34 */
            }

            else if (perm[i] == 3) {
                opus_multistream_encoder_ctl(dep_449, 11002, ); /* vertex #57 */
            }

        }
    //}



    /* * * function pool #48 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(4, E.eatIntBw( NBYTES_FOR_FACTORIAL(4) ));
    
        // initializing argument 'a_eWe'


        // initializing argument 'a_YCq'



        for (int i=0; i<4; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decode(dep_262, dep_267, 3, (int16_t *)dep_269, 480, 0); /* vertex #46 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4016, 1); /* vertex #48 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_448, 4022, ); /* vertex #35 */
            }

            else if (perm[i] == 3) {
                opus_multistream_encoder_ctl(dep_449, 4016, ); /* vertex #58 */
            }

        }
    //}



    /* * * function pool #49 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(4, E.eatIntBw( NBYTES_FOR_FACTORIAL(4) ));
    
        // initializing argument 'a_LNO'



        for (int i=0; i<4; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decode(dep_262, dep_267, 3, (int16_t *)dep_269, 960, 0); /* vertex #47 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4010, 10); /* vertex #49 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_448, 4010, ); /* vertex #36 */
            }

            else if (perm[i] == 3) {
                opus_multistream_encoder_ctl(dep_449, 4002, *dep_494); /* vertex #59 */
            }

        }
    //}



    /* * * function pool #50 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(4, E.eatIntBw( NBYTES_FOR_FACTORIAL(4) ));
    
        // initializing argument 'pcm_GYp'
        for (uint64_t i_0=0; i_0<1920; ++i_0) {
            pcm_GYp[i_0] = 0 /* WO */;
        }


        // initializing argument 'a_QgA'



        for (int i=0; i<4; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decode_float(dep_262, dep_267, 3, (float *)&pcm_GYp, 960, 0); /* vertex #48 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4004, 1105); /* vertex #50 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_448, 4014, ); /* vertex #37 */
            }

            else if (perm[i] == 3) {
                opus_multistream_encoder_ctl(dep_449, 4043, dep_494); /* vertex #60 */
            }

        }
    //}



    /* * * function pool #51 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(4, E.eatIntBw( NBYTES_FOR_FACTORIAL(4) ));
    
        auto s_bZL[] = {dep_262, dep_75};

        // initializing argument 'a_eqe'



        for (int i=0; i<4; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decoder_destroy(s_bZL[E.eat1() % 2]); /* vertex #49 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4008, 1105); /* vertex #51 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_448, 4008, *dep_494); /* vertex #38 */
            }

            else if (perm[i] == 3) {
                opus_multistream_encoder_ctl(dep_449, 4042, ); /* vertex #61 */
            }

        }
    //}



    /* * * function pool #52 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(4, E.eatIntBw( NBYTES_FOR_FACTORIAL(4) ));
    
        // initializing argument 'a_Uiq'



        for (int i=0; i<4; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_287 = opus_multistream_decoder_get_size(-1, -1); /* vertex #52 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4036, 18); /* vertex #52 */
            }

            else if (perm[i] == 2) {
                opus_encode(dep_448, dep_454, (int32_t *)*dep_494, (uint8_t *)dep_458, 1500); /* vertex #39 */
            }

            else if (perm[i] == 3) {
                opus_multistream_encoder_ctl(dep_449, 4010, ); /* vertex #62 */
            }

        }
    //}



    /* * * function pool #53 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(4, E.eatIntBw( NBYTES_FOR_FACTORIAL(4) ));
    
        // initializing argument 'Fs_lgc'
        int32_t Fs_lgc_0 = -8000;

        // Dependence family #298 Definition
        dep_298 = (int32_t )Fs_lgc_0;
        // initializing argument 'mapping_PsK'
        for (uint64_t i_0=0; i_0<256; ++i_0) {
            mapping_PsK[i_0] = 0;
        }

        // Dependence family #291 Definition
        dep_291 = (uint8_t *)&mapping_PsK;
        // initializing argument 'error_whx'
        int32_t error_whx_0 = 0;
        int32_t *error_whx_1 = &error_whx_0;

        // Dependence family #297 Definition
        dep_297 = (int32_t *)error_whx_1;

        // initializing argument 'a_iVy'



        for (int i=0; i<4; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_285 = opus_multistream_decoder_create(dep_298, dep_287, 1, E.eat4(), (const uint8_t *)dep_291, dep_297); /* vertex #53 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4012, 1); /* vertex #53 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_448, 4031, dep_494); /* vertex #40 */
            }

            else if (perm[i] == 3) {
                opus_multistream_encoder_ctl(dep_449, 4014, ); /* vertex #63 */
            }

        }
    //}



    /* * * function pool #54 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(4, E.eatIntBw( NBYTES_FOR_FACTORIAL(4) ));
    
        // initializing argument 'error_FPB'



        for (int i=0; i<4; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_285 = opus_multistream_decoder_create(dep_298, dep_287, 1, E.eat4(), (const uint8_t *)dep_291, NULL); /* vertex #54 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4014, 90); /* vertex #54 */
            }

            else if (perm[i] == 2) {
                opus_packet_pad((uint8_t *)dep_458, *dep_494, E.eat4()); /* vertex #41 */
            }

            else if (perm[i] == 3) {
                opus_multistream_encoder_ctl(dep_449, 4028); /* vertex #64 */
            }

        }
    //}



    /* * * function pool #55 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(4, E.eatIntBw( NBYTES_FOR_FACTORIAL(4) ));
    

        for (int i=0; i<4; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_multistream_decoder_get_size(1, 1); /* vertex #55 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4002, 280130); /* vertex #55 */
            }

            else if (perm[i] == 2) {
                opus_packet_pad((uint8_t *)dep_458, *dep_494, E.eat4()); /* vertex #42 */
            }

            else if (perm[i] == 3) {
                opus_multistream_decoder_ctl(dep_451, 4028); /* vertex #65 */
            }

        }
    //}



    /* * * function pool #56 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(4, E.eatIntBw( NBYTES_FOR_FACTORIAL(4) ));
    
        // initializing argument 'pcm_qom'
        for (uint64_t i_0=0; i_0<160; ++i_0) {
            pcm_qom[i_0] = v_Qam[E.eat1() % 2];
        }



        for (int i=0; i<4; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_multistream_decoder_init(dep_285, dep_298, dep_287, 1, E.eat4(), (const uint8_t *)dep_291); /* vertex #56 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encode(dep_190, (const int16_t *)&pcm_qom, 160, (uint8_t *)dep_192, 2460); /* vertex #56 */
            }

            else if (perm[i] == 2) {
                opus_packet_unpad((uint8_t *)dep_458, *dep_494); /* vertex #43 */
            }

            else if (perm[i] == 3) {
                opus_multistream_decoder_ctl(dep_452, 4028); /* vertex #66 */
            }

        }
    //}



    /* * * function pool #57 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(4, E.eatIntBw( NBYTES_FOR_FACTORIAL(4) ));
    
        // initializing argument 'pcm_dGR'
        for (uint64_t i_0=0; i_0<buflen; ++i_0) {
            pcm_dGR[i_0] = E.buf_eat2();
        }

        // Dependence family #455 Definition
        dep_455 = (int16_t *)pcm_dGR;


        for (int i=0; i<4; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_285 = opus_multistream_decoder_create(48000, 2, 1, 0, (const uint8_t *)dep_291, dep_297); /* vertex #57 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4024, 3002); /* vertex #57 */
            }

            else if (perm[i] == 2) {
                dep_473 = opus_decode(dep_450, (uint8_t *)dep_458, *dep_494, dep_455, 5760, 0); /* vertex #44 */
            }

            else if (perm[i] == 3) {
                opus_multistream_decoder_ctl(dep_452, 4028); /* vertex #67 */
            }

        }
    //}



    /* * * function pool #58 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_285 = opus_multistream_decoder_create(48000, 2, 1, 0, (const uint8_t *)dep_291, dep_297); /* vertex #58 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4006, 0); /* vertex #58 */
            }

            else if (perm[i] == 2) {
                opus_multistream_encode(dep_449, dep_454, (int32_t *)*dep_494, (uint8_t *)dep_458, 1500); /* vertex #68 */
            }

        }
    //}



    /* * * function pool #59 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_multistream_decoder_destroy(dep_285); /* vertex #59 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4020, 1); /* vertex #59 */
            }

            else if (perm[i] == 2) {
                opus_multistream_encoder_ctl(dep_449, 4031, dep_494); /* vertex #69 */
            }

        }
    //}



    /* * * function pool #60 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_285 = opus_multistream_decoder_create(48000, 1, 4, 1, (const uint8_t *)dep_291, dep_297); /* vertex #96 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4042, 1); /* vertex #60 */
            }

            else if (perm[i] == 2) {
                opus_multistream_packet_pad((uint8_t *)dep_458, *dep_494, E.eat4(), 2); /* vertex #70 */
            }

        }
    //}



    /* * * function pool #61 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_multistream_decoder_init(dep_285, 48000, 1, 0, 0, (const uint8_t *)dep_291); /* vertex #60 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4046, 0); /* vertex #61 */
            }

            else if (perm[i] == 2) {
                opus_multistream_packet_pad((uint8_t *)dep_458, *dep_494, E.eat4(), 2); /* vertex #71 */
            }

        }
    //}



    /* * * function pool #62 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_multistream_decoder_init(dep_285, 48000, 1, 1, -1, (const uint8_t *)dep_291); /* vertex #61 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4016, 1); /* vertex #62 */
            }

            else if (perm[i] == 2) {
                opus_multistream_packet_unpad((uint8_t *)dep_458, *dep_494, 2); /* vertex #72 */
            }

        }
    //}



    /* * * function pool #63 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_multistream_decoder_destroy(dep_285); /* vertex #62 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4010, 10); /* vertex #63 */
            }

            else if (perm[i] == 2) {
                dep_481 = opus_multistream_decode(dep_451, (uint8_t *)dep_458, *dep_494, dep_456, 5760, 0); /* vertex #73 */
            }

        }
    //}



    /* * * function pool #64 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_285 = opus_multistream_decoder_create(48000, 2, 1, 1, (const uint8_t *)dep_291, dep_297); /* vertex #97 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4004, 1105); /* vertex #64 */
            }

            else if (perm[i] == 2) {
                opus_multistream_decoder_ctl(dep_451, 4031, dep_494); /* vertex #74 */
            }

        }
    //}



    /* * * function pool #65 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_multistream_decoder_destroy(dep_285); /* vertex #63 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4008, 1105); /* vertex #65 */
            }

            else if (perm[i] == 2) {
                dep_481 = opus_multistream_decode(dep_452, (uint8_t *)dep_458, E.eat4(), dep_456, E.eat4(), E.eat4()); /* vertex #75 */
            }

        }
    //}



    /* * * function pool #66 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'request_oFm'
        int32_t request_oFm_0 = 0;
        int32_t *request_oFm_1 = &request_oFm_0;



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_285 = opus_multistream_decoder_create(48000, 255, 255, 1, (const uint8_t *)dep_291, dep_297); /* vertex #98 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4036, 18); /* vertex #66 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_448, 4002, *request_oFm_1); /* vertex #76 */
            }

        }
    //}



    /* * * function pool #67 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_285 = opus_multistream_decoder_create(48000, -1, 1, 1, (const uint8_t *)dep_291, dep_297); /* vertex #64 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4012, 1); /* vertex #67 */
            }

            else if (perm[i] == 2) {
                opus_encode(dep_448, dep_454, (char *)*dep_494, (uint8_t *)dep_458, 1500); /* vertex #103 */
            }

        }
    //}



    /* * * function pool #68 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_285 = opus_multistream_decoder_create(48000, 0, 1, 1, (const uint8_t *)dep_291, dep_297); /* vertex #65 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4014, 90); /* vertex #68 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_448, 4031, dep_494); /* vertex #77 */
            }

        }
    //}



    /* * * function pool #69 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_285 = opus_multistream_decoder_create(48000, 1, -1, 2, (const uint8_t *)dep_291, dep_297); /* vertex #66 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4002, 280130); /* vertex #69 */
            }

            else if (perm[i] == 2) {
                dep_493 = opus_decode(dep_450, (uint8_t *)dep_458, *dep_494, dep_455, 5760, 0); /* vertex #104 */
            }

        }
    //}



    /* * * function pool #70 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'pcm_pZH'
        for (uint64_t i_0=0; i_0<160; ++i_0) {
            pcm_pZH[i_0] = v_wnL[E.eat1() % 11];
        }



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_285 = opus_multistream_decoder_create(48000, 1, -1, -1, (const uint8_t *)dep_291, dep_297); /* vertex #67 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encode(dep_190, (const int16_t *)&pcm_pZH, 160, (uint8_t *)dep_192, 2460); /* vertex #70 */
            }

            else if (perm[i] == 2) {
                opus_decoder_ctl(dep_450, 4031, dep_494); /* vertex #78 */
            }

        }
    //}



    /* * * function pool #71 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'out_toc_jZy'
        uint8_t out_toc_jZy_0 = 0 /* WO */;
        uint8_t *out_toc_jZy_1 = &out_toc_jZy_0;

        // initializing argument 'frames_quV'
        for (uint64_t i_0=0; i_0<48; ++i_0) {
            frames_quV_0[i_0] = 0 /* WO */;
            frames_quV_1[i_0] = &frames_quV_0[i_0];
        }

        // initializing argument 'size_Xxq'
        for (uint64_t i_0=0; i_0<48; ++i_0) {
            size_Xxq[i_0] = 0 /* WO */;
        }

        // initializing argument 'payload_offset_upO'
        int32_t payload_offset_upO_0 = 0 /* WO */;
        int32_t *payload_offset_upO_1 = &payload_offset_upO_0;



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_285 = opus_multistream_decoder_create(48000, 256, 255, 1, (const uint8_t *)dep_291, dep_297); /* vertex #68 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4024, 3001); /* vertex #71 */
            }

            else if (perm[i] == 2) {
                opus_packet_parse((uint8_t *)dep_458, *dep_494, out_toc_jZy_1, (const uint8_t **)&frames_quV_1, (int16_t *)&size_Xxq, payload_offset_upO_1); /* vertex #79 */
            }

        }
    //}



    /* * * function pool #72 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'data_iPr'
        uint8_t data_iPr_0 = E.eat1();
        uint8_t *data_iPr_1 = &data_iPr_0;



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_285 = opus_multistream_decoder_create(48000, 256, 255, 0, (const uint8_t *)dep_291, dep_297); /* vertex #69 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4006, 0); /* vertex #72 */
            }

            else if (perm[i] == 2) {
                dep_493 = opus_decode((OpusDecoder **)*dep_453, data_iPr_1, *dep_494, dep_456, 5760, 0); /* vertex #80 */
            }

        }
    //}



    /* * * function pool #73 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_285 = opus_multistream_decoder_create(48000, 3, 2, 0, (const uint8_t *)dep_291, dep_297); /* vertex #70 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4020, 1); /* vertex #73 */
            }

            else if (perm[i] == 2) {
                opus_decoder_ctl((OpusDecoder **)*dep_453, 4031, dep_494); /* vertex #81 */
            }

        }
    //}



    /* * * function pool #74 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'data_ybe'
        uint8_t data_ybe_0 = E.eat1();
        uint8_t *data_ybe_1 = &data_ybe_0;



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_285 = opus_multistream_decoder_create(48000, 3, 2, 1, (const uint8_t *)dep_291, dep_297); /* vertex #71 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4042, 1); /* vertex #74 */
            }

            else if (perm[i] == 2) {
                dep_493 = opus_decode((OpusDecoder **)*dep_453, data_ybe_1, *dep_494, dep_456, 5760, 0); /* vertex #82 */
            }

        }
    //}



    /* * * function pool #75 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_multistream_decoder_destroy(dep_285); /* vertex #72 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4046, 1); /* vertex #75 */
            }

            else if (perm[i] == 2) {
                opus_decoder_ctl((OpusDecoder **)*dep_453, 4031, dep_494); /* vertex #83 */
            }

        }
    //}



    /* * * function pool #76 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_285 = opus_multistream_decoder_create(48001, 5, 4, 1, (const uint8_t *)dep_291, dep_297); /* vertex #100 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4016, 1); /* vertex #76 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_448, 4028); /* vertex #84 */
            }

        }
    //}



    /* * * function pool #77 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_285 = opus_multistream_decoder_create(48000, 4, 2, 1, (const uint8_t *)dep_291, dep_297); /* vertex #73 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4010, 0); /* vertex #77 */
            }

            else if (perm[i] == 2) {
                opus_encoder_destroy(dep_448); /* vertex #85 */
            }

        }
    //}



    /* * * function pool #78 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_multistream_decoder_ctl(dep_285, 4031, &dep_287); /* vertex #74 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4004, 1101); /* vertex #78 */
            }

            else if (perm[i] == 2) {
                opus_multistream_encoder_ctl(dep_449, 4028); /* vertex #105 */
            }

        }
    //}



    /* * * function pool #79 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'request_dAO'

        // Dependence family #286 Definition
        dep_286 = (char **)NULL;


        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_multistream_decoder_ctl(dep_285, 5122, -1, dep_286); /* vertex #75 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4008, -1000); /* vertex #79 */
            }

            else if (perm[i] == 2) {
                opus_multistream_encoder_destroy(dep_449); /* vertex #86 */
            }

        }
    //}



    /* * * function pool #80 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_multistream_decoder_ctl(dep_285, 5122, 1, dep_286); /* vertex #76 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4036, 12); /* vertex #80 */
            }

            else if (perm[i] == 2) {
                opus_decoder_ctl(dep_450, 4028); /* vertex #106 */
            }

        }
    //}



    /* * * function pool #81 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_multistream_decoder_ctl(dep_285, 5122, 2, dep_286); /* vertex #77 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4012, 0); /* vertex #81 */
            }

            else if (perm[i] == 2) {
                opus_decoder_destroy(dep_450); /* vertex #87 */
            }

        }
    //}



    /* * * function pool #82 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_multistream_decoder_ctl(dep_285, 5122, 0, dep_286); /* vertex #78 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4014, 41); /* vertex #82 */
            }

            else if (perm[i] == 2) {
                opus_multistream_decoder_ctl(dep_451, 4028); /* vertex #107 */
            }

        }
    //}



    /* * * function pool #83 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'request_pbt'
        OpusDecoder request_pbt_0;


        OpusDecoder *request_pbt_1 = &request_pbt_0;
        OpusDecoder **request_pbt_2 = &request_pbt_1;

        // Dependence family #300 Definition
        dep_300 = (OpusDecoder **)request_pbt_2;


        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_multistream_decoder_ctl(dep_285, 5122, dep_287, dep_300); /* vertex #79 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_190, 4002, 21425); /* vertex #83 */
            }

            else if (perm[i] == 2) {
                opus_multistream_decoder_destroy(dep_451); /* vertex #88 */
            }

        }
    //}



    /* * * function pool #84 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'pcm_CtX'
        for (uint64_t i_0=0; i_0<40; ++i_0) {
            pcm_CtX[i_0] = v_EYN[E.eat1() % 36];
        }



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decoder_ctl(*dep_300, 4045, &dep_287); /* vertex #80 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encode(dep_190, (const int16_t *)&pcm_CtX, 40, (uint8_t *)dep_192, 2460); /* vertex #84 */
            }

            else if (perm[i] == 2) {
                opus_multistream_decoder_destroy(dep_452); /* vertex #108 */
            }

        }
    //}



    /* * * function pool #85 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_multistream_decoder_ctl(dep_285, 4034, 15); /* vertex #81 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_destroy(dep_190); /* vertex #85 */
            }

            else if (perm[i] == 2) {
                opus_decoder_destroy((OpusDecoder **)*dep_453); /* vertex #89 */
            }

        }
    //}



    /* * * function pool #86 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'request_gfg'
        OpusDecoder request_gfg_0;


        OpusDecoder *request_gfg_1 = &request_gfg_0;
        OpusDecoder **request_gfg_2 = &request_gfg_1;

        // Dependence family #301 Definition
        dep_301 = (OpusDecoder **)request_gfg_2;

        // initializing argument 'mapping_lSX'
        for (uint64_t i_0=0; i_0<255; ++i_0) {
            mapping_lSX[i_0] = v_VqT[E.eat1() % 255];
        }

        // initializing argument 'error_ZiJ'
        int32_t error_ZiJ_0 = E.eat4();
        int32_t *error_ZiJ_1 = &error_ZiJ_0;

        // Dependence family #197 Definition
        dep_197 = (int32_t *)error_ZiJ_1;

        // initializing argument 'Fs_xEM'
        for (uint64_t i_0=0; i_0<5; ++i_0) {
            Fs_xEM[i_0] = E.eat4();
        }

        // Dependence family #417 Definition
        dep_417 = (int32_t *)&Fs_xEM;
        // initializing argument 'channels_tTn'
        for (uint64_t i_0=0; i_0<2; ++i_0) {
            channels_tTn[i_0] = E.eat4();
        }

        // Dependence family #418 Definition
        dep_418 = (int32_t *)&channels_tTn;


        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_multistream_decoder_ctl(dep_285, 5122, dep_287, dep_301); /* vertex #82 */
            }

            else if (perm[i] == 1) {
                dep_196 = opus_multistream_encoder_create(8000, 255, 254, 1, (const uint8_t *)&mapping_lSX, 2051, dep_197); /* vertex #86 */
            }

            else if (perm[i] == 2) {
                dep_396 = opus_decoder_create((int32_t *)*dep_417, (int32_t *)*dep_418, dep_494); /* vertex #109 */
            }

        }
    //}



    /* * * function pool #87 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'application_gWt'
        for (uint64_t i_0=0; i_0<3; ++i_0) {
            application_gWt[i_0] = E.eat4();
        }



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decoder_ctl(*dep_301, 4045, &dep_287); /* vertex #83 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_196, 4024, 3001); /* vertex #87 */
            }

            else if (perm[i] == 2) {
                dep_395 = opus_encoder_create((int32_t *)*dep_417, (int32_t *)*dep_418, (int32_t *)*&application_gWt, dep_494); /* vertex #110 */
            }

        }
    //}



    /* * * function pool #88 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'request_tgR'
        for (uint64_t i_0=0; i_0<11; ++i_0) {
            request_tgR[i_0] = E.eat4();
        }



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_multistream_decoder_ctl(dep_285, 4009, &dep_287); /* vertex #84 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_196, 4006, 0); /* vertex #88 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_395, 4002, (int32_t *)*&request_tgR); /* vertex #111 */
            }

        }
    //}



    /* * * function pool #89 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'request_lfV'
        for (uint64_t i_0=0; i_0<4; ++i_0) {
            request_lfV[i_0] = E.eat4();
        }



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_multistream_decoder_ctl(dep_285, -5); /* vertex #85 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_196, 4020, 0); /* vertex #89 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_395, 4022, (int32_t *)*&request_lfV); /* vertex #112 */
            }

        }
    //}



    /* * * function pool #90 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'application_CZB'
        for (uint64_t i_0=0; i_0<3; ++i_0) {
            application_CZB[i_0] = E.eat4();
        }



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_multistream_decoder_ctl(dep_285, 4028); /* vertex #86 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_196, 4042, 0); /* vertex #90 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_395, 4006, (int32_t *)*&application_CZB); /* vertex #113 */
            }

        }
    //}



    /* * * function pool #91 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'application_lOG'
        for (uint64_t i_0=0; i_0<3; ++i_0) {
            application_lOG[i_0] = E.eat4();
        }



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_multistream_decoder_destroy(dep_285); /* vertex #87 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_196, 4022, 2); /* vertex #91 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_395, 4020, (int32_t *)*&application_lOG); /* vertex #114 */
            }

        }
    //}



    /* * * function pool #92 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'request_WPE'
        for (uint64_t i_0=0; i_0<11; ++i_0) {
            request_WPE[i_0] = E.eat4();
        }



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_285 = opus_multistream_decoder_create(48000, 2, 1, 1, (const uint8_t *)dep_291, dep_297); /* vertex #99 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_196, 4046, 1); /* vertex #92 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_395, 4010, (int32_t *)*&request_WPE); /* vertex #115 */
            }

        }
    //}



    /* * * function pool #93 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'data_ZZW'
        for (uint64_t i_0=0; i_0<1276; ++i_0) {
            data_ZZW[i_0] = -4;
        }

        // Dependence family #290 Definition
        dep_290 = (uint8_t *)&data_ZZW;
        // initializing argument 'pcm_dEb'
        for (uint64_t i_0=0; i_0<1920; ++i_0) {
            pcm_dEb[i_0] = 0 /* WO */;
        }

        // Dependence family #293 Definition
        dep_293 = (int16_t *)&pcm_dEb;

        // initializing argument 'request_YrX'
        for (uint64_t i_0=0; i_0<6; ++i_0) {
            request_YrX[i_0] = E.eat4();
        }



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_multistream_decode(dep_285, (const uint8_t *)dep_290, 51, (int16_t *)dep_293, 960, 0); /* vertex #88 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_196, 4016, 1); /* vertex #93 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_395, 4004, (int32_t *)*&request_YrX); /* vertex #116 */
            }

        }
    //}



    /* * * function pool #94 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'request_ZoU'
        for (uint64_t i_0=0; i_0<4; ++i_0) {
            request_ZoU[i_0] = E.eat4();
        }



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_multistream_decode(dep_285, (const uint8_t *)dep_290, -1, (int16_t *)dep_293, 960, 0); /* vertex #89 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_196, 4010, 2); /* vertex #94 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_395, 4024, (int32_t *)*&request_ZoU); /* vertex #117 */
            }

        }
    //}



    /* * * function pool #95 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(4, E.eatIntBw( NBYTES_FOR_FACTORIAL(4) ));
    
        // initializing argument 'application_xai'
        for (uint64_t i_0=0; i_0<3; ++i_0) {
            application_xai[i_0] = E.eat4();
        }



        for (int i=0; i<4; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_multistream_decode(dep_285, (const uint8_t *)dep_290, -1, (int16_t *)dep_293, 960, 0); /* vertex #90 */
            }

            else if (perm[i] == 1) {
                opus_multistream_decode(dep_285, (const uint8_t *)dep_290, 3, (int16_t *)dep_293, 60, 0); /* vertex #91 */
            }

            else if (perm[i] == 2) {
                opus_multistream_encoder_ctl(dep_196, 4004, 1101); /* vertex #95 */
            }

            else if (perm[i] == 3) {
                opus_encoder_ctl(dep_395, 4012, (int32_t *)*&application_xai); /* vertex #118 */
            }

        }
    //}



    /* * * function pool #96 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'request_ZwM'
        for (uint64_t i_0=0; i_0<4; ++i_0) {
            request_ZwM[i_0] = E.eat4();
        }



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_multistream_decode(dep_285, (const uint8_t *)dep_290, 3, (int16_t *)dep_293, 480, 0); /* vertex #92 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_196, 4008, -1000); /* vertex #96 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_395, 4014, (int32_t *)*&request_ZwM); /* vertex #119 */
            }

        }
    //}



    /* * * function pool #97 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'channels_OJa'
        for (uint64_t i_0=0; i_0<2; ++i_0) {
            channels_OJa[i_0] = E.eat4();
        }



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_multistream_decode(dep_285, (const uint8_t *)dep_290, 3, (int16_t *)dep_293, 960, 0); /* vertex #93 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_196, 4036, 14); /* vertex #97 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_395, 4036, (int32_t *)*&channels_OJa); /* vertex #120 */
            }

        }
    //}



    /* * * function pool #98 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'pcm_jIq'
        for (uint64_t i_0=0; i_0<1920; ++i_0) {
            pcm_jIq[i_0] = 0 /* WO */;
        }


        // initializing argument 'application_SFJ'
        for (uint64_t i_0=0; i_0<3; ++i_0) {
            application_SFJ[i_0] = E.eat4();
        }



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_multistream_decode_float(dep_285, (const uint8_t *)dep_290, 3, (float *)&pcm_jIq, 960, 0); /* vertex #94 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_196, 4012, 0); /* vertex #98 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_395, 4042, (int32_t *)*&application_SFJ); /* vertex #121 */
            }

        }
    //}



    /* * * function pool #99 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'channels_nII'
        for (uint64_t i_0=0; i_0<2; ++i_0) {
            channels_nII[i_0] = E.eat4();
        }



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_multistream_decoder_destroy(dep_285); /* vertex #95 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_196, 4014, 57); /* vertex #99 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_395, 4016, (int32_t *)*&channels_nII); /* vertex #122 */
            }

        }
    //}



    /* * * function pool #100 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'data_mTk'
        for (uint64_t i_0=0; i_0<1276; ++i_0) {
            data_mTk[i_0] = -4;
        }

        // Dependence family #306 Definition
        dep_306 = (uint8_t *)&data_mTk;
        // initializing argument 'frames_Amj'
        for (uint64_t i_0=0; i_0<48; ++i_0) {
            frames_Amj_0[i_0] = 0 /* WO */;
            frames_Amj_1[i_0] = &frames_Amj_0[i_0];
        }

        // Dependence family #310 Definition
        dep_310 = (uint8_t **)&frames_Amj_1;
        // initializing argument 'size_ugp'


        // initializing argument 'request_GvA'
        int32_t request_GvA_0 = 0;
        int32_t *request_GvA_1 = &request_GvA_0;

        // Dependence family #434 Definition
        dep_434 = (int32_t *)request_GvA_1;


        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_packet_parse((const uint8_t *)dep_306, 1, &dep_287, (const uint8_t **)dep_310, NULL, dep_297); /* vertex #101 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_196, 4002, 3642675); /* vertex #100 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_395, 4040, *dep_434); /* vertex #123 */
            }

        }
    //}



    /* * * function pool #101 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'size_awg'
        for (uint64_t i_0=0; i_0<48; ++i_0) {
            size_awg[i_0] = 0 /* WO */;
        }

        // Dependence family #311 Definition
        dep_311 = (int16_t *)&size_awg;

        // initializing argument 'pcm_ceA'
        for (uint64_t i_0=0; i_0<5100; ++i_0) {
            pcm_ceA[i_0] = 0;
        }

        // initializing argument 'data_IJq'
        for (uint64_t i_0=0; i_0<627300; ++i_0) {
            data_IJq[i_0] = 0 /* WO */;
        }


        // initializing argument 'pcm_UTi'
        for (uint64_t i_0=0; i_0<buflen; ++i_0) {
            pcm_UTi[i_0] = E.buf_eat2();
        }

        // initializing argument 'data_Gln'
        for (uint64_t i_0=0; i_0<1757; ++i_0) {
            data_Gln[i_0] = 0 /* WO */;
        }

        // Dependence family #389 Definition
        dep_389 = (uint8_t *)&data_Gln;


        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_313 = opus_packet_parse((const uint8_t *)dep_306, 4, &dep_287, (const uint8_t **)dep_310, (int16_t *)dep_311, dep_297); /* vertex #102 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encode(dep_196, (const int16_t *)&pcm_ceA, 20, (uint8_t *)&data_IJq, 627300); /* vertex #101 */
            }

            else if (perm[i] == 2) {
                dep_390 = opus_encode(dep_395, pcm_UTi, *dep_434, (uint8_t *)dep_389, 1500); /* vertex #126 */
            }

        }
    //}



    /* * * function pool #102 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'len_hsa'
        int32_t len_hsa_0 = 0;

        // Dependence family #304 Definition
        dep_304 = (int32_t )len_hsa_0;

        // initializing argument 'st_ieP'
        OpusDecoder st_ieP_0;


        OpusDecoder *st_ieP_1 = &st_ieP_0;

        // initializing argument 'pcm_omw'
        for (uint64_t i_0=0; i_0<buflen; ++i_0) {
            pcm_omw[i_0] = E.buf_eat2();
        }



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_313 = opus_packet_parse((const uint8_t *)dep_306, dep_304, &dep_287, (const uint8_t **)dep_310, (int16_t *)dep_311, dep_297); /* vertex #103 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_destroy(dep_196); /* vertex #102 */
            }

            else if (perm[i] == 2) {
                opus_decode(st_ieP_1, (uint8_t *)dep_389, dep_390, pcm_omw, 5760, 0); /* vertex #127 */
            }

        }
    //}



    /* * * function pool #103 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'mapping_rbd'
        for (uint64_t i_0=0; i_0<192; ++i_0) {
            mapping_rbd[i_0] = v_NHw[E.eat1() % 192];
        }

        // initializing argument 'error_YIU'
        int32_t error_YIU_0 = E.eat4();
        int32_t *error_YIU_1 = &error_YIU_0;

        // Dependence family #200 Definition
        dep_200 = (int32_t *)error_YIU_1;


        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_313 = opus_packet_parse(dep_306, 1, &dep_287, (const uint8_t **)dep_310, (int16_t *)dep_311, dep_297); /* vertex #104 */
            }

            else if (perm[i] == 1) {
                dep_199 = opus_multistream_encoder_create(8000, 192, 189, 3, (const uint8_t *)&mapping_rbd, 2051, dep_200); /* vertex #103 */
            }

            else if (perm[i] == 2) {
                opus_encoder_destroy(dep_395); /* vertex #124 */
            }

        }
    //}



    /* * * function pool #104 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_313 = opus_packet_parse(dep_306, 2, &dep_287, (const uint8_t **)dep_310, (int16_t *)dep_311, dep_297); /* vertex #105 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_199, 4024, 3002); /* vertex #104 */
            }

            else if (perm[i] == 2) {
                opus_decoder_destroy(dep_396); /* vertex #125 */
            }

        }
    //}



    /* * * function pool #105 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_313 = opus_packet_parse(dep_306, E.eat4(), &dep_287, (const uint8_t **)dep_310, (int16_t *)dep_311, dep_297); /* vertex #106 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_199, 4006, 0); /* vertex #105 */
            }

        }
    //}



    /* * * function pool #106 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_313 = opus_packet_parse(dep_306, E.eat4(), &dep_287, (const uint8_t **)dep_310, (int16_t *)dep_311, dep_297); /* vertex #107 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_199, 4020, 0); /* vertex #106 */
            }

        }
    //}



    /* * * function pool #107 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_313 = opus_packet_parse(dep_306, E.eat4(), &dep_287, (const uint8_t **)dep_310, (int16_t *)dep_311, dep_297); /* vertex #108 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_199, 4042, 0); /* vertex #107 */
            }

        }
    //}



    /* * * function pool #108 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_313 = opus_packet_parse(dep_306, E.eat4(), &dep_287, (const uint8_t **)dep_310, (int16_t *)dep_311, dep_297); /* vertex #109 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_199, 4022, -1000); /* vertex #108 */
            }

        }
    //}



    /* * * function pool #109 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_313 = opus_packet_parse(dep_306, 1, &dep_287, (const uint8_t **)dep_310, (int16_t *)dep_311, dep_297); /* vertex #110 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_199, 4046, 0); /* vertex #109 */
            }

        }
    //}



    /* * * function pool #110 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_313 = opus_packet_parse(dep_306, 1275, &dep_287, (const uint8_t **)dep_310, (int16_t *)dep_311, dep_297); /* vertex #111 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_199, 4016, 0); /* vertex #110 */
            }

        }
    //}



    /* * * function pool #111 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_313 = opus_packet_parse(dep_306, 1275, &dep_287, (const uint8_t **)dep_310, (int16_t *)dep_311, dep_297); /* vertex #112 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_199, 4010, 0); /* vertex #111 */
            }

        }
    //}



    /* * * function pool #112 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_313 = opus_packet_parse(dep_306, 1275, &dep_287, (const uint8_t **)dep_310, (int16_t *)dep_311, dep_297); /* vertex #113 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_199, 4004, 1102); /* vertex #112 */
            }

        }
    //}



    /* * * function pool #113 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_313 = opus_packet_parse(dep_306, 1275, &dep_287, (const uint8_t **)dep_310, (int16_t *)dep_311, dep_297); /* vertex #114 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_199, 4008, -1000); /* vertex #113 */
            }

        }
    //}



    /* * * function pool #114 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_313 = opus_packet_parse(dep_306, E.eat4(), &dep_287, (const uint8_t **)dep_310, (int16_t *)dep_311, dep_297); /* vertex #115 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_199, 4036, 8); /* vertex #114 */
            }

        }
    //}



    /* * * function pool #115 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_313 = opus_packet_parse(dep_306, 1278, &dep_287, (const uint8_t **)dep_310, (int16_t *)dep_311, dep_297); /* vertex #116 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_199, 4012, 0); /* vertex #115 */
            }

        }
    //}



    /* * * function pool #116 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_packet_get_samples_per_frame(dep_306, 48000); /* vertex #117 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_199, 4014, 0); /* vertex #116 */
            }

        }
    //}



    /* * * function pool #117 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_313 = opus_packet_parse(dep_306, 2, &dep_287, (const uint8_t **)dep_310, (int16_t *)dep_311, dep_297); /* vertex #118 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_199, 4002, 15360); /* vertex #117 */
            }

        }
    //}



    /* * * function pool #118 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    
        // initializing argument 'pcm_lLE'
        for (uint64_t i_0=0; i_0<3840; ++i_0) {
            pcm_lLE[i_0] = 0;
        }

        // initializing argument 'data_unj'
        for (uint64_t i_0=0; i_0<472320; ++i_0) {
            data_unj[i_0] = 0 /* WO */;
        }



        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_313 = opus_packet_parse(dep_306, E.eat4(), &dep_287, (const uint8_t **)dep_310, (int16_t *)dep_311, dep_297); /* vertex #119 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encode(dep_199, (const int16_t *)&pcm_lLE, 20, (uint8_t *)&data_unj, 472320); /* vertex #118 */
            }

        }
    //}



    /* * * function pool #119 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_packet_get_samples_per_frame(dep_306, 48000); /* vertex #120 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_destroy(dep_199); /* vertex #119 */
            }

        }
    //}



    /* * * function pool #120 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    
        // initializing argument 'streams_mcW'
        int32_t streams_mcW_0 = 0 /* WO */;
        int32_t *streams_mcW_1 = &streams_mcW_0;

        // initializing argument 'coupled_streams_kiO'
        int32_t coupled_streams_kiO_0 = 0 /* WO */;
        int32_t *coupled_streams_kiO_1 = &coupled_streams_kiO_0;

        // initializing argument 'mapping_WEq'
        for (uint64_t i_0=0; i_0<3; ++i_0) {
            mapping_WEq[i_0] = 0 /* WO */;
        }

        // initializing argument 'error_MZY'
        int32_t error_MZY_0 = E.eat4();
        int32_t *error_MZY_1 = &error_MZY_0;

        // Dependence family #203 Definition
        dep_203 = (int32_t *)error_MZY_1;


        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_313 = opus_packet_parse(dep_306, E.eat4(), &dep_287, (const uint8_t **)dep_310, (int16_t *)dep_311, dep_297); /* vertex #121 */
            }

            else if (perm[i] == 1) {
                dep_202 = opus_multistream_surround_encoder_create(24000, 3, 1, streams_mcW_1, coupled_streams_kiO_1, (uint8_t *)&mapping_WEq, 2049, dep_203); /* vertex #120 */
            }

        }
    //}



    /* * * function pool #121 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_313 = opus_packet_parse(dep_306, 1278, &dep_287, (const uint8_t **)dep_310, (int16_t *)dep_311, dep_297); /* vertex #122 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_202, 4024, 3001); /* vertex #121 */
            }

        }
    //}



    /* * * function pool #122 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_313 = opus_packet_parse(dep_306, E.eat4(), &dep_287, (const uint8_t **)dep_310, (int16_t *)dep_311, dep_297); /* vertex #123 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_202, 4006, 1); /* vertex #122 */
            }

        }
    //}



    /* * * function pool #123 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_313 = opus_packet_parse(dep_306, E.eat4(), &dep_287, (const uint8_t **)dep_310, (int16_t *)dep_311, dep_297); /* vertex #124 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_202, 4020, 1); /* vertex #123 */
            }

        }
    //}



    /* * * function pool #124 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_313 = opus_packet_parse(dep_306, E.eat4(), &dep_287, (const uint8_t **)dep_310, (int16_t *)dep_311, dep_297); /* vertex #125 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_202, 4042, 0); /* vertex #124 */
            }

        }
    //}



    /* * * function pool #125 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_313 = opus_packet_parse(dep_306, E.eat4(), &dep_287, (const uint8_t **)dep_310, (int16_t *)dep_311, dep_297); /* vertex #126 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_202, 4022, -1000); /* vertex #125 */
            }

        }
    //}



    /* * * function pool #126 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_313 = opus_packet_parse(dep_306, E.eat4(), &dep_287, (const uint8_t **)dep_310, (int16_t *)dep_311, dep_297); /* vertex #127 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_202, 4046, 0); /* vertex #126 */
            }

        }
    //}



    /* * * function pool #127 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_313 = opus_packet_parse(dep_306, E.eat4(), &dep_287, (const uint8_t **)dep_310, (int16_t *)dep_311, dep_297); /* vertex #128 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_202, 4016, 0); /* vertex #127 */
            }

        }
    //}



    /* * * function pool #128 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_313 = opus_packet_parse(dep_306, 127, &dep_287, (const uint8_t **)dep_310, (int16_t *)dep_311, dep_297); /* vertex #129 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_202, 4010, 0); /* vertex #128 */
            }

        }
    //}



    /* * * function pool #129 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_313 = opus_packet_parse(dep_306, E.eat4(), &dep_287, (const uint8_t **)dep_310, (int16_t *)dep_311, dep_297); /* vertex #130 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_202, 4004, 1101); /* vertex #129 */
            }

        }
    //}



    /* * * function pool #130 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_313 = opus_packet_parse(dep_306, E.eat4(), &dep_287, (const uint8_t **)dep_310, (int16_t *)dep_311, dep_297); /* vertex #131 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_202, 4008, 1101); /* vertex #130 */
            }

        }
    //}



    /* * * function pool #131 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    
        // initializing argument 'channels_uCW'
        int32_t channels_uCW_0 = 0;

        // Dependence family #332 Definition
        dep_332 = (int32_t )channels_uCW_0;


        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_327 = opus_encoder_get_size(dep_332); /* vertex #132 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_202, 4036, 8); /* vertex #131 */
            }

        }
    //}



    /* * * function pool #132 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    
        // initializing argument 'Fs_isN'
        int32_t Fs_isN_0 = -8000;

        // Dependence family #335 Definition
        dep_335 = (int32_t )Fs_isN_0;
        // initializing argument 'error_chr'
        int32_t error_chr_0 = 0;
        int32_t *error_chr_1 = &error_chr_0;

        // Dependence family #333 Definition
        dep_333 = (int32_t *)error_chr_1;


        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_326 = opus_encoder_create(dep_335, dep_332, 2048, dep_333); /* vertex #133 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_202, 4012, 1); /* vertex #132 */
            }

        }
    //}



    /* * * function pool #133 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    
        // initializing argument 'error_tJo'



        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_326 = opus_encoder_create(dep_335, dep_332, 2048, NULL); /* vertex #134 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_202, 4002, 84315); /* vertex #133 */
            }

        }
    //}



    /* * * function pool #134 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    
        // initializing argument 'pcm_Nln'
        for (uint64_t i_0=0; i_0<2880; ++i_0) {
            pcm_Nln[i_0] = v_kOF[E.eat2() % 814];
        }

        // initializing argument 'data_IAG'
        for (uint64_t i_0=0; i_0<7380; ++i_0) {
            data_IAG[i_0] = 0 /* WO */;
        }

        // Dependence family #204 Definition
        dep_204 = (uint8_t *)&data_IAG;


        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_destroy(dep_326); /* vertex #135 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encode(dep_202, (const int16_t *)&pcm_Nln, 960, (uint8_t *)dep_204, 7380); /* vertex #134 */
            }

        }
    //}



    /* * * function pool #135 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_get_size(2); /* vertex #278 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_202, 4024, 3002); /* vertex #135 */
            }

        }
    //}



    /* * * function pool #136 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_init(dep_326, dep_335, dep_332, 2048); /* vertex #136 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_202, 4006, 1); /* vertex #136 */
            }

        }
    //}



    /* * * function pool #137 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    
        // initializing argument 'error_bSn'



        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_326 = opus_encoder_create(48000, 2, -1000, NULL); /* vertex #137 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_202, 4020, 0); /* vertex #137 */
            }

        }
    //}



    /* * * function pool #138 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_326 = opus_encoder_create(48000, 2, -1000, dep_333); /* vertex #138 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_202, 4042, 1); /* vertex #138 */
            }

        }
    //}



    /* * * function pool #139 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    
        // initializing argument 'error_RCu'



        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_326 = opus_encoder_create(48000, 2, 2048, NULL); /* vertex #139 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_202, 4022, -1000); /* vertex #139 */
            }

        }
    //}



    /* * * function pool #140 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_destroy(dep_326); /* vertex #140 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_202, 4046, 1); /* vertex #140 */
            }

        }
    //}



    /* * * function pool #141 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_326 = opus_encoder_create(48000, 2, 2051, dep_333); /* vertex #276 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_202, 4016, 1); /* vertex #141 */
            }

        }
    //}



    /* * * function pool #142 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4027, &dep_327); /* vertex #141 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_202, 4010, 6); /* vertex #142 */
            }

        }
    //}



    /* * * function pool #143 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_destroy(dep_326); /* vertex #142 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_202, 4004, 1101); /* vertex #143 */
            }

        }
    //}



    /* * * function pool #144 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_326 = opus_encoder_create(48000, 2, 2049, dep_333); /* vertex #277 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_202, 4008, -1000); /* vertex #144 */
            }

        }
    //}



    /* * * function pool #145 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4027, &dep_327); /* vertex #143 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_202, 4036, 9); /* vertex #145 */
            }

        }
    //}



    /* * * function pool #146 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_destroy(dep_326); /* vertex #144 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_202, 4012, 1); /* vertex #146 */
            }

        }
    //}



    /* * * function pool #147 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_326 = opus_encoder_create(48000, 2, 2048, dep_333); /* vertex #279 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_202, 4014, 5); /* vertex #147 */
            }

        }
    //}



    /* * * function pool #148 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4027, &dep_327); /* vertex #145 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_ctl(dep_202, 4002, 775410); /* vertex #148 */
            }

        }
    //}



    /* * * function pool #149 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    
        // initializing argument 'request_axE'


        // initializing argument 'pcm_YrA'
        for (uint64_t i_0=0; i_0<4320; ++i_0) {
            pcm_YrA[i_0] = v_hBS[E.eat2() % 413];
        }



        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4027, NULL); /* vertex #146 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encode(dep_202, (const int16_t *)&pcm_YrA, 1440, (uint8_t *)dep_204, 7380); /* vertex #149 */
            }

        }
    //}



    /* * * function pool #150 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4029, &dep_327); /* vertex #147 */
            }

            else if (perm[i] == 1) {
                opus_multistream_encoder_destroy(dep_202); /* vertex #150 */
            }

        }
    //}



    /* * * function pool #151 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    
        // initializing argument 'request_TPs'


        // initializing argument 'Fs_Saz'
        int32_t Fs_Saz_0 = E.eat4();

        // Dependence family #107 Definition
        dep_107 = (int32_t )Fs_Saz_0;
        auto s_sOq[] = {E.eat4(), dep_107};
        // initializing argument 'channels_sEo'
        int32_t channels_sEo_0 = E.eat4();

        // Dependence family #103 Definition
        dep_103 = (int32_t )channels_sEo_0;
        auto s_Pok[] = {E.eat4(), dep_103};
        // initializing argument 'error_eCm'
        int32_t error_eCm_0 = 0 /* WO */;
        int32_t *error_eCm_1 = &error_eCm_0;

        // initializing argument 'error_RZj'
        int32_t error_RZj_0 = 0 /* WO */;
        int32_t *error_RZj_1 = &error_RZj_0;

        // Dependence family #93 Definition
        dep_93 = (int32_t *)error_RZj_1;
        auto s_kgR[] = {error_eCm_1, dep_93};


        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4029, NULL); /* vertex #148 */
            }

            else if (perm[i] == 1) {
                dep_208 = opus_encoder_create(s_sOq[E.eat1() % 2], s_Pok[E.eat1() % 2], 2049, s_kgR[E.eat1() % 2]);
                dep_98 = dep_208; /* vertex #151 */
            }

        }
    //}



    /* * * function pool #152 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'request_LGm'
        int32_t request_LGm_0 = 0;
        int32_t *request_LGm_1 = &request_LGm_0;

        // Dependence family #104 Definition
        dep_104 = (int32_t *)request_LGm_1;


        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, -5); /* vertex #149 */
            }

            else if (perm[i] == 1) {
                opus_encoder_ctl(dep_98, 4002, *dep_104); /* vertex #1 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_208, 4010, 10); /* vertex #152 */
            }

        }
    //}



    /* * * function pool #153 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'request_SrF'


        // initializing argument 'request_yzH'
        int32_t request_yzH_0 = 0;
        int32_t *request_yzH_1 = &request_yzH_0;



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4001, NULL); /* vertex #150 */
            }

            else if (perm[i] == 1) {
                opus_encoder_ctl(dep_98, 4008, *request_yzH_1); /* vertex #17 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_208, 4014, 6); /* vertex #153 */
            }

        }
    //}



    /* * * function pool #154 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'request_fbJ'
        int32_t request_fbJ_0 = 0;
        int32_t *request_fbJ_1 = &request_fbJ_0;



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4000, dep_327); /* vertex #151 */
            }

            else if (perm[i] == 1) {
                opus_encoder_ctl(dep_98, 4006, *request_fbJ_1); /* vertex #18 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_208, 4002, 6000); /* vertex #154 */
            }

        }
    //}



    /* * * function pool #155 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'request_voJ'
        int32_t request_voJ_0 = 0;
        int32_t *request_voJ_1 = &request_voJ_0;


        // initializing argument 'pcm_PWN'
        for (uint64_t i_0=0; i_0<960; ++i_0) {
            pcm_PWN[i_0] = v_zIV[E.eat1() % 2];
        }

        // initializing argument 'data_wWg'
        for (uint64_t i_0=0; i_0<2000; ++i_0) {
            data_wWg[i_0] = 0 /* WO */;
        }

        // Dependence family #211 Definition
        dep_211 = (uint8_t *)&data_wWg;


        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4000, dep_327); /* vertex #152 */
            }

            else if (perm[i] == 1) {
                opus_encoder_ctl(dep_98, 4020, *request_voJ_1); /* vertex #19 */
            }

            else if (perm[i] == 2) {
                dep_210 = opus_encode(dep_208, (const int16_t *)&pcm_PWN, 960, (uint8_t *)dep_211, 2000); /* vertex #155 */
            }

        }
    //}



    /* * * function pool #156 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'request_uyN'
        int32_t request_uyN_0 = 0;
        int32_t *request_uyN_1 = &request_uyN_0;



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4000, dep_327); /* vertex #153 */
            }

            else if (perm[i] == 1) {
                opus_encoder_ctl(dep_98, 4010, *request_uyN_1); /* vertex #20 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_208, 4024, 3001); /* vertex #156 */
            }

        }
    //}



    /* * * function pool #157 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'request_RYz'
        int32_t request_RYz_0 = 0;
        int32_t *request_RYz_1 = &request_RYz_0;



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4001, &dep_327); /* vertex #154 */
            }

            else if (perm[i] == 1) {
                opus_encoder_ctl(dep_98, 4012, *request_RYz_1); /* vertex #21 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_208, 4042, 1); /* vertex #157 */
            }

        }
    //}



    /* * * function pool #158 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'request_CCx'
        int32_t request_CCx_0 = 0;
        int32_t *request_CCx_1 = &request_CCx_0;



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4000, dep_327); /* vertex #155 */
            }

            else if (perm[i] == 1) {
                opus_encoder_ctl(dep_98, 4022, *request_CCx_1); /* vertex #22 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_208, 4008, 1104); /* vertex #158 */
            }

        }
    //}



    /* * * function pool #159 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'request_TSh'
        int32_t request_TSh_0 = 0;
        int32_t *request_TSh_1 = &request_TSh_0;



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4001, &dep_327); /* vertex #156 */
            }

            else if (perm[i] == 1) {
                opus_encoder_ctl(dep_98, 4016, *request_TSh_1); /* vertex #23 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_208, 4012, 1); /* vertex #159 */
            }

        }
    //}



    /* * * function pool #160 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'request_cHa'


        // initializing argument 'request_kUF'
        int32_t request_kUF_0 = 0;
        int32_t *request_kUF_1 = &request_kUF_0;



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4003, NULL); /* vertex #157 */
            }

            else if (perm[i] == 1) {
                opus_encoder_ctl(dep_98, 4014, *request_kUF_1); /* vertex #24 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_208, 4002, 15600); /* vertex #160 */
            }

        }
    //}



    /* * * function pool #161 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'request_Xgf'
        int32_t request_Xgf_0 = 0;
        int32_t *request_Xgf_1 = &request_Xgf_0;


        // initializing argument 'pcm_vGp'
        for (uint64_t i_0=0; i_0<2880; ++i_0) {
            pcm_vGp[i_0] = v_uCU[E.eat1() % 92];
        }



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4002, 1073741832); /* vertex #158 */
            }

            else if (perm[i] == 1) {
                opus_encoder_ctl(dep_98, 4027, request_Xgf_1); /* vertex #25 */
            }

            else if (perm[i] == 2) {
                dep_210 = opus_encode(dep_208, (const int16_t *)&pcm_vGp, 2880, (uint8_t *)dep_211, 122); /* vertex #161 */
            }

        }
    //}



    /* * * function pool #162 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4003, &dep_327); /* vertex #159 */
            }

            else if (perm[i] == 1) {
                opus_encoder_ctl(dep_98, 4036, 16); /* vertex #26 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_208, 4024, 3002); /* vertex #162 */
            }

        }
    //}



    /* * * function pool #163 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'request_POV'
        int32_t request_POV_0 = 0;
        int32_t *request_POV_1 = &request_POV_0;

        // Dependence family #158 Definition
        dep_158 = (int32_t *)request_POV_1;


        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4002, dep_327); /* vertex #160 */
            }

            else if (perm[i] == 1) {
                opus_encoder_ctl(dep_98, 4040, *dep_158); /* vertex #27 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_208, 4002, 27000); /* vertex #163 */
            }

        }
    //}



    /* * * function pool #164 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'pcm_YoN'
        for (uint64_t i_0=0; i_0<2880; ++i_0) {
            pcm_YoN[i_0] = 0;
        }



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4002, dep_327); /* vertex #161 */
            }

            else if (perm[i] == 1) {
                dep_99 = opus_decoder_create(dep_107, dep_103, dep_93); /* vertex #2 */
            }

            else if (perm[i] == 2) {
                dep_210 = opus_encode(dep_208, (const int16_t *)&pcm_YoN, 2880, (uint8_t *)dep_211, 122); /* vertex #164 */
            }

        }
    //}



    /* * * function pool #165 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4002, dep_327); /* vertex #162 */
            }

            else if (perm[i] == 1) {
                opus_encoder_ctl(dep_98, 4040, *dep_158); /* vertex #3 */
            }

            else if (perm[i] == 2) {
                opus_encoder_destroy(dep_208); /* vertex #165 */
            }

        }
    //}



    /* * * function pool #166 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'error_ZDQ'
        int32_t error_ZDQ_0 = 0 /* WO */;
        int32_t *error_ZDQ_1 = &error_ZDQ_0;



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4003, &dep_327); /* vertex #163 */
            }

            else if (perm[i] == 1) {
                opus_encoder_ctl(dep_98, 11002, 1002); /* vertex #4 */
            }

            else if (perm[i] == 2) {
                dep_212 = opus_encoder_create(48000, 1, 2049, error_ZDQ_1); /* vertex #166 */
            }

        }
    //}



    /* * * function pool #167 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'a_OhW'



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4002, dep_327); /* vertex #164 */
            }

            else if (perm[i] == 1) {
                opus_encoder_ctl(dep_98, 4012, ); /* vertex #5 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_212, 4010, 6); /* vertex #167 */
            }

        }
    //}



    /* * * function pool #168 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'request_BWB'

        // Dependence family #151 Definition
        dep_151 = (char **)NULL;


        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4003, &dep_327); /* vertex #165 */
            }

            else if (perm[i] == 1) {
                opus_encoder_ctl(dep_98, 4008, (char **)*dep_151); /* vertex #6 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_212, 4024, 3001); /* vertex #168 */
            }

        }
    //}



    /* * * function pool #169 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'request_uzN'



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4023, NULL); /* vertex #166 */
            }

            else if (perm[i] == 1) {
                opus_encoder_ctl(dep_98, 11002, (char **)*dep_151); /* vertex #29 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_212, 4008, 1105); /* vertex #169 */
            }

        }
    //}



    /* * * function pool #170 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4022, dep_327); /* vertex #167 */
            }

            else if (perm[i] == 1) {
                opus_encoder_ctl(dep_98, 4022, (char **)*dep_151); /* vertex #30 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_212, 4014, 26); /* vertex #170 */
            }

        }
    //}



    /* * * function pool #171 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'request_GoR'
        int32_t request_GoR_0 = 0;
        int32_t *request_GoR_1 = &request_GoR_0;

        // initializing argument 'frame_size_FZH'
        int32_t frame_size_FZH_0 = dep_107;

        // initializing argument 'data_jap'
        for (uint64_t i_0=0; i_0<buflen; ++i_0) {
            for (uint64_t i_1=0; i_1<2; ++i_1) {
                for (uint64_t i_2=0; i_2<buflen; ++i_2) {
                    data_jap_0[i_0][i_1][i_2] = E.buf_eat1();
                }

                data_jap_1[i_0][i_1] = (uint8_t*)data_jap_0[i_0][i_1];
            }
        }


        // Dependence family #105 Definition
        dep_105 = (uint8_t **)data_jap_1;


        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4022, dep_327); /* vertex #168 */
            }

            else if (perm[i] == 1) {
                dep_101 = opus_encode(dep_98, *request_GoR_1, frame_size_FZH_0, (uint8_t **)*dep_105, 1500); /* vertex #7 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_212, 4002, 27000); /* vertex #171 */
            }

        }
    //}



    /* * * function pool #172 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'pcm_sXe'
        for (uint64_t i_0=0; i_0<960; ++i_0) {
            pcm_sXe[i_0] = 0;
        }

        // initializing argument 'data_XeV'
        for (uint64_t i_0=0; i_0<2000; ++i_0) {
            data_XeV[i_0] = 0 /* WO */;
        }

        // Dependence family #215 Definition
        dep_215 = (uint8_t *)&data_XeV;


        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4022, dep_327); /* vertex #169 */
            }

            else if (perm[i] == 1) {
                opus_packet_get_samples_per_frame((uint8_t **)*dep_105, dep_107); /* vertex #31 */
            }

            else if (perm[i] == 2) {
                dep_214 = opus_encode(dep_212, (const int16_t *)&pcm_sXe, 960, (uint8_t *)dep_215, 2000); /* vertex #172 */
            }

        }
    //}



    /* * * function pool #173 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4023, &dep_327); /* vertex #170 */
            }

            else if (perm[i] == 1) {
                opus_packet_get_nb_frames((uint8_t **)*dep_105, (int32_t *)dep_101); /* vertex #32 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_212, 4024, 3002); /* vertex #173 */
            }

        }
    //}



    /* * * function pool #174 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'pcm_Fhw'
        for (uint64_t i_0=0; i_0<480; ++i_0) {
            pcm_Fhw[i_0] = v_VPl[E.eat1() % 3];
        }



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4022, dep_327); /* vertex #171 */
            }

            else if (perm[i] == 1) {
                opus_encoder_ctl(dep_98, 4002, *dep_104); /* vertex #8 */
            }

            else if (perm[i] == 2) {
                dep_214 = opus_encode(dep_212, (const int16_t *)&pcm_Fhw, 480, (uint8_t *)dep_215, 19); /* vertex #174 */
            }

        }
    //}



    /* * * function pool #175 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'request_tQL'
        for (uint64_t i_0=0; i_0<2; ++i_0) {
            request_tQL[i_0] = 0 /* DEAD */;
        }



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4023, &dep_327); /* vertex #172 */
            }

            else if (perm[i] == 1) {
                opus_encoder_ctl(dep_98, 4031, (int32_t *)&request_tQL); /* vertex #9 */
            }

            else if (perm[i] == 2) {
                opus_encoder_destroy(dep_212); /* vertex #175 */
            }

        }
    //}



    /* * * function pool #176 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'request_YpC'
        int32_t request_YpC_0 = 96000;

        // Dependence family #166 Definition
        dep_166 = (int32_t )request_YpC_0;

        // initializing argument 'error_sbJ'
        int32_t error_sbJ_0 = 0 /* WO */;
        int32_t *error_sbJ_1 = &error_sbJ_0;



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4008, dep_327); /* vertex #173 */
            }

            else if (perm[i] == 1) {
                opus_decoder_ctl(dep_99, 4039, dep_166); /* vertex #10 */
            }

            else if (perm[i] == 2) {
                dep_216 = opus_encoder_create(8000, 1, 2049, error_sbJ_1); /* vertex #176 */
            }

        }
    //}



    /* * * function pool #177 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4008, dep_327); /* vertex #174 */
            }

            else if (perm[i] == 1) {
                opus_decoder_ctl(dep_99, 4039, dep_166); /* vertex #11 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_216, 4010, 3); /* vertex #177 */
            }

        }
    //}



    /* * * function pool #178 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'data_oSn'
        uint8_t data_oSn_0 = E.eat1();
        uint8_t *data_oSn_1 = &data_oSn_0;

        // initializing argument 'pcm_JSz'
        for (uint64_t i_0=0; i_0<buflen; ++i_0) {
            pcm_JSz[i_0] = E.buf_eat2();
        }

        // Dependence family #122 Definition
        dep_122 = (int16_t *)pcm_JSz;


        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4008, dep_327); /* vertex #175 */
            }

            else if (perm[i] == 1) {
                dep_166 = opus_decode(dep_99, data_oSn_1, (int32_t *)dep_101, dep_122, dep_166, 1); /* vertex #12 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_216, 4004, 1101); /* vertex #178 */
            }

        }
    //}



    /* * * function pool #179 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4008, dep_327); /* vertex #176 */
            }

            else if (perm[i] == 1) {
                dep_166 = opus_decode(dep_99, (uint8_t **)*dep_105, (int32_t *)dep_101, dep_122, dep_166, 0); /* vertex #13 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_216, 4002, 6000); /* vertex #179 */
            }

        }
    //}



    /* * * function pool #180 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'data_sbs'
        uint8_t data_sbs_0 = E.eat1();
        uint8_t *data_sbs_1 = &data_sbs_0;


        // initializing argument 'pcm_thA'
        for (uint64_t i_0=0; i_0<160; ++i_0) {
            pcm_thA[i_0] = 0;
        }

        // initializing argument 'data_AJX'
        for (uint64_t i_0=0; i_0<1000; ++i_0) {
            data_AJX[i_0] = 0 /* WO */;
        }

        // Dependence family #219 Definition
        dep_219 = (uint8_t *)&data_AJX;


        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4008, dep_327); /* vertex #177 */
            }

            else if (perm[i] == 1) {
                dep_166 = opus_decode(dep_99, data_sbs_1, (int32_t *)dep_101, dep_122, dep_166, 0); /* vertex #14 */
            }

            else if (perm[i] == 2) {
                dep_218 = opus_encode(dep_216, (const int16_t *)&pcm_thA, 160, (uint8_t *)dep_219, 1000); /* vertex #180 */
            }

        }
    //}



    /* * * function pool #181 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'request_oQX'
        int32_t request_oQX_0 = 0 /* WO */;
        int32_t *request_oQX_1 = &request_oQX_0;



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4008, dep_327); /* vertex #178 */
            }

            else if (perm[i] == 1) {
                opus_decoder_ctl(dep_99, 4031, request_oQX_1); /* vertex #15 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_216, 4006, 0); /* vertex #181 */
            }

        }
    //}



    /* * * function pool #182 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4009, &dep_327); /* vertex #179 */
            }

            else if (perm[i] == 1) {
                opus_encoder_destroy(dep_98); /* vertex #16 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_216, 4010, 0); /* vertex #182 */
            }

        }
    //}



    /* * * function pool #183 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4008, -1000); /* vertex #180 */
            }

            else if (perm[i] == 1) {
                opus_decoder_destroy(dep_99); /* vertex #28 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_216, 4004, 1102); /* vertex #183 */
            }

        }
    //}



    /* * * function pool #184 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    
        // initializing argument 'request_GvW'



        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4009, NULL); /* vertex #181 */
            }

            else if (perm[i] == 1) {
                opus_encoder_ctl(dep_216, 4002, 2867); /* vertex #184 */
            }

        }
    //}



    /* * * function pool #185 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    
        // initializing argument 'pcm_iJy'
        for (uint64_t i_0=0; i_0<960; ++i_0) {
            pcm_iJy[i_0] = v_DkZ[E.eat1() % 2];
        }



        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4004, dep_327); /* vertex #182 */
            }

            else if (perm[i] == 1) {
                dep_218 = opus_encode(dep_216, (const int16_t *)&pcm_iJy, 960, (uint8_t *)dep_219, 1000); /* vertex #185 */
            }

        }
    //}



    /* * * function pool #186 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_encoder_ctl(dep_326, 4004, dep_327); /* vertex #183 */
            }

            else if (perm[i] == 1) {
                opus_encoder_destroy(dep_216); /* vertex #186 */
            }

        }
    //}



    /* * * function pool #187 * * */
    //{
        opus_encoder_ctl(dep_326, 4004, dep_327); /* vertex #184 */

    //}


    /* * * function pool #188 * * */
    //{
        opus_encoder_ctl(dep_326, 4004, dep_327); /* vertex #185 */

    //}


    /* * * function pool #189 * * */
    //{
        opus_encoder_ctl(dep_326, 4004, dep_327); /* vertex #186 */

    //}


    /* * * function pool #190 * * */
    //{
        opus_encoder_ctl(dep_326, 4004, dep_327); /* vertex #187 */

    //}


    /* * * function pool #191 * * */
    //{
        opus_encoder_ctl(dep_326, 4005, &dep_327); /* vertex #188 */

    //}


    /* * * function pool #192 * * */
    //{
        // initializing argument 'request_UbN'

        opus_encoder_ctl(dep_326, 4005, NULL); /* vertex #189 */

    //}


    /* * * function pool #193 * * */
    //{
        // initializing argument 'request_raq'

        opus_encoder_ctl(dep_326, 4017, NULL); /* vertex #190 */

    //}


    /* * * function pool #194 * * */
    //{
        opus_encoder_ctl(dep_326, 4016, dep_327); /* vertex #191 */

    //}


    /* * * function pool #195 * * */
    //{
        opus_encoder_ctl(dep_326, 4016, dep_327); /* vertex #192 */

    //}


    /* * * function pool #196 * * */
    //{
        opus_encoder_ctl(dep_326, 4016, dep_327); /* vertex #193 */

    //}


    /* * * function pool #197 * * */
    //{
        opus_encoder_ctl(dep_326, 4017, &dep_327); /* vertex #194 */

    //}


    /* * * function pool #198 * * */
    //{
        opus_encoder_ctl(dep_326, 4016, dep_327); /* vertex #195 */

    //}


    /* * * function pool #199 * * */
    //{
        opus_encoder_ctl(dep_326, 4017, &dep_327); /* vertex #196 */

    //}


    /* * * function pool #200 * * */
    //{
        // initializing argument 'request_PwQ'

        opus_encoder_ctl(dep_326, 4011, NULL); /* vertex #197 */

    //}


    /* * * function pool #201 * * */
    //{
        opus_encoder_ctl(dep_326, 4010, dep_327); /* vertex #198 */

    //}


    /* * * function pool #202 * * */
    //{
        opus_encoder_ctl(dep_326, 4010, dep_327); /* vertex #199 */

    //}


    /* * * function pool #203 * * */
    //{
        opus_encoder_ctl(dep_326, 4010, dep_327); /* vertex #200 */

    //}


    /* * * function pool #204 * * */
    //{
        opus_encoder_ctl(dep_326, 4011, &dep_327); /* vertex #201 */

    //}


    /* * * function pool #205 * * */
    //{
        opus_encoder_ctl(dep_326, 4010, dep_327); /* vertex #202 */

    //}


    /* * * function pool #206 * * */
    //{
        opus_encoder_ctl(dep_326, 4011, &dep_327); /* vertex #203 */

    //}


    /* * * function pool #207 * * */
    //{
        // initializing argument 'request_OWG'

        opus_encoder_ctl(dep_326, 4013, NULL); /* vertex #204 */

    //}


    /* * * function pool #208 * * */
    //{
        opus_encoder_ctl(dep_326, 4012, dep_327); /* vertex #205 */

    //}


    /* * * function pool #209 * * */
    //{
        opus_encoder_ctl(dep_326, 4012, dep_327); /* vertex #206 */

    //}


    /* * * function pool #210 * * */
    //{
        opus_encoder_ctl(dep_326, 4012, dep_327); /* vertex #207 */

    //}


    /* * * function pool #211 * * */
    //{
        opus_encoder_ctl(dep_326, 4013, &dep_327); /* vertex #208 */

    //}


    /* * * function pool #212 * * */
    //{
        opus_encoder_ctl(dep_326, 4012, dep_327); /* vertex #209 */

    //}


    /* * * function pool #213 * * */
    //{
        opus_encoder_ctl(dep_326, 4013, &dep_327); /* vertex #210 */

    //}


    /* * * function pool #214 * * */
    //{
        // initializing argument 'request_YdY'

        opus_encoder_ctl(dep_326, 4015, NULL); /* vertex #211 */

    //}


    /* * * function pool #215 * * */
    //{
        opus_encoder_ctl(dep_326, 4014, dep_327); /* vertex #212 */

    //}


    /* * * function pool #216 * * */
    //{
        opus_encoder_ctl(dep_326, 4014, dep_327); /* vertex #213 */

    //}


    /* * * function pool #217 * * */
    //{
        opus_encoder_ctl(dep_326, 4014, dep_327); /* vertex #214 */

    //}


    /* * * function pool #218 * * */
    //{
        opus_encoder_ctl(dep_326, 4015, &dep_327); /* vertex #215 */

    //}


    /* * * function pool #219 * * */
    //{
        opus_encoder_ctl(dep_326, 4014, dep_327); /* vertex #216 */

    //}


    /* * * function pool #220 * * */
    //{
        opus_encoder_ctl(dep_326, 4015, &dep_327); /* vertex #217 */

    //}


    /* * * function pool #221 * * */
    //{
        // initializing argument 'request_iAA'

        opus_encoder_ctl(dep_326, 4007, NULL); /* vertex #218 */

    //}


    /* * * function pool #222 * * */
    //{
        opus_encoder_ctl(dep_326, 4006, dep_327); /* vertex #219 */

    //}


    /* * * function pool #223 * * */
    //{
        opus_encoder_ctl(dep_326, 4006, dep_327); /* vertex #220 */

    //}


    /* * * function pool #224 * * */
    //{
        opus_encoder_ctl(dep_326, 4006, dep_327); /* vertex #221 */

    //}


    /* * * function pool #225 * * */
    //{
        opus_encoder_ctl(dep_326, 4007, &dep_327); /* vertex #222 */

    //}


    /* * * function pool #226 * * */
    //{
        opus_encoder_ctl(dep_326, 4006, dep_327); /* vertex #223 */

    //}


    /* * * function pool #227 * * */
    //{
        opus_encoder_ctl(dep_326, 4007, &dep_327); /* vertex #224 */

    //}


    /* * * function pool #228 * * */
    //{
        // initializing argument 'request_FlD'

        opus_encoder_ctl(dep_326, 4021, NULL); /* vertex #225 */

    //}


    /* * * function pool #229 * * */
    //{
        opus_encoder_ctl(dep_326, 4020, dep_327); /* vertex #226 */

    //}


    /* * * function pool #230 * * */
    //{
        opus_encoder_ctl(dep_326, 4020, dep_327); /* vertex #227 */

    //}


    /* * * function pool #231 * * */
    //{
        opus_encoder_ctl(dep_326, 4020, dep_327); /* vertex #228 */

    //}


    /* * * function pool #232 * * */
    //{
        opus_encoder_ctl(dep_326, 4021, &dep_327); /* vertex #229 */

    //}


    /* * * function pool #233 * * */
    //{
        opus_encoder_ctl(dep_326, 4020, dep_327); /* vertex #230 */

    //}


    /* * * function pool #234 * * */
    //{
        opus_encoder_ctl(dep_326, 4021, &dep_327); /* vertex #231 */

    //}


    /* * * function pool #235 * * */
    //{
        // initializing argument 'request_YCM'

        opus_encoder_ctl(dep_326, 4025, NULL); /* vertex #232 */

    //}


    /* * * function pool #236 * * */
    //{
        opus_encoder_ctl(dep_326, 4024, dep_327); /* vertex #233 */

    //}


    /* * * function pool #237 * * */
    //{
        opus_encoder_ctl(dep_326, 4024, dep_327); /* vertex #234 */

    //}


    /* * * function pool #238 * * */
    //{
        opus_encoder_ctl(dep_326, 4024, dep_327); /* vertex #235 */

    //}


    /* * * function pool #239 * * */
    //{
        opus_encoder_ctl(dep_326, 4025, &dep_327); /* vertex #236 */

    //}


    /* * * function pool #240 * * */
    //{
        opus_encoder_ctl(dep_326, 4024, dep_327); /* vertex #237 */

    //}


    /* * * function pool #241 * * */
    //{
        opus_encoder_ctl(dep_326, 4025, &dep_327); /* vertex #238 */

    //}


    /* * * function pool #242 * * */
    //{
        // initializing argument 'request_NyQ'

        opus_encoder_ctl(dep_326, 4037, NULL); /* vertex #239 */

    //}


    /* * * function pool #243 * * */
    //{
        opus_encoder_ctl(dep_326, 4036, dep_327); /* vertex #240 */

    //}


    /* * * function pool #244 * * */
    //{
        opus_encoder_ctl(dep_326, 4036, dep_327); /* vertex #241 */

    //}


    /* * * function pool #245 * * */
    //{
        opus_encoder_ctl(dep_326, 4036, dep_327); /* vertex #242 */

    //}


    /* * * function pool #246 * * */
    //{
        opus_encoder_ctl(dep_326, 4037, &dep_327); /* vertex #243 */

    //}


    /* * * function pool #247 * * */
    //{
        opus_encoder_ctl(dep_326, 4036, dep_327); /* vertex #244 */

    //}


    /* * * function pool #248 * * */
    //{
        opus_encoder_ctl(dep_326, 4037, &dep_327); /* vertex #245 */

    //}


    /* * * function pool #249 * * */
    //{
        opus_encoder_ctl(dep_326, 4043, &dep_327); /* vertex #246 */

    //}


    /* * * function pool #250 * * */
    //{
        // initializing argument 'request_iCn'

        opus_encoder_ctl(dep_326, 4043, NULL); /* vertex #247 */

    //}


    /* * * function pool #251 * * */
    //{
        opus_encoder_ctl(dep_326, 4042, dep_327); /* vertex #248 */

    //}


    /* * * function pool #252 * * */
    //{
        opus_encoder_ctl(dep_326, 4042, dep_327); /* vertex #249 */

    //}


    /* * * function pool #253 * * */
    //{
        opus_encoder_ctl(dep_326, 4042, dep_327); /* vertex #250 */

    //}


    /* * * function pool #254 * * */
    //{
        opus_encoder_ctl(dep_326, 4043, &dep_327); /* vertex #251 */

    //}


    /* * * function pool #255 * * */
    //{
        opus_encoder_ctl(dep_326, 4042, dep_327); /* vertex #252 */

    //}


    /* * * function pool #256 * * */
    //{
        opus_encoder_ctl(dep_326, 4043, &dep_327); /* vertex #253 */

    //}


    /* * * function pool #257 * * */
    //{
        // initializing argument 'request_KEJ'

        opus_encoder_ctl(dep_326, 4041, NULL); /* vertex #254 */

    //}


    /* * * function pool #258 * * */
    //{
        opus_encoder_ctl(dep_326, 4040, 5001); /* vertex #255 */

    //}


    /* * * function pool #259 * * */
    //{
        opus_encoder_ctl(dep_326, 4040, 5002); /* vertex #256 */

    //}


    /* * * function pool #260 * * */
    //{
        opus_encoder_ctl(dep_326, 4040, 5003); /* vertex #257 */

    //}


    /* * * function pool #261 * * */
    //{
        opus_encoder_ctl(dep_326, 4040, 5004); /* vertex #258 */

    //}


    /* * * function pool #262 * * */
    //{
        opus_encoder_ctl(dep_326, 4040, 5005); /* vertex #259 */

    //}


    /* * * function pool #263 * * */
    //{
        opus_encoder_ctl(dep_326, 4040, 5006); /* vertex #260 */

    //}


    /* * * function pool #264 * * */
    //{
        opus_encoder_ctl(dep_326, 4040, 5007); /* vertex #261 */

    //}


    /* * * function pool #265 * * */
    //{
        opus_encoder_ctl(dep_326, 4040, 5008); /* vertex #262 */

    //}


    /* * * function pool #266 * * */
    //{
        opus_encoder_ctl(dep_326, 4040, 5009); /* vertex #263 */

    //}


    /* * * function pool #267 * * */
    //{
        opus_encoder_ctl(dep_326, 4040, dep_327); /* vertex #264 */

    //}


    /* * * function pool #268 * * */
    //{
        opus_encoder_ctl(dep_326, 4040, dep_327); /* vertex #265 */

    //}


    /* * * function pool #269 * * */
    //{
        opus_encoder_ctl(dep_326, 4040, dep_327); /* vertex #266 */

    //}


    /* * * function pool #270 * * */
    //{
        opus_encoder_ctl(dep_326, 4041, &dep_327); /* vertex #267 */

    //}


    /* * * function pool #271 * * */
    //{
        opus_encoder_ctl(dep_326, 4040, dep_327); /* vertex #268 */

    //}


    /* * * function pool #272 * * */
    //{
        opus_encoder_ctl(dep_326, 4041, &dep_327); /* vertex #269 */

    //}


    /* * * function pool #273 * * */
    //{
        // initializing argument 'request_jzm'

        opus_encoder_ctl(dep_326, 4031, NULL); /* vertex #270 */

    //}


    /* * * function pool #274 * * */
    //{
        // initializing argument 'request_vxI'

        opus_encoder_ctl(dep_326, 4031, NULL); /* vertex #271 */

    //}


    /* * * function pool #275 * * */
    //{
        opus_encoder_ctl(dep_326, 4028); /* vertex #272 */

    //}


    /* * * function pool #276 * * */
    //{
        // initializing argument 'pcm_hxO'
        for (uint64_t i_0=0; i_0<1920; ++i_0) {
            pcm_hxO[i_0] = 0 /* WO */;
        }

        // initializing argument 'data_xjZ'
        for (uint64_t i_0=0; i_0<1276; ++i_0) {
            data_xjZ[i_0] = 0 /* WO */;
        }

        // Dependence family #329 Definition
        dep_329 = (uint8_t *)&data_xjZ;
        dep_327 = opus_encode(dep_326, (int16_t *)&pcm_hxO, 960, (const uint8_t *)dep_329, 1276); /* vertex #273 */

    //}


    /* * * function pool #277 * * */
    //{
        // initializing argument 'pcm_MYS'
        for (uint64_t i_0=0; i_0<1920; ++i_0) {
            pcm_MYS[i_0] = 0 /* WO */;
        }

        dep_327 = opus_encode_float(dep_326, (float *)&pcm_MYS, 960, (const uint8_t *)dep_329, 1276); /* vertex #274 */

    //}


    /* * * function pool #278 * * */
    //{
        opus_encoder_destroy(dep_326); /* vertex #275 */

    //}


    /* * * function pool #279 * * */
    //{
        dep_338 = opus_repacketizer_get_size(); /* vertex #280 */

    //}


    /* * * function pool #280 * * */
    //{
        // initializing argument 'rp_CdE'
        OpusRepacketizer rp_CdE_0;

        OpusRepacketizer *rp_CdE_1 = &rp_CdE_0;

        // Dependence family #341 Definition
        dep_341 = (OpusRepacketizer *)rp_CdE_1;
        dep_341 = opus_repacketizer_init(dep_341); /* vertex #281 */

    //}


    /* * * function pool #281 * * */
    //{
        dep_341 = opus_repacketizer_create(); /* vertex #282 */

    //}


    /* * * function pool #282 * * */
    //{
        opus_repacketizer_get_nb_frames(dep_341); /* vertex #283 */

    //}


    /* * * function pool #283 * * */
    //{
        // initializing argument 'data_OcY'
        for (uint64_t i_0=0; i_0<buflen; ++i_0) {
            data_OcY[i_0] = E.buf_eat1();
        }

        // Dependence family #342 Definition
        dep_342 = (uint8_t *)data_OcY;
        opus_repacketizer_cat(dep_341, dep_342, 0); /* vertex #284 */

    //}


    /* * * function pool #284 * * */
    //{
        opus_repacketizer_cat(dep_341, dep_342, 2); /* vertex #285 */

    //}


    /* * * function pool #285 * * */
    //{
        opus_repacketizer_cat(dep_341, dep_342, 1); /* vertex #286 */

    //}


    /* * * function pool #286 * * */
    //{
        opus_repacketizer_cat(dep_341, dep_342, 1); /* vertex #287 */

    //}


    /* * * function pool #287 * * */
    //{
        opus_repacketizer_cat(dep_341, dep_342, 2); /* vertex #288 */

    //}


    /* * * function pool #288 * * */
    //{
        opus_repacketizer_cat(dep_341, dep_342, 251); /* vertex #289 */

    //}


    /* * * function pool #289 * * */
    //{
        opus_repacketizer_cat(dep_341, dep_342, 2); /* vertex #290 */

    //}


    /* * * function pool #290 * * */
    //{
        opus_repacketizer_cat(dep_341, dep_342, 100); /* vertex #291 */

    //}


    /* * * function pool #291 * * */
    //{
        opus_repacketizer_cat(dep_341, dep_342, 3); /* vertex #292 */

    //}


    /* * * function pool #292 * * */
    //{
        opus_repacketizer_cat(dep_341, dep_342, 3); /* vertex #293 */

    //}


    /* * * function pool #293 * * */
    //{
        opus_repacketizer_init(dep_341); /* vertex #294 */

    //}


    /* * * function pool #294 * * */
    //{
        opus_packet_get_samples_per_frame(dep_342, 8000); /* vertex #295 */

    //}


    /* * * function pool #295 * * */
    //{
        opus_packet_get_samples_per_frame(dep_342, 8000); /* vertex #296 */

    //}


    /* * * function pool #296 * * */
    //{
        dep_336 = opus_repacketizer_cat(dep_341, dep_342, E.eat4()); /* vertex #297 */

    //}


    /* * * function pool #297 * * */
    //{
        opus_repacketizer_get_nb_frames(dep_341); /* vertex #298 */

    //}


    /* * * function pool #298 * * */
    //{
        // initializing argument 'data_WgH'
        for (uint64_t i_0=0; i_0<buflen; ++i_0) {
            data_WgH[i_0] = E.buf_eat1();
        }

        // Dependence family #343 Definition
        dep_343 = (uint8_t *)data_WgH;
        dep_336 = opus_repacketizer_out_range(dep_341, 0, E.eat4(), dep_343, 61346); /* vertex #299 */

    //}


    /* * * function pool #299 * * */
    //{
        // initializing argument 'maxlen_Oag'
        int32_t maxlen_Oag_0 = E.eat4();

        // Dependence family #348 Definition
        dep_348 = (int32_t )maxlen_Oag_0;
        opus_repacketizer_out(dep_341, dep_343, dep_348); /* vertex #300 */

    //}


    /* * * function pool #300 * * */
    //{
        opus_packet_unpad(dep_343, dep_348); /* vertex #301 */

    //}


    /* * * function pool #301 * * */
    //{
        opus_packet_pad(dep_343, dep_348, E.eat4()); /* vertex #302 */

    //}


    /* * * function pool #302 * * */
    //{
        opus_packet_pad(dep_343, E.eat4(), E.eat4()); /* vertex #303 */

    //}


    /* * * function pool #303 * * */
    //{
        opus_packet_unpad(dep_343, E.eat4()); /* vertex #304 */

    //}


    /* * * function pool #304 * * */
    //{
        opus_multistream_packet_unpad(dep_343, dep_348, 1); /* vertex #305 */

    //}


    /* * * function pool #305 * * */
    //{
        opus_multistream_packet_pad(dep_343, dep_348, E.eat4(), 1); /* vertex #306 */

    //}


    /* * * function pool #306 * * */
    //{
        opus_multistream_packet_pad(dep_343, E.eat4(), E.eat4(), 1); /* vertex #307 */

    //}


    /* * * function pool #307 * * */
    //{
        opus_multistream_packet_unpad(dep_343, E.eat4(), 1); /* vertex #308 */

    //}


    /* * * function pool #308 * * */
    //{
        opus_repacketizer_out(dep_341, dep_343, E.eat4()); /* vertex #309 */

    //}


    /* * * function pool #309 * * */
    //{
        opus_repacketizer_out(dep_341, dep_343, 1); /* vertex #310 */

    //}


    /* * * function pool #310 * * */
    //{
        opus_repacketizer_out(dep_341, dep_343, 0); /* vertex #311 */

    //}


    /* * * function pool #311 * * */
    //{
        opus_repacketizer_init(dep_341); /* vertex #312 */

    //}


    /* * * function pool #312 * * */
    //{
        opus_repacketizer_init(dep_341); /* vertex #313 */

    //}


    /* * * function pool #313 * * */
    //{
        opus_repacketizer_cat(dep_341, dep_342, 5); /* vertex #355 */

    //}


    /* * * function pool #314 * * */
    //{
        opus_repacketizer_cat(dep_341, dep_342, 9); /* vertex #314 */

    //}


    /* * * function pool #315 * * */
    //{
        dep_338 = opus_repacketizer_out(dep_341, dep_343, 61346); /* vertex #315 */

    //}


    /* * * function pool #316 * * */
    //{
        dep_338 = opus_repacketizer_out_range(dep_341, 0, 1, dep_343, 61346); /* vertex #316 */

    //}


    /* * * function pool #317 * * */
    //{
        dep_338 = opus_repacketizer_out_range(dep_341, 1, 2, dep_343, 61346); /* vertex #317 */

    //}


    /* * * function pool #318 * * */
    //{
        opus_repacketizer_init(dep_341); /* vertex #318 */

    //}


    /* * * function pool #319 * * */
    //{
        opus_repacketizer_cat(dep_341, dep_342, 9); /* vertex #356 */

    //}


    /* * * function pool #320 * * */
    //{
        opus_repacketizer_cat(dep_341, dep_342, 3); /* vertex #319 */

    //}


    /* * * function pool #321 * * */
    //{
        dep_338 = opus_repacketizer_out(dep_341, dep_343, 61346); /* vertex #320 */

    //}


    /* * * function pool #322 * * */
    //{
        opus_repacketizer_init(dep_341); /* vertex #321 */

    //}


    /* * * function pool #323 * * */
    //{
        opus_repacketizer_cat(dep_341, dep_342, 8); /* vertex #357 */

    //}


    /* * * function pool #324 * * */
    //{
        opus_repacketizer_cat(dep_341, dep_342, 8); /* vertex #322 */

    //}


    /* * * function pool #325 * * */
    //{
        dep_338 = opus_repacketizer_out(dep_341, dep_343, 61346); /* vertex #323 */

    //}


    /* * * function pool #326 * * */
    //{
        opus_repacketizer_init(dep_341); /* vertex #324 */

    //}


    /* * * function pool #327 * * */
    //{
        opus_repacketizer_cat(dep_341, dep_342, 10); /* vertex #358 */

    //}


    /* * * function pool #328 * * */
    //{
        opus_repacketizer_cat(dep_341, dep_342, 10); /* vertex #325 */

    //}


    /* * * function pool #329 * * */
    //{
        dep_338 = opus_repacketizer_out(dep_341, dep_343, 61346); /* vertex #326 */

    //}


    /* * * function pool #330 * * */
    //{
        opus_packet_get_samples_per_frame(dep_342, 8000); /* vertex #327 */

    //}


    /* * * function pool #331 * * */
    //{
        opus_repacketizer_init(dep_341); /* vertex #359 */

    //}


    /* * * function pool #332 * * */
    //{
        dep_336 = opus_repacketizer_cat(dep_341, dep_342, dep_338); /* vertex #328 */

    //}


    /* * * function pool #333 * * */
    //{
        opus_repacketizer_out(dep_341, dep_343, 61346); /* vertex #329 */

    //}


    /* * * function pool #334 * * */
    //{
        // initializing argument 'maxlen_bZf'
        int32_t maxlen_bZf_0 = E.eat4();

        // Dependence family #352 Definition
        dep_352 = (int32_t )maxlen_bZf_0;
        opus_repacketizer_out(dep_341, dep_343, dep_352); /* vertex #330 */

    //}


    /* * * function pool #335 * * */
    //{
        opus_packet_unpad(dep_343, dep_352); /* vertex #331 */

    //}


    /* * * function pool #336 * * */
    //{
        opus_packet_pad(dep_343, dep_352, E.eat4()); /* vertex #332 */

    //}


    /* * * function pool #337 * * */
    //{
        opus_packet_pad(dep_343, E.eat4(), E.eat4()); /* vertex #333 */

    //}


    /* * * function pool #338 * * */
    //{
        opus_packet_unpad(dep_343, E.eat4()); /* vertex #334 */

    //}


    /* * * function pool #339 * * */
    //{
        opus_multistream_packet_unpad(dep_343, dep_352, 1); /* vertex #335 */

    //}


    /* * * function pool #340 * * */
    //{
        opus_multistream_packet_pad(dep_343, dep_352, E.eat4(), 1); /* vertex #336 */

    //}


    /* * * function pool #341 * * */
    //{
        opus_multistream_packet_pad(dep_343, E.eat4(), E.eat4(), 1); /* vertex #337 */

    //}


    /* * * function pool #342 * * */
    //{
        opus_multistream_packet_unpad(dep_343, E.eat4(), 1); /* vertex #338 */

    //}


    /* * * function pool #343 * * */
    //{
        opus_repacketizer_out(dep_341, dep_343, E.eat4()); /* vertex #339 */

    //}


    /* * * function pool #344 * * */
    //{
        opus_repacketizer_out(dep_341, dep_343, 1); /* vertex #340 */

    //}


    /* * * function pool #345 * * */
    //{
        opus_repacketizer_out(dep_341, dep_343, 0); /* vertex #341 */

    //}


    /* * * function pool #346 * * */
    //{
        opus_packet_pad(dep_343, 4, 4); /* vertex #342 */

    //}


    /* * * function pool #347 * * */
    //{
        opus_multistream_packet_pad(dep_343, 4, 4, 1); /* vertex #343 */

    //}


    /* * * function pool #348 * * */
    //{
        opus_packet_pad(dep_343, 4, 5); /* vertex #344 */

    //}


    /* * * function pool #349 * * */
    //{
        opus_multistream_packet_pad(dep_343, 4, 5, 1); /* vertex #345 */

    //}


    /* * * function pool #350 * * */
    //{
        opus_packet_pad(dep_343, 0, 5); /* vertex #346 */

    //}


    /* * * function pool #351 * * */
    //{
        opus_multistream_packet_pad(dep_343, 0, 5, 1); /* vertex #347 */

    //}


    /* * * function pool #352 * * */
    //{
        opus_packet_unpad(dep_343, 0); /* vertex #348 */

    //}


    /* * * function pool #353 * * */
    //{
        opus_multistream_packet_unpad(dep_343, 0, 1); /* vertex #349 */

    //}


    /* * * function pool #354 * * */
    //{
        opus_packet_unpad(dep_343, 4); /* vertex #350 */

    //}


    /* * * function pool #355 * * */
    //{
        opus_multistream_packet_unpad(dep_343, 4, 1); /* vertex #351 */

    //}


    /* * * function pool #356 * * */
    //{
        opus_packet_pad(dep_343, 5, 4); /* vertex #352 */

    //}


    /* * * function pool #357 * * */
    //{
        opus_multistream_packet_pad(dep_343, 5, 4, 1); /* vertex #353 */

    //}


    /* * * function pool #358 * * */
    //{
        opus_repacketizer_destroy(dep_341); /* vertex #354 */

    //}




    return 0;
}

// ------------------------------------------------------------------------------------------------
