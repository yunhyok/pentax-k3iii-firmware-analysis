# 2026년 11월 펌웨어 대조 기록 — K-3 Mark III (v0.5.0)

지금까지의 검수 두 번([2026-11-review.md](2026-11-review.md), [2026-11-second-review.md](2026-11-second-review.md))은 원본 펌웨어 없이 했습니다. 이번에는 실제 펌웨어 2.20을 구해, 펌웨어를 읽는 검증기를 모두 다시 돌렸습니다. 같은 펌웨어로 카메라의 색 처리 경로를 확정하고 Lightroom용 프로파일(DCP) 생성 도구를 만들었습니다. 이 문서는 그 기록입니다.

모든 작업은 PC에서 했습니다. 카메라에서 실행한 것은 없고, 이번에는 Lightroom도 실행하지 않았습니다.

## 무엇을 했나

| 대상 | 한 일 |
|---|---|
| 펌웨어 확보 | 리코 공식 다운로드 페이지에서 받은 `fwdc233b.bin`(2.20)의 해시를 `evidence.json`과 대조했습니다 |
| 기존 검증기 | 펌웨어를 읽는 검증기와 재현 스크립트 101개를 실제 펌웨어로 다시 돌리고, 출력 107개를 커밋된 JSON과 비교했습니다 |
| 저장소 결함 | `verify_bank_writers.py`의 Windows 전용 환경 변수 의존을 고쳤습니다 |
| 색 처리 | 카메라의 색 설정 루틴 전체를 에뮬레이터에서 실행해 색 처리 경로를 정하고, 펌웨어 값으로 DCP를 만드는 도구와 비교 도구를 더했습니다 |
| 문서 | 새 문서 2쪽(`analysis/firmware-color-pipeline.html`, `analysis/firmware-dcp.html`)을 쓰고, 낡은 서술이 남은 기존 문서 7쪽(첫 화면 포함)과 README를 고쳤습니다 |

## 펌웨어 확보

| 항목 | 값 |
|---|---|
| 출처 | 리코 공식 페이지 <https://www.ricoh-imaging.co.jp/english/support/digital/k-3-3.html>의 `k3III_v220.zip` |
| 패키지 `fwdc233b.bin` SHA-256 | `3c9d466b8160689867af2f58ff2cf0bf3363bc3b42daff43685a33171b91eb1a` (`evidence.json`과 같음) |
| 풀어낸 스트림 `decoded.bin` SHA-256 | `7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9` (`evidence.json`과 같음) |
| RTOS 레코드 | SHA-256 `342d2f35…f1dfb4`, 적재 주소 `0x52500000` (검증기가 고정해 둔 값과 같음) |

`inspect_firmware.py fwdc233b.bin`으로 한 번 더 풀어도 `decoded.bin`의 해시가 같았고, 만든 `inventory.json`도 같았습니다. 레코드 15개는 `inventory.json`의 오프셋과 크기로 잘라 냈고 각 해시가 `inventory.json`과 맞았습니다. 저장소의 스크립트(`rtos_catalog.py`, `package_roundtrip.py`, `verify_m0_memory.py`)도 같은 방식으로 자릅니다.

원본 펌웨어와 풀어낸 파일은 이번에도 저장소에 넣지 않았습니다.

## 기존 검증기를 펌웨어로 다시 돌린 결과

### 실행 환경

- Python 3.12.3, unicorn 2.1.4, numpy, Pillow. 여기에 저장소의 요구 사항 파일과 문서에 적힌 버전으로 `capstone==5.0.9`(모듈은 5.0.7로 보고하며, 스크립트가 확인하는 값도 이것), `z3-solver==5.3.1.0`, `pyelftools==0.33`을 더했습니다.
- `trace_raw_recipes.py`만 따로 만든 환경의 `angr==10.0.5`로 돌렸습니다.
- 작업마다 `python -B`, 제한 시간 900초, 저장소 루트(재현 폴더는 그 폴더)를 현재 폴더로 했습니다. 실행 중 저장소의 파일은 바뀌지 않았습니다.

### 숫자로 본 결과

| 항목 | 값 |
|---|---|
| 실행 횟수 | 122회. 자체 시험은 따로 셌고, 입력을 두 형태(`decoded.bin`과 잘라 낸 레코드)로 받는 스크립트는 둘 다 돌렸습니다 |
| 대상 스크립트 | 101개 (검증기와 재현 폴더의 실행 파일) |
| 판정 | 118회 통과. 첫 시도 실패 3회는 모두 실행 환경 문제였고 고친 뒤 다시 돌려 통과. 1회는 비공개 입력이 없어 실행 불가 |
| 스크립트 기준 | 101개 모두 통과. 펌웨어와 맞지 않은 결과는 0개 |
| 커밋된 JSON과 비교 | 출력 107개. 104개는 바이트까지 같음(줄바꿈만 통일). 3개는 입력 해시 필드만 다름 |
| 걸린 시간 | 모두 합해 약 11.5분. 가장 오래 걸린 것은 `tools/verify_colorspace_clip.py`(276초), `verify_colorspace_text.py`(124초), `verify_colorspace_render.py`(113초) |

입력 해시만 다른 세 개는 커밋할 때 잘라 낸 레코드로 돌렸던 스크립트입니다. 이번에 `decoded.bin`으로도 돌렸기 때문에 `input_sha256`(그리고 `verify_stubby_romfs.py`의 `disk_input_sha256_after`)가 `7ff301d5…`로 나왔습니다. 같은 스크립트를 레코드로 돌린 출력은 바이트까지 같았습니다.

| 스크립트 | 커밋된 입력 | 다시 돌린 입력 |
|---|---|---|
| `verify_m0_diagnostic_serial.py` | M0 레코드 `63dd8f3b…` | `decoded.bin` (`m0.bin` 실행은 같음) |
| `verify_stubby_load_auth.py` | LINUX 레코드 `fcb11ce8…` | `decoded.bin` (`linux.bin` 실행은 같음) |
| `verify_stubby_romfs.py` | LINUX 레코드 `fcb11ce8…` | `decoded.bin` (`linux.bin` 실행은 같음) |

### 분야별 대상

| 분야 | 개수 | 예 |
|---|---|---|
| 업데이트 과정 | 22 | `verify_update_*.py` 21개, `verify_selector_policy.py` |
| 부팅과 저장소 | 22 | `verify_m0_*`, `verify_bank_*`, `verify_boot_*`, `verify_partition_*`, `verify_stubby_*`, `verify_initfs_layout.py` 등 |
| AF | 17 | `verify_af_*.py` |
| 색·ISP·JPEG | 14 | `verify_color_math.py`, `verify_gamma_tone.py`, `verify_r2y_controls.py`, `verify_isp_*`, `verify_jpeg_quantization.py`, `tools/check_color_mode_boundaries.py`, `trace_raw_recipes.py` 등 |
| UI와 화면 자원 | 12 | `verify_colorspace_*`, `tools/verify_colorspace_*`, `tools/verify_ui_*`, `verify_icon_resources.py`, `icon_resource_probe.py` 등 |
| 재현 폴더 | 7 | `allocator-replay`, `registry-replay`, `rmw-proof`의 실행 파일과 시험, `rmw-scope`의 자산 없는 시험 |
| 기본 도구·명령 | 4 | `inspect_firmware.py`, `rtos_catalog.py`, `verify_command_analysis.py`, `verify_findings.py` |
| 재구축 | 3 | `package_roundtrip.py` + `verify_package_roundtrip.py`, `verify_numeric_kernels.py`, `tools/verify_qflag_scope.py` |

분야 구분은 이 기록에서 붙인 것입니다. `rmw-scope`는 펌웨어 없이 도는 시험만 돌았습니다(아래 "돌리지 못한 것").

### 첫 시도에서 실패한 세 개

| 스크립트 | 원인 | 조치와 결과 |
|---|---|---|
| `verify_bank_writers.py` | 4행이 Windows 전용 환경 변수 `TEMP`를 읽어 Linux·macOS에서 가져오기 단계에서 `KeyError: 'TEMP'`로 멈춤. 쓰지 않는 비공개 경로를 추가하던 줄 | `TEMP`를 정해 다시 돌려 통과(14사례, `analysis/bank-writer-checks.json`과 같음). 저장소에서 그 줄을 지운 뒤 `TEMP` 없이 다시 돌려도 14사례 통과, 출력이 같음 |
| `trace_raw_recipes.py` | `angr`가 설치되지 않음 | `angr` 10.0.5로 다시 돌려 통과, `analysis/raw-recipes.json`과 같음 |
| `tools/verify_qflag_scope.py` | `pyelftools`가 없음. 이 스크립트가 가져오는 `verify_recompiled_integration`이 모듈 첫머리에서 `elftools`를 가져옴 | `pyelftools` 0.33으로 다시 돌려 통과, `analysis/qflag-scope.json`과 같음 |

이 밖에 작업자의 명령 실수가 하나 있었습니다. `package_roundtrip.py`는 `--report`를 하위 명령 앞에만 받는데 뒤에 붙였습니다. 고친 뒤 통과했고 위 집계에는 넣지 않았습니다.

### 돌리지 못한 것

| 스크립트 | 이유 |
|---|---|
| `analysis/rmw-scope/verify.py`, `test_verify.py --decoded` | 따로 받아야 하는 `accepted31.json`(7,200,103바이트, SHA-256 `95a5ce68…`)이 저장소에도 작업 환경에도 없음. `test_verify.py`는 `--accepted31` 없이 `--decoded`만 주면 실행을 거부함. 자산 없는 시험만 통과(`asset-free-test-results.json`과 같음). 커밋된 `proof-test-results.json`과 `verified.json`은 펌웨어로 다시 확인하지 못함 |
| `tools/verify_recompiled_kernels.py`, `tools/verify_recompiled_integration.py` | 해시로 고정한 공식 Zig 0.15.2 x86-64 Windows `zig.exe`가 필요함. `recompiled-kernels.json`, `recompiled-integration.json`은 다시 확인하지 못함 |
| `tools/check_ui_render_chain.py` | Q7 패키지 `fwdc603p.bin`, `main-expanded.elf`, 실행 기록 두 개가 필요함. K-3 Mark III가 아닌 Q7 검사 |

펌웨어를 읽지 않는 검사는 대상에서 뺐습니다. Lightroom 출력·표본 사진·Adobe DNG SDK·Zig가 필요한 `tools/check_lightroom_*.py` 17개와 `check_color_engine_bridge.py`, `check_color_scene_transfer.py`, `check_color_tone_residual.py`, `check_neutral_rois.py`, 다른 저장소나 사이트 JSON을 보는 `tools/check_cross_ui_text.py`, `check_site.py`, `check_research_program.py`, 검증기가 아닌 의사 C 생성기 `decompile_sample.py`입니다.

### 함께 확인한 것

- 패키지 왕복: 풀었다가 다시 묶은 패키지가 원본과 바이트까지 같았습니다(`3c9d466b…`). `icon_resource_probe`의 ICONBIN 후보를 넣어 묶은 파일의 해시는 커밋된 후보 해시 `9531b07d…`와 같았습니다. 묶기 보고서는 `analysis/package-icon-repack.json`과, `verify_package_roundtrip.py`의 출력은 `analysis/package-roundtrip-checks.json`과 바이트까지 같았습니다.
- `rtos_catalog.py`의 TSV는 `analysis/command-analysis.tsv`의 해당 열과 957행 모두 같았습니다.
- 출력 파일이 없는 검증기(`verify_command_analysis.py`, `verify_deep_analysis.py`, `verify_findings.py`)는 기대값을 코드 안에 두거나 커밋된 TSV·JSON과 스스로 비교합니다. 모두 종료 코드 0이었습니다.

### 읽을 때 주의할 점

- `tools/verify_ui_surface_producers.py`, `verify_ui_viewport_producers.py`, `verify_colorspace_clip.py`는 커밋된 JSON을 "어느 주소를 읽을지" 알려 주는 틀로 씁니다. 값은 모두 펌웨어에서 다시 계산하고 결과 해시가 커밋된 파일과 같아야 통과합니다. 값은 재현했지만 주소의 선택은 커밋된 파일과 독립이 아닙니다.
- `--compare` 옵션이 있는 검증기(`verify_af_adaptive_input`, `verify_af_driver_pwm`, `verify_af_motor_fields`, `verify_af_pwm_parameters`, `verify_af_state_producers`, `verify_nr_candidates`, `verify_colorspace_clip`)는 그 옵션을 켜서 스크립트 스스로도 같은지 확인하게 했습니다.

## 고친 결함과 발견한 문제

| 파일 | 문제 | 처리 |
|---|---|---|
| `verify_bank_writers.py` | `sys.path.insert(0,str(Path(os.environ['TEMP'])/'pentax-neon-emulation'))` 한 줄이 Windows의 `%TEMP%`를 요구해, 문서에 적힌 명령이 Linux·macOS에서 실패함 | 그 줄을 지웠습니다. 쓰지 않는 비공개 경로였습니다. `TEMP` 없이 14사례 통과, 출력은 커밋된 JSON과 같음 |
| `trace_raw_recipes.py` | `angr`가 필요하지만 의존성으로 적혀 있지 않음 | 고치지 않고 기록만 합니다 |
| `tools/verify_qflag_scope.py` | 가져오는 모듈 때문에 `pyelftools`가 필요하지만 해당 문서에 의존성으로 적혀 있지 않음 | 고치지 않고 기록만 합니다 |

## 새 색 처리 작업

### 한 일

카메라가 JPEG을 만들 때 색 처리 하드웨어에 넣는 값을 펌웨어가 어떻게 만드는지, 루틴 전체를 실행해 확인했습니다. 이전에는 함수 하나씩을 손으로 만든 매개변수로 돌렸습니다. 이번에는 카메라 자신의 설정 채움 코드가 메뉴 수준의 값(Custom Image, 채도·색상·키·대비·하이라이트·섀도, 색공간, 노출 이득)에서 15개 단계의 설정을 만듭니다. 19개 모드 모두 펌웨어 assert 없이 끝났습니다. 운영체제 기능은 대역으로 바꿨고, 샤프닝 단계와 단계 뒤의 두 루틴은 건너뛰었으며, 나머지 입력은 0입니다.

레지스터의 뜻은 같은 프로세서 계열의 공개 SDK 헤더(<https://github.com/killsmm/m10v_mono>의 `im_r2y.h`, `__fr2y6a.h`)에서 가져왔습니다. 형제 기종 GR III의 공개 분석(<https://github.com/judgem00/gr3-look-editor>)이 같은 단계 목록과 에뮬레이션 방법을 적어 두었고, 에뮬레이터의 배치는 그것을 따랐습니다. 그 분석이 `CC0CTL`의 비트 하나를 밝기 혼합 단계라고 본 부분은 공개 헤더(소수점 위치 필드)와 맞지 않아 헤더를 따랐습니다.

### 정해진 것

| 항목 | 내용 | 수준 |
|---|---|---|
| 색 행렬 출력의 색공간 | AdobeRGB에서만 곱하는 행렬이 표준 "선형 sRGB → 선형 Adobe RGB (1998)" 행렬과 0.000277 안에서 같음. 그래서 앞 단계의 출력은 선형 sRGB | 확인 |
| 행렬의 크기 | 19개 모드 모두 소수점 위치 1, 각 행의 합이 정확히 256(= 1.0). 이전 문서의 "행의 합 2 × gain"에서 기본 gain이 128 | 확인 |
| 감마 곡선 | 256점 16비트 곡선, 하드웨어 표는 그 상위 10비트. AdobeRGB에서는 sRGB 표를 sRGB 식으로 풀고 지수 2.2(563/256)로 다시 부호화한 표와 10비트 한 단계의 0.947 안에서 같음. 그래서 곡선의 출력은 sRGB 부호화 값 | 확인 |
| YC 변환 | 색상 0에서 모든 모드가 JFIF/BT.601 정수 행렬 | 확인 |
| 색차 억제 | 모든 모드에서 켜져 있고 밝기를 기준으로 Cb·Cr 이득을 낮춤 | 확인 |
| 노출 배율 | DNG의 BaselineExposure를 계산하는 루틴의 식(상수 1448, 2048, 65536 등). 공개 표본 #4678에서 식의 값 −0.8371, DNG 태그 −0.8373 | 정적 분석 |
| 다축 색 보정 | 모든 모드가 같은 기본 설정, 모든 화소가 영역 0. 하드웨어 식은 공개되지 않았고 모델에 넣지 않음 | 미확인 |

계수 값과 곡선 값은 공개하지 않습니다. 근거 JSON에는 해시와 구조만 있습니다.

### 새 도구와 근거 파일

| 파일 | 내용 |
|---|---|
| `tools/k3iii_tuning_emulator.py` | 색 설정 루틴을 Unicorn 에뮬레이터에서 실행 |
| `tools/firmware_color_model.py` | 펌웨어 색 단계의 계산과 DCP 태그로의 변환 |
| `tools/build_firmware_dcp.py` | Custom Image 16종의 DCP 생성 |
| `tools/check_firmware_color.py` | 모드별 해시·구조·공개 표준 대조를 근거 JSON과 비교 |
| `tools/compare_camera_jpeg.py` | 같은 RAW의 카메라 JPEG과 색차 비교 |
| `tools/check_dcp_against_sdk.py`, `tools/dng_sdk_harness.cpp` | LookTable·톤 곡선 계산을 Adobe DNG SDK의 참조 루틴과 대조(SDK 소스는 사용자가 준비, 하네스에 Adobe 코드 없음) |
| `tools/profile_bridge.py` | 선택 태그 네 개 추가: `ProfileEmbedPolicy`, `ProfileCopyright`, `BaselineExposureOffset`, `DefaultBlackRender` |
| `tests/test_firmware_color_model.py` | 단위 시험 11개. `PENTAX_K3III_DECODED`를 주면 펌웨어 실행 시험 하나가 더 돎 |
| `analysis/firmware-color-pipeline.json` | 모드별 레지스터 해시와 구조, 공개 표준과의 대조 |
| `analysis/firmware-color-validation.json` | 카메라 JPEG 비교, 프로파일과 모델의 차이, SDK 대조, 배제한 가설, 한계 |

필요한 패키지는 생성·검사 도구가 `unicorn==2.1.4`와 `numpy`, 비교 도구가 여기에 `rawpy`와 `opencv-python-headless`, SDK 대조가 `g++`와 `numpy`입니다.

### 카메라 JPEG과 비교한 결과

방법: RAW의 2×2 화소를 하나로 묶은 절반 크기 영상, 촬영 때의 화이트밸런스, 16×16 화소 블록 평균. JPEG에는 렌즈 보정과 크롭이 있어 위치만 맞췄습니다(ECC 아핀 정합). 색과 톤의 매개변수는 하나도 맞추지 않았습니다. "모델"은 펌웨어의 색 단계를 직접 계산한 값이고, "DCP"는 만든 프로파일을 DNG SDK의 참조 처리 순서로 적용한 값입니다.

| 표본 | 모드·색공간 | 평탄 블록 모델 / DCP | 전체 블록 모델 / DCP | 평탄 블록 수 |
|---|---|---|---|---|
| raw.pixls.us #4678 (CC0, 카메라 펌웨어 1.01, ISO 100) | Natural · AdobeRGB | 0.852 / 0.904 | 0.928 / 0.985 | 17,639 |
| Imaging Resource 표본 (카메라 펌웨어 1.10, ISO 100) | Bright · sRGB | 1.382 / 1.381 | 1.295 / 1.296 | 5,240 |

값은 CIEDE2000 평균입니다. 대조 실험으로 Bright 표본에 Natural 설정을 적용하면 채도 높은 평탄 블록의 값이 0.76에서 3.81로 커졌습니다.

- 프로파일과 모델의 차이: Natural, 무작위 색 60,000개에서 내부 평균 0.048(최대 1.44), 색역 가장자리 평균 0.046(최대 2.23). LookTable이 없으면 평균 1.65였습니다.
- SDK 대조: DNG SDK 1.7.1의 `RefBaselineHueSatMap`, `RefBaselineRGBTone`을 컴파일해 프로파일 다섯 개를 돌린 결과가 Python 모델과 sRGB 8비트 기준 평균 0.017~0.020, 최대 0.41만 달랐습니다. SDK 전체는 빌드하지 않았습니다(libjxl 필요). 프로파일 읽기, 행렬, 노출 처리는 이 대조에 들지 않습니다.
- 이전에 실제 Lightroom으로 잰 값(K-3 Mark III 행렬 후보 2.028, Camera Bright 1.421, Adobe Standard 1.944)은 Lightroom TIFF의 픽셀 중앙값입니다. 위 값과 재는 방법이 달라 순위를 매기지 않습니다.

### 한계

- 장면 둘, 모두 ISO 100. 표본을 찍은 카메라 펌웨어는 1.01과 1.10이고 분석한 것은 2.20입니다. 다른 ISO와 조명은 재지 않았고, 지원하는 Custom Image 16종 가운데 14종은 카메라 JPEG과 비교하지 않았습니다.
- Lightroom은 실행하지 않았습니다. 실제 Lightroom은 자체 처리 버전과 노출 처리를 쓰므로 얼마나 가까운지는 Lightroom에서 재야 합니다.
- 두 표본 모두 섀도 보정이 자동이었습니다. 에뮬레이션의 톤 조절 표는 항등이고, 카메라 JPEG은 무채색 영역에서 모델보다 8비트 한두 단계 밝았습니다. 원인은 풀지 못했습니다.
- 총 노출이 음수인 #4678에서는 참조 처리가 LookTable 뒤에 어둡게 하므로 채도 높은 색의 차이가 커졌습니다(DCP 1.00, 모델 0.42).
- 화이트밸런스 이득과 색 행렬 앞 단계(검정 레벨, 디모자이크)는 추적하지 않았고 비교에는 RAW의 촬영 값을 썼습니다. DNG의 ColorMatrix 행 배율은 공개 표본 한 대에서 얻었습니다.
- 섀도·하이라이트 보정, 선명도, 디지털 필터, HDR, 렌즈 보정, 노이즈 감소, 샤프닝은 프로파일에 들어가지 않습니다.
- 저장소에는 생성 도구만 있고 프로파일 파일, 펌웨어, 계수 표는 없습니다.

## 기존 문서에서 고친 서술

새 결과와 어긋나게 된 문장만 고쳤습니다. 이전 실험의 수치와 식은 그대로 두었습니다.

| 문서 | 원래 내용 | 고친 내용 |
|---|---|---|
| `guide-lightroom.html` | "이 연구에서 받을 수 있는 카메라 색 프로파일은 아직 없습니다", "펌웨어의 값을 DCP로 옮기기: 미확인" | 펌웨어 DCP 생성 도구와 비교 결과(Natural 0.90, Bright 1.38)를 요약·현황 표·새 절·읽는 순서 맨 앞에 넣고 한계를 같은 자리에 적음. 이전 실측은 "이전 방식"으로 남김 |
| `lightroom-bridge.html` | 현황 표 "펌웨어의 값을 DCP로 옮기기 — 미확인" | K-3 Mark III에서 확인한 내용과 남은 Lightroom 측정으로 바꿈. 지원 태그 표에 새 태그 네 개 추가 |
| `guide-color.html` | "픽셀이 실제로 계산되는 식과 순서는 확인하지 못했습니다", 색좌표 미확인 | 단계 순서는 공개 헤더 기준(모델), 행렬 출력은 선형 sRGB(확인)로 바꾸고 새 문서를 지도·현황·읽는 순서에 넣음 |
| `color-algorithms.html` | 미확인 목록의 "행렬이 받는 RGB의 원색과 전달함수", "실기 RAW·JPEG와의 일치" | 본문은 그대로 두고 "추가 확인" 상자를 더함. 미확인 문장은 문서 범위로 한정하고 상자를 가리킴 |
| `color-lightroom.html`, `pipeline-report.html` | "DNG 규격이 정한 방향의 행렬로 바꿀 수 없습니다", "카메라 JPEG와 색을 맞춘 모드별 프로파일은 아직 없습니다" | 과거형으로 바꾸고 새 문서를 가리키는 문장을 붙임 |
| `index.html`, `README.md` | Lightroom 목표의 상태 "배포할 프로파일은 아직 없음" | 생성 도구, 비교 결과, Lightroom 미측정을 적음. README에 새 도구 표와 펌웨어 대조 요약을 넣음 |

## 검사

- 단위 시험 243개(지난 기록의 232개에 펌웨어 색 모델 시험 11개를 더함)가 통과했습니다. 펌웨어를 실제로 실행하는 시험 하나는 `PENTAX_K3III_DECODED`가 없어 건너뛰었습니다.
- 위 검증기 실행의 전체 표와 명령은 작업 환경의 실행 기록에 있고 저장소에는 넣지 않았습니다.
