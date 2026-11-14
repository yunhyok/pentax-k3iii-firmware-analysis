# PENTAX K-3 Mark III 펌웨어 2.20 분석

리코가 배포한 K-3 Mark III 펌웨어 `fwdc233b.bin`을 풀어, 카메라가 부팅하고 사진의 색을 만들고 초점을 맞추고 메뉴를 그리는 코드를 추적한 연구 기록입니다. K-3 II·Q7과 함께 진행하는 세 기종 연구의 중심 저장소이기도 합니다.

**문서는 여기서 읽습니다 → [https://yunhyok.github.io/pentax-k3iii-firmware-analysis/](https://yunhyok.github.io/pentax-k3iii-firmware-analysis/)**

<img src="assets/photos/pentax-k3iii.jpg" alt="PENTAX K-3 Mark III" width="320">

<sub>사진: © Jörgens.Mi/Wikipedia, [CC BY-SA 3.0](https://creativecommons.org/licenses/by-sa/3.0/), [Wikimedia Commons](https://commons.wikimedia.org/wiki/File:Pentax_K3III_jm136770_ji.jpg) (크기 축소). 자세한 출처는 [assets/photos/CREDITS.md](assets/photos/CREDITS.md).</sub>

> **먼저 알아 둘 점.** 모든 분석은 PC에서 했습니다. 수정한 펌웨어를 카메라에 설치하거나 실행한 적이 없습니다. 이 저장소에는 카메라에 넣을 수 있는 펌웨어가 없고 원본 펌웨어와 제조사 코드도 없습니다.

## 무엇을 알아냈나

세 기종(K-3 Mark III, K-3 II, Q7)을 같은 네 가지 질문으로 조사합니다. K-3 Mark III에서 온 지점은 다음과 같습니다.

| 질문 | 알아낸 것 | 아직 모르는 것 |
|---|---|---|
| 펌웨어를 고쳐서 다시 만들 수 있는가 | 무변경 재포장이 배포본과 바이트까지 같음. 색 행렬 함수를 C로 다시 짜서 넣은 후보가 원본 코드의 헤더·체크섬 검사를 통과 | 카메라가 수정본을 받아들이는지, 부팅하는지, 부팅 단계의 인증 |
| Lightroom에서 카메라의 색을 낼 수 있는가 | 카메라의 색 설정 루틴 전체를 에뮬레이터에서 실행해 색 처리 경로를 정함. 펌웨어에서 읽은 색 표(JSON)와 Custom Image 16종의 프로파일(DCP)을 공개. 펌웨어 없이 같은 계산을 하는 엔진이 에뮬레이터와 10,087개 사례에서 모두 같음. 카메라가 기록한 JPEG과 PC에서 비교한 평탄 블록 평균 ΔE00은 Natural 0.90, Bright 0.91 (맞춘 매개변수 없음) | 실제 Lightroom에서의 결과 (위 값은 Adobe DNG SDK의 참조 처리 순서로 계산). 장면 둘·ISO 100·두 모드만 비교. 나머지 14종은 카메라 출력과 비교하지 않음. 이전에 실제 Lightroom으로 잰 시험용 프로파일은 Adobe의 Camera Matching보다 가깝지 않았고, 재는 방법이 달라 두 결과를 바로 견줄 수 없음 |
| AF 동작을 바꿀 수 있는가 | AF 계산의 기본 연산, 렌즈 능력에 따른 구동 방식 분기, 요청 큐와 완료 통지 | 실제 렌즈 통신·모터 이동·초점 정확도 |
| 이 카메라의 화면을 다른 기종에 옮길 수 있는가 | 색공간 선택 화면의 선택·확정·취소와 입력 처리, 아이콘 자원 형식 | 실제 버튼 입력에서 LCD까지. 이식은 시작하지 않음 |

세 기종을 나란히 비교한 현황은 [세 기종 연구 본부](https://yunhyok.github.io/pentax-k3iii-firmware-analysis/analysis/research-program.html)에 있습니다.

## 문서 안내

**새 조사:** [펌웨어로 확정한 색 처리 경로](https://yunhyok.github.io/pentax-k3iii-firmware-analysis/analysis/firmware-color-pipeline.html)와 [펌웨어 값으로 만드는 색 프로파일](https://yunhyok.github.io/pentax-k3iii-firmware-analysis/analysis/firmware-dcp.html)을 정리했습니다. 실제 펌웨어 2.20으로 카메라의 색 설정 코드를 실행해 Lightroom용 프로파일을 만드는 방법과, 카메라 JPEG과 비교한 결과·한계를 담았습니다.

**프로파일:** Custom Image 16종의 프로파일(DCP)을 [프로파일](https://yunhyok.github.io/pentax-k3iii-firmware-analysis/analysis/color-profiles.html) 절에서 받을 수 있습니다. 모드마다 설명 문서가 있습니다. 프로파일은 각 모드의 출고 설정으로 만들었습니다. 펌웨어 없이 프로파일을 만드는 도구의 설계와 검사는 [프로파일 생성 프로그램 타당성 검토](https://yunhyok.github.io/pentax-k3iii-firmware-analysis/analysis/profile-maker-feasibility.html)에 있습니다.

**펌웨어 대조:** 그동안의 검수는 펌웨어 없이 했습니다. 이번에 리코 공식 페이지에서 받은 펌웨어 2.20(해시가 `evidence.json`과 같음)으로 펌웨어를 읽는 검증기와 재현 스크립트 101개를 다시 돌렸고 101개 모두 결과를 재현했습니다. 비공개 입력, Windows 전용 컴파일러, Q7 펌웨어가 필요한 네 개는 돌리지 못했습니다. 기록은 [docs/audit/2026-11-firmware-verification.md](docs/audit/2026-11-firmware-verification.md)에 있습니다.

**이전 조사:** [RAW 노이즈 감소를 끌 수 있는가](https://yunhyok.github.io/pentax-k3iii-firmware-analysis/analysis/raw-nr-feasibility.html)를 정리했습니다. K-3 III ISO 200·K-3 II ISO 1600의 공개 NR 감지 근거와 제어 후보, 아직 넘지 못한 검증 관문을 담았습니다. 설치용 NR 패치가 아니라 연구 결과입니다.

주제마다 안내 문서가 있습니다. 안내 문서에서 전체 그림을 본 뒤 세부 문서로 들어가면 읽기 쉽습니다.

| 주제 | 안내 문서 |
|---|---|
| 시작하기 | [개요](https://yunhyok.github.io/pentax-k3iii-firmware-analysis/) · [펌웨어 구조와 하드웨어](https://yunhyok.github.io/pentax-k3iii-firmware-analysis/analysis/firmware-structure.html) · [세 기종 연구 본부](https://yunhyok.github.io/pentax-k3iii-firmware-analysis/analysis/research-program.html) · [용어집](https://yunhyok.github.io/pentax-k3iii-firmware-analysis/glossary.html) |
| 부팅과 저장소 | [부팅과 저장소 안내](https://yunhyok.github.io/pentax-k3iii-firmware-analysis/analysis/guide-boot.html) |
| 펌웨어 업데이트 과정 | [업데이트 과정 안내](https://yunhyok.github.io/pentax-k3iii-firmware-analysis/analysis/guide-update.html) |
| 펌웨어 재구축 | [재구축 안내](https://yunhyok.github.io/pentax-k3iii-firmware-analysis/analysis/guide-rebuild.html) |
| RTOS 명령과 셸 | [RTOS 명령 안내](https://yunhyok.github.io/pentax-k3iii-firmware-analysis/analysis/guide-rtos.html) |
| 카메라 내부 색 처리 | [색 처리 안내](https://yunhyok.github.io/pentax-k3iii-firmware-analysis/analysis/guide-color.html) |
| Lightroom 색 프로파일 (세 기종) | [Lightroom 색 프로파일 안내](https://yunhyok.github.io/pentax-k3iii-firmware-analysis/analysis/guide-lightroom.html) · [K-3 Mark III 색 프로파일 모음](https://yunhyok.github.io/pentax-k3iii-firmware-analysis/analysis/color-profiles.html) |
| AF와 렌즈 제어 | [AF와 렌즈 제어 안내](https://yunhyok.github.io/pentax-k3iii-firmware-analysis/analysis/guide-af.html) · [세 기종 AF 기초 비교](https://yunhyok.github.io/pentax-k3iii-firmware-analysis/analysis/af-foundations.html) |
| UI와 화면 자원 | [UI와 화면 자원 안내](https://yunhyok.github.io/pentax-k3iii-firmware-analysis/analysis/guide-ui.html) · [UI 이식 설계 (세 기종)](https://yunhyok.github.io/pentax-k3iii-firmware-analysis/analysis/ui-port-contract.html) |

문서는 결과마다 얼마나 확실한지를 네 가지로 표시합니다: **확인**(원본 코드를 PC 에뮬레이터에서 실행해 관측), **정적 분석**(코드를 읽어서 판단), **모델**(실물 대신 넣은 값), **미확인**. 자세한 뜻은 [개요의 “검증 수준 읽는 법”](https://yunhyok.github.io/pentax-k3iii-firmware-analysis/#levels)에 있습니다.

GitHub에서 HTML 파일을 열면 소스가 보입니다. 오프라인으로 읽으려면 저장소를 내려받아 `index.html`을 브라우저로 여세요.

## 직접 확인하기

펌웨어 없이, 공개된 문서·근거 파일·도구가 서로 맞는지 검사합니다. Python 3.12와 아래 패키지가 필요합니다.

`tools/check_site.py`와 `tools/site_chrome.py`를 실행하려면 Git으로 복제한 저장소가 필요합니다. 릴리스 ZIP은 압축을 풀고 `index.html`을 브라우저에서 열어 읽을 수 있습니다.

```bash
python -m pip install unicorn==2.1.4 numpy==1.26.4 Pillow==10.4.0 tifffile==2023.4.12 opencv-python-headless==4.11.0.86 scikit-image==0.24.0
python inspect_firmware.py --self-test
python verify_findings.py --self-test
python inspect_adobe_profiles.py --self-test
python -m unittest discover -s tests -v
python tools/check_research_program.py
python tools/check_site.py
```

리코 공식 사이트에서 받은 `fwdc233b.bin`이 있으면 압축 해제부터 다시 해 볼 수 있습니다.

```bash
python inspect_firmware.py fwdc233b.bin --output-dir .private/my-decode
python verify_findings.py .private/my-decode/decoded.bin
```

주제별 검증기(`verify_*.py`, `tools/*.py`)의 사용법은 각 문서의 “재현 방법” 절에 있습니다.

### 펌웨어 값으로 색 프로파일 만들기 (K-3 Mark III)

펌웨어에서 읽은 색 표는 `analysis/k3iii-color-tables.json`에 있습니다. 행렬 34개, 채도·색상 행렬 묶음, 감마 기준 곡선, 채도 억제 값, 조색 오프셋, DNG 행렬 표, Custom Image별 출고 설정, Auto Select 장면 표가 들어 있습니다. Custom Image 16종의 DCP는 `profiles/k3iii/k3iii-firmware-<mode>.dcp`에 있습니다. 하나가 약 950 KB이고 16개를 합하면 약 15 MB입니다. 펌웨어 파일은 저장소에 없습니다.

펌웨어 없이 프로파일을 만들려면 `tools/make_k3iii_profile.py`를 씁니다. 이 도구는 색 표 JSON만 읽습니다. 펌웨어 사본(`fwdc233b.bin`, 2.20)이 있으면 에뮬레이터 경로로 같은 프로파일을 만들고 결과를 확인할 수 있습니다. 같은 PC에서 두 경로로 만든 16개 파일은 바이트까지 같습니다.

| 도구 | 하는 일 | 필요한 것 |
|---|---|---|
| `tools/make_k3iii_profile.py` | 색 표 JSON만으로 DCP를 만듦(`--mode`, `--all --output-dir`, `--from-raw RAW`, 설정 6종 `--saturation --hue --key --contrast --highlight --shadow`, `--neutral`, `--color-space`, `--look-matrix` + `--name`, `--color-matrix-from`, `--table`). 주지 않은 설정은 카메라의 출고 값을 씀 | numpy |
| `tools/k3iii_color_engine.py` | 펌웨어와 같은 정수 계산을 하는 색 엔진. 색 표 JSON만 읽음 | numpy |
| `tools/check_color_engine.py` | 엔진을 펌웨어 에뮬레이터와 대조해 `analysis/k3iii-color-engine-checks.json`과 비교. `--decoded`가 없으면 공개 해시만 검사 | numpy (`--decoded`에는 unicorn 2.1.4) |
| `tools/check_profile_accuracy.py` | 공개한 프로파일 각각을 색 모델과 대조해 `analysis/k3iii-profile-accuracy.json`과 비교 | numpy |
| `tools/export_color_tables.py` | 풀어 둔 펌웨어 이미지에서 색 표를 읽어 JSON을 씀 | numpy |
| `tools/build_profile_pages.py` | DCP 16개, `analysis/color-profiles.html`, 모드별 문서 16개, `analysis/k3iii-profile-data.json`을 만듦(`--check`) | numpy |

펌웨어 사본으로 확인하는 도구는 다음과 같습니다.

| 도구 | 하는 일 | 필요한 것 |
|---|---|---|
| `tools/k3iii_tuning_emulator.py` | 카메라의 색 설정 루틴(ImageTuning)을 CPU 에뮬레이터에서 실행해 색 레지스터 값을 읽음 | unicorn 2.1.4, numpy |
| `tools/firmware_color_model.py` | 펌웨어 색 단계(색 행렬 → 감마 → YC 변환 → 채도 억제)를 계산하고 DCP 태그로 옮기는 모델 | numpy |
| `tools/build_firmware_dcp.py` | Custom Image 16종의 DCP를 만듦(`--mode` 또는 `--all`, 슬라이더·색공간 옵션) | unicorn 2.1.4, numpy |
| `tools/check_firmware_color.py` | 모드별 레지스터 해시와 구조, 공개 표준과의 대조를 `analysis/firmware-color-pipeline.json`과 비교 | unicorn 2.1.4, numpy |
| `tools/compare_camera_jpeg.py` | 같은 RAW의 카메라 JPEG과 펌웨어 모델·DCP의 색차(ΔE00)를 계산. RAW의 설정 기록(메이커노트 태그 0x0247)을 읽어 씀(`--contrast` 등으로 바꿀 수 있음) | unicorn 2.1.4, numpy, rawpy, opencv-python-headless |
| `tools/check_dcp_against_sdk.py`, `tools/dng_sdk_harness.cpp` | DCP의 LookTable·톤 곡선 계산을 Adobe DNG SDK의 참조 루틴과 대조. SDK 소스는 따로 받아야 하며 하네스에는 Adobe 코드가 없음 | g++, numpy |
| `tools/profile_bridge.py` | JSON으로 DCP를 만드는 기존 도구. `ProfileEmbedPolicy`, `ProfileCopyright`, `BaselineExposureOffset`, `DefaultBlackRender` 태그를 추가로 받음 | 표준 라이브러리 |

```bash
python tools/make_k3iii_profile.py --all --output-dir my-profiles
python tools/make_k3iii_profile.py --from-raw IMGP0001.PEF --output IMGP0001.dcp
python tools/check_color_engine.py --compare analysis/k3iii-color-engine-checks.json
python tools/check_profile_accuracy.py --compare analysis/k3iii-profile-accuracy.json
```

```bash
python -m pip install unicorn==2.1.4 numpy rawpy opencv-python-headless
python inspect_firmware.py fwdc233b.bin --output-dir .private/my-decode
python tools/build_firmware_dcp.py .private/my-decode/decoded.bin --all --output-dir my-profiles
python tools/check_firmware_color.py .private/my-decode/decoded.bin --compare analysis/firmware-color-pipeline.json
python tools/compare_camera_jpeg.py IMGP0001.PEF --jpeg IMGP0001.JPG --decoded .private/my-decode/decoded.bin
```

근거 파일은 `analysis/firmware-color-pipeline.json`(모드별 해시와 구조), `analysis/firmware-color-validation.json`(비교 결과와 한계), `analysis/k3iii-color-engine-checks.json`(엔진과 에뮬레이터 대조: 10,087개 사례, 불일치 0), `analysis/k3iii-profile-accuracy.json`(프로파일과 색 모델 대조)입니다. 단위 테스트는 펌웨어 없이 도는 `tests/test_color_engine.py`와 `tests/test_firmware_color_model.py`이고, 환경 변수 `PENTAX_K3III_DECODED`에 `decoded.bin` 경로를 주면 펌웨어를 실제로 실행하는 시험도 돕니다. Lightroom에서의 결과는 아직 재지 않았습니다.

## 저장소 구성

| 경로 | 내용 |
|---|---|
| `index.html`, `glossary.html`, `analysis/*.html` | 분석 문서 |
| `analysis/*.json`, `analysis/*.tsv`, `evidence.json` | 측정 결과(근거 파일) |
| `analysis/research-program.json` | 세 기종 현황 데이터. `tools/build_research_program.py`가 HTML로 만듭니다 |
| `inspect_firmware.py`, `verify_*.py`, `tools/` | 분석·검증 도구 |
| `profiles/k3iii/` | Custom Image 16종의 Lightroom 프로파일(DCP) |
| `source/` | 재배포 조건을 확인한 공개 소스 사본과, 직접 작성한 재구성 C 코드(`source/reconstructed/`) |
| `tests/` | 단위 테스트 |
| `assets/`, `site-map.json`, `tools/site_chrome.py`, `tools/check_site.py` | 문서 스타일, 문서 목록, 내비게이션 갱신·검사 도구 |
| `docs/audit/` | 문서 검수 기록 (무엇을 확인했고 무엇을 고쳤는지, 판단이 필요한 항목) |
| `docs/releases/` | 릴리스 노트 |

문서를 추가하거나 순서를 바꿀 때는 `site-map.json`을 고친 뒤 `python tools/site_chrome.py`를 실행하면 모든 문서의 상단 메뉴와 이전·다음 링크가 갱신됩니다.

## 릴리스

[릴리스 목록](https://github.com/yunhyok/pentax-k3iii-firmware-analysis/releases)에서 문서와 도구를 묶은 ZIP과 SHA-256을 받을 수 있습니다. `docs/releases/<태그>.md`를 main에 병합하면 릴리스 워크플로가 검사를 돌린 뒤 릴리스를 만듭니다.

## 공개 범위

공개 자료는 직접 작성한 분석·검증 도구, 측정 결과, 재배포 조건을 확인한 공개 소스 사본입니다. 펌웨어에서 읽은 색 표(`analysis/k3iii-color-tables.json`)와 Custom Image 16종의 프로파일(`profiles/k3iii/`)도 공개합니다. 펌웨어 없이 도는 색 엔진과 프로파일 생성 도구도 저장소에 있습니다. 원본 펌웨어 파일과 제조사 코드의 디컴파일 결과는 공개하지 않습니다. 리코의 펌웨어 이용 조건에는 복제, 역분석, 양도를 제한하는 조항이 있습니다. 색 표를 공개한 것은 저장소 소유자의 결정입니다. 제조사의 비공개 소스나 전체 펌웨어 빌드 환경을 복구한 것이 아닙니다. 사진의 라이선스는 [assets/photos/CREDITS.md](assets/photos/CREDITS.md)에 따로 적었습니다.

## 관련 저장소

- [K-3 II 펌웨어 분석](https://github.com/yunhyok/pentax-k3ii-firmware-analysis)
- [Q7 펌웨어 분석](https://github.com/yunhyok/pentax-q7-firmware-analysis)
