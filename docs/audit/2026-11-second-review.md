# 2026년 11월 2차 검수 기록 — K-3 Mark III (v0.4.0)

v0.3.0부터 v0.3.2까지 새 문서가 올라온 뒤, 그 문서들을 검수하고 사이트 전체의 문장을 다시 다듬었습니다. 이 문서는 그 결과입니다. 1차 기록은 [2026-11-review.md](2026-11-review.md)에 있습니다.

## 무엇을 했나

| 대상 | 한 일 |
|---|---|
| v0.3.x에서 새로 올라온 문서 35쪽 (Lightroom 12쪽, AF 9쪽, UI 7쪽, 재구축 4쪽, 부팅·업데이트·시작 3쪽) | 근거 JSON·검증기·테스트와 대조한 뒤, 다른 문서와 같은 형식(요약 → 확인한 범위 → 배경 → 본문 → 한계 → 재현 → 출처)으로 다시 쓰고 그림을 넣었습니다 |
| Markdown 메모 `docs/research/RAW_NR_FEASIBILITY_20261113_KO.md` | 검수해 사이트 문서 `analysis/raw-nr-feasibility.html`로 옮겼습니다. 메모 파일에는 안내 문구와 링크만 남겼습니다 |
| 내용이 덧붙은 기존 문서 6쪽 | 덧붙은 부분을 근거와 대조하고 문서 구조에 맞춰 넣었습니다 |
| 주제 안내 문서 | Lightroom, AF, UI 안내 문서를 새로 썼습니다. 부팅, 업데이트, 재구축 안내에는 새 문서를 넣었습니다 |
| 세 기종 연구 본부 (`research-program.html`) | 기종별 카드를 한 줄에 하나씩 놓고, 긴 본문을 목록으로, 근거 문서 목록을 접이식으로 바꿨습니다. 문장도 다듬었습니다 |
| 기존 문서 45쪽 | 내용은 그대로 두고 문장만 다듬었습니다 |

모두 94쪽이고 그림은 181개입니다.

### 한계

이번에도 원본 펌웨어 없이 검수했습니다. 문서가 공개된 근거 JSON·검증기와 맞는지 확인했고, 검증기를 펌웨어에 다시 돌리지는 않았습니다. Lightroom과 Adobe DNG SDK를 다시 실행하지도 않았습니다. 펌웨어 없이 도는 검사(단위 시험 232개, `tools/check_site.py`, `tools/check_research_program.py --verify-sources`, 재현 폴더 네 곳의 자체 시험)는 통과했습니다.

`analysis/research-checkpoint.html`이 요약하는 연구 여덟 건은 근거가 아직 공개되지 않았습니다. 그 문서의 수치는 `research-checkpoint.json`과 같은지만 확인했고, 결과 자체는 검수할 수 없었습니다.

## Lightroom 색 프로파일을 릴리스에 넣지 않은 이유

"연구가 Lightroom용 카메라 색 프로파일을 낼 만큼 진척됐는가"를 따로 검토했습니다. 결론은 아직 아닙니다. 그래서 v0.4.0에는 색 프로파일을 넣지 않았습니다.

**지금 있는 것**

- 펌웨어에서 꺼낸 값으로 만든 프로파일은 어느 기종에도 없습니다. `lightroom-bridge.html`의 현황 표가 적은 대로, 펌웨어에서 찾은 색 행렬을 DNG가 정의하는 방향의 행렬로 바꾸는 방법을 아직 모릅니다.
- 세 기종의 "행렬 시험 프로파일"은 공개 DNG 파일에 카메라가 적어 둔 태그(ColorMatrix와 광원)를 그대로 옮긴 파일입니다. 태그는 여섯 개뿐이고 새로운 색 정보가 없습니다.
- K-3 II에는 여기에 톤 곡선을 더한 후보가 하나 있습니다(`profiles/pentax-k3ii-1376-composed-tone-offline-v1.dcp`). 차트 한 장의 무채색 패치 여섯 개로 맞춘 곡선입니다.

**카메라 JPEG와 비교한 결과** (숫자가 작을수록 카메라 JPEG에 가깝습니다)

| 기종 | 연구 후보 | Adobe가 Lightroom에 넣어 둔 프로파일 | 조건 |
|---|---|---|---|
| K-3 II, 차트 #1376 | 톤 후보 1.786 (최대 6.113) | Camera Natural 1.620, Adobe Standard 3.640 | 패치 24개의 ΔE00 평균, ProPhoto TIFF 기준. 후보는 Lightroom 16.0, Adobe 프로파일은 15.6에서 측정. 후보의 곡선을 맞춘 바로 그 차트 |
| K-3 II, 장면 #1363 | 톤 후보 4.057 | Camera Natural 3.948, Adobe Standard 5.026 | 영역 24곳의 평균. 곡선을 맞출 때 쓰지 않은 야외 장면, 다른 바디 |
| K-3 Mark III, 스튜디오 장면 | 행렬 시험 2.028 / 4.922 | Camera Bright 1.421 / 2.636, Adobe Standard 1.944 / 4.548 | 픽셀 ΔE00의 중앙값 / 90백분위수. 영역 55곳, 80,662픽셀 |
| Q7, 스튜디오 장면 | 행렬 시험 2.211 / 4.787 | Adobe Standard 2.803 / 5.955 | 같은 지표. 영역 39곳, 56,927픽셀. 이미지 전체의 위치 맞춤은 기준을 넘겨 일부 영역만 비교 |

출처는 `lightroom-render-comparison.json`(`gamut.renders`의 ProPhoto 값. sRGB TIFF 기준으로는 Camera Natural 1.615, Adobe Standard 3.476), `lightroom-composed-tone.json`, `lightroom-studio-reference.json`, `color-scene-transfer.html`입니다.

**판정의 근거**

1. K-3 II와 K-3 Mark III에서는 Lightroom에 이미 들어 있는 Adobe의 카메라 매칭 프로파일이 연구 후보보다 카메라 JPEG에 가깝습니다. 후보를 배포해도 쓰는 사람이 얻는 것이 없습니다.
2. Q7에서는 후보가 Adobe Standard보다 가까웠지만, 장면 한 장의 일부 영역에서 얻은 값입니다. 두 결과 사이에 화이트밸런스 표시값이 달랐고(5100 K/−17과 4900 K/−7), 후보는 DNG의 태그를 옮긴 것일 뿐입니다.
3. 연구가 스스로 정한 통과 기준을 채우지 못했습니다. `research-program.json`의 색 검증 단계는 "학습에 쓰지 않은 동일 촬영 쌍과 복수 조명"에서의 비교와 "실험 전에 정한 허용치"를 요구합니다. 지금은 기종마다 장면 하나, 조명 하나입니다. K-3 II 톤 후보는 자신의 허용값 가운데 하나를 넘겼습니다(주황 패치 0.892, 허용값 0.75. `delivery_tolerances_met`이 false).
4. 표본을 찍은 펌웨어가 분석한 펌웨어와 다릅니다(K-3 Mark III 1.10과 2.20, K-3 II 1.10과 1.12, Q7 1.00과 1.01).
5. K-3 II 톤 후보는 실제 Lightroom 출력에서 두 패치의 파란 채널 순서가 뒤집혔습니다. 원인은 찾지 못했습니다.

저장소의 `profiles/` 폴더에 있는 K-3 II 톤 후보 파일은 실험 기록으로 남겨 둔 것입니다. 정확한 색을 얻으려고 설치할 프로파일이 아닙니다. 이 내용은 새 문서 [`analysis/guide-lightroom.html`](https://yunhyok.github.io/pentax-k3iii-firmware-analysis/analysis/guide-lightroom.html)에 독자용으로 정리했습니다.

## 고친 내용

수치·주소·해시는 근거와 거의 모두 맞았습니다. 고친 것은 주로 뒤 문서가 이미 해결했는데 앞 문서에 남아 있던 서술, 빠진 한계, 형식입니다.

### 사실 관계가 틀렸거나 낡았던 곳

| 문서 | 원래 내용 | 고친 내용 | 근거 |
|---|---|---|---|
| `ui-port-contract.html` | 현황 표: "K-3 Mark III: 글자의 최종 표면 복사와 완성된 화면 픽셀 — 미확인" | 글자 비트맵 생성과 합성 표면 전송은 원본 코드로 실행했습니다(확인·모델). viewport와 표면 경로는 정적 분석입니다. 미확인은 "실제 메뉴 순서로 글자를 찍는 연결, 최상위 생산자, 완성된 화면 픽셀"로 좁혔습니다 | `colorspace-text.html`, `colorspace-clip.html`, `ui-viewport-producers.json` |
| `ui-port-contract.html` | 접점 표: "미확인: 문자열의 실제 내용, 글꼴" | "미확인: 언어 0 밖의 문자열·글꼴, 최종 합성" | `colorspace-render.html` |
| `stubby-load-auth.html` | "wrapper 안의 간접 호출(0xa46)이 무엇을 부르는지 확인하지 못했다" | ROMFS 시험에서 mount가 등록한 callback `0xe5c`로 가는 것을 원본 실행으로 확인했습니다 | `stubby-romfs-checks.json`의 `cases[2].critical_trace` |
| `stubby-load-auth.html` | "상위 적재 경로와의 연결, DTB 보조 함수 내부는 남은 경계" | 로더 연속 실행이 DTB 경로 찾기와 4바이트 기록까지 원본으로 실행했고, 보드 주소 읽기에서 멈췄습니다 | `stubby-loader-checks.json`의 `cases[1].executed_ranges` |
| `update-bank-selection.html` | 요약에서 "수정한 이미지가 받아들여지거나 부팅된다는 증거가 아닙니다"라는 한계 문장이 지워져 있었음 | 되살렸습니다 | v0.2.0 판 |
| `af-drive-architecture.html` | 나눗셈 호출자가 `0x8902` 다음에 하는 일이 빠져 있었음 | 보통은 이어서 `0x8900` 작성 함수를 부르고, 대체 조건일 때만 다른 경로로 갑니다 | `verify_af_packet_8902.py` 320–338행, 사례 19–26 |
| `guide-rebuild.html` | "모든 확인은 원본 기계어를 에뮬레이터로 실행하거나 파일 바이트를 대조하는 방식" | RMW 증명은 분석자가 옮긴 모형을 검사 도구로 확인한 것이어서, 그 방식을 문장에 더했습니다 | `rmw-proof/verified.json`의 `native_replay: false` |
| `color-tone-residual.html` | 위치 맞춤의 최대 잔차 "2.707픽셀" | 2.706픽셀 | `color-tone-residual.json` (2.70645…) |
| `color-tone-residual.html` | "보정 후 7번 패치가 최대"만 적음 | 보정 뒤에 오차가 오히려 커진 패치가 여섯 개(6·7·9·11·12·15번)라는 사실을 보탰습니다 | 같은 JSON의 패치별 값 |
| `lightroom-composed-tone.html` | 사전 기준을 채우지 못했다는 판정이 본문 뒤쪽에만 있음. 오탈자 "0.25 이했습니다" | 판정을 요약·소개글 맨 앞에 올렸습니다. "0.25 이하였습니다" | `lightroom-composed-tone.json`, `tests/test_lightroom_composed_tone.py` |
| `raw-nr-feasibility.html` (옛 메모) | K-3 II 사용설명서 High-ISO NR 링크가 PDF 46쪽(초점 설정 화면)을 가리킴 | PDF 44쪽 (인쇄된 42쪽) | 리코 K-3 II 사용설명서 |
| `research-program.json`, `research-checkpoint.html` | 작업 도구의 사용량에 관한 내부 메모 문장이 공개 문서에 들어 있음 | 삭제 | 공개 문서와 무관한 내용 |
| Lightroom 문서 여섯 쪽, `README.md` | "색 비교는 K-3 II 사진 한 장뿐", "K-3 Mark III와 Q7은 측정하지 않음", "시험 DCP 8개" 같은 낡은 서술 | 현재 상태로 고치고 뒤 문서로 연결했습니다 | `lightroom-studio-baseline.html`, `lightroom-studio-reference.html`, `color-scene-transfer.html`, `lightroom-composed-tone.html` |

### 형식을 바로잡은 곳

- 새 문서 여러 쪽이 페이지 안에 자체 스타일을 넣거나 정의되지 않은 클래스를 쓰고 있었습니다. 공용 스타일로 바꿨습니다.
- `color-tone-residual.html`의 외부 SVG 그림은 색이 고정되어 어두운 화면에서 보이지 않았습니다. 문서 안의 그림으로 다시 그렸습니다.
- `af-motor-fields.html`에 닫는 태그가 두 번 들어가 있었습니다.
- PowerShell 전용 명령을 일반 명령으로 바꿨습니다.
- 표의 열 이름 "원본 명령"(`af-driver-pwm.html`)은 실제로 실행한 명령 수여서 그렇게 고쳤습니다.
- `research-checkpoint.html`: 해시는 로컬 근거를 가리킬 뿐이고 요약만으로는 결과를 재현할 수 없다는 점을 경고 상자로 올렸습니다.

## 문장 다듬기

한국어 윤문 규칙(humanize-korean)을 적용했습니다. 내용 명사·수치·코드는 그대로 두고 문형만 고치는 방식입니다.

- 연결어미 바로 뒤의 쉼표("~하고, ~")를 뺐습니다. 기존 문서에서 752곳입니다.
- 문단 375개와 `research-program.json`의 문자열 18개를 고쳐 썼습니다. 긴 문장을 나누고, "A가 아니라 B입니다" 식 대구와 "~라는 뜻입니다" 식 종결을 직접 서술로 바꿨습니다. 고친 문단마다 태그, 숫자·주소·영문 식별자, 코드가 원문과 같은지 기계로 확인한 뒤 반영했습니다.
- 목록의 "라벨 — 설명"에 쓴 대시 86개를 쌍점이나 마침표로 바꿨습니다.

| 지표 (본문 산문 기준) | 이전 (90쪽) | 이후 (94쪽) |
|---|---|---|
| 연결어미 뒤 쉼표 | 999 | 1 |
| 90자를 넘는 문장 | 181 | 111 |
| "~라는 뜻입니다" 류 종결 | 25 | 5 |
| "A가 아니라 B" 류 대구 | 72 | 30 |
| 설명을 잇는 대시 | 266 | 1 |

남은 긴 문장은 대부분 해시, 파일 경로, 링크나 수치의 나열입니다. 남은 대구는 오해를 바로잡는 문장이라 그대로 두었습니다. 개편 전 문서에 있던 16진수 주소와 해시는 새 문서에 모두 남아 있습니다.

## 판단이 필요한 항목

**근거 JSON에서 찾지 못했거나 서로 다른 것** (원문대로 두었습니다)

- `lightroom-as-shot.html`: "다른 수학 커널 대조, 실수 25개, 최대 차이 6.66×10⁻¹⁶"은 `lightroom-as-shot.json`에 없습니다. 비슷한 기록은 `lightroom-pef-neutral.json`에 있고 값은 4.44×10⁻¹⁶입니다.
- `color-scene-transfer.html`: "두 RAW는 펌웨어 1.10이 같고 바디 식별자가 다르다"는 링크된 JSON에서 찾지 못했습니다.
- `af-joint-control.html`: 본문은 "원본 명령 700개와 35개 명령 구간"이라고 하는데 공개 JSON의 `source_ranges`는 39개입니다. 비공개 대조와 범위가 다를 수 있습니다.
- `selector-policy.html`: "M0 레코드 길이가 working BOOTPARA `+0x0c`에 반영"된다고 하지만, JSON에서 보이는 것은 헤더 버퍼 `+0x0c`에 92,164를 저장한 것뿐입니다.
- `rmw-scope/report.html`은 "나머지 44바이트"라고 쓰고, `research-program.json`과 `research-checkpoint.json`은 "8바이트 증명, 40바이트 남음"이라고 씁니다. 인접한 4바이트의 증명이 아직 공개되지 않아서 생긴 차이입니다. 문서에 그렇게 적었습니다.
- `registry-replay/report.html`: InitTask 키 `0x80005b37`은 개편 전 문서에만 있습니다.
- `af-state-producers.html`: 근거 JSON의 확인 주소에 `0x52f0b45c`가 있는데 무엇을 쓰는 명령인지 JSON만으로는 알 수 없습니다.
- `af-adaptive-input.html`: 타이머가 `0x1e0000a4`를 읽는다는 내용은 `research-checkpoint.html`에서 왔고, 그 근거는 공개되지 않았습니다.

**해석의 수위**

- `colorspace-text.html`, `cross-ui-text.html`: 커버리지 값 1에서 글자색 0.4, 배경 0.6으로 섞입니다. 값과 덮인 정도가 비례하는지는 확인하지 못해 그런 해석을 쓰지 않았습니다. 값 0xff 칸의 색이 부분 커버리지의 글자색과 다른 점도 설명하지 못했습니다.
- ReloadTimer, Udc라는 이름은 Fujitsu 계열 마이크로컨트롤러의 주변장치 이름(16비트 리로드 타이머, 업다운 카운터)과 같습니다. 1차 자료로 이 칩과의 대응을 확인하지 못해 본문에 넣지 않았습니다.
- `guide-ui.html`의 지도에서 "다시 그리기 요청 → 행 그리기" 사이를 미확인으로 표시한 것은 두 근거를 묶은 판단입니다(입력 문서가 표시 갱신 입구에서 멈춘 것, viewport JSON의 `actual_menu_reachability_verified: false`).
- `ui-surface-producers.html`의 접이식 표에서 두 주소의 뜻은 JSON의 구간 이름에서 추론했습니다.
- `rmw-scope/report.html`의 레코드 역할 이름(head, length, tail)은 분석상 해석입니다.
- `stubby-romfs.html`: wrapper의 첫 인자가 공개 소스 `_filesystem_read`의 rootfstype에 해당한다고 단정하지 않고 구조가 같다는 데까지만 적었습니다.

**외부 자료를 열지 못한 것**

- Adobe의 DNG 규격 PDF와 SDK 배포 페이지 일부가 열리지 않았습니다. ActiveArea의 좌표 순서, 블랙 레벨 차감 설명, ProfileToneCurve 태그 정의는 SDK 소스의 줄 번호 인용과 2차 자료로 대신 확인했습니다. Q7 저장소의 검수에서는 같은 규격 PDF를 열어 쪽 번호까지 확인했습니다.

**이미 게시한 릴리스 노트**

- `docs/releases/v0.3.1.md`, `v0.3.2.md`에는 "독립 검토", "인계" 같은 작업 과정의 말이 있습니다. 게시된 노트는 고치지 않았습니다.

## 근거 JSON·스크립트에서 발견한 문제

`research-program.json`의 문장과 내부 메모만 고쳤습니다. 아래는 손대지 않았습니다. 결과에 영향을 주는 것은 없습니다.

| 파일 | 문제 |
|---|---|
| `analysis/lightroom-as-shot.json` | 문서가 말하는 다른 수학 커널 대조 기록이 없음 |
| `analysis/allocator-replay/`, `registry-replay/`, `rmw-proof/`, `rmw-scope/`의 `document-qa.json` | 개편 전 HTML을 기준으로 한 문서 검사 기록(해시, `browser_rendered: false`)이라 지금 문서와 맞지 않음 |
| `analysis/raw-test-inputs.json`, `analysis/lightroom-bridge.json` | "not run" 항목이 이후 수행된 실험을 반영하지 않음 (1차 기록에서도 지적) |
| `analysis/lightroom-tone-comparison.json`과 `analysis/lightroom-tone-coordinates.json` | 같은 비교(ACR3 곡선 대 곡선 없음)의 패치 ΔE00이 다름(평균 0.000448 대 0.000269). Lightroom 버전이 15.6과 16.0으로 다르고, 뒤쪽 기록에는 측정 영역이 적혀 있지 않음 |
| `analysis/lightroom-composed-tone.json` | "후보 파일은 로컬에서 생성"이라는 경고 문구가 있지만 파일은 `profiles/`에 커밋되어 있음 |

## 외부 자료로 확인한 사실 (요약)

- Adobe DNG SDK 1.7.1 Build 2768은 2026-10-13 배포, DNG 규격 최신판은 1.7.1.0. `dng_validate`의 Stage 1·2·3 순서.
- CIEDE2000: ISO/CIE 11664-6:2022, Sharma·Wu·Dalal(2005)의 시험 자료. PCHIP 보간은 단조성을 지킵니다(SciPy 문서).
- LibRaw 0.22.0은 PENTAX 태그 0x0201을 촬영 때의 화이트밸런스로 읽습니다.
- 리코의 초점 구동 표기(Body AF, SDM, DC, PLM)와 K-3 Mark III 지원 문서의 KAF2·KAF3·KAF4 설명. PWM의 동작(TI DRV8235 데이터시트).
- 알파 혼합의 기본식(Porter·Duff 1984), UTF-16의 정의(Unicode), 클리핑(Microsoft GDI 문서), 프레임 버퍼(Linux 커널 문서), 색인 색(W3C PNG).
- ARM의 STREX 반환값과 MPIDR 읽기, `linux,initrd-end`가 범위에 포함되지 않는 끝 주소라는 점(Linux 커널 문서), Stubby 1.60.1 공개 소스의 ROMFS 읽기와 전압 계산.
- Photons to Photos의 PDR 도표에서 노이즈 감소 표시가 처음 나타나는 감도는 K-3 Mark III ISO 200, K-3 II ISO 1600입니다. 내려받은 페이지의 SHA-256이 `raw-nr-public-evidence.json`의 기록과 같습니다. 리코의 "multi-dimensional image space filtering" 설명, 2.20에서 2.13 이전으로 되돌릴 수 없다는 안내도 확인했습니다.
