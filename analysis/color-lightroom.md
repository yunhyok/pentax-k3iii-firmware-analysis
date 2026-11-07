# K-3 Mark III v2.20 컬러모드와 Lightroom 활용 연구

조사일은 2026-11-07이다. 대상은 이 저장소에서 해시를 검증한 K-3 Mark III v2.20이다. 제조사의 색 표현 설명, 펌웨어에서 확인한 선택값·처리 경로, Adobe 파일에서 측정한 구조를 각각 출처와 함께 기록한다.

## 컬러모드 목록

실제 셸 선택 테이블 `0x5387a414`의 22개 레코드와, 공통 모드 값을 리소스 인덱스로 바꾸는 `0x53a767d8`의 32바이트를 대조했다. 일부 도움말에는 SATOBI 등을 연속 번호로 적어 놓았으나 실제 처리기는 아래 번호를 사용한다. 아래의 enum은 공통 설정의 내부 값이며 EXIF 태그 값으로 해석하면 안 된다. 색 표현은 제조사 설명의 요약이다. [선택값·리소스 주소·해시](color-resources.json) · [리코 일반 모드 설명](https://www.ricoh-imaging.co.jp/english/products/custom_image/) · [계절 모드 설명](https://www.ricoh-imaging.co.jp/english/products/custom_image/special/index.html)

| 모드 | 내부 enum → 리소스 인덱스 | 색·톤 특성 | 이 PC의 Adobe Camera Matching |
|---|---|---|---|
| Auto Select | 0 → 0 | 장면에 따라 실제 모드 선택 | 고정 프로파일 대응에 하위 선택 필요 |
| Bright | 2 → 2 | 청색·녹색과 선명한 색 표현 | 설치 확인 |
| Natural | 1 → 1 | 균형 잡힌 채도·계조 | 설치 확인 |
| Portrait | 3 → 3 | 피부의 분홍·마젠타 표현 | 설치 확인 |
| Landscape | 4 → 4 | 청색·녹색·노랑 강조 | 설치 확인 |
| Vibrant · miyabi | 5 → 5 | 선명한 적·녹·청, 마젠타 계열 | 설치 확인 |
| Radiant · pop | 6 → 6 | 높은 채도·대비·키 | 추가 매칭 필요 |
| Muted · honoka | 7 → 7 | 낮은 채도·대비, 높은 키 | 추가 매칭 필요 |
| Flat | 8 → 8 | 후처리용 낮은 대비 | 추가 매칭 필요 |
| Bleach Bypass | 9 → 9 | 낮은 채도·키, 높은 대비 | 추가 매칭 필요 |
| Reversal Film | 10 → 10 | 깊은 검정과 고유한 톤 곡선 | 추가 매칭 필요 |
| Monochrome | 11 → 11 | 흑백, 색 필터·토닝 조절 | 필터·토닝별 매칭 필요 |
| Cross Processing | 12 → 12 | 선택·랜덤 결과에 따른 색 이동 | 하위 선택별 매칭 필요 |
| SATOBI | 23 → 26 | 시안 청색, 탁한 노랑, 바랜 빨강 | 추가 매칭 필요 |
| HARUBENI | 24 → 27 | 봄의 분홍·빨강 강조 | 추가 매칭 필요 |
| KATEN | 25 → 28 | 여름 하늘의 풍부한 청색 | 추가 매칭 필요 |
| KYUSHU | 26 → 29 | 절제된 주홍·황색과 깊은 청록 | 추가 매칭 필요 |
| FUYUNO | 27 → 30 | 낮은 채도, 푸른 흰색과 높은 키 | 추가 매칭 필요 |
| Gold | 31 → 31 | 밝은 영역의 노랑과 어두운 영역의 청색 | 추가 매칭 필요 |

내부 테이블에는 enum 28·29·30을 각각 인덱스 32·33·34로 보내는 Monochrome Standard·Hard·Soft도 있다. 테이블 존재만으로 컬러 센서 K-3 Mark III에서 이 세 항목을 메뉴로 선택할 수 있다고 판단할 수는 없다. Auto Select와 Cross Processing은 선택값을 바꾸는 경로가 있어 위에 보인 직접 인덱스의 기본 레코드만으로 최종 결과를 정할 수 없다. [모드별 관측 범위](color-resources.json)

SATOBI는 v1.31, KATEN은 v1.50, KYUSHU는 v1.60, FUYUNO는 v1.70, HARUBENI는 v1.80, Gold는 v2.10에서 추가됐다. 대상 v2.20은 이전 기능을 포함한다. 계절 모드의 카메라 선택에는 렌즈 조건이 있다. KATEN은 HD D FA 21 또는 HD DA 15, KYUSHU는 FA 43·DA 21·40·70, FUYUNO는 FA 31·DA 35 Macro, HARUBENI는 FA 77·DA 20–40 계열이 공식 목록에 있다. 정확한 렌즈 버전은 해당 버전의 제조사 목록을 따른다. [공식 변경 이력과 호환 렌즈](https://www.ricoh-imaging.co.jp/english/support/digital/k-3-3.html)

## RAW 현상에서 JPEG 모듈까지

RAW 현상 함수 `0x52e74574`는 진단 문자열로 `CreateRawDevelopRecipeSequence`에 대응한다. 여기서 `0x52e73044`를 통해 종류·연산 번호·추가 인수를 갖는 레시피 항목을 쌓는다. RAW 현상의 UI 선택값은 `0x529cb350`에서 공통 설정값으로 변환된다. 예를 들어 UI 값 6이 SATOBI의 공통 enum 23으로 바뀌고, UI 값 0은 촬영 당시 공통 설정을 읽는다. [추가 분석 구간과 호출 위치](deep-evidence.json)

후속 분석에서는 레시피 소비자·모듈 큐·가상 호출을 연결하고, 레시피 operation 4/5가 Develop1/2, 7이 JPEG, 8이 StoreImage임을 확인했다. Develop은 파생 ImageTuning 구현을 거쳐 앞서 찾은 색·감마·톤 함수를 호출한다. 팩토리 번호는 이보다 1 크므로 서로 혼용하면 안 된다. [정확한 번호·레시피·호출 관계](color-algorithms.md)

| 추적 단계 | 확인한 코드·데이터 | 남은 연결 |
|---|---|---|
| RAW 현상 레시피 구성 | `0x52e74574 → 0x52e73044`, 소비자 `0x52e9e520`와 모듈 제출, 네 입력의 246개 항목 확인 | 나머지 연산의 의미와 전체 실동작 |
| Custom Image 선택값 변환 | `0x529cb350`, 공통 설정 `+0x264e` | 현상 상태에 따른 모든 파라미터 전달 |
| ImageTuning 설정 | `0x53127b28`에서 모드 읽기, `0x53129e78`에서 리소스 선택 | WB·센서 보정과의 수치 조합 |
| 색·톤 파라미터 계산 | `0x5312a8fc`에서 색 행렬·감마·톤 등의 설정 함수 호출 | 하드웨어 픽셀 처리 순서와 각 단계의 비트 폭 |
| JPEG 처리 모듈 생성·실행 | 팩토리 8번 `0x52e615fc → 0x52e5eea0`, 레시피 operation 7이 `0x52e5eca0` 실행 및 하위 객체 제출에 연결 | 버퍼 평면·픽셀 형식과 하위 압축 드라이버 |

`0x5312a8fc`의 설정 호출에서는 ColorMatrix, MultiAxial, 휘도 노이즈 감소, YCbCrMatrix, ColorReference, 좌표 스케일, 색 LPF, 에지 강조, YCbCr 연산, Gamma, ToneControl, 리사이즈·필터 설정을 확인했다. 팩토리에는 PixelCorrect, WbCalc, RawWbCalc, Develop1·2, BackResize, RawCodec 등의 생성 경로도 있다. 이 증거는 생산용 RAW 현상·영상 설정·JPEG 모듈의 위치를 특정한다. 설정 함수의 호출 순서를 센서 픽셀이 하드웨어를 통과하는 순서로 그대로 해석할 수는 없다. 전체 RAW→JPEG 버퍼 흐름과 완료 콜백 연결은 일부 미해결이다. [바이트 해시와 직접 호출 증거](deep-evidence.json)

## 펌웨어 색 변환 데이터

부팅 코드의 리터럴 `RTOS+0x450`은 원본 `0x53ce7d40`에서 RAM `0x54500000`으로 `0x65a80`바이트를 옮기도록 지정한다. 이 대응으로 초기화된 RAM의 리소스 포인터를 BIN의 원본 바이트까지 역추적했다. ColorMatrix·MultiAxial·YCbCrMatrix의 포인터 배열은 각각 3행×35항이며 조사한 세 행의 값은 동일했다. 다만 실행 후 RAM이 변경되는지는 별도 관측이 필요하다. [원본 오프셋과 83개 관측 구간](color-resources.json) · [독립 검증기](../verify_deep_analysis.py)

**후속 추적에 따른 명칭 정정:** 이전에 ColorReference라고 기록한 `0x54561b58` 표는 `0x5313f5c8 → 파라미터 +0x18 → 0x53132698`로 이어지며, 할당 시 진단 이름은 `m_YCbCrMatrixTuning`이다. 실제 ColorReference는 파라미터 `+0x28`을 사용한다. 기존 주소·해시·모드 매핑은 유지하고 공개 JSON의 해당 키를 `ycbcrmatrix`·`ycbcrmatrix_pointer`로 바로잡았다. [상세 알고리즘과 호출 근거](color-algorithms.md)

ImageTuning의 선택 함수 `0x53129e78`은 모드 인덱스를 계산하고 `0x5313f570`, `0x5313f59c`, `0x5313f5c8`에서 세 종류의 리소스 포인터를 얻는다. ColorMatrix 디스크립터의 선두 필드는 공통 행렬, 모드별 행렬, 필터별 행렬 포인터 배열을 가리킨다. 3×3 행렬의 각 원소는 signed 16-bit이고 곱셈 함수 `0x5312cd40`은 내적에 `4096`을 더한 뒤 13비트를 이동하고 하위 16비트를 저장한다. 따라서 단위 계수는 `8192`인 Q13이다. 자연색 모드의 개별 행렬은 단위행렬이지만 앞에 공통 행렬과 다른 색 처리 단계가 있다. [선택 레코드와 피연산자 해시](color-resources.json)

위 행렬 함수의 실제 ARM 바이트를 Unicorn 2.1.4의 Cortex-A7 모델에서 실행했다. 단위행렬, 부호 혼합, 0, int16 최댓값·최솟값과 난수 행렬을 포함한 21개 사례에서 독립 계산과 일치했다. 32비트 누산의 wraparound, 반올림 상수, 논리 우측 이동과 16비트 저장을 반영했다. 이 실험은 행렬 산술을 검증하며 센서 RGB·XYZ·작업 RGB 중 어느 좌표계인지까지 증명하지 않는다. [실행 결과](numerical-checks.json) · [재현 코드](../verify_numeric_kernels.py)

Gold는 별도의 R·G·B 곡선 `0x53c1557c`, `0x53c1598c`, `0x53c15d8c`를 고르며 각 곡선의 확인된 구간은 uint16 256항이다. Reversal Film은 일반 감마 생성 경로와 다른 분기를 사용한다. 이번에 저장한 자료에는 실제 모드별 행렬과 이 곡선들의 원본 바이트가 포함된다. 공개 자료에는 주소·크기·해시를 기록했다. 전 단계의 보정값, 보간 규칙, 좌표계와 출력 단계가 함께 확인되어야 정확한 Adobe 변환으로 이어질 수 있다. [곡선과 모드별 리소스 색인](color-resources.json)

## Adobe에서 이미 제공하는 다섯 모드

조사 PC의 Adobe 공용 CameraProfiles 폴더에서 K-3 Mark III 전용 **Camera Bright, Camera Natural, Camera Portrait, Camera Landscape, Camera Vibrant** DCP를 확인했다. 각 파일의 `UniqueCameraModel`은 `PENTAX K-3 Mark III`다. Adobe 공식 지원표에도 이 모델의 DNG·PEF 및 Camera Matching 지원이 명시되어 있다. 최소 지원 버전은 Camera Raw 13.3, Lightroom 4.3, Lightroom Classic 10.3이다. [Adobe 카메라 지원표](https://helpx.adobe.com/camera-raw/desktop/dng-and-file-formats/camera-raw-plug-supported-cameras.html)

이 다섯 파일은 각각 다음 구조를 갖는다. 수치는 설치된 파일의 IFD를 직접 읽어 확인했다. 배열의 실제 계수는 공개 자료에서 제외했다. [파일별 크기·태그·SHA-256](adobe-profiles.json) · [읽기 전용 검사 도구](../inspect_adobe_profiles.py)

| 항목 | 측정 결과 |
|---|---|
| ColorMatrix1·2 | 각 3×3, 다섯 모드 간 동일 |
| ForwardMatrix1·2 | 각 3×3, 다섯 모드가 서로 다른 값 |
| CalibrationIlluminant1·2 | 17, 21 |
| ProfileToneCurve | FLOAT 128개, 입력·출력 64쌍 |
| ProfileLookTableDims | 색상 36 × 채도 8 × 명도 16 |
| ProfileLookTableData | FLOAT 13,824개 = 4,608격자 × 3성분 |
| ProfileLookTableEncoding | 1 |

톤 곡선과 LookTable은 각각 Bright·Landscape가 같은 바이트를 쓰고, Natural·Portrait·Vibrant가 또 다른 같은 바이트를 쓴다. 그러나 ForwardMatrix는 다섯 모드 모두 다르다. 따라서 이 파일들의 차이를 톤 곡선이나 LUT 하나만으로 설명할 수 없다. Adobe Standard DCP도 별도로 확인했으며, 그 파일의 HueSatMap 크기는 90×30×1이고 두 조명용 데이터가 들어 있다. [태그별 해시](adobe-profiles.json)

Lightroom에서 K-3 Mark III의 원본 DNG 또는 PEF를 열고 프로파일 브라우저의 Camera Matching 그룹에서 위 모드를 선택하는 경로를 사용할 수 있다. Adobe는 Camera Matching을 카메라 JPEG의 색·톤에 대응시키는 프로파일로 설명한다. 설치 파일의 존재와 구조는 확인했으며, 실제 RAW를 열어 각 프로파일을 적용하는 UI·픽셀 비교는 수행하지 않았다. [Adobe 프로파일 설명](https://helpx.adobe.com/camera-raw/desktop/edit-and-enhance-images/tone-and-color/adjust-color-rendering-camera-camera.html)

## 추가 모드를 옮길 수 있는 조건

DCP는 카메라 모델별 센서 색 변환, 조명, HSV 보정표, 톤 곡선을 기술한다. Adobe 규격의 LookTable은 노출 보정 이후, 톤 곡선 이전에 적용하는 HSV 변환이며, 펌웨어의 ISP용 배열을 그대로 넣으려면 좌표계·정규화·적용 순서가 모두 대응해야 한다. 이번 파일 검사에서 발견한 Adobe의 36×8×16 크기는 Adobe 파일의 구조를 뜻한다. 펌웨어의 표 크기에 대한 근거로 사용할 수는 없다. [DNG 1.7.1 규격, 49–57·100–104쪽](https://helpx.adobe.com/content/dam/help/en/camera-raw/digital-negative/jcr_content/root/content/flex/items/position/position-par/download_section_733958301/download-1/DNG_Spec_1_7_1_0.pdf)

추가적인 색 표현은 **기준 DCP를 고정한 XMP Enhanced Profile**로 구성할 수 있다. Adobe SDK는 DCP 이후의 HSV LookTable과 처리 후반부의 RGB→RGB LUT를 구별한다. SDK의 생성 절차에서는 `.cube` LUT를 Camera Raw의 새 프로파일에 넣을 수 있으며, 2018 SDK가 설명하는 최대 크기는 32³이다. SATOBI·Gold처럼 색조를 바꾸는 효과에 적용할 수 있는 형식이다. 효과별 실제 계수와 카메라 출력 대조가 있어야 해당 모드와의 일치도를 판단할 수 있다. [Adobe Profiles SDK 안내](https://helpx.adobe.com/camera-raw/desktop/dng-and-file-formats/digital-negative.html) · [SDK ZIP의 Enhanced Profiles.pdf, 1–3·8–10·18–20쪽](https://download.adobe.com/pub/adobe/lightroom/profile-sdk/ACR_and_Lightroom_Profile_SDK.zip)

실제 매칭 프로파일 제작에는 다음 자료가 필요하다. 아래 절차는 후속 실험 설계이며 색차 측정 결과는 아직 없다.

1. 같은 RAW를 카메라의 RAW 현상으로 각 Custom Image의 JPEG 또는 TIFF로 출력한다. 모드, 세부 파라미터, 화이트밸런스, 노출 보정, 색공간, 렌즈 보정, 명료도와 노이즈 감소 설정을 기록한다. 리코는 RAW 현상에서 Custom Image와 이러한 설정을 변경할 수 있다고 명시한다. [K-3 Mark III 사양의 RAW Development](https://www.ricoh-imaging.co.jp/english/products/k-3-3/spec/)
2. 동일 RAW를 Adobe에서 고정한 기준 DCP, 화이트밸런스, 노출과 자동 보정 설정으로 현상한다. 두 결과를 같은 색공간으로 변환하고, 계조 차트·색 패치·피부·식생·고채도 장면을 확보한다. 두 조명 이상과 노출 변화, 별도 검증 장면을 사용해 특정 사진에만 맞는 변환을 피한다.
3. 색·톤 변환을 추정해 XMP의 HSV 표 또는 RGB LUT로 표현한다. Adobe의 처리 단계에 맞춰 표의 입력·출력 색공간을 고정하고, 기준 DCP에 이미 들어 있는 톤·색 변환의 중복 적용을 확인한다.
4. 제작에 쓰지 않은 장면에서 평균·상위 분위 색차, 중성축·피부색 오차, 하이라이트 클리핑과 계조를 비교한다. 위치에 따라 달라지는 샤프닝·노이즈 감소·렌즈 보정과 장면 적응형 처리는 LUT만으로 일치시킬 수 없어 따로 평가한다.

Auto Select는 장면별 모드 선택을 포함하고, Cross Processing은 랜덤·프리셋·저장된 선택에 따라 결과가 달라진다. 고정 프로파일 제작 시에는 실제 선택된 하위 모드나 특정 결과를 대상으로 삼아야 한다. Monochrome은 필터·토닝 설정별로 목표가 달라진다. [리코 제품 사양](https://www.ricoh-imaging.co.jp/english/products/k-3-3/spec/) · [리코 Custom Image 설명](https://www.ricoh-imaging.co.jp/english/products/custom_image/)

현재 확인된 다섯 Adobe 프로파일은 바로 활용할 수 있는 기존 후보이고, 추가 모드는 검증용 RAW와 목표 출력, 색 처리 계수의 연결을 더 확보해야 한다. 이번 연구에서 새 `.dcp`·`.xmp`의 카메라 매칭 정확도나 RAW→JPEG 전체 픽셀 일치도를 입증한 결과는 없다.

## Adobe 파일 구조 재확인

사용자가 설치한 프로파일을 입력으로 지정한다. 검사기는 모델명, 프로파일명, 표 크기와 데이터 해시만 출력한다.

```powershell
python inspect_adobe_profiles.py --self-test
python inspect_adobe_profiles.py "C:\ProgramData\Adobe\CameraRaw\CameraProfiles\Camera\Pentax K-3 Mark III\PENTAX K-3 Mark III Camera Bright.dcp"
```
