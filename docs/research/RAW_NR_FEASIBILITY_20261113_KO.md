# 01 / RAW 노이즈 감소 — K-3 III·K-3 II 펌웨어 수정 가능성

검토일: 2026-11-13. 대상: **K-3 Mark III 컬러 2.20**, **K-3 II 1.12**. Monochrome 제외.

**판정: NR 제어 후보를 추적할 근거 확보. 저장 RAW의 NR을 끄는 패치는 아직 미확정.**

펌웨어를 풀고 다시 포장하는 기술은 두 저장소에 존재. 이번 검토의 핵심 미해결점은 **어느 처리가 PEF/DNG 저장 전에 실행되는지**, **어떤 설정이 그 처리만 우회하는지**의 입증. 체크섬 통과와 정상 촬영은 서로 다른 조건.

## 02 / 공개 측정 — 두 기종의 시작 감도 구분

| 항목 | K-3 Mark III 컬러 | K-3 II |
|---|---|---|
| Photons to Photos에서 NR 표시가 처음 나타나는 ISO | **200** | **1600** |
| 그 이전의 표시 없는 측정점 | 100·125·160 | 100–1250 |
| 분석한 공식 펌웨어 | 2.20, `fwdc233b.bin` | 1.12, `fwdc230b.bin` |
| 정확한 RAW 필터 수식·계수 | 미확정 | 미확정 |
| 저장 RAW에 대한 On/Off 실증 | 미수행 | 미수행 |

근거: [Photons to Photos PDR 비교](https://www.photonstophotos.net/Charts/PDR.htm#Pentax%20K-3%20II,Pentax%20K-3%20III), [RAW 읽기 노이즈](https://www.photonstophotos.net/Charts/RN_ADU.htm#Pentax%20K-3%20II_14,Pentax%20K-3%20III_14). 아래쪽 삼각형은 사이트가 판별한 NR 표시. 표시가 없는 ISO에서도 모든 전처리가 없다는 뜻은 아님. 이는 기고 RAW의 측정 결과이며 **이번에 분석한 펌웨어 버전의 재측정 결과는 아님**.

두 기종의 High-ISO NR 메뉴에는 Off 존재. 따라서 “메뉴에서 NR을 끌 수 없음”과 “메뉴 Off 뒤에도 RAW 전처리가 남음”을 구분할 것. 장노출 NR은 별도 항목. [Mark III 설명서 인쇄 p.52·58](https://www.ricoh-imaging.co.jp/english/support/man-pdf/k-3-3.pdf#page=60), [K-3 II 설명서 인쇄 p.39·42](https://www.ricoh-imaging.co.jp/english/support/man-pdf/k-3-2.pdf#page=46).

Photons to Photos의 [기고 지침](https://www.photonstophotos.net/Collaborations/Collaboration_Overview.htm)은 NR 끄기 또는 최소화를 요구하며 High ISO NR을 끄도록 안내. 해당 기고 파일 각각의 실제 메뉴 상태는 이번 검토에서 독립 확인하지 않음. ISO 400 부근의 읽기 노이즈 변화만으로 NR 강도나 센서 변환 이득 전환을 단정하지 않을 것.

## 03 / 알고리즘 — 확인된 범위와 가설

Ricoh는 K-3 III의 영상 처리에 **다차원 영상 공간 필터링**을 사용한다고 설명. PRIME V와 2세대 가속기 조합도 명시. 그러나 이 설명에는 RAW 저장 전후의 위치, 필터 커널, 계수, 전용 칩 내부 구현이 없음. [공식 Imaging Power 설명](https://www.ricoh-imaging.co.jp/english/products/k-3-3/feature/02.html).

K-3 III 펌웨어의 `IQ_nr` 하위 경로에는 원래 크기·1/2·1/4 크기 작업 공간 산술과 두 활성화 필드가 존재. **다중 스케일 처리를 지원하는 NR 경로라는 정적 근거**. 이것만으로 RAW의 강제 NR이 동일 경로라거나 wavelet·bilateral·BM3D·median 중 특정 알고리즘이라고 결론 내릴 수 없음. K-3 II에 동일 알고리즘을 적용했다는 근거도 없음.

| 구분할 후보 | RAW에서 확인할 특성 | 판별 한계 |
|---|---|---|
| 선형 공간 평활화 | 같은 CFA 색 위치 간 공분산, 정규화 전력 스펙트럼의 고주파 감쇠 | 센서 자체 상관·후처리 혼입과 분리 필요 |
| 순위 필터·이상치 치환 | 극단값 감소, 주변 픽셀 값과의 일치율, 작은 광점의 손실 | 불량 화소 보정과 혼동 가능 |
| 신호 의존 공간 필터·다중 스케일 처리 | 밝기·경계·국소 분산에 따라 달라지는 감쇠 | 출력 RAW만으로 유일한 내부 알고리즘 복원 불가 |
| 블랙 레벨·행/열 보정·변환 이득 | 히스토그램 바닥, 행/열 구조, 포화점과 분산 관계 | 노이즈 분산 감소만으로 공간 NR이라 부를 수 없음 |

분석 방법 참고: [Claff, Energy Spectra and Filtering](https://photonstophotos.net/GeneralTopics/Sensors_%26_Raw/Sensor_Analysis_Primer/Energy_Spectra_and_Filtering.htm), [Shelley, 픽셀 수준 star-eater 진단](https://www.markshelley.co.uk/Astronomy/SonyA7S/diagnosingstareater.html). 후자는 Sony 사례의 방법 참고이며 Pentax에 같은 필터가 있다는 증거가 아님.

## 04 / K-3 III 정적 분석 — 우선 추적할 지점

공식 배포본을 다시 내려받아 기존 도구로 해제. 기존 저장소의 SHA-256과 일치. 아래 주소는 **2.20 RTOS의 분석 주소**이며 장치 메모리에 값을 쓰라는 지시가 아님.

| 지점 | 이번에 확인한 내용 | 아직 확인하지 못한 연결 |
|---|---|---|
| `0x530bc14c` | NR 작업 공간 배치 및 조건부 하위 호출. 입력 객체 `+0xc0`, `+0xc1` 바이트를 읽음 | 저장 RAW의 필터인지, 각 바이트의 정확한 의미 |
| `0x5258e1b4` | 진단 명령 `IQ_nr`에서 위 함수 호출 | 일반 촬영에서도 이 진단 명령이 사용되는지 |
| `0x52e56830` | 다른 호출부도 같은 함수 호출. 상위 설정의 `+0x27` → NR 객체 `+0xc0`, `+0x26` → `+0xc1` 전달 | 상위 설정 생산자, ISO·메뉴값과의 관계, 출력 버퍼의 최종 소비자 |
| `0x530a3ffc` | 두 플래그를 1로 놓고 작업 공간 크기를 질의하는 호출. 두 번째 인자가 크기 출력 포인터 | 이 호출 자체는 픽셀 NR 실행 증거가 아님 |
| `0x5313c4c8` 주변 | `NoiseReductionCoordinator` 진단 및 `GetYFilterFlag` 이름과 연결되는 비교 경로 | 비교 인자의 단위, ISO 역치, RAW와 JPEG 중 적용 대상 |
| `NR_ENABLE`, `DISABLE_PPU_NR_PARAM` | 해당 문자열 존재 확인 | 실제 RAW 우회 비트나 사용자 메뉴로 확정 불가 |

따라갈 연결:

```text
ISO·촬영 모드·메뉴 설정
          ↓ [생산자 미확정]
상위 설정 +0x27 / +0x26
          ↓ [정적 전달 확인]
NR 객체 +0xc0 / +0xc1 → 0x530bc14c → 하위 처리
          ↓ [출력 버퍼 연결 미확정]
PEF/DNG 저장 입력인지, JPEG 현상 입력인지 판별
```

원본 구간은 Capstone 5.0.7로 읽고, 주소·필드 접근·직접 호출을 별도 표준 라이브러리 검증기로 대조. **전체 제어 흐름 실행, 픽셀 산술 실행, 실기 MMIO 관측은 미수행.** 문자열만 발견된 지점은 실행 가능 API나 사용자 설정으로 취급하지 않음.

기존 근거: [RTOS NR 경로](../../analysis/index.html#imaging), [NR 후보 검증 결과](../../analysis/nr-candidates.json), [검증 도구](../../verify_nr_candidates.py). 기존 분석 기준 커밋: `8115cf6795fc9751c5fe00396027c1b19084c442`.

## 05 / 수정 가능성 — 패키지 재구성과 RAW 제어를 분리

| 관문 | 현재 상태 | 통과 조건 |
|---|---|---|
| 펌웨어 읽기·재포장 | 두 기종에 기존 도구 존재. 이번에 원본 해제 해시 재확인 | 지정 버전의 원본·수정 범위·체크섬 고정 |
| 대상 필터 식별 | K-3 III 제어 필드 후보, K-3 II LNR 진단 후보 확보 | RAW 저장 버퍼까지 호출·데이터 흐름 연결 |
| 필터 단독 우회 | 미확정 | NR을 꺼도 출력 버퍼·완료 통지·캐시·DMA 순서 정상 유지 |
| 사용자 On/Off | 구현 전 | 검증된 제어값을 별도 설정과 연결. 원래 동작을 기본값으로 유지 |
| 설치·부팅·복구 | 실기 미검증 | 변경본 수용·정상 부팅·복구 수단 각각 검증 |
| 화질 검증 | 실기 미검증 | Off에서 필터 지표 변화, On에서 원래 결과 분포 복원 |

**기술적 결론: 조사 지속 가치 있음. 지금 바로 설치 가능한 NR On/Off 펌웨어를 만들 수 있다고 판단할 근거는 부족.** 펌웨어가 제어하는 ISP 레지스터나 디스크립터라면 우회 가능성 존재. 센서·가속기 내부의 고정 처리이고 우회 경로가 없다면 주 CPU 펌웨어만으로 해결하기 어려움. 어느 경우인지 아직 미확정.

기존 K-3 III [재패키징](../../analysis/selective-repack.html) 및 [재컴파일 통합](../../analysis/recompiled-integration.html)은 PC에서의 패키지·헤더·가산 체크섬 검증. 카메라의 전체 인증이나 부팅 성공 증거가 아님. [공식 2.20 안내](https://www.ricoh-imaging.co.jp/english/support/digital/k-3-3.html)는 이전 버전으로 복귀할 수 없다고 명시하므로, 단순 다운그레이드를 복구 수단으로 가정하지 않을 것.

## 06 / 후속 과제 — 우선순위와 완료 기준

1. **NR-01 / RAW 재현 자료 확보.** K-3 III: ISO 100·160·200·250·400. K-3 II: ISO 100·800·1250·1600·2000. 실제 펌웨어 버전, 셔터 방식, 노출·온도, 메뉴 화면을 기록할 것. 장노출 NR·High-ISO NR을 끄고 Pixel Shift·HDR·다중 노출·AA 시뮬레이터는 사용하지 않을 것. 짧은 노출의 암프레임과 두 밝기 평탄광을 조건별 최소 8장씩 촬영할 것. 파일명으로 조건을 추측하지 않을 것.
2. **NR-02 / 저장 RAW 측정.** 디모자이킹 전 CFA를 R·G1·G2·B로 나누고 같은 색 격자에서 비교할 것. 원래 블랙 레벨을 보존하고 차분 전에 음수를 잘라내지 않을 것. 프레임 쌍 차분으로 고정 패턴을 줄이고 분산·공분산·2D 전력 스펙트럼·이상치 비율 계산. 평탄광 노출과 포화 비율을 통제할 것. 임계 ISO 전후에서 메뉴 Off/High와 PEF/DNG를 추가 비교할 것.
3. **NR-03 / 생산자·소비자 추적.** III는 `+0x27/+0x26` 설정 생산자와 NR 출력 버퍼 소비자부터 조사. II는 LNR 제어 레지스터의 쓰기 함수와 RAW 저장 분기부터 조사. 완료 기준은 센서 입력 → 해당 NR → PEF/DNG 저장의 연결 및 ISO 의존 조건 확인.
4. **NR-04 / PC 우회 모형 검증.** NR을 건너뛸 때에도 유효한 입력/출력 버퍼, 길이, 완료 신호가 유지되는지 확인. 전체 함수를 무조건 반환시키는 방식은 피할 것. 메뉴 상태·사진 모드·연사·RAW/JPEG 조합별 영향을 확인할 것.
5. **NR-05 / 실기 후보 판단.** 위 관문 통과 후 복구 가능한 시험 환경에서만 후보 평가. On/Off의 RAW 지표, 미세 디테일·광점, 핫픽셀·밴딩, 저장 실패·정지 여부를 함께 비교할 것.

NR-01·02와 NR-03은 독립 진행 가능. NR-04·05는 앞선 필터 식별 결과에 종속. 최초 시험은 DNG 또는 PEF 한 형식으로 진행하고, 효과가 확인되는 경계 조건에 두 형식과 메뉴 비교를 집중할 것.

## 07 / 재현과 근거 파일

```powershell
# 이 저장소에서 실행. decoded.bin은 inspect_firmware.py로 해제한 정확한 2.20 파일.
python verify_nr_candidates.py k3iii .private/my-decode/decoded.bin --compare analysis/nr-candidates.json
python -m unittest discover -s tests -p test_nr_candidates.py -v

# K-3 II 1.12 해제 파일도 같은 검증기로 검사 가능.
python verify_nr_candidates.py k3ii <K-3-II-decoded.bin> --compare <K-3-II-repo>/analysis/nr-candidates.json
```

| 파일 | 내용 |
|---|---|
| [nr-candidates.json](../../analysis/nr-candidates.json) | K-3 III 문자열 주소·직접 호출·검토 구간 해시 |
| [raw-nr-public-evidence.json](../../analysis/raw-nr-public-evidence.json) | P2P 원문 해시·조회일·기종별 감지 경계·판독 절차 |
| [K-3 II 별도 검토](https://github.com/yunhyok/pentax-k3ii-firmware-analysis/blob/main/docs/research/RAW_NR_FEASIBILITY_20261113_KO.md) | K-3 II LNR 근거와 기종별 후속 과제 |

해제 파일 SHA-256: III `7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9`, II `1b87bf35b290e4b4e8910beb4055c34f97504b65e249ad65e5ccc0402bd14cfc`.

검증 기록: 새 검증기의 합성 테스트 **3개 통과**. 두 실물 배포본의 해제 파일에서 문자열 6개·명령/리터럴 12개·직접 호출 4개·검토 구간 5개 대조. 기존 K-3 III 검증기에서도 명령 957개·검토 구간 42개·전달 위치 17,914개 일치. 문서 로컬 링크 및 두 저장소의 기존 공개 문서 검사 통과. 이 수치는 NR 해제 기능의 성공률이 아님.

공개 측정 근거는 별도 조사 에이전트가 확인하고, 본 검토에서 PDR 원문 해시와 ISO 경계를 재확인. 펌웨어 근거는 직접 받은 공식 배포본에서 별도 검증. 원본 펌웨어·제조사 디컴파일 코드·설치 후보는 공개하지 않음. 제조사 [III](https://www.ricoh-imaging.co.jp/english/support/digital/k-3-3.html)·[II](https://www.ricoh-imaging.co.jp/english/support/digital/k3_2.html) 배포 조건의 법적 효력을 판단하는 문서는 아님.
