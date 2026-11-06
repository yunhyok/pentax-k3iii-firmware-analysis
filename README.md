# PENTAX K-3 Mark III v2.20 펌웨어 분석

**이 펌웨어에서 Linux 셸 스크립트 원문을 꺼낼 수 있고, 컴파일된 함수는 기계어에서 동작을 추적할 수 있다.** Linux UART 함수 한 개는 제조사가 배포한 C 소스와 대응시켰다. 촬영·영상처리 RTOS에서는 HDMI 명령 처리기의 흐름을 복원했다. 카메라 전체를 다시 빌드하는 데 필요한 비공개 C/C++ 소스, 원래의 타입·주석·빌드 프로젝트는 확보하지 못했다.

## 확보한 코드

| 파일 | 출처 | 확인한 내용 |
|---|---|---|
| [update-rc.d](source/update-rc.d) | BIN의 Linux 초기 파일시스템에 들어 있는 스크립트 원문 | 시작·종료 런레벨에 맞춰 init 스크립트 링크를 관리한다. 추출한 4,816바이트가 리코 v2.20 OSS 묶음의 `update-rc.d-0.7-r5-patched.tar.gz → git/update-rc.d`와 일치한다. GPL-2.0-or-later. |
| [run-postinsts](source/run-postinsts) | 같은 파일시스템에 들어 있는 스크립트 원문 | 패키지 설치 후 처리를 담당하는 템플릿이다. 경로 치환 전 원문 1,773바이트가 OpenEmbedded의 morty 브랜치와 일치한다. MIT. [업스트림 소스](https://github.com/openembedded/openembedded-core/blob/morty/meta/recipes-devtools/run-postinsts/run-postinsts/run-postinsts) |
| [usio.c](source/usio.c) | 리코가 v2.20용으로 배포한 Linux 커널의 `drivers/tty/serial/usio.c` | SOCIONEXT UART 드라이버. 아래에 실제 BIN과 대조한 함수, 주소, 레지스터 비트를 기록했다. GPL v2. |

두 셸 파일의 BIN 내부 경로는 각각 `license/update-rc.d/update-rc.d.txt`와 `license/run-postinsts/run-postinsts.txt`다. 두 파일은 배포용 소스 사본이며 카메라 부팅 시 이 경로에서 실행됐다는 증거는 없다. 원저작권 표시와 소스에 적용되는 라이선스를 보존했다. [GPL](source/COPYING) · [MIT](source/COPYING.MIT)

리코의 같은 버전 OSS 묶음은 195,945,425바이트이며 커널, Stubby 부트로더, BusyBox, glibc, systemd 등 18개 패키지 아카이브가 들어 있다. `linux-kernel-1.60.1.tar.gz`는 패키지 이름이며, 실제 커널 버전은 **4.4.15**다. 전체 OSS 소스는 제조사에서 받을 수 있다. [모델·버전별 목록](https://www.ricoh-imaging.co.jp/english/products/oss/) · [K-3 Mark III v2.20 소스 묶음](https://www.ricoh-imaging.co.jp/japan/products/oss/k-3-3/K3mkIII_220.tar.gz)

## 대상 파일과 내부 구조

| 항목 | 실측 결과 |
|---|---|
| 입력 | `fwdc233b.bin`, 35,106,716바이트 |
| 입력 SHA-256 | `3c9d466b8160689867af2f58ff2cf0bf3363bc3b42daff43685a33171b91eb1a` |
| 패키지 대조 | 보유 중인 `k3III_v220.zip`의 BIN과 SHA-256 일치. ZIP의 나머지 세 파일은 OpenSSL과 ZXing의 라이선스·고지 문서 |
| 빌드·배포 | BIN 헤더의 빌드 시각 2024-10-08 15:31:16 JST. 리코의 v2.20 배포일 2024-10-30 |
| 압축 해제 | BIN의 `0x80`에서 시작해 3,202개 블록을 해제. 결과 78,683,892바이트. 독립 디코더의 출력과 전체 바이트 일치 |

디코딩한 스트림 처음부터 이름·종류·길이를 따라가면 15개 레코드가 이어진다. 아래 오프셋은 **압축 해제한 스트림에서 페이로드가 시작하는 위치**다. 15개 레코드 뒤의 4,841,096바이트와 원본 BIN의 압축 스트림 뒤 280바이트는 서로 다른 영역이다. 이 분석에서는 두 영역의 용도를 확정하지 않았다. 전체 레코드의 길이·오프셋·SHA-256 및 REA ZIP 증거 ID는 [측정값](evidence.json)에 있다. [공식 펌웨어 안내](https://www.ricoh-imaging.co.jp/english/support/digital/k-3-3.html) · [비교에 사용한 디코더](https://github.com/Trimz/Ricoh3x/blob/0ed425ad4e31b336624ba4709dc28962ace2d629/tools/pdec.py)

| 레코드 | 시작 | 바이트 | 확인한 내용 |
|---|---:|---:|---|
| RTOS | `0x1C19C` | 25,483,200 | ARM 예외 벡터, 시작 코드, 카메라 명령 처리기 |
| DSP | `0x186996C` | 4,194,304 | DSP 이름의 별도 페이로드. 칩 모델과 알고리즘 미확인 |
| LINUX | `0x1C6997C` | 3,062,784 | 부트 코드, 압축 커널, 장치 트리 |
| INITFS | `0x1F5558C` | 14,452,736 | ROMFS 안의 gzip 압축 newc CPIO. 일반 파일 396개 중 20개가 셸 스크립트 형식이며 그중 2개는 라이선스 경로의 소스 사본 |
| SHELLCMD | `0x2D5BDBC` | 61,312 | 서로 다른 RTOS 주소를 가리키는 명령 957개와 주소가 0인 종료 표식 1개 |

## 어떤 칩을 대상으로 빌드했는가

`LINUX + 0x2E3BE0`에서 유효한 장치 트리(DTB)의 헤더와 속성을 파싱했다. 루트 `compatible`에는 `milbeaut,sc2000a` 및 `socionext,milbeaut-evb`가 들어 있다. 모델명은 `Socionext SC2000A EVB w/ RTOS and NETSEC`, Linux에 기술된 CPU 노드는 `/cpus/cpu@3`이고 호환 문자열은 `arm,cortex-a7`이다. 커널 내장 설정에도 `CONFIG_ARCH_MILBEAUT=y`가 있다. **첨부 펌웨어의 Linux가 Socionext Milbeaut SC2000A 계열과 Cortex-A7을 대상으로 한다**는 직접 증거다. [검증 코드](verify_findings.py) · [DTB 포맷](https://devicetree-specification.readthedocs.io/en/stable/flattened-format.html)

리코는 K-3 II의 영상 엔진을 PRIME III, K-3 Mark III의 영상 엔진과 가속기를 PRIME V 및 2세대 accelerator unit으로 구분한다. Socionext는 SC2000을 Milbeaut M10V 계열의 쿼드 Cortex-A7 제품으로 설명한다. K-3 Mark III 전용 독립 분석도 이 계열을 지목한다. 리코 공개 커널에는 R03010 보드와 GR III 보드의 설정 파일이 함께 있다. 이 자료는 플랫폼 공유의 근거지만, 두 카메라의 펌웨어·보드가 동일하다거나 K-3 II의 모든 하위 시스템이 교체됐다고 판단할 근거는 부족하다. 실장 패키지의 각인, 카메라의 실동작 클럭 및 별도 가속기의 부품번호는 미확인이다. [리코 K-3 II](https://www.ricoh-imaging.co.jp/english/products/k-3-2/feature/05.html) · [리코 K-3 Mark III](https://www.ricoh-imaging.co.jp/english/products/k-3-3/feature/02.html) · [Socionext SC2000 사양](https://www.socionext.com/en/pr/sn_pr20170105_01e.pdf) · [akinas의 K-3 Mark III 분석](https://ameblo.jp/akinas/entry-12845980402.html)

## 실제 코드와 대조한 동작

**Linux UART.** 커널 Image 안의 압축 심볼 테이블(kallsyms)에서 43,829개 심볼을 복원했다. `usio_tx_empty`는 가상 주소 `0x8015FDF0`, 압축 해제한 커널 Image 오프셋 `0x157DF0`에 있다. 다음 심볼까지의 14바이트를 Thumb 명령 5개로 읽으면 UART 레지스터 기준 주소에서 오프셋 3의 바이트를 읽고 비트 0을 반환한다. 이는 송신기의 empty 상태를 반환하는 공개 C 함수와 일치한다. 별도로 `usio_ops.tx_empty` 포인터 값이 `0x8015FDF1`임을 확인했다. 하위 1비트는 Thumb 명령 상태를 나타낸다. 커널의 내장 설정은 `CONFIG_SERIAL_SN_USIO=y`이며 장치 트리에서 UART 인스턴스 `0x1E700010`은 활성 상태로 기술돼 있다. [레지스터 정의](source/usio.c#L61-L62) · [함수](source/usio.c#L266-L270) · [콜백 등록](source/usio.c#L449-L450)

**Linux 카메라 서비스.** INITFS에서 회수한 `etc/rc.local`은 무선 드라이버를 로드하고 카메라 제어 데몬의 준비 표식을 기다린다. 이어 USB·시스템 관리 데몬을 시작한다. 일반 모드에서는 네트워크·Bluetooth Low Energy 서비스를 시작하고, 저장장치 마운트 후 웹 API를, MTP 장치 생성 후 MTP 서비스를 시작하도록 작성돼 있다. `usr/bin/ble_init.sh`에서 위 드라이버의 장치명인 `/dev/ttyUSI1`을 확인했다. 이는 파일에 적힌 시작 순서이며 실기 부팅 로그는 수집하지 않았다.

**RTOS HDMI 명령.** 벡터 기준 레지스터에 기록하는 값, 예외 처리기 포인터와 SHELLCMD의 명령 주소를 독립적으로 대조해 RTOS의 적재 기준 주소를 `0x52500000`으로 추정했다. 명령 표의 `App_ChangeHdmi` 주소는 `0x52508000`이다. RTOS 오프셋 `0x8000`에서 시작하는 56바이트 전체를 디스어셈블했다. 추가 인수가 있으면 첫 인수를 10진수로 해석하는 경로를 거쳐 하위 8비트를 설정 갱신 함수로 넘기며, 처리기는 0을 반환한다. 하위 함수는 값 비교 결과에 따라 21개 레코드의 `+0x970` 필드에 해당 바이트를 기록한다. 실제 HDMI 모드와 출력 신호의 변화는 확인하지 않았다. [함수 범위를 확인하는 코드](verify_findings.py)

**RTOS 초기화.** 리셋 벡터에서 이어지는 주 코어 초기화 경로의 일부는 `0x65A80`바이트를 복사하고 메모리 구간을 0으로 채운다. 이어 보조 코어가 확인하는 표식을 기록하고 ARM `SEV` 명령을 내보낸다. 별도의 4개 명령 함수(`0x52500508`)는 `0x1D001000`에 32비트 값 3을 기록한다. 로컬에서 두 함수(이 레지스터 기록 함수와 HDMI 처리기)에 대해 angr로 C 형태의 의사코드를 생성하고 ARM 명령과 대조했다. HDMI 함수의 스택 프레임과 간접 반환은 도구가 부정확하게 표현해 해당 부분은 명령어를 기준으로 판독했다.

## 재현

Python 3 표준 라이브러리만 사용한다. 첫 명령의 출력 폴더는 새 경로여야 한다. 펌웨어 파일을 읽을 수 있는 위치에서 다음을 실행한다.

```console
python inspect_firmware.py fwdc233b.bin --output-dir .private/my-decode
python verify_findings.py .private/my-decode/decoded.bin
```

첫 명령은 `decoded.bin`과 블록별 원본·출력 매핑을 담은 `inventory.json`을 저장한다. 두 번째 명령은 이 버전의 디코딩 결과 SHA-256을 검사한 뒤 DTB, 커널 설정, 초기 파일시스템, 공개 셸 원문, UART·HDMI 함수 범위를 검증한다. 입력 파일 없이 도구 자체를 점검하려면 두 스크립트에 각각 `--self-test`를 전달한다.

자동 디컴파일까지 재현하려면 별도 Python 환경에 `angr==10.0.5`를 설치한다. 아래 명령은 원본 RTOS 해시와 함수 범위를 검사한 뒤 디컴파일러의 C 형태 출력을 표준 출력으로 보낸다. 디컴파일 경고는 표준 오류에 표시된다.

```console
python decompile_sample.py .private/my-decode/decoded.bin hdmi
python decompile_sample.py .private/my-decode/decoded.bin register-write
```

REA는 배포 ZIP과 구성원의 해시를 확인하는 데 사용했다. Windows의 REA 펌웨어 스캐너는 Linux Binwalk 공급자가 필요해 실행되지 않았다. 위의 압축 해제·커널 심볼 복원·함수 분석은 각각 별도 도구로 수행했다. 리코의 펌웨어 사용 약관 3·4·6항에는 복제·역분석·양도 제한이 명시되어 있다. 이 저장소의 공개 범위는 재배포 조건을 확인한 OSS 파일, 직접 작성한 분석 도구와 측정 결과다. 원본 BIN, 추출한 독점 코드, RTOS 디컴파일 출력은 로컬에만 보관했다. 카메라 플래싱, 실기 실행, 전체 펌웨어 재빌드는 수행하지 않았다. [리코 배포 약관](https://www.ricoh-imaging.co.jp/english/support/digital/k-3-3.html) · [커널 심볼 복원 도구](https://github.com/marin-m/vmlinux-to-elf) · [angr 디컴파일러](https://docs.angr.io/en/latest/analyses/decompiler.html)
