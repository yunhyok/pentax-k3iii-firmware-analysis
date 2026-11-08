# PENTAX K-3 Mark III v2.20 펌웨어 분석

[세 기종 연구 본부](https://yunhyok.github.io/pentax-k3iii-firmware-analysis/analysis/research-program.html)에서 K-3 Mark III·K-3 II·Q7의 재구축, Lightroom 색 프로파일, AF 제어, UI 이식 연구를 함께 확인할 수 있습니다. 검증 단계와 미해결 과제, 다음 조사를 근거별로 기록합니다. [3기종 Lightroom·DCP 생성 연구](analysis/lightroom-bridge.html)도 추가했습니다.

분석 문서는 HTML로 제공합니다. 저장소를 내려받아 `index.html`을 브라우저에서 열면 표·도식과 문서 간 링크를 오프라인으로 읽을 수 있습니다. GitHub의 HTML 파일 화면은 소스 보기입니다.

- [세 기종 통합 현황·검증 기준](analysis/research-program.html)
- [독립 C 코드의 ARM 재컴파일·원본 비교](analysis/recompiled-kernels.html)
- [재컴파일한 색 행렬 함수의 배치·재패키징](analysis/recompiled-integration.html)
- [원본 압축 블록을 보존한 작은 수정 패키지](analysis/selective-repack.html)
- [업데이트 파일 입력·버퍼 할당 경로](analysis/update-memory.html)
- [파일 인터페이스와 입력·해제 버퍼 수명](analysis/update-file-lifetimes.html)
- [업데이트 파일 경로·volume record·종료 처리 45사례](analysis/update-volume-finalization.html)
- [SD·Emmc 객체와 완료 통지 72사례](analysis/update-media-completion.html) · [R 파티션의 sector 주소와 I/O 25사례](analysis/update-partition-io.html)
- [부트 헤더 출력과 파티션 표의 구분](analysis/header-alias-consumer.html) · [완료 통지 이후 UI 작업·handle 처리](analysis/update-ui-consumer.html)
- [UI 타이머 예약·취소·콜백 39사례](analysis/update-ui-timer.html) · [커널 호출·64비트 시각 계산 17사례](analysis/update-timer-abi.html)
- [TTimPeriod 설정·카운터 증가 20사례](analysis/update-timer-clock.html) · [하위 시간 변환의 32비트 산술·6,754회 실행](analysis/update-subtick-arithmetic.html)
- [타이머 등록·지연 콜백 20사례](analysis/update-timer-irq.html) · [시각 조회 출력 12사례](analysis/update-clock-readers.html) · [기한 큐 삽입 18사례](analysis/update-timer-insertion.html)
- [실제 DNG 표본·DCP 시험 준비](analysis/raw-test-inputs.html)
- [ColorChecker 24패치·ICC 색차 비교 절차](analysis/color-comparison-protocol.html)
- [Lightroom 실제 TIFF 6개·프로파일·출력 색공간 비교](analysis/lightroom-render-comparison.html)
- [Lightroom 톤 곡선 생략·항등·Lift·ACR3 실제 출력 비교](analysis/lightroom-tone-comparison.html)
- [K-3 III·Q7 시험 DCP의 실제 Lightroom TIFF 출력](analysis/lightroom-model-exports.html)
- [색 모드·채도·대비에 따른 행렬과 감마 변화](analysis/color-mode-boundaries.html)
- [세 기종 색공간 선택 화면의 UI 이식 설계](analysis/ui-port-contract.html)
- [K-3 III 색공간 선택·확정·취소 경로](analysis/colorspace-ui.html)
- [방향 입력·포커스·경계 이동 50사례](analysis/colorspace-ui-input.html)
- [세 기종 AF 변경을 위한 기초 경계 비교](analysis/af-foundations.html)
- [렌즈 구동 선택·명령·응답의 AF 기초 연구](analysis/af-drive-architecture.html)
- [AF 요청 큐·전달 응답·완료 통지](analysis/af-request-consumer.html)
- [ICONBIN 구조·아이콘 렌더링 검증](analysis/icon-resources.html)
- [전체 안내·펌웨어 구조·재현 절차](index.html)
- [JPEG·ISP·WB·색공간·클리핑 최신 보고서](analysis/pipeline-report.html)
- [M0 reset·SRAM remap·bank alias 최신 분석](analysis/startup-storage.html)
- [업데이트 검사·ICONBIN 적재 최신 분석](analysis/update-resources.html)
- [수정 펌웨어·UI 이식 선행 연구](analysis/research-roadmap.html)
- [RTOS 명령 957개](analysis/index.html) · [셔터·AF](analysis/dispatch-af.html)
- [컬러모드·Lightroom](analysis/color-lightroom.html) · [색 처리 수식](analysis/color-algorithms.html)

이 README만 GitHub 기본 진입 문서로 Markdown을 유지합니다. 공개 자료는 자체 분석·검증 도구와 재배포 조건을 확인한 OSS 소스입니다. 원본 펌웨어·추출 계수·독점 코드의 디컴파일 C는 로컬에 보관합니다. 원래의 비공개 소스나 전체 펌웨어 빌드 프로젝트를 복구한 결과가 아닙니다.
