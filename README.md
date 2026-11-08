# PENTAX K-3 Mark III v2.20 펌웨어 분석

[세 기종 연구 본부](https://yunhyok.github.io/pentax-k3iii-firmware-analysis/analysis/research-program.html)에서 K-3 Mark III·K-3 II·Q7의 재구축, Lightroom 색 프로파일, AF 제어, UI 이식 연구를 함께 확인할 수 있습니다. 검증 단계와 미해결 과제, 다음 조사를 근거별로 기록합니다. [3기종 Lightroom·DCP 생성 연구](analysis/lightroom-bridge.html)도 추가했습니다.

분석 문서는 HTML로 제공합니다. 저장소를 내려받아 `index.html`을 브라우저에서 열면 표·도식과 문서 간 링크를 오프라인으로 읽을 수 있습니다. GitHub의 HTML 파일 화면은 소스 보기입니다.

- [세 기종 통합 현황·검증 기준](analysis/research-program.html)
- [독립 C 코드의 ARM 재컴파일·원본 비교](analysis/recompiled-kernels.html)
- [실제 DNG 표본·DCP 시험 준비](analysis/raw-test-inputs.html)
- [전체 안내·펌웨어 구조·재현 절차](index.html)
- [JPEG·ISP·WB·색공간·클리핑 최신 보고서](analysis/pipeline-report.html)
- [M0 reset·SRAM remap·bank alias 최신 분석](analysis/startup-storage.html)
- [업데이트 검사·ICONBIN 적재 최신 분석](analysis/update-resources.html)
- [수정 펌웨어·UI 이식 선행 연구](analysis/research-roadmap.html)
- [RTOS 명령 957개](analysis/index.html) · [셔터·AF](analysis/dispatch-af.html)
- [컬러모드·Lightroom](analysis/color-lightroom.html) · [색 처리 수식](analysis/color-algorithms.html)

이 README만 GitHub 기본 진입 문서로 Markdown을 유지합니다. 공개 자료는 자체 분석·검증 도구와 재배포 조건을 확인한 OSS 소스입니다. 원본 펌웨어·추출 계수·독점 코드의 디컴파일 C는 로컬에 보관합니다. 원래의 비공개 소스나 전체 펌웨어 빌드 프로젝트를 복구한 결과가 아닙니다.
