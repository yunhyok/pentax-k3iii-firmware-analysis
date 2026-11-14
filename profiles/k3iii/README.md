# K-3 Mark III Custom Image 프로파일 (DCP)

PENTAX K-3 Mark III의 Custom Image 16종에 맞춘 Lightroom·Camera Raw용 카메라 프로파일입니다. 값은 펌웨어 2.20에서 읽은 색 표([`analysis/k3iii-color-tables.json`](../../analysis/k3iii-color-tables.json))로 계산했습니다.

설명과 내려받기: <https://yunhyok.github.io/pentax-k3iii-firmware-analysis/analysis/color-profiles.html>

## 파일

`k3iii-firmware-<mode>.dcp` 16개입니다. Lightroom에는 “K-3 III Firmware Natural”처럼 보입니다.

natural, bright, portrait, landscape, vibrant, radiant, muted, flat, bleach-bypass, reversal-film, monochrome, satobi, harubeni, katen, kyushu, fuyuno

Auto Select, Cross Processing, Gold는 프로파일이 없습니다.

## 알아 둘 점

- **Lightroom에서 확인하지 않았습니다.** 수치는 Adobe DNG SDK의 기준 처리 순서를 PC에서 다시 계산한 것입니다.
- 카메라가 기록한 JPEG과 비교한 모드는 Natural과 Bright 둘입니다. 평탄 영역의 평균 ΔE00은 0.90과 0.91입니다.
- 프로파일은 Custom Image마다 카메라의 출고 설정으로 만들었습니다(Bright는 대비 +1, Flat은 대비 −4 등). 설정을 바꿔 찍은 사진에는 같은 설정으로 다시 만든 프로파일이 맞습니다.
- Bleach Bypass와 HARUBENI의 출고 설정에 든 조색은 들어 있지 않습니다. 이 형식의 프로파일은 회색을 물들이지 못합니다.
- 그림자 보정, 하이라이트 보정, 명료도, 샤프니스, 노이즈 감소, 렌즈 보정은 프로파일 밖의 처리입니다.

## 다시 만들기

펌웨어 없이 만들 수 있습니다. numpy만 필요합니다.

```bash
python tools/make_k3iii_profile.py --all --output-dir my-profiles
```

```bash
python tools/make_k3iii_profile.py --from-raw IMGP0001.PEF --output IMGP0001.dcp
```

이 폴더의 파일은 `tools/build_profile_pages.py`가 만듭니다. `python tools/build_profile_pages.py --check`로 색 표에서 그대로 다시 만들어지는지 확인합니다. numpy 판에 따라 표의 실수 값이 마지막 자리에서 달라질 수 있어 이 검사는 허용오차 안에서 비교합니다.
