# 단계 03 보고서 — 최종 정리: README 결과 절

> 발표자료(슬라이드 원고·발표 대본)는 이 레포에서 만들지 않기로 해서 `docs/presentation/`을 삭제했다(사용자 결정).

## 만든 파일

| 파일 | 내용 |
|---|---|
| `evaluation/describe.py` | 구분 근거용 기술 통계(시나리오별 IP·UA 집합, 요청 수·초당 요청 수, 요청 모양, 403 수, 이름 지정 수). 설명에만 쓰고 탐지 규칙에는 넣지 않았다 |
| `evaluation/results/03-describe.json` | 위 통계 결과 |
| `README.md` (끝에 추가) | `## Category 3 결과 — Kubernetes Audit Log 기반 SA 오용 탐지` 절. 요약, 실행 방법, 데이터, 구분 근거, 탐지 기준, 탐지 결과, 오탐·미탐 분석, 한계 |

기술 통계에서 새로 확인한 점: "빠른 반복 열거"인 abnormal_3의 초당 요청 수(평균 10.3)가 normal(평균 11.4)보다 낮다. 속도로 구분하지 않는다는 근거로 README에 넣었다.

## 숫자 대조 결과
README 추가 절의 숫자를 JSON(`01-baseline.json`, `02-upgrade.json`, `03-describe.json`)과 임시 스크립트로 대조했다. 비교표 6행이 JSON과 같고, 개별 숫자도 모두 일치했다(불일치 0). README의 "한계" 소절이 보고서 02의 6절과 문장 단위로 같은지도 확인했다.

그 밖의 확인:
- `git diff 270bf2d HEAD -- README.md`: 추가된 줄만 있다(107줄 추가, 삭제 0).
- 그 밖의 원본 파일 diff 없음.
- 테스트 45개 통과. `evaluate.py`를 다시 실행해도 `01-baseline.json`과 `02-upgrade.json`이 단계 02와 같다(git diff 없음).

## 막힌 점
없음.

## 제안
없음.
