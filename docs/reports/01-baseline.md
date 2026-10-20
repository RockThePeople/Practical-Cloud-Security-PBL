# 단계 01 보고서 — 파서, 기본 탐지(R1~R3), 데이터셋, 기본 평가

## 1. 만든 것

| 파일 | 역할 |
|---|---|
| `detector/parser.py` | audit JSON Lines → 감시 SA 요청 목록. auditID로 여러 줄(stage)을 요청 1건으로 묶는다. 읽을 수 없는 줄은 건너뛰고 센다 |
| `detector/rules.py` | 기본 규칙 R1(Secret 접근), R2(exec·attach·portforward), R3(403 또는 forbid). 모든 알림 severity는 `high` |
| `detector/__main__.py` | CLI. 요청 수, 알림 목록, 규칙별 알림 수 출력 (`--json` 지원) |
| `scenarios/normal_misconfig.sh` | 정상 조회 5개 + 권한 없는 `get secret app-tls` 3회 (설정 실수가 있는 정상 앱) |
| `evaluation/collect.py` | 5개 시나리오 × 5바퀴 = 에피소드 25개 수집 |
| `evaluation/evaluate.py` | 클러스터 없이 `data/`만 읽어 평가. 반사실 재현 포함 |
| `tests/` | 파서·규칙·반사실 변환 단위 테스트 20개 |
| `data/episodes/`, `data/manifest.csv` | 에피소드 25개와 목록 |
| `evaluation/results/01-baseline.json` | 평가 결과 |

```bash
python3 -m unittest discover tests            # 20개 통과
python3 -m detector data/episodes/04_abnormal_2_1.jsonl [--json]
python3 evaluation/collect.py                 # 클러스터 필요, 약 8분
python3 evaluation/evaluate.py                # 클러스터 불필요
```

## 2. 데이터셋

에피소드(episode) = 스크립트 1회 실행 동안 audit.log에 늘어난 줄 전체. 라벨은 파일 단위로만 붙였다(normal·normal_misconfig는 benign, abnormal_1~3은 attack). 25회 모두 한 번에 성공했고 다시 실행하거나 로테이션된 경우는 없었다.

| 시나리오 | 라벨 | 실행 수 | 1회당 감시 SA 요청 수 |
|---|---|---|---|
| normal | benign | 5 | 5 (5회 모두 같음) |
| normal_misconfig | benign | 5 | 8 (5회 모두 같음) |
| abnormal_1 | attack | 5 | 1 (5회 모두 같음) |
| abnormal_2 | attack | 5 | 2 (5회 모두 같음) |
| abnormal_3 | attack | 5 | 18 (5회 모두 같음) |

## 3. 기본 탐지 결과

용어
- **TP(참 양성)**: 공격 요청을 표시함. **FP(거짓 양성, 오탐)**: 정상 요청을 표시함. **FN(거짓 음성, 놓침)**: 공격 요청을 표시하지 않음. **TN(참 음성)**: 정상 요청을 표시하지 않음.
- **precision(정밀도)** = TP/(TP+FP): 표시한 것 중 진짜 공격의 비율. **recall(재현율)** = TP/(TP+FN): 공격 중 표시한 것의 비율.

**실행 단위:** 공격 실행 15/15 탐지, 정상 실행 5/10 오탐. 오탐 5회는 모두 normal_misconfig다.

**요청 단위:**

| TP | FP | FN | TN | precision | recall |
|---|---|---|---|---|---|
| 40 | 15 | 65 | 50 | 0.727 | 0.381 |

**abnormal_3 1회당:** 알림 12.0개, 사건 12.0개 (기본 탐지는 알림 1개를 사건 1개로 센다)

**시나리오별:**

| 시나리오 | 실행 | 요청 | 표시한 요청 | R1 | R2 | R3 |
|---|---|---|---|---|---|---|
| normal | 5 | 25 | 0 | 0 | 0 | 0 |
| normal_misconfig | 5 | 40 | 15 | 15 | 0 | 15 |
| abnormal_1 | 5 | 5 | 5 | 5 | 0 | 5 |
| abnormal_2 | 5 | 10 | 5 | 0 | 5 | 5 |
| abnormal_3 | 5 | 90 | 30 | 30 | 0 | 30 |

놓친 공격 요청(FN): abnormal_2 `list pods 200` × 5, abnormal_3 `list pods 200` × 30, `list configmaps 200` × 30

## 4. 한계 3가지

**한계 1 — 조각으로만 본다.** 규칙이 요청 1건씩만 보기 때문에, 공격 흐름 안의 정상 모양 조회는 놓친다.
- 놓친 정상 모양 조회: abnormal_2 5건(exec 직전의 `list pods`), abnormal_3 60건(`list pods` 30 + `list configmaps` 30). 합계 65건이 FN 65건 전부다.
- 하나의 열거 공격(abnormal_3)이 1회당 알림 12개로 쪼개진다.

**한계 2 — 403이면 무조건 의심한다.** 모든 알림이 `high`이고, 설정 실수로 생긴 403과 공격을 구분하지 못한다.
- normal_misconfig 오탐 실행 5/5, 오탐 요청 15건(= FP 15건 전부). 요청 1건마다 R1·R3 알림 2개씩, 모두 30개다.

**한계 3 — 최소 권한이 깨지면 놓친다.** 반사실(메모리 안에서 감시 SA의 403→200, forbid→allow로 바꾼 사본) 결과:
- R3 알림: 55개 → 0개. abnormal_3 1회당 알림: 12 → 6.
- 실행 단위(15/15, 오탐 5/10)와 요청 단위(TP 40, FP 15, FN 65, TN 50, precision 0.727, recall 0.381)는 **변화 없음**.
- 이유: 표시된 요청은 모두 R1(resource가 secrets) 또는 R2(subresource가 exec)에도 걸린다. R1·R2는 응답 코드와 무관한 규칙이라, R3가 사라져도 표시 여부는 같다. 이 데이터셋에서 R3만으로 표시되는 요청은 없다.

## 5. 이전 측정값과 비교

| 항목 | 이전 | 이번 | 결과 |
|---|---|---|---|
| precision | 0.727 | 0.727 | 같음 |
| recall | 0.381 | 0.381 | 같음 |
| 공격 실행 탐지 | 15/15 | 15/15 | 같음 |
| misconfig 오탐 | 5/5 | 5/5 | 같음 |
| abnormal_3 1회당 알림 | 12 | 12.0 | 같음 |

## 6. 막힌 점과 제안

막힌 점: 없음.

제안
- 반사실의 "변화 없음"은 이 데이터셋에 R3 단독 표시 요청이 없어서다. 권한 밖이면서 secrets·exec가 아닌 요청(예: 권한 없는 리소스 list)이 있어야 차이가 보인다. 새 시나리오가 필요하므로 여기에는 기록만 한다.
