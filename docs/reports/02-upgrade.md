# 단계 02 보고서 — 보완 1~3, 원래·반사실 평가, 최종 비교표

## 1. 만든 것

| 파일 | 역할 |
|---|---|
| `detector/common.py` | 공통 정의: `shape_severity`, `failed`, 허용 목록(README의 Role 권한) |
| `detector/upgrade.py` | 탐지기 u12·u123: 등급 매긴 R1·R3, C1·C2·C3, A1, 사건 묶기. `run(requests, mode)` |
| `detector/__main__.py` | CLI에 `--mode base\|u12\|u123` 추가(기본값 u123). 사건 목록도 출력 |
| `evaluation/evaluate.py` | 탐지기 3종 × 데이터 2종 = 6행 계산. `01-baseline.json`도 같은 내용으로 다시 만든다 |
| `tests/test_upgrade.py` | 테스트 25개 추가(전체 45개) |
| `evaluation/results/02-upgrade.json` | 비교표 6행과 행별 FN·FP |

```bash
python3 -m unittest discover tests                                   # 45개 통과
python3 -m detector data/episodes/05_abnormal_3_1.jsonl --mode u12    # base | u12 | u123
python3 evaluation/evaluate.py                                        # 클러스터 불필요
```

`01-baseline.json`은 단계 01 파일과 바이트 단위로 같다(`cmp`로 확인, 테스트로도 확인).

## 2. 보완별 규칙

**severity(심각도)**: 알림의 등급. low < medium < high이며, 평가에서는 **medium 이상만 탐지로 센다**(low는 "사람이 확인할 것" 정도의 기록).

| 한계 | 보완 | 규칙 |
|---|---|---|
| 1. 조각으로만 본다 | 보완 1: 요청을 묶어 본다 | **C1 열거 패턴(medium)**: 30초 창 안에 거부된 이름 없는 list/watch가 있고 리소스가 2종 이상이면, 창 안의 요청 전부를 알림 하나로 묶는다 |
| 1. 조각으로만 본다 | 보완 1 | **C3 정찰 후 진입(high)**: exec류 직전 10초 안의 pods get/list를 exec와 함께 묶는다 |
| 1. 조각으로만 본다 | 보완 1 | **사건 묶기**: 30초 안에 이어지는 알림을 사건 하나로 합친다. 사건 등급 = 묶인 알림 중 최고 등급 |
| 2. 403이면 무조건 의심 | 보완 2: 요청 모양으로 등급 | R1·R3의 severity = `shape_severity`(exec류 high, 이름 없는 list/watch medium, 이름 지정 get low, 그 밖 medium). R2는 high 유지 |
| 2. 403이면 무조건 의심 | 보완 2 | **C2 권한 설정 확인(low)**: 같은 대상의 이름 지정 get이 3회 이상 거부되면 low 알림 하나로 묶는다 |
| 3. 최소 권한이 깨지면 놓친다 | 보완 3: 응답 코드 대신 허용 목록 | **A1 허용 목록 밖**: README의 Role 권한({pods, services, configmaps} × {get, list}) 밖이면 코드와 무관하게 알림. 이름 없는 list/watch·exec류 high, 이름 지정 get low, 그 밖 medium |
| 3. 최소 권한이 깨지면 놓친다 | 보완 3 | **C1 계기 확장**: 허용 목록 밖의 이름 없는 list/watch도 C1의 계기로 인정한다 |

u12 = 보완 1·2, u123 = 보완 1~3.

## 3. 최종 비교표

반사실 = 메모리 안에서 감시 SA의 403→200, forbid→allow로 바꾼 사본(최소 권한이 깨진 상황).

| 탐지기 | 데이터 | 공격 실행 탐지 | 정상 실행 오탐 | TP | FP | FN | TN | precision | recall | abnormal_3 1회당 알림 / 사건 |
|---|---|---|---|---|---|---|---|---|---|---|
| base | original | 15/15 | 5/10 | 40 | 15 | 65 | 50 | 0.727 | 0.381 | 12.0 / 12.0 |
| base | counterfactual | 15/15 | 5/10 | 40 | 15 | 65 | 50 | 0.727 | 0.381 | 6.0 / 6.0 |
| u12 | original | 15/15 | 0/10 | 105 | 0 | 0 | 65 | 1.000 | 1.000 | 13.0 / 1.0 |
| u12 | counterfactual | 15/15 | 0/10 | 45 | 0 | 60 | 65 | 1.000 | 0.429 | 6.0 / 1.0 |
| u123 | original | 15/15 | 0/10 | 105 | 0 | 0 | 65 | 1.000 | 1.000 | 19.0 / 1.0 |
| u123 | counterfactual | 15/15 | 0/10 | 105 | 0 | 0 | 65 | 1.000 | 1.000 | 13.0 / 1.0 |

알림 수는 low를 포함한 전체, 사건 수는 medium 이상 사건만 센다.

## 4. 한계별 변화

**한계 1 (조각으로만 본다)** — base/original → u12/original
- FN 65 → 0, recall 0.381 → 1.000. abnormal_2의 `list pods` 5건은 C3가, abnormal_3의 `list pods`·`list configmaps` 60건은 C1이 묶었다.
- abnormal_3 1회당 사건 12 → 1. 알림은 12 → 13개로 오히려 1개 늘었다(R1 6 + R3 6 + C1 1). 알림 수는 줄지 않고, 사건 묶기로 사람이 볼 단위가 1개가 된다.

**한계 2 (403이면 무조건 의심)** — base/original → u12/original
- 정상 실행 오탐 5/10 → 0/10, FP 15 → 0, precision 0.727 → 1.000.
- normal_misconfig의 `get secrets app-tls` 403은 이름 지정 get이라 R1·R3가 low가 되고, C2(low) 1개로 묶인다. 알림은 남지만 탐지로는 세지 않는다.

**한계 3 (최소 권한이 깨지면 놓친다)** — u12/counterfactual → u123/counterfactual
- u12는 반사실에서 FN 0 → 60, recall 1.000 → 0.429로 떨어진다. 거부(403)가 사라져 C1의 계기가 없어졌기 때문이다(C1 알림 5 → 0).
- u123은 반사실에서도 FN 0, recall 1.000. A1이 secrets list를 응답 코드와 무관하게 high로 잡고, 같은 요청이 C1의 계기가 되어 abnormal_3 전체를 묶는다(C1 알림 5개 유지).
- base는 반사실에서도 지표가 같다(단계 01과 동일). R1·R2가 응답 코드와 무관한 규칙이어서다.

## 5. 오탐·미탐 분석

| 행 | 남은 FN | 남은 FP |
|---|---|---|
| base / original | abnormal_2 `list pods 200` × 5, abnormal_3 `list pods 200` × 30, `list configmaps 200` × 30 | normal_misconfig `get secrets 403` × 15 |
| base / counterfactual | 위와 같음 | normal_misconfig `get secrets 200` × 15 |
| u12 / original | 없음 | 없음 |
| u12 / counterfactual | abnormal_3 `list pods 200` × 30, `list configmaps 200` × 30 | 없음 |
| u123 / original | 없음 | 없음 |
| u123 / counterfactual | 없음 | 없음 |

## 6. 남는 한계
- 공격자가 Secret 이름을 알고 이름을 지정해 get하면 low로만 잡힌다(R1·R3·A1 모두 low, 3회 이상 거부되어도 C2 low).
- 허용 목록은 앱이 바뀔 때마다 사람이 갱신해야 한다.
- 30초보다 느린 열거는 하나로 묶이지 않는다.
- 실제 탈취에서는 정상 앱과 공격자가 같은 토큰과 IP를 쓸 수 있다.
- 규칙을 같은 4개 시나리오를 보고 설계했고, 같은 데이터로 평가했다. 별도 검증 데이터가 없다. 그래서 precision·recall 1.000은 일반 성능이 아니라 "이 4개 시나리오에 맞췄다"는 뜻으로 읽어야 한다.
- R1·R2와 겹치지 않는 권한 밖 요청이 데이터에 없어서, R3 단독의 효과는 측정하지 못했다.
- 창 크기의 여유를 시험하지 못했다. abnormal_3 실행은 1회 약 1.7~1.8초, abnormal_2의 `list pods`→exec 간격은 약 0.04초로, 30초·10초 창의 경계 근처 데이터가 없다.
- 정상 앱의 조회가 공격 직전·직후 30초 안에 섞이면 C1이 그 정상 조회까지 묶는다(창 안 요청 "전부"를 묶기 때문). 이 데이터셋은 에피소드를 따로 평가해 이런 섞임이 없다.
- 알림 수 자체는 줄지 않는다(u123 abnormal_3 1회당 19개). 줄어드는 것은 사건 수다.

## 7. 이전 측정값과 비교

| 항목 | 이전 | 이번 | 결과 |
|---|---|---|---|
| u12 원래 precision | 1.000 | 1.000 | 같음 |
| u12 원래 recall | 1.000 | 1.000 | 같음 |
| u12 원래 abnormal_3 사건 | 1개 | 1.0개 | 같음 |
| u12 반사실 recall | 0.429 | 0.429 | 같음 |

## 8. 막힌 점과 제안

막힌 점: 없음.

제안
- 별도 검증 데이터(설계에 쓰지 않은 시나리오, 예: 느린 열거, 정상 조회와 섞인 공격)로 다시 평가한다.
