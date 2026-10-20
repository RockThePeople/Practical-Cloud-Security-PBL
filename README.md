# 실무클라우드보안 PBL Project
**한국어** | [English](README_EN.md)

| 실습 | 관찰 도구 | 정상 행위 | 비정상 행위 |
| --- | --- | --- | --- |
| Category 1 | Falco | 설정·임시 파일·health check | shadow·token 접근, 셸 실행 |
| Category 2 | Hubble | 서비스 경로·DNS 통신 | 직접 접근·내부 탐색·비정상 포트 |
| Category 3 | Audit Log | Pod·ConfigMap·Service 조회 | Secret·Pod exec·반복 조회 |

## 1. 준비

- Ubuntu 22.04/24.04 또는 Debian 12
- x86_64 또는 ARM64
- `sudo` 사용 권한

Docker Engine, kind, kubectl, Helm, Cilium, Hubble, Falco는 미리 설치하지 않아도 됩니다.

## 2. 설치

저장소를 clone한 뒤 프로젝트 루트에서 실행합니다.

```bash
cd pbl-project
chmod +x install.sh category1/*.sh category2/*.sh category3/*.sh
./install.sh
```

Docker를 처음 설치한 경우 스크립트가 로그아웃을 요청할 수 있습니다. 그때는 VM에서 로그아웃 후 다시 로그인하고 `./install.sh`를 한 번 더 실행합니다.

설치 결과를 확인합니다.

```bash
kubectl get nodes
kubectl get pods -A
```

노드 3개가 `Ready`이고 워크로드, Cilium, Hubble, Falco Pod가 `Running`이면 준비 완료입니다. 노드 3개는 별도 VM이 아니라 현재 VM의 Docker 컨테이너입니다.

## 3. 실습

모든 명령은 프로젝트 루트에서 실행합니다.

```bash
# Category 1: Falco
./category1/normal.sh
./category1/abnormal_1.sh
./category1/abnormal_2.sh
./category1/abnormal_3.sh

# Category 2: Hubble
./category2/normal.sh
./category2/abnormal_1.sh
./category2/abnormal_2.sh
./category2/abnormal_3.sh

# Category 3: Kubernetes Audit Log
./category3/normal.sh
./category3/abnormal_1.sh
./category3/abnormal_2.sh
./category3/abnormal_3.sh
```

로그를 실시간으로 보는 방법은 각 문서를 따릅니다.

- [Category 1 - Falco](category1/README.md)
- [Category 2 - Hubble](category2/README.md)
- [Category 3 - Audit Log](category3/README.md)

각 Category의 `logs/normal.log`, `logs/abnormal_1.log`부터 `logs/abnormal_3.log`까지는 예상 로그 예시입니다. 실제 로그의 Pod 이름, IP, 시간은 실행할 때마다 달라집니다.

## Category 3 결과 — Kubernetes Audit Log 기반 SA 오용 탐지

### 요약
- 같은 ServiceAccount(`pbl-crypto-platform-app`)의 정상 사용과 공격성 사용을 kube-apiserver Audit Log만으로 구분하는 탐지기를 만들었다(Python 표준 라이브러리만 사용).
- 기본 탐지(README 관찰점 R1~R3)는 precision 0.727, recall 0.381이었다. 보완 1~3을 더한 u123은 원래 데이터와 반사실 데이터 모두에서 precision·recall 1.000이다.
- 단, 이 1.000은 규칙을 설계할 때 본 데이터로 평가한 값이다. 자세한 과정은 [단계 01 보고서](docs/reports/01-baseline.md), [단계 02 보고서](docs/reports/02-upgrade.md)에 있다.

### 실행 방법

```bash
python3 -m unittest discover tests                                    # 단위 테스트
python3 -m detector data/episodes/05_abnormal_3_1.jsonl --mode u123    # 탐지 CLI (base | u12 | u123, --json)
python3 evaluation/evaluate.py                                         # 평가 (클러스터 불필요)
python3 evaluation/describe.py                                         # 구분 근거용 기술 통계
python3 evaluation/collect.py                                          # 데이터 다시 수집 (kind 클러스터 필요, 약 8분)
```

### 데이터
- 시나리오 5종 × 5회 = 실행(에피소드) 25개: `normal`, `normal_misconfig`(benign), `abnormal_1`~`abnormal_3`(attack). 파일은 `data/episodes/`, 목록은 `data/manifest.csv`.
- `normal_misconfig`(`scenarios/normal_misconfig.sh`)는 정상 조회 5개 뒤에 권한 없는 `get secret app-tls`를 3번 시도하는 정상 앱이다. "403이면 공격"이라는 가정이 틀리는 경우를 보려고 넣었다.
- 라벨은 파일(실행) 단위로만 붙였다. attack 실행의 감시 SA 요청은 모두 공격, benign 실행의 요청은 모두 정상으로 본다.

### 정상/공격 구분 근거
`evaluation/describe.py`의 시나리오별 통계(`evaluation/results/03-describe.json`):

| 시나리오 | 라벨 | 출발지 IP | UA | 요청/회 | 초당 요청(평균) | 403/회 | 이름 지정/회 | 요청 모양 |
|---|---|---|---|---|---|---|---|---|
| normal | benign | 172.19.0.1 | kubectl | 5 | 11.4 | 0 | 1 | list pods·services·configmaps, get pods |
| normal_misconfig | benign | 172.19.0.1 | kubectl | 8 | 11.1 | 3 | 4 | 위 + get secrets |
| abnormal_1 | attack | 172.19.0.1 | kubectl | 1 | - | 1 | 0 | list secrets |
| abnormal_2 | attack | 172.19.0.1 | kubectl, curl | 2 | 49.8 | 1 | 1 | list pods, create pods/exec |
| abnormal_3 | attack | 172.19.0.1 | kubectl | 18 | 10.3 | 6 | 0 | list pods·secrets·configmaps |

| 구분 | 항목 | 이유 |
|---|---|---|
| 쓰지 않음 | 출발지 IP | 모든 실행이 `172.19.0.1`로 같다 |
| 쓰지 않음 | User-Agent | 모두 `kubectl/v1.37.1`. abnormal_2의 exec 1건만 `curl/7.81.0`인데, 도구는 공격자가 쉽게 바꾼다 |
| 쓰지 않음 | 속도(빈도) | "빠른 열거"인 abnormal_3이 초당 10.3건으로 normal(11.4건)보다 느리다. abnormal_2의 49.8은 요청 2건이 0.04초 간격인 것뿐이다 |
| 쓰지 않음 | 토큰 ID | 모든 스크립트가 실행마다 새 토큰을 발급한다(`kubectl create token`). 정상·공격 모두 실행마다 바뀐다 |
| 씀 | 리소스 | 정상은 pods·services·configmaps만, 공격은 secrets를 조회한다 |
| 씀 | subresource | `pods/exec`는 공격(abnormal_2)에만 있다 |
| 씀 | 이름 유무 | Secret을 이름 없이 통째로 list(열거)하는 것은 공격, 이름을 지정한 get은 설정 실수(misconfig)에만 있다 |
| 씀 | 응답 코드 | 403은 권한 밖 시도의 신호다. 단, misconfig에도 있으므로 단독으로는 부족하다 |
| 씀 | 허용 목록 | README의 Role 권한({pods, services, configmaps} × {get, list}) 밖이면 응답 코드와 무관하게 표시한다 |
| 씀 | 시간적 묶음 | 공격 흐름 안의 정상 모양 조회를 묶는다(30초 열거 창, exec 직전 10초) |

### 탐지 기준
severity(심각도)는 알림의 등급이다(low < medium < high). 평가에서는 **medium 이상만 탐지로 센다**.

| 탐지기 | 규칙 | 내용 |
|---|---|---|
| base | R1 Secret 접근 | `resource == secrets` (high) |
| base | R2 다른 workload 진입 | pods의 exec·attach·portforward (high) |
| base | R3 권한 밖 요청 | `code == 403` 또는 `decision == forbid` (high) |
| u12 (보완 1) | C1 열거 패턴 | 30초 창 안에 거부된 이름 없는 list/watch + 리소스 2종 이상 → 창 안 요청 전부를 묶음 (medium) |
| u12 (보완 1) | C3 정찰 후 진입 | exec 직전 10초 안의 pods get/list를 exec와 묶음 (high) |
| u12 (보완 1) | 사건 묶기 | 30초 안에 이어지는 알림을 사건 하나로. 사건 등급 = 최고 등급 |
| u12 (보완 2) | 등급 매기기 | R1·R3를 요청 모양으로: exec류 high, 이름 없는 list/watch medium, 이름 지정 get low |
| u12 (보완 2) | C2 권한 설정 확인 | 같은 대상의 이름 지정 get이 3회 이상 거부 → low 알림 하나 |
| u123 (보완 3) | A1 허용 목록 밖 | 허용 목록 밖이면 응답 코드와 무관하게 알림. 이름 없는 list/watch·exec류 high, 이름 지정 get low, 그 밖 medium |
| u123 (보완 3) | C1 계기 확장 | 허용 목록 밖의 이름 없는 list/watch도 C1의 계기로 인정 |

### 탐지 결과
`evaluation/results/02-upgrade.json`:

| 탐지기 | 데이터 | 공격 실행 탐지 | 정상 실행 오탐 | TP | FP | FN | TN | precision | recall | abnormal_3 1회당 알림 / 사건 |
|---|---|---|---|---|---|---|---|---|---|---|
| base | original | 15/15 | 5/10 | 40 | 15 | 65 | 50 | 0.727 | 0.381 | 12.0 / 12.0 |
| base | counterfactual | 15/15 | 5/10 | 40 | 15 | 65 | 50 | 0.727 | 0.381 | 6.0 / 6.0 |
| u12 | original | 15/15 | 0/10 | 105 | 0 | 0 | 65 | 1.000 | 1.000 | 13.0 / 1.0 |
| u12 | counterfactual | 15/15 | 0/10 | 45 | 0 | 60 | 65 | 1.000 | 0.429 | 6.0 / 1.0 |
| u123 | original | 15/15 | 0/10 | 105 | 0 | 0 | 65 | 1.000 | 1.000 | 19.0 / 1.0 |
| u123 | counterfactual | 15/15 | 0/10 | 105 | 0 | 0 | 65 | 1.000 | 1.000 | 13.0 / 1.0 |

- **TP / FP / FN / TN**: 공격 요청을 표시함 / 정상 요청을 표시함(오탐) / 공격 요청을 놓침(미탐) / 정상 요청을 표시하지 않음. 요청 단위로 센다.
- **precision(정밀도)** = TP / (TP + FP): 표시한 요청 중 진짜 공격의 비율.
- **recall(재현율)** = TP / (TP + FN): 공격 요청 중 표시한 요청의 비율.
- **반사실(counterfactual)**: Role이 넓게 잘못 설정된 상황을 흉내 내려고, 평가 코드 안에서만 감시 SA의 403을 200(forbid를 allow)으로 바꾼 것이다. 실제 권한은 바꾸지 않았다.
- 알림 수는 low를 포함한 전체, 사건 수는 medium 이상 사건만 센다.

### 오탐·미탐 분석

| 탐지기 / 데이터 | 남은 미탐(FN) | 남은 오탐(FP) |
|---|---|---|
| base / original | abnormal_2 `list pods 200` × 5, abnormal_3 `list pods 200` × 30, `list configmaps 200` × 30 | normal_misconfig `get secrets 403` × 15 |
| base / counterfactual | 위와 같음 | normal_misconfig `get secrets 200` × 15 |
| u12 / original | 없음 | 없음 |
| u12 / counterfactual | abnormal_3 `list pods 200` × 30, `list configmaps 200` × 30 | 없음 |
| u123 / original | 없음 | 없음 |
| u123 / counterfactual | 없음 | 없음 |

- base의 미탐 65건은 모두 공격 흐름 안의 정상 모양 조회다. 요청을 하나씩만 보기 때문이다(보완 1이 해결).
- base의 오탐 15건은 모두 misconfig의 이름 지정 Secret get이다. 403이면 무조건 high이기 때문이다(보완 2가 low로 낮춤).
- u12의 반사실 미탐 60건은 403이 사라져 C1의 계기가 없어졌기 때문이다(보완 3의 허용 목록이 해결).

### 한계
- **precision·recall 1.000은 규칙을 설계할 때 본 4개 시나리오(+misconfig)와 같은 데이터로 평가한 결과다. 일반 성능이 아니다.**
- 공격자가 Secret 이름을 알고 이름을 지정해 get하면 low로만 잡힌다(R1·R3·A1 모두 low, 3회 이상 거부되어도 C2 low).
- 허용 목록은 앱이 바뀔 때마다 사람이 갱신해야 한다.
- 30초보다 느린 열거는 하나로 묶이지 않는다.
- 실제 탈취에서는 정상 앱과 공격자가 같은 토큰과 IP를 쓸 수 있다.
- 규칙을 같은 4개 시나리오를 보고 설계했고, 같은 데이터로 평가했다. 별도 검증 데이터가 없다. 그래서 precision·recall 1.000은 일반 성능이 아니라 "이 4개 시나리오에 맞췄다"는 뜻으로 읽어야 한다.
- R1·R2와 겹치지 않는 권한 밖 요청이 데이터에 없어서, R3 단독의 효과는 측정하지 못했다.
- 창 크기의 여유를 시험하지 못했다. abnormal_3 실행은 1회 약 1.7~1.8초, abnormal_2의 `list pods`→exec 간격은 약 0.04초로, 30초·10초 창의 경계 근처 데이터가 없다.
- 정상 앱의 조회가 공격 직전·직후 30초 안에 섞이면 C1이 그 정상 조회까지 묶는다(창 안 요청 "전부"를 묶기 때문). 이 데이터셋은 에피소드를 따로 평가해 이런 섞임이 없다.
- 알림 수 자체는 줄지 않는다(u123 abnormal_3 1회당 19개). 줄어드는 것은 사건 수다.
