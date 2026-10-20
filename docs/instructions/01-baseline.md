# 단계 01 — 파서, 기본 탐지(R1~R3), 데이터셋, 기본 평가

## 목적
README 관찰점 3개로 기본 탐지기를 만든다. 에피소드 25개로 평가해서, 기본 탐지의 결과와 한계 3가지를 숫자로 보인다.

## 하지 않는 것
- 보완 규칙(C1~C3, 사건 묶기, severity 구분, 허용 목록 A1)은 만들지 않는다 (단계 02).
- `normal_misconfig` 외의 새 시나리오는 만들지 않는다.
- 판정에 토큰 ID, auditID, 타임스탬프 원값, IP, UA, 이벤트 순서를 쓰지 않는다. auditID는 요청을 묶는 데만 쓴다.
- 빈도 규칙, 실시간 모드, Falco 연동은 하지 않는다.
- 원본 샘플 로그(`category3/logs/`)는 단위 테스트에만 쓰고 평가에는 쓰지 않는다.

## 할 일

### 1. 지시서 저장
이 문서를 `docs/instructions/01-baseline.md`로 저장한다.

### 2. 파서 — `detector/parser.py`
- 입력은 audit JSON Lines 파일이다. JSON으로 읽을 수 없는 줄은 건너뛰고 개수를 센다.
- 감시 SA(`system:serviceaccount:pbl-security:pbl-crypto-platform-app`, 인자로 바꿀 수 있게 한다)의 줄만 남긴다.
- **auditID로 묶어 요청 1건으로 만든다.** 대표 줄은 ResponseComplete를 쓰고, 없으면 마지막 stage를 쓴다.
- 요청의 필드는 다음과 같다: `audit_id`, `time`(requestReceivedTimestamp를 datetime으로 바꾼 값), `verb`, `resource`, `subresource`, `namespace`, `name`(없으면 None), `code`, `decision`(annotation `authorization.k8s.io/decision`), `user_agent`, `source_ips`, `stages`(stage 목록).
- `time`은 정렬과 단계 02의 시간창 계산에만 쓴다.

### 3. 기본 규칙 — `detector/rules.py`
감시 SA 요청 1건마다 아래 규칙을 각각 판정한다. 한 요청이 여러 규칙에 걸리면 알림이 여러 개 나온다(예: secrets 403은 R1과 R3).

| 규칙 | 조건 |
| --- | --- |
| R1 Secret 접근 | `resource == "secrets"` |
| R2 다른 workload 진입 | `resource == "pods"`이고 subresource가 exec, attach, portforward 중 하나 |
| R3 권한 밖 요청 | `code == 403` 또는 `decision == "forbid"` |

- 알림 필드는 `rule`, `severity`, `reason`(한국어 한 줄), `audit_ids`, `time`이다.
- 기본 탐지는 등급을 나누지 않으므로 **모든 알림의 severity를 `high`로** 둔다. 이 점이 한계 2의 원인이다.
- 기본 탐지에는 사건 묶기가 없다. 알림 1개를 사건 1개로 센다.

### 4. CLI — `python3 -m detector <파일.jsonl> [--sa 이름] [--json]`
요청 수, 알림 목록(시각, 규칙, severity, verb·resource·subresource·name·code, 이유), 규칙별 알림 수를 출력한다. `--json`을 주면 같은 내용을 JSON으로 출력한다.

### 5. `scenarios/normal_misconfig.sh`
- `category3`의 스크립트에서 `ensure_lab_identity`와 공통 설정을 복사해 온다. 원본을 source하지 않는다.
- `normal.sh`와 같은 조회 5개를 실행한 뒤 `get secret app-tls`를 3회 시도한다. 기대 결과는 403 세 번이다. 실패해도 스크립트가 멈추지 않게 한다.
- 이 스크립트는 원본과 같은 방식이라 bash로 쓴다(Python 규칙의 예외).

### 6. 데이터 수집 — `evaluation/collect.py`
- 순서는 `normal → normal_misconfig → abnormal_1 → abnormal_2 → abnormal_3`이고, 이를 5바퀴 돌려 에피소드 25개를 만든다.
- 각 실행은 단계 00과 같은 방식이다. 실행 전 줄 수를 재고, 실행하고, 2초 기다린 뒤 줄 수를 다시 재서 증가분만 저장한다. 실행 사이에는 약 8초 쉰다.
- 로테이션이 감지되거나(줄 수 감소) 스크립트가 0이 아닌 값으로 끝나면, 그 실행을 버리고 1회 다시 실행한다. 다시 실패하면 멈추고 보고한다.
- 저장 위치는 `data/episodes/<순번2자리>_<시나리오>_<바퀴>.jsonl`이다. 관리자 줄과 시스템 줄도 그대로 둔다(필터링은 파서가 한다).
- `data/manifest.csv`의 열: `episode_id, scenario, label, round, file, started_at, total_lines, sa_requests`
- `label`은 normal과 normal_misconfig가 `benign`, abnormal_1~3이 `attack`이다. **라벨은 파일 단위로만 붙이고, 이벤트 순서나 토큰 발급 위치로 정하지 않는다.**

### 7. 평가 — `evaluation/evaluate.py`
- 클러스터 없이 `data/`만 읽는다. 에피소드마다 탐지기를 따로 돌린다.
- 요청 정답: attack 에피소드의 감시 SA 요청은 모두 공격이고, benign 에피소드의 요청은 모두 정상이다.
- 요청 판정: severity가 medium 이상인 알림이 하나라도 걸리면 "표시함"이다.
- 지표 (결과는 `evaluation/results/01-baseline.json`에 저장하고 같은 내용을 Markdown 표로 출력한다):
  1. 실행 단위: 공격 실행 탐지 수(/15), 정상 실행 오탐 수(/10). 알림이 하나라도 있으면 "탐지"다.
  2. 요청 단위: TP, FP, FN, TN, precision, recall
  3. abnormal_3 1회당 평균 알림 수와 사건 수
  4. 시나리오별 표: 실행 수, 요청 수, 표시한 요청 수, 규칙별 알림 수
- **반사실 재현:** 메모리 안에서만 감시 SA 요청의 `code 403→200`, `decision forbid→allow`로 바꾼 사본을 만들어 같은 지표를 다시 계산한다. 데이터 파일은 바꾸지 않는다. 결과는 같은 JSON의 `counterfactual` 키에 둔다.
- 놓친 공격 요청(FN)은 시나리오별로 `verb resource code` 조합과 개수를 출력한다.

### 8. 테스트 — `tests/`
`python3 -m unittest discover tests`로 실행한다.
- 파서: `category3/logs/`의 샘플로 auditID 묶기(여러 줄이 1건이 되는지), 403과 forbid 추출, exec의 subresource 추출을 확인한다. 잘못된 JSON 줄은 건너뛰는지도 확인한다.
- 규칙: 직접 만든 요청 몇 개로 R1~R3이 걸리는 경우와 걸리지 않는 경우를 확인한다. secrets 403이면 알림이 2개인지도 본다.
- 반사실 변환: 감시 SA가 아닌 요청은 바뀌지 않는지 확인한다.

### 9. 보고서 — `docs/reports/01-baseline.md` (한국어, 짧게)
1. 만든 것: 파일 목록과 실행 명령
2. 데이터셋: 시나리오별 실행 수, 실행 1회당 감시 SA 요청 수
3. 기본 탐지 결과: 7번의 지표 1~4. TP/FP/FN/TN, precision, recall은 처음 나올 때 한 줄로 설명한다.
4. 한계 3가지를 숫자로:
   - 한계 1(조각으로만 본다): abnormal_2와 abnormal_3에서 놓친 정상 모양 조회 수, abnormal_3 1회당 알림 수
   - 한계 2(403이면 무조건 의심): normal_misconfig의 오탐 실행 수와 오탐 요청 수
   - 한계 3(최소 권한이 깨지면 놓친다): 반사실에서 R3 알림이 몇 개에서 몇 개로 줄었는지, 그리고 실행·요청 지표의 변화. 변화가 작으면 작다고 그대로 적고, 이유(R1·R2는 응답 코드와 무관한 규칙이라는 점)를 한 줄로 쓴다.
5. 이전 측정값과 비교: precision 0.727, recall 0.381, 공격 실행 15/15, misconfig 5/5 오탐, abnormal_3 1회당 알림 12개. 같은지 다른지만 적고, 다르면 이유를 추정하지 말고 값만 적는다.
6. 막힌 점과 제안

### 10. 커밋
`[단계01] 기본 탐지와 데이터셋`을 커밋하고 main에 push한다. `data/`는 커밋하고, `tmp/`는 커밋하지 않는다.

## 완료 조건
- `python3 -m unittest discover tests`가 모두 통과한다.
- `data/episodes/`에 파일 25개와 `data/manifest.csv`가 있고, manifest의 sa_requests가 시나리오별로 일정하다(normal 5, misconfig 8, abnormal_1 1, abnormal_2 2, abnormal_3 18).
- `python3 evaluation/evaluate.py`가 클러스터 없이 실행되고 `evaluation/results/01-baseline.json`을 만든다.
- 원본 파일 diff가 없다(단계 00과 같은 명령으로 확인).
- 보고서에 9번의 6개 절이 모두 있다.
