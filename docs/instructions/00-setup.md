# 단계 00 — 작업 규칙, 클러스터 확인, audit 모양 확인

## 목적
1. 이후 단계에서 지킬 작업 규칙(CLAUDE.md)을 만든다.
2. 레포를 다시 fork했으므로 kind 클러스터가 아직 살아 있는지 확인한다.
3. `category3/`의 스크립트 4개를 1회씩 실행한다. 감시 SA의 요청이 audit.log에 어떤 모양으로 찍히는지 확인해서, 단계 01의 파서 설계 근거로 삼는다.

## 하지 않는 것
- 파서, 탐지 규칙, 평가 코드는 만들지 않는다 (단계 01).
- `normal_misconfig`와 데이터셋 25개도 만들지 않는다 (단계 01).
- 원본 파일(`install.sh`, `workload/`, `category1~3/`)은 수정하지 않는다. 루트 `.gitignore`에 항목을 추가하는 것만 허용한다.
- 클러스터를 재설치하지 않는다. 클러스터가 없거나 망가져 있으면 멈추고 보고한다. 재설치 여부는 사용자가 정한다.
- 이번 단계에서 쓰는 임시 분석 명령은 커밋하지 않는다.

## 할 일

### 1. 이 지시서 저장
이 문서를 `docs/instructions/00-setup.md`로 저장한다.

### 2. CLAUDE.md 생성 (레포 루트, 아래 내용 그대로)

```
# CLAUDE.md — Category 3 (Kubernetes Audit Log) 작업 규칙

## 과제
같은 ServiceAccount(system:serviceaccount:pbl-security:pbl-crypto-platform-app)의
정상 API 사용과 공격성 API 사용을 kube-apiserver Audit Log만으로 구분한다.
흐름: README 관찰점으로 기본 탐지 → 한계 3가지 → 한 번 업그레이드.

## 규칙
- 원본 파일(install.sh, workload/, category1~3/)은 수정하지 않는다. 루트 .gitignore에 항목을 추가하는 것만 예외로 허용한다.
- 새 코드는 detector/, scenarios/, evaluation/, tests/에, 데이터는 data/에 둔다. 임시 파일은 tmp/에 두고 커밋하지 않는다.
- Python 표준 라이브러리와 unittest만 쓴다.
- 지시서(docs/instructions/)에 없는 것은 만들지 않는다. 범위를 넓히고 싶으면 보고서의 "제안"에 한 줄로만 적는다.
- 새 공격 시나리오는 만들지 않는다. 실제 Secret 탈취, exec 성공, 권한 변경도 하지 않는다.
- 판정에 쓰지 않는 필드: 토큰 ID(user.extra의 credential-id, JTI), auditID, 타임스탬프 원값, 관리자 이벤트와의 순서. 출발지 IP와 UA로도 구분하지 않는다. (auditID는 요청 묶기에, 위 필드들은 평가 스크립트의 정답 라벨 붙이기에만 쓸 수 있다.)
- 빈도(요청량·속도) 임계값 규칙은 만들지 않는다.
- 막히면 추측으로 우회하지 않는다. 보고서에 막힌 지점과 에러 원문을 적고 멈춘다.

## 파일·커밋
- 지시서: docs/instructions/NN-*.md / 보고서: docs/reports/NN-*.md
- 커밋 메시지: [단계NN] 요약. 작업이 끝나면 main에 push한다.
- 보고서는 한국어로 짧게 쓴다. 독자는 보안·Kubernetes 입문자이므로, 전문 용어는 처음 나올 때 한 줄로 설명한다.
```

### 3. `.gitignore`에 추가
`__pycache__/`, `*.pyc`, `tmp/`

### 4. 클러스터 상태 확인
아래 명령을 실행하고 결과를 요약한다(PATH에 `$HOME/.local/bin`이 있어야 한다).
- `kind get clusters`
- `kubectl get nodes`
- `kubectl get pods -A` (Running이 아닌 것만 따로 적는다)
- `docker exec pbl-security-control-plane ls -l /var/log/kubernetes/`
- `docker exec pbl-security-control-plane wc -l /var/log/kubernetes/audit.log`

클러스터가 없거나 audit.log가 없으면 여기서 멈추고 보고서만 쓴다.

### 5. 스크립트 4개를 1회씩 실행하고 증가분 저장
- 먼저 각 스크립트를 읽고, 어느 디렉터리에서 어떻게 실행해야 하는지 확인한다.
- `normal`, `abnormal_1`, `abnormal_2`, `abnormal_3` 순서로 다음을 반복한다.
  1. 실행 전 audit.log 줄 수를 잰다.
  2. 스크립트를 1회 실행한다(stdout/stderr는 `tmp/stage00/<이름>.out`에 저장).
  3. 2초 기다린 뒤 줄 수를 다시 잰다.
  4. 증가한 줄만 `tmp/stage00/<이름>.jsonl`에 저장한다.
  5. 다음 스크립트까지 약 8초 쉰다.
- 실행 후 줄 수가 실행 전보다 적으면 로테이션이 일어난 것이다. 이 경우 그 실행은 버리고 보고서에 적는다.

### 6. 감시 SA 요청의 모양 요약
임시 명령으로 각 `.jsonl`에서 `user.username`이 감시 SA인 줄만 골라, 스크립트별로 다음을 표로 정리한다.
- 줄 수와 고유 auditID 수(= 요청 수)
- auditID 하나당 stage 목록(예: RequestReceived + ResponseComplete)
- 요청별 verb, resource, subresource, name 유무, responseStatus.code, annotation `authorization.k8s.io/decision`
- userAgent와 sourceIPs의 고유값

감시 SA가 아닌 줄(관리자의 토큰 발급, apply 등)은 사용자와 개수만 적는다.

### 7. 이전 관찰과 대조
아래 항목마다 "일치/불일치"와 실제 값을 적는다.
1. pods·services·secrets는 요청당 2줄, configmaps는 1줄, exec는 ResponseStarted와 ResponseComplete로 찍힌다.
2. 정상과 공격의 출발지 IP와 UA가 같다(예외는 abnormal_2의 exec 하나로, curl이다).
3. 거부된 요청은 code 403과 decision forbid를 함께 가진다.
4. 요청 수: normal 5건, abnormal_1 1건, abnormal_2 2건(list 200, exec 403), abnormal_3 18건(그중 secrets 6건이 403).
5. 감시 SA 요청 바로 앞에 관리자의 토큰 발급 이벤트가 찍힌다.

### 8. 보고서와 커밋
`docs/reports/00-setup.md`에 다음 순서로 짧게 쓴다.
1. 클러스터 상태
2. 스크립트별 요약표
3. 이전 관찰 대조 결과
4. 막힌 점(없으면 "없음")
5. 제안(있으면 한 줄씩)

커밋 `[단계00] 작업 규칙과 audit 모양 확인`을 만들고 main에 push한다.

## 완료 조건
- `CLAUDE.md`, `.gitignore`, `docs/instructions/00-setup.md`, `docs/reports/00-setup.md`가 main에 push되어 있다.
- `tmp/`는 커밋되지 않았다.
- `git diff --stat 270bf2d HEAD -- install.sh workload category1 category2 category3`의 출력이 비어 있다(원본 무수정).
- 보고서에 스크립트 4개의 요청 수 표와 7번 대조 결과 5개가 모두 있다.

## 추가 지시

### 결정
1. 히스토리는 `270bf2d`부터 다시 시작한다. main은 `270bf2d → [단계00] 커밋 1개`가 되어야 한다.
2. 클러스터는 지우고 다시 설치한다.
3. CLAUDE.md에 `.generated/` 보호 규칙을 다시 넣는다.

### A. 히스토리 정리 (재설치보다 먼저 한다)
1. `git branch backup/old-attempt 42fe2ef`로 로컬 백업을 만든다. 이 브랜치는 push하지 않는다.
2. `git reset --hard 270bf2d`
3. `git checkout backup/old-attempt -- CLAUDE.md docs/instructions/00-setup.md docs/reports/00-setup.md`
4. `.gitignore`는 원본 내용에 다음 항목만 더한다(원본에 이미 있으면 넣지 않는다): `__pycache__/`, `*.pyc`, `tmp/`, `.generated/`
5. `data/stage00/`처럼 이전 시도에서 온 파일이 작업 폴더에 남아 있지 않은지 `git status`로 확인한다.

### B. CLAUDE.md 규칙 추가
"## 규칙" 맨 위에 다음 줄을 넣는다.
```
- 레포 폴더와 .generated/는 지우거나 옮기지 않는다. 클러스터가 이 폴더를 bind mount해서 audit 정책과 audit.log를 쓴다. .generated/는 커밋하지 않는다.
```

### C. 클러스터 재설치
1. `kind get clusters`로 클러스터 이름을 확인하고 `kind delete cluster --name <이름>`을 실행한다.
2. 레포 루트에서 `INSTALL_BIN_DIR=$HOME/.local/bin ./install.sh`를 실행한다.
3. 원래 지시서 4번의 확인 명령을 다시 실행한다. audit.log가 있고, `kubectl get pods -A`를 한 번 실행한 뒤 줄 수가 늘어나는지 확인한다.
4. 설치가 실패하면 멈추고 에러 원문을 보고서에 적는다.

### D. 원래 지시서 5~8번 진행
- 보고서 `docs/reports/00-setup.md`는 실제 결과로 다시 쓴다.
- 맨 앞에 "재설치 경위" 절을 3줄 이내로 둔다. 원인(`.generated/` 삭제), 조치(히스토리 리셋, 재설치), 재발 방지(CLAUDE.md 규칙)를 적는다.

### E. 커밋과 push
- 커밋 하나로 만든다: `[단계00] 작업 규칙과 audit 모양 확인`
- `git push --force-with-lease origin main`

### 완료 조건 (원래 조건에 추가)
- `git log --oneline origin/main`의 결과가 `270bf2d` 위에 [단계00] 커밋 1개뿐이다.
- `.generated/`와 `tmp/`는 커밋되지 않았다.
- 보고서의 대조 결과 5개가 "미확인"이 아니라 실제 값으로 채워져 있다.
