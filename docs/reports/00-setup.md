# 단계 00 보고서 — 작업 규칙, 클러스터 확인, audit 모양 확인

## 재설치 경위
- 원인: 예전 레포 폴더를 지울 때 `.generated/`도 함께 지워졌다. 클러스터는 이 폴더를 bind mount(호스트 폴더를 컨테이너 경로에 연결)해서 audit 정책과 `audit.log`를 쓰기 때문에 `audit.log`가 사라졌다.
- 조치: main을 `270bf2d`로 되돌리고(이전 시도는 로컬 브랜치 `backup/old-attempt`에만 보관), kind 클러스터를 지운 뒤 `install.sh`로 다시 설치했다.
- 재발 방지: `CLAUDE.md` 규칙 맨 위에 "레포 폴더와 `.generated/`는 지우거나 옮기지 않는다" 규칙을 넣었다.

용어
- **Audit Log**: kube-apiserver(클러스터의 모든 API 요청을 받는 서버)가 "누가, 무엇을, 어떤 결과로" 요청했는지 남기는 기록. 한 줄이 JSON 하나다.
- **SA(ServiceAccount)**: 사람 대신 프로그램이 쓰는 Kubernetes 계정. 여기서는 감시 대상 `system:serviceaccount:pbl-security:pbl-crypto-platform-app`.
- **auditID**: 요청 하나에 붙는 ID. 한 요청이 여러 줄(stage)로 찍히면 같은 auditID를 가진다.
- **stage**: 요청 처리 단계. `RequestReceived`(받음), `ResponseStarted`(응답 시작, exec 같은 스트리밍에만), `ResponseComplete`(응답 끝).
- **decision**: annotation `authorization.k8s.io/decision`. RBAC(역할 기반 권한) 검사 결과로, `allow`(허용) 또는 `forbid`(거부)다.

## 1. 클러스터 상태 (재설치 후)

| 확인 항목 | 결과 |
|---|---|
| `kind get clusters` | `pbl-security` |
| `kubectl get nodes` | control-plane, worker, worker2 모두 `Ready` (v1.31.0) |
| `kubectl get pods -A` | 25개 모두 Running. Running이 아닌 Pod 없음 |
| `ls -l /var/log/kubernetes/` | `audit.log` 있음 (약 11.7MB) |
| `wc -l audit.log` | 5201줄 → `kubectl get pods -A` 1회 후 5213줄 (증가 확인) |

`install.sh`는 exit 0으로 끝났다. `.generated/`(audit, audit-logs, kind-config.yaml)가 다시 만들어졌다.

## 2. 스크립트별 요약표

실행: 레포 루트에서 `./category3/<이름>.sh`. 4개 모두 exit 0이고 로테이션(로그 파일 교체)은 없었다.

### 요청 수

| 스크립트 | 증가 줄 수(전체) | 감시 SA 줄 수 | 감시 SA 요청 수(고유 auditID) | 그 외 줄 (사용자: 개수) |
|---|---|---|---|---|
| normal | 38 | 9 | 5 | kubernetes-admin 17, system:apiserver 4, system:anonymous 3, kube-controller-manager 2, cilium-operator 2, kube-scheduler 1 |
| abnormal_1 | 22 | 2 | 1 | kubernetes-admin 8, kube-controller-manager 3, cilium-operator 3, kube-scheduler 2, system:apiserver 2, system:anonymous 2 |
| abnormal_2 | 26 | 4 | 2 | kubernetes-admin 8, kube-controller-manager 4, kube-scheduler 3, cilium-operator 3, system:anonymous 2, cilium 2 |
| abnormal_3 | 57 | 30 | 18 | kubernetes-admin 8, system:anonymous 5, kube-controller-manager 4, system:apiserver 4, cilium-operator 3, kube-scheduler 2, cilium 1 |

kubernetes-admin 줄은 스크립트가 시작할 때 실행하는 `kubectl apply`(SA·Role·RoleBinding 확인)와 `kubectl create token`(SA 토큰 발급)에서 나온다. normal은 재설치 직후 첫 실행이어서 SA·Role·RoleBinding을 새로 `create`했다(17줄). 나머지 세 스크립트는 이미 있으므로 `get`만 했다(8줄).

### 감시 SA 요청의 모양

| 스크립트 | 개수 | verb | resource | subresource | name | code | decision | stage |
|---|---|---|---|---|---|---|---|---|
| normal | 2 | list | pods | - | 없음 | 200 | allow | RequestReceived + ResponseComplete |
| normal | 1 | get | pods | - | 있음 | 200 | allow | RequestReceived + ResponseComplete |
| normal | 1 | list | services | - | 없음 | 200 | allow | RequestReceived + ResponseComplete |
| normal | 1 | list | configmaps | - | 없음 | 200 | allow | ResponseComplete |
| abnormal_1 | 1 | list | secrets | - | 없음 | 403 | forbid | RequestReceived + ResponseComplete |
| abnormal_2 | 1 | list | pods | - | 없음 | 200 | allow | RequestReceived + ResponseComplete |
| abnormal_2 | 1 | create | pods | exec | 있음 | 403 | forbid | ResponseStarted + ResponseComplete |
| abnormal_3 | 6 | list | pods | - | 없음 | 200 | allow | RequestReceived + ResponseComplete |
| abnormal_3 | 6 | list | secrets | - | 없음 | 403 | forbid | RequestReceived + ResponseComplete |
| abnormal_3 | 6 | list | configmaps | - | 없음 | 200 | allow | ResponseComplete |

- normal의 `list pods` 2건: 하나는 `get pods`, 하나는 `get pod -l app=frontend`(라벨로 골라 이름 얻기)다.
- userAgent 고유값: `kubectl/v1.37.1 (linux/amd64) kubernetes/f78e722` (4개 스크립트 공통), `curl/7.81.0` (abnormal_2의 exec 1건만)
- sourceIPs 고유값: `172.19.0.1` (4개 스크립트 공통)
- configmaps가 1줄인 이유: audit 정책(`.generated/audit/audit-policy.yaml`)의 마지막 규칙이 pods·services·secrets 외의 리소스에 `omitStages: RequestReceived`를 건다. 토큰 발급(`serviceaccounts/token`)도 같은 이유로 1줄이다.

## 3. 이전 관찰 대조 결과

| # | 이전 관찰 | 결과 | 실제 값 |
|---|---|---|---|
| 1 | pods·services·secrets는 요청당 2줄, configmaps는 1줄, exec는 ResponseStarted+ResponseComplete | 일치 | pods·services·secrets: RequestReceived+ResponseComplete, configmaps: ResponseComplete만, exec: ResponseStarted+ResponseComplete |
| 2 | 정상과 공격의 IP·UA가 같다(예외: abnormal_2 exec는 curl) | 일치 | IP는 모두 `172.19.0.1`. UA는 모두 `kubectl/v1.37.1 …`이고 abnormal_2 exec만 `curl/7.81.0` |
| 3 | 거부된 요청은 code 403과 decision forbid를 함께 가진다 | 일치 | 403 8건(secrets 7, exec 1) 모두 forbid. 200 18건은 모두 allow |
| 4 | 요청 수 normal 5, abnormal_1 1, abnormal_2 2(list 200, exec 403), abnormal_3 18(secrets 6건 403) | 일치 | 5 / 1 / 2(list pods 200, create pods/exec 403) / 18(pods 6·configmaps 6은 200, secrets 6은 403) |
| 5 | 감시 SA 요청 바로 앞에 관리자의 토큰 발급 이벤트가 찍힌다 | 부분 일치 | 4개 모두 첫 SA 요청 전에 `kubernetes-admin create serviceaccounts/token`이 1건 있다. 바로 앞 줄인 경우는 abnormal_2·abnormal_3뿐이다. normal은 사이에 system:apiserver 2줄, abnormal_1은 kube-scheduler·cilium-operator 2줄이 끼었다 |

## 4. 막힌 점
없음. (재설치 전 상황은 위 "재설치 경위" 참고.)

## 5. 제안
- 단계 01에서 "토큰 발급 직후"를 쓸 때는 "바로 다음 줄"이 아니라 "다른 사용자 줄이 끼어도 된다"고 가정해야 한다(평가 라벨용으로만).
- 첫 실행 때 normal에 관리자의 SA·Role·RoleBinding `create`가 섞이므로, 데이터셋 수집 때는 첫 실행을 버리거나 이 차이를 기록해 두면 좋다.
