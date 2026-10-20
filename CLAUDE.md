# CLAUDE.md — Category 3 (Kubernetes Audit Log) 작업 규칙

## 과제
같은 ServiceAccount(system:serviceaccount:pbl-security:pbl-crypto-platform-app)의
정상 API 사용과 공격성 API 사용을 kube-apiserver Audit Log만으로 구분한다.
흐름: README 관찰점으로 기본 탐지 → 한계 3가지 → 한 번 업그레이드.

## 규칙
- 레포 폴더와 .generated/는 지우거나 옮기지 않는다. 클러스터가 이 폴더를 bind mount해서 audit 정책과 audit.log를 쓴다. .generated/는 커밋하지 않는다.
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
