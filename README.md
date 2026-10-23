# open-e2ee-tor

Tor onion 서버를 거쳐 계정끼리 파일을 종단간 암호화로 주고받는 CLI 프로그램입니다.
서버는 암호문만 중계하며, 접속 기록을 남기지 않습니다.

## 사용

```
o2ee signup --id <아이디>        가입 신청 (관리자 승인 필요)
o2ee login --id <아이디>
o2ee send --target <아이디> --file <파일>
o2ee send --target <아이디> --dir <폴더>
o2ee inbox
o2ee download <전송 ID> [--output <폴더>]
o2ee status
o2ee update
o2ee logout
```

- 비밀번호는 터미널에서만 입력받습니다.
- 처음 주고받는 상대는 지문을 다른 경로로 확인해야 합니다.

## 설치

서버의 `http://<onion 주소>/guide`에서 받고, 서명을 확인한 뒤 설치합니다.

## 서버

```
sudo apt install tor
deploy/install-server.sh
o2ee-server set-admin-password --data-dir ~/.local/share/o2ee-server/data
```

관리자 페이지는 서버 컴퓨터의 `http://127.0.0.1:8788/`에서만 열립니다.

## 릴리스

```
deploy/make-release.sh <onion 주소> <minisign.pub>
minisign -Sm manifest.json <바이너리>       # 오프라인 컴퓨터에서
o2ee-server publish-release --data-dir <데이터 폴더> --from <서명한 폴더>
```

## 개발

```
cargo test --workspace --locked
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check
```

보안 범위와 한계는 [THREAT_MODEL.txt](THREAT_MODEL.txt)에 있습니다.
