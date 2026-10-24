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
가입 승인, 계정 관리, 파일 저장소 폴더 변경, 서버 재시작을 할 수 있습니다.
저장소 폴더를 바꾸면 다음 재시작 때 파일이 새 폴더로 옮겨집니다.

## 릴리스

최초 한 번 키를 외부 USB나 안전한 저장장치에 보관합니다.
```
minisign -G -p ~/o2ee-release.pub -s /media/user/USB/o2ee-release.key

# 여기서 ~/o2ee-release.pub는 공개 키 파일 경로이고
# o2ee-release.key는 릴리스 서명용 개인 키로, 서버 컴퓨터가 아닌 곳에 안전하게 보관해야 합니다.
```

버전 변경, 빌드, 서명, 게시를 한 번에 합니다. 개인 키 비밀번호는 터미널에서 묻습니다.
```
deploy/make-release.sh \
  --onion "<onion 주소>" \
  --pub ~/o2ee-release.pub \
  --key /media/user/USB/o2ee-release.key \
  --server-data-dir ~/.local/share/o2ee-server/data \
  --version "0.1.0" \
  --name "o2ee-x86_64-linux"
```

- `--version`은 이미 게시한 버전보다 높아야 하며, `Cargo.toml`과 `Cargo.lock`에 반영되므로 커밋합니다.
- `--name`은 생략하면 `o2ee-<CPU>-<OS>`입니다.
- `--key`를 빼면 빌드까지만, `--server-data-dir`을 빼면 서명까지만 합니다(서명을 오프라인 컴퓨터에서 할 때).
- 결과물은 `target/o2ee-release/`에 남습니다.

## 개발

```
cargo test --workspace --locked
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check
```

보안 범위와 한계는 [THREAT_MODEL.txt](THREAT_MODEL.txt)에 있습니다.
