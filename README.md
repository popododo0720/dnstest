# rdns

Rust로 바닥부터 구현한 DNS 서버. 권한(authoritative) 서버 + 캐싱 포워더.
외부 DNS 라이브러리 없이 RFC 1035 와이어 포맷을 직접 구현.

## 실행

```sh
cargo build --release
./target/release/rdns --zone zones/example.lab.zone
dig @127.0.0.1 -p 5300 www.example.lab A
```

| 옵션 | 기본값 | 설명 |
|---|---|---|
| `--listen` | 127.0.0.1:5300 | 리슨 주소 (UDP+TCP) |
| `--upstream` | 1.1.1.1:53 | 업스트림 리졸버 |
| `--zone` | - | 존 파일 (반복 가능) |
| `--no-forward` | - | 포워딩 끄기 (권한 전용) |

## 구조 (Cargo workspace)

```
crates/
  dns-proto     와이어 포맷: 네임 압축, 메시지, EDNS0
  dns-zone      존 파일 파서 + 권한 lookup (와일드카드, CNAME 체이싱)
  dns-cache     TTL 캐시 + 네거티브 캐싱 (RFC 2308)
  dns-resolver  존 → 캐시 → 업스트림 순 해석, UDP/TCP 포워딩
  rdns          바이너리: UDP/TCP 리스너, CLI
```

테스트: `cargo test`
