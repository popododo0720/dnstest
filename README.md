# rdns

Rust로 바닥부터 구현한 DNS 서버. 권한(authoritative) 서버 + 캐싱 포워더 + 관리 REST API.
외부 DNS 라이브러리 없이 RFC 1035 와이어 포맷을 직접 구현.

## 실행

```sh
cargo build --release
./target/release/rdns --config rdns.example.toml
dig @127.0.0.1 -p 5300 www.example.lab A
```

설정은 `rdns.example.toml` 참고 (리슨 주소, 업스트림 페일오버, 재귀 허용 ACL,
레이트리밋, 캐시 크기, API). `kill -HUP`으로 존 핫리로드.

## 관리 API (PowerDNS 스타일)

인증: `X-API-Key` 헤더.

```sh
K='X-API-Key: changeme'; B=http://127.0.0.1:8081/api/v1
curl -H "$K" $B/zones                  # 존 목록
curl -H "$K" $B/zones/example.lab.     # 존 상세 (rrsets)
curl -H "$K" -X PATCH $B/zones/example.lab. \
  -d '{"rrsets":[{"name":"db.example.lab.","type":"A","ttl":120,"records":["10.0.0.77"]}]}'
curl -H "$K" -X POST $B/zones -d '{"name":"new.lab.","rrsets":[...]}'   # 존 생성
curl -H "$K" -X DELETE $B/zones/new.lab.
curl -H "$K" $B/statistics             # 서버 통계
```

변경은 즉시 반영되고(SOA 시리얼 자동 증가) `zone_dir`에 존 파일로 영속화된다.

## 성능

SO_REUSEPORT 멀티워커 + 존/캐시 응답은 recv 루프에서 인라인 처리(태스크 스폰 없음).
동일 존, 권한 전용, dnsperf 10초 (48코어):

| | BIND9 9.18 | rdns |
|---|---|---|
| QPS (T8 c32) | 509k | **650k (+28%)** |
| QPS (T16 c64) | 611k | **913k (+49%)** |
| 평균 지연 (T16) | 750µs | **495µs** |

## 구조 (Cargo workspace)

```
crates/
  dns-proto     와이어 포맷: 네임 압축, 메시지, EDNS0
  dns-zone      존 파일 파서/직렬화 + 권한 lookup + rrset 편집
  dns-cache     TTL 캐시 + 네거티브 캐싱 (RFC 2308)
  dns-metrics   통계 카운터
  dns-guard     재귀 ACL(CIDR) + 클라이언트별 레이트리밋
  dns-resolver  존 → 캐시 → 업스트림 해석, singleflight, 페일오버
  rdns          바이너리: UDP/TCP 리스너, 관리 API, 설정
```

테스트: `cargo test`
