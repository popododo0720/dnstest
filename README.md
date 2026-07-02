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

변경은 즉시 반영되고(SOA 시리얼 자동 증가) `zone_dir`에 존 파일로 영속화되며,
설정된 세컨더리들에게 NOTIFY가 나간다.

## 존 전송 / 이중화

- **프라이머리**: AXFR-out (`[transfer].allow` ACL) + 존 변경 시 NOTIFY 발송.
  BIND9를 세컨더리로 붙여 상호운용 검증됨.
- **세컨더리**: `[[secondary]]`로 선언하면 SOA 시리얼 폴링 + NOTIFY 수신으로
  프라이머리에서 자동 AXFR (RFC 1982 시리얼 연산).
- **조건부 포워딩**: `[[forward]]`로 특정 존만 지정 업스트림으로.

## RPZ (도메인 차단/싱크홀)

`[rpz].file`에 한 줄씩: `phishing.bad`(NXDOMAIN), `malware.bad 10.66.66.66`(싱크홀).
서브도메인까지 커버, SIGHUP으로 리로드.

그 외: serve-stale(RFC 8767, 업스트림 전체 장애 시 만료 캐시로 응답),
`version.bind CH TXT` 호환.

## TSIG (전송 인증, RFC 8945)

`[[tsig_key]]`로 HMAC-SHA256/512 키 등록. `transfer.require_tsig`로 AXFR/IXFR에
서명 강제, `secondary.tsig_key`로 인바운드 전송 서명. dig `-y`와 상호운용 검증됨.

## IXFR (증분 전송, RFC 1995)

존 변경 저널(API/전송 시 자동 기록)로 증분 응답. 클라이언트 serial이 저널에
없으면 전체 AXFR로 폴백. `dig IXFR=<serial>`로 검증됨.

## DNSSEC (온라인 서명, RFC 8080)

`[dnssec]`로 Ed25519(알고리즘 15) 키를 지정/자동생성. DO 비트가 있으면 응답에
RRSIG를, 부재 증명(NXDOMAIN/NODATA)에 NSEC+RRSIG를, apex에 DNSKEY를 붙인다.
DS는 기동 시 로그로 출력(부모존 업로드용). 존 변경/리로드 시 자동 재서명.
**dnspython+cryptography 독립 검증기로 positive/DNSKEY/MX/NSEC 전부 검증 통과.**

## DoT / DoH

- **DoT** (RFC 7858): `[tls].dot_listen`(보통 :853). `dig +tls`, TLS1.3 검증됨.
- **DoH** (RFC 8484): `[tls].doh_listen`. HTTP/1.1 — `curl`의 POST(application/
  dns-message)와 GET(`?dns=base64url`) 검증됨.

인증서는 `[tls].cert`/`key`(PEM)로 지정, 없으면 자체서명 생성(개발용).

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
  dns-proto     와이어 포맷: 네임 압축, 메시지, EDNS0, TSIG/DNSSEC canonical
  dns-zone      존 파일 파서/직렬화 + 권한 lookup + rrset 편집
  dns-cache     TTL 캐시 + 네거티브 캐싱 (RFC 2308) + serve-stale
  dns-metrics   통계 카운터
  dns-guard     재귀 ACL(CIDR) + 클라이언트별 레이트리밋
  dns-tsig      TSIG HMAC-SHA256/512 (RFC 8945)
  dns-dnssec    DNSSEC 온라인 서명: DNSKEY/RRSIG/NSEC/DS (Ed25519)
  dns-tls       DoT/DoH TLS 설정 + DoH 코덱
  dns-resolver  존 → 캐시 → 업스트림 해석, singleflight, 페일오버, RPZ, DNSSEC
  dns-xfr       AXFR/IXFR 송수신, NOTIFY, 저널, 세컨더리 리프레시
  rdns          바이너리: UDP/TCP/DoT/DoH 리스너, 관리 API, 설정
```

테스트: `cargo test` (54개)

## 알려진 한계

- **DoH는 HTTP/1.1** — curl(POST/GET)과 상호운용되나 HTTP/2(ALPN h2)만 쓰는
  클라이언트(예: `dig +https`)와는 안 됨. h2는 미구현.
- **DNSSEC는 온라인 서명(권한 서버)만** — 검증 리졸버(업스트림 RRSIG 검증)는
  미구현. NSEC3, RSA/ECDSA 알고리즘, 키 롤오버 자동화도 스코프 밖(Ed25519 단일 키).
- **IXFR 저널은 인메모리** — 재시작 시 초기화(다음 IXFR은 AXFR 폴백).
- TSIG 다중 메시지 AXFR은 매 메시지 서명 방식(BIND의 매 N번째 서명과 호환은
  단일 메시지 존에서 확인).

미구현(알려진 한계): DNSSEC, IXFR(AXFR로 폴백), TSIG(전송은 IP ACL로 통제), DoT/DoH
