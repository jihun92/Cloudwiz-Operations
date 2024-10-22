엑셀 개인 사용자 ip를 추가


```
[table]
환경	SG Name	IP 버전	유형	프로토콜	포트 범위	소스	설명	비고
dev	Management SG dev	IPv4	SSH	tcp	22-22	0.0.0.0/0	SSH 접근 허용	
dev	Management SG dev	IPv4	사용자 지정 TCP	tcp	15672-15672	0.0.0.0/0	RabbitMQ 관리 서비스 접근 허용	
dev	Management SG dev	IPv4	사용자 지정 TCP	tcp	27017-27017	0.0.0.0/0	MongoDB 서비스 접근 허용	
dev	Management SG dev	IPv4	사용자 지정 TCP	tcp	6379-6379	0.0.0.0/0	Redis 서비스 접근 허용	
dev	Management SG dev	IPv4	사용자 지정 TCP	tcp	8080-8080	0.0.0.0/0	API 접근 허용	

[요구사항]
위 [table]에 데이터를 추가하려고합니다.
Management SG dev에 정의된 모든 포트를 아래 사용자들과 1:1 매핑될 수 있게 개인사용자들을 추가하여 [table]을 다시 출력해주세요. 
[table]의 항목은 절대 삭제하거나 변경하지마세요
환경이 dev일 경우에는 table에서 삭제해주세요.
환경을 stg와 prd를 추가하여 생성해주세요.
SG Name은 환경에 맞춰 이름을 변경해주세요.
비고는 " ~ 접근 허용 - 이름" 형식으로 추가해주세요


name	ip
윤병재	121.160.10.129
김명은	221.145.113.194
주진우	121.139.82.169
이대훈	124.5.252.6
이창주	58.29.145.217
```

--

yaml 파일 생성 프롬프트
```
첨부한 sg_table.csv 데이터를 활용하여 data_sg.yaml 형식의 yaml 파일을 생성해주세요.
```

yaml 파일 업데이트 프롬프트 - Management SG에 개발자 추가
```
위 데이터는 개발자명과 개발자가 사용하는 ip입니다. 위 데이터를 활용하여 아래 요구사항을 해결해주세요.

[요구사항]
위 정의된 개발자들도 Management SG에 정의된 22, 27017, 8080, 15672, 6379번 등 모든 포트를 사용할 수 있어야합니다. Management SG에 각 포트를 각 사용자들에게 인바운드 규칙으로 추가될 수 있도록 yaml을 수정해주세요.
```
