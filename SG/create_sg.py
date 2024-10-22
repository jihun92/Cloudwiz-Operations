import os
import boto3
import yaml
import logging
import re
from datetime import datetime

# AWS 클라이언트 생성
ec2_client = boto3.client('ec2')

# 로그 설정
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger()

def log_message(message):
    """현재 시간과 함께 로그 메시지를 출력합니다."""
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logger.info(f"[{current_time}] {message}")

def log_separator():
    """로그에서 구분선을 출력합니다."""
    logger.info(f"{'-' * 50}")

def log_rule_change_summary(group_name, added_rules, deleted_rules):
    """규칙 변경 사항을 출력합니다."""
    log_message(f"보안 그룹 {group_name}의 규칙 변경 사항:")
    if added_rules:
        log_message(f"  추가될 규칙:")
        for rule in added_rules:
            log_message(f"    - [추가] 프로토콜: {rule[0]}, 포트 범위: {rule[1]}-{rule[2]}, 소스: {rule[3]}, 설명: {rule[4]}")
    if deleted_rules:
        log_message(f"  삭제될 규칙:")
        for rule in deleted_rules:
            log_message(f"    - [삭제] 프로토콜: {rule[0]}, 포트 범위: {rule[1]}-{rule[2]}, 소스: {rule[3]}, 설명: {rule[4]}")

def clean_description(description):
    """설명에서 허용되지 않는 문자를 제거하고 한글을 제거하며 최대 256자로 제한합니다."""
    valid_chars = re.compile(r'[^a-zA-Z0-9. _\-:/()#,@[\]+=&;{}!$*]')
    clean_desc = valid_chars.sub('', description)
    if len(clean_desc) > 256:
        clean_desc = clean_desc[:256]
    return clean_desc

def create_security_group(group_name, description, vpc_id):
    """보안 그룹을 생성하고 보안 그룹 ID를 반환합니다."""
    try:
        response = ec2_client.create_security_group(
            GroupName=group_name,
            Description=description,
            VpcId=vpc_id
        )
        group_id = response['GroupId']
        log_message(f"보안 그룹 생성됨: {group_name} (ID: {group_id})")
        return group_id, 'created'
    except ec2_client.exceptions.ClientError as e:
        if 'InvalidGroup.Duplicate' in str(e):
            log_message(f"건너뜀: 보안 그룹 {group_name} 이미 존재함.")
            return None, 'skipped'
        else:
            log_message(f"오류 발생: 보안 그룹 {group_name}, 오류: {str(e)}")
            return None, 'failed'

def add_rule_to_security_group(group_id, rule, direction):
    """보안 그룹에 규칙을 추가합니다."""
    cleaned_description = clean_description(rule['description'])
    
    if rule['protocol'] == 'icmp':
        ip_permissions = {
            'IpProtocol': rule['protocol'],
            'FromPort': -1,  # ICMP의 경우 FromPort와 ToPort가 필요 없음
            'ToPort': -1,
            'IpRanges': [{'CidrIp': rule['source'], 'Description': cleaned_description}]
        }
    else:
        ip_permissions = {
            'IpProtocol': rule['protocol'],
            'FromPort': int(rule['port_range'].split('-')[0]),
            'ToPort': int(rule['port_range'].split('-')[1]),
            'IpRanges': [{'CidrIp': rule['source'], 'Description': cleaned_description}]
        }

    try:
        if direction == 'inbound':
            ec2_client.authorize_security_group_ingress(
                GroupId=group_id,
                IpPermissions=[ip_permissions]
            )
        elif direction == 'outbound':
            ec2_client.authorize_security_group_egress(
                GroupId=group_id,
                IpPermissions=[ip_permissions]
            )
        log_message(f"규칙 추가됨: {rule['type']} {rule['port_range']} {rule['source']} {rule['description']} -> {group_id}")
        return 'added'
    except ec2_client.exceptions.ClientError as e:
        if 'InvalidPermission.Duplicate' in str(e):
            log_message(f"건너뜀: 규칙 이미 존재함 -> {group_id}")
            return 'skipped'
        else:
            log_message(f"오류 발생: 보안 그룹 {group_id}에 규칙 추가 실패, 오류: {str(e)}")
            return 'failed'

def remove_existing_rules(group_id):
    """기존 보안 그룹의 인바운드 규칙을 제거하고, 삭제된 규칙 목록을 반환합니다."""
    try:
        sg = ec2_client.describe_security_groups(GroupIds=[group_id])
        ingress_rules = sg['SecurityGroups'][0].get('IpPermissions', [])
        if ingress_rules:
            ec2_client.revoke_security_group_ingress(GroupId=group_id, IpPermissions=ingress_rules)
            log_message(f"모든 기존 규칙 삭제됨: {group_id}")
        return ingress_rules
    except ec2_client.exceptions.ClientError as e:
        log_message(f"오류 발생: 보안 그룹 {group_id} 규칙 삭제 실패, 오류: {str(e)}")
        return 'failed'

def list_yaml_files(directory):
    return [f for f in os.listdir(directory) if f.endswith('.yaml') or f.endswith('.yml')]

def select_yaml_file(directory):
    yaml_files = list_yaml_files(directory)
    if not yaml_files:
        print("디렉토리에 YAML 파일이 없습니다.")
        return None
    print("사용할 YAML 파일을 선택하세요:")
    for i, filename in enumerate(yaml_files, start=1):
        print(f"{i}. {filename}")
    while True:
        try:
            choice = int(input("YAML 파일 번호를 입력하세요: ")) - 1
            if 0 <= choice < len(yaml_files):
                return os.path.join(directory, yaml_files[choice])
            else:
                print("유효하지 않은 선택입니다. 올바른 번호를 선택하세요.")
        except ValueError:
            print("번호를 입력하세요.")

def compare_rules(current_rules, yaml_rules):
    """현재 보안 그룹 규칙과 YAML에서 정의한 규칙을 비교하여 추가 및 삭제할 규칙을 반환합니다."""
    current_rules_set = set()
    yaml_rules_set = set()

    for rule in current_rules:
        for ip_range in rule['IpRanges']:
            current_rules_set.add((rule['IpProtocol'], rule['FromPort'], rule['ToPort'], ip_range['CidrIp'], ip_range.get('Description', '')))

    for rule in yaml_rules:
        protocol = rule.get('protocol', 'tcp')
        port_range = rule.get('port_range', '0-0')
        source = rule.get('source', '0.0.0.0/0')
        description = rule.get('description', '')

        from_port, to_port = port_range.split('-')
        
        yaml_rules_set.add((protocol, int(from_port), int(to_port), source, description))

    added_rules = yaml_rules_set - current_rules_set
    deleted_rules = current_rules_set - yaml_rules_set

    return added_rules, deleted_rules

def main():
    summary = {
        "success": set(),
        "skipped": set(),
        "failed": set(),
        "created": set(),
        "updated": {}
    }

    log_message("보안 그룹 생성 작업을 시작합니다...")
    log_separator()

    current_directory = os.path.dirname(os.path.realpath(__file__))
    selected_yaml_file = select_yaml_file(current_directory)
    if not selected_yaml_file:
        log_message("YAML 파일이 선택되지 않았습니다. 종료합니다.")
        return

    try:
        with open(selected_yaml_file, 'r', encoding='utf-8') as file:
            data = yaml.safe_load(file)
    except FileNotFoundError:
        log_message(f"오류: {selected_yaml_file} 파일을 찾을 수 없습니다.")
        summary["failed"].add(selected_yaml_file)
        return

    vpc_id = data.get('common', {}).get('vpc_id')
    if not vpc_id:
        log_message("오류: VPC ID가 공통 섹션에 없습니다.")
        summary["failed"].add("VPC ID 누락")
        return

    sg_name_to_id = {}

    for sg in data['security_groups']:
        group_name = sg['name']
        try:
            response = ec2_client.describe_security_groups(
                Filters=[
                    {'Name': 'group-name', 'Values': [group_name]},
                    {'Name': 'vpc-id', 'Values': [vpc_id]}
                ]
            )
            if response['SecurityGroups']:
                sg_id = response['SecurityGroups'][0]['GroupId']
                sg_name_to_id[group_name] = sg_id
        except ec2_client.exceptions.ClientError as e:
            log_message(f"오류: 보안 그룹 {group_name} 설명 실패: {str(e)}")
            summary["failed"].add(group_name)

    groups_to_update = [sg['name'] for sg in data['security_groups']]
    log_message(f"업데이트할 보안 그룹: {', '.join(groups_to_update)}")

    for sg in data['security_groups']:
        group_name = sg['name']
        description = sg['description']

        log_message(f"보안 그룹 처리 중: {group_name}")
        log_separator()

        group_id, creation_status = create_security_group(group_name, description, vpc_id)
        if creation_status == 'skipped':
            log_message(f"기존 보안 그룹 {group_name}의 규칙을 확인합니다.")
            group_id = sg_name_to_id[group_name]

            current_rules = ec2_client.describe_security_groups(GroupIds=[group_id])['SecurityGroups'][0].get('IpPermissions', [])
            if 'rules' in sg and sg['rules'] is not None:
                yaml_rules = sg['rules']
                added_rules, deleted_rules = compare_rules(current_rules, yaml_rules)

                if not added_rules and not deleted_rules:
                    log_message(f"규칙 변경 사항 없음: {group_name}. 업데이트 건너뜀.")
                    summary["skipped"].add(group_name)
                    continue

                log_rule_change_summary(group_name, added_rules, deleted_rules)

                confirmation = input(f"y/n: {group_name} 보안 그룹의 규칙을 변경하시겠습니까? ").strip().lower()
                if confirmation == 'y':
                    deleted_rules = remove_existing_rules(group_id)
                    if deleted_rules == 'failed':
                        summary["failed"].add(group_name)
                        log_separator()
                        continue
                    summary["updated"][group_name] = {'added': [], 'deleted': deleted_rules}

                    for rule in sg['rules']:
                        rule_status = add_rule_to_security_group(group_id, rule, 'inbound')
                        if rule_status == 'failed':
                            summary["failed"].add(group_name)
                        else:
                            summary["updated"][group_name]['added'].append(rule)
                else:
                    log_message(f"건너뜀: 보안 그룹 {group_name}의 규칙 업데이트")
                    summary["skipped"].add(group_name)
            else:
                log_message(f"보안 그룹 {group_name}에 규칙이 정의되어 있지 않음. 규칙 추가 건너뜀.")
        elif creation_status == 'failed':
            summary["failed"].add(group_name)
            log_separator()
            continue
        else:
            summary["created"].add(group_name)

            if 'rules' in sg and sg['rules'] is not None:
                for rule in sg['rules']:
                    rule_status = add_rule_to_security_group(group_id, rule, 'inbound')
                    if rule_status == 'failed':
                        summary["failed"].add(group_name)
                    else:
                        summary["success"].add(group_name)

        log_separator()

    log_separator()
    log_message("보안 그룹 생성 작업 완료.")

    if summary["created"]:
        log_message(f"새로 생성된 보안 그룹: {', '.join(summary['created'])}")
    
    if summary["updated"]:
        for group_name, changes in summary["updated"].items():
            log_message(f"업데이트된 보안 그룹: {group_name}")
            if changes["deleted"]:
                for rule in changes["deleted"]:
                    for ip_range in rule['IpRanges']:
                        log_message(f"삭제된 규칙 - 유형: {rule['IpProtocol']}, 포트 범위: {rule['FromPort']}-{rule['ToPort']}, 소스: {ip_range['CidrIp']}, 설명: {ip_range.get('Description', '')}")
            if changes["added"]:
                for rule in changes["added"]:
                    log_message(f"추가된 규칙 - 유형: {rule['type']}, 포트 범위: {rule['port_range']}, 소스: {rule['source']}, 설명: {rule['description']}")

    log_message("요약 보고서:")
    log_message(f"성공: {len(summary['success'])} - {', '.join(summary['success'])}")
    log_message(f"건너뜀: {len(summary['skipped'])} - {', '.join(summary['skipped'])}")
    log_message(f"실패: {len(summary['failed'])} - {', '.join(summary['failed'])}")
    log_separator()

if __name__ == "__main__":
    main()
