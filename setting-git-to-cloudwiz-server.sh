#!/bin/bash

# 사용자 이메일 설정
email="devops"
key_name="devops_id_rsa"

# 1. SSH 키 생성 (기존 키와 충돌하지 않도록 이름 지정)
echo "Generating new SSH key..."
ssh-keygen -t rsa -b 4096 -C "$email" -f ~/.ssh/$key_name -N ""

# 2. SSH 에이전트 실행
echo "Starting the SSH agent..."
eval "$(ssh-agent -s)"

# 3. 새로 생성한 SSH 키를 SSH 에이전트에 추가
echo "Adding the new SSH key to the SSH agent..."
ssh-add ~/.ssh/$key_name

# 4. 공개 키 출력 (GitHub에 등록할 수 있도록)
echo "Here is your new public key. Copy it and add it to your GitHub account:"
cat ~/.ssh/$key_name.pub

# GitHub SSH 키 추가 페이지 안내
echo "Go to https://github.com/settings/keys to add your new SSH key."

# 5. GitHub 연결 테스트
echo "Testing SSH connection to GitHub..."
ssh -T git@github.com

