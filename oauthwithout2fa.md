คู่มือ: login VM ด้วยรหัสผ่านจาก API (ฉบับ sudo ตรวจกับ API)

สรุปพฤติกรรม

Column 1	Column 2
เรื่อง	ผล
login	ใช้ username/password จาก API (ไม่ต้อง adduser ล่วงหน้า)
ครั้งแรกที่เข้า	สร้าง /home/<user> ให้อัตโนมัติ (สิทธิ์ 700)
สิทธิ์ตั้งต้น	user ทั่วไป ไม่มี sudo จนกว่า admin จะเปิดให้ในข้อ 6
sudo	ถามรหัสผ่านแล้ว ตรวจกับ API (ไม่ใช่รหัสผ่านในเครื่อง)
user ในเครื่อง (root, user01)	ใช้รหัสผ่านเครื่องตามเดิม ไม่ถูกส่งไป API


0) เตรียมก่อนเริ่ม

* เปิด SSH session ของ root/admin ค้างไว้ตลอดการตั้งค่า และมี admin local ที่ login ด้วย SSH key สำรองไว้

apt update && apt install -y curl jq socat
cp /etc/pam.d/sshd /etc/pam.d/sshd.bak
cp /etc/pam.d/sudo /etc/pam.d/sudo.bak

* (socat ใช้ทดสอบเท่านั้น)

1) Script ตรวจรหัสผ่าน

/usr/local/sbin/pam_api_auth.sh

#!/bin/bash
TOKEN_URL="https://example.com/login"
CLIENT_ID="1231"
CLIENT_SECRET="ggez"

BASE=1000000000
REG=/var/lib/apiusers

# pam_exec ส่งรหัสผ่านทาง stdin ลงท้ายด้วย NUL
IFS= read -r -d '' PASSWORD
[ -z "$PAM_USER" ] || [ -z "$PASSWORD" ] && exit 1

# user ในเครื่อง/system user (UID < BASE) ไม่ยิง API ให้ common-auth จัดการ
UID_NOW=$(id -u "$PAM_USER" 2>/dev/null) || exit 1
[ "$UID_NOW" -ge "$BASE" ] || exit 1

enc() { V="$1" jq -rn 'env.V|@uri'; }
BODY="username=$(enc "$PAM_USER")&password=$(enc "$PASSWORD")&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&grant_type=old"

RESP=$(printf '%s' "$BODY" | curl -s --max-time 5 -w '\n%{http_code}' -X POST "$TOKEN_URL" \
  -H 'Content-Type: application/x-www-form-urlencoded' --data @-)
CODE=${RESP##*$'\n'}
JSON=${RESP%$'\n'*}

OK=$(printf '%s' "$JSON" | U="$PAM_USER" jq -r \
  '(.result=="Success" and .username==env.U and ((.access_token//"")|length>0))' 2>/dev/null)

if [ "$OK" = "true" ]; then
  if [ -e "$REG/$UID_NOW" ] && [ "$(cat "$REG/$UID_NOW")" != "$PAM_USER" ]; then
    logger -t pam_api_auth "UID collision user=$PAM_USER"; exit 1
  fi
  printf '%s' "$PAM_USER" > "$REG/$UID_NOW"
  logger -t pam_api_auth "OK user=$PAM_USER service=${PAM_SERVICE:-?}"
  exit 0
fi

R=$(printf '%s' "$JSON" | jq -r '.result // "none"' 2>/dev/null)
logger -t pam_api_auth "FAIL user=$PAM_USER service=${PAM_SERVICE:-?} http=$CODE result=$R pwlen=${#PASSWORD}"
exit 1
chown root:root /usr/local/sbin/pam_api_auth.sh
chmod 755 /usr/local/sbin/pam_api_auth.sh

PAM_SERVICE ทำให้ log แยกได้ว่าเป็น sshd หรือ sudo

2) userdb service (ทำให้ user “มีตัวตน” โดยไม่ต้อง adduser)

/usr/local/sbin/apiuser-userdb

#!/bin/bash
BASE=1000000000
REG=/var/lib/apiusers
SVC=io.local.apiuser
RE='^[a-z0-9_][a-z0-9_.+-]{0,62}(@[a-z0-9][a-z0-9.-]{0,62})?$'

uid_of() { echo $((BASE + 16#$(printf '%s' "$1" | md5sum | cut -c1-7))); }
send()   { printf '%s\0' "$1"; }
nf()     { send '{"error":"io.systemd.UserDatabase.NoRecordFound"}'; }

user_rec() { jq -nc --arg n "$1" --argjson u "$2" --arg s "$SVC" \
  '{parameters:{record:{userName:$n,uid:$u,gid:$u,realName:$n,homeDirectory:("/home/"+$n),shell:"/bin/bash",disposition:"regular",service:$s},incomplete:false}}'; }
group_rec() { jq -nc --arg n "$1" --argjson g "$2" --arg s "$SVC" \
  '{parameters:{record:{groupName:$n,gid:$g,disposition:"regular",service:$s},incomplete:false}}'; }

while IFS= read -r -d '' MSG; do
  eval "$(jq -r '@sh "M=\(.method) UN=\(.parameters.userName//"") UI=\(.parameters.uid//"") GN=\(.parameters.groupName//"") GI=\(.parameters.gid//"")"' <<<"$MSG")"
  case "$M" in
    *GetUserRecord)
      if [[ $UN =~ $RE ]]; then user_rec "$UN" "$(uid_of "$UN")" | { read -r l; send "$l"; }
      elif [[ $UI =~ ^[0-9]+$ && -f $REG/$UI ]]; then N=$(<"$REG/$UI"); user_rec "$N" "$UI" | { read -r l; send "$l"; }
      else nf; fi ;;
    *GetGroupRecord)
      if [[ $GN =~ $RE ]]; then group_rec "$GN" "$(uid_of "$GN")" | { read -r l; send "$l"; }
      elif [[ $GI =~ ^[0-9]+$ && -f $REG/$GI ]]; then N=$(<"$REG/$GI"); group_rec "$N" "$GI" | { read -r l; send "$l"; }
      else nf; fi ;;
    *GetMemberships) nf ;;
    *) send '{"error":"org.varlink.service.MethodNotFound"}' ;;
  esac
done

/etc/systemd/system/io.local.apiuser.socket

[Socket]
ListenStream=/run/systemd/userdb/io.local.apiuser
Accept=yes
SocketMode=0666

[Install]
WantedBy=sockets.target

/etc/systemd/system/io.local.apiuser@.service

[Service]
ExecStart=/usr/local/sbin/apiuser-userdb
StandardInput=socket
StandardOutput=inherit
chmod 755 /usr/local/sbin/apiuser-userdb
mkdir -p /var/lib/apiusers && chmod 700 /var/lib/apiusers
systemctl daemon-reload
systemctl enable --now io.local.apiuser.socket

ทดสอบ: getent passwd artonk และ id artonk

3) PAM สำหรับ SSH (login + สร้าง /home)

แก้ /etc/pam.d/sshd:

# ส่วน auth: ใส่ก่อน @include common-auth
auth sufficient pam_exec.so quiet expose_authtok /usr/local/sbin/pam_api_auth.sh
@include common-auth
...
# ท้ายกลุ่ม session
session required pam_mkhomedir.so skel=/etc/skel umask=0077

4) PAM สำหรับ sudo (ตรวจรหัสผ่านกับ API)

แก้ /etc/pam.d/sudo:

auth sufficient pam_exec.so quiet expose_authtok /usr/local/sbin/pam_api_auth.sh
@include common-auth
@include common-account
@include common-session-noninteractive

(ให้เพิ่มเฉพาะบรรทัดแรกก่อน @include common-auth บรรทัดอื่นคือของเดิม ห้ามลบ)

ผลที่ได้:

* API user: รหัสผ่านถูกตรวจกับ API
* admin local (user01): script จบด้วย exit 1 โดยไม่ยิง API (เพราะ UID < BASE) แล้วตกไป common-auth ใช้รหัสผ่านเครื่อง

ข้อสำคัญ: บรรทัดนี้เพียงอย่างเดียว ยังไม่ให้สิทธิ์ sudo แค่ทำให้ sudo รู้วิธีตรวจรหัสผ่าน ว่าใครได้ใช้ sudo ได้ขึ้นกับ sudoers ในข้อ 6

5) ตั้งค่า SSH

sshd -T | grep -Ei '^(usepam|passwordauthentication|kbdinteractiveauthentication)'

ต้องเป็น yes ทั้งสามตัว ถ้าไม่ใช่ สร้าง /etc/ssh/sshd_config.d/50-api-auth.conf:

UsePAM yes
PasswordAuthentication yes
KbdInteractiveAuthentication yes
sshd -t && systemctl restart ssh

ถ้ามีไฟล์ชื่อขึ้นก่อน (เช่น 50-cloud-init.conf) ที่ตั้ง PasswordAuthentication no ต้องแก้ไฟล์นั้นด้วย

6) กำหนดสิทธิ์ sudo (เลือกรูปแบบเดียวหรือผสมได้)

ค่าตั้งต้นคือ ไม่มีใครมี sudo ให้สร้างไฟล์ใน /etc/sudoers.d/ ตามรูปแบบที่ต้องการ แล้วตรวจก่อนใช้เสมอ:

visudo -cf /etc/sudoers.d/90-api-sudo
chmod 440 /etc/sudoers.d/90-api-sudo

แบบ A: ให้เฉพาะรายชื่อ (แนะนำ)

User_Alias APIADMINS = artonk, lol
APIADMINS ALL=(ALL:ALL) ALL

แบบ B: ทุกคนใช้ sudo ได้ แต่จำกัดเฉพาะคำสั่งที่กำหนด

Cmnd_Alias APICMDS = /usr/bin/systemctl restart nginx, /usr/bin/systemctl status *, /usr/bin/apt update
ALL ALL=(root) APICMDS

ใช้ path เต็มเสมอ และอย่าให้คำสั่งที่เปิด shell หรือแก้ไฟล์ได้ (vim, less, find, bash, tar, cp ฯลฯ) เพราะหลุดเป็น root ได้ ระวัง * ซึ่งยอมให้ใส่ argument อะไรก็ได้

แบบ C: ทุกคนที่ login ได้ มี sudo เต็ม (ไม่แนะนำ)

ALL ALL=(ALL:ALL) ALL

ใครมีบัญชีใน API ก็ได้ root ผลข้างเคียงคือ user local ที่มีรหัสผ่านก็ใช้ sudo ได้ด้วย

แบบ D: ผสม (ทุกคนจำกัดคำสั่ง แต่บางคนเต็ม)

Cmnd_Alias APICMDS = /usr/bin/systemctl status *, /usr/bin/journalctl
User_Alias APIADMINS = artonk
ALL ALL=(root) APICMDS
APIADMINS ALL=(ALL:ALL) ALL

ตัวเลือกปรับแต่งเพิ่ม (ใส่ในไฟล์เดียวกันได้)

Defaults timestamp_timeout=5     # จำรหัส 5 นาที (ลดจำนวนครั้งที่ยิง API; 0 = ถามทุกครั้ง)
Defaults passwd_tries=3
Defaults:APIADMINS !lecture

ถ้าอยากให้ “ถามทุกครั้งที่ sudo” ตั้ง timestamp_timeout=0 แต่ทุกคำสั่งจะยิง API

การเพิ่ม/ถอนสิทธิ์

* เพิ่มคน: แก้ User_Alias แล้ว visudo -cf ... มีผลทันที ไม่ต้อง restart
* ถอนสิทธิ์ทั้งหมด: rm -f /etc/sudoers.d/90-api-sudo
* ตรวจ: login เป็น user นั้นแล้วรัน sudo -k; sudo -l

ถ้าอยากให้ “ตรวจจาก API ว่าใครควรมี sudo” (ตามบทบาท)

ตอนนี้ sudoers ผูกกับชื่อใน /etc/sudoers.d เท่านั้น ถ้า API มีฟิลด์บอกสิทธิ์ (เช่น role) ต้องให้ pam_api_auth.sh อ่านฟิลด์นั้นเมื่อ service=sudo แล้ว exit 1 ถ้าไม่มีสิทธิ์ ส่งตัวอย่าง response ที่มีฟิลด์นั้นมา จะเขียนให้ (ตัด access_token ออกก่อนส่ง)

7) ทดสอบ

# ทดสอบ script ด้วยมือ
read -rsp 'password: ' PW; echo
printf '%s\0' "$PW" | PAM_USER=artonk PAM_SERVICE=test /usr/local/sbin/pam_api_auth.sh; echo "exit=$?"; unset PW

จากเครื่องอื่น:

ssh -l artonk <vm-ip>

หลัง login: pwd (ต้องเป็น /home/artonk), id, ls -ld /home/artonk, แล้ว sudo -l

ดู log:

journalctl -t pam_api_auth -n 10 --no-pager

ต้องเห็น service=sshd ตอน login และ service=sudo ตอนใช้ sudo

ทดสอบเพิ่ม: รหัสผิดต้องเข้าไม่ได้, user ที่ไม่อยู่ใน sudoers ต้องได้ “not in the sudoers file”, และ user01 ยัง login/sudo ด้วยรหัสเครื่องได้

8) แก้ปัญหาที่พบบ่อย

Column 1	Column 2
อาการ	สาเหตุ / วิธีแก้
http=401 ... pwlen เกินความยาวจริง (เช่น 24 แทน 8)	คีย์บอร์ด Windows เป็นภาษาไทย (ไทย 1 ตัว = 3 ไบต์) สลับเป็น EN
Invalid user ... user unknown	ระบบมองไม่เห็น user ตรวจ getent passwd <ชื่อ>, regex, และใน cmd ของ Windows ห้ามใส่ ' ครอบชื่อ
login ผ่านแล้วหลุด login_get_lastlog: Cannot find account for uid	ไม่มีไฟล์ /var/lib/apiusers/<uid> ตรวจว่า script เขียน registry ได้
Could not chdir to home directory	ยังไม่ใส่ pam_mkhomedir ใน /etc/pam.d/sshd
sudo ขึ้น “Sorry, try again”	ยังไม่ใส่ pam_exec ใน /etc/pam.d/sudo หรือรหัสผ่านผิด ดู journalctl -t pam_api_auth ว่ามี service=sudo ไหม
sudo ขึ้น “is not in the sudoers file”	รหัสผ่านผ่านแล้ว แต่ยังไม่ได้ให้สิทธิ์ในข้อ 6
sudo รหัสถูกแต่ติดที่ขั้น account	เพิ่มก่อน @include common-account ใน /etc/pam.d/sudo: account sufficient pam_succeed_if.so uid >= 1000000000 quiet
ชื่อมี @ แล้ว getent ว่าง	nss-systemd อาจไม่รับชื่อที่มี @ ให้ใช้รูปแบบ xxx-at-domain แล้วให้ script แปลงกลับก่อนยิง API
lslogins -a / getent passwd ไม่เห็น API user	ปกติของวิธีนี้ (lookup ได้ทีละชื่อเท่านั้น) ดูรายชื่อจาก ls /var/lib/apiusers
pam_systemd: Failed to create session	เกิดกับ user01/su ด้วย เป็นเรื่อง logind ของ VM ไม่กระทบ login


9) ข้อควรระวังด้านความปลอดภัย

* รหัส API ที่มี sudo = root ใครที่ชื่อตรงกับ sudoers และมีรหัสใน API ได้ root ทันที ถ้า API ถูกเจาะหรือรหัสรั่ว ผู้โจมตีได้ root ทุก VM ที่ตั้งแบบนี้ ควรให้สิทธิ์เต็มเฉพาะคนที่จำเป็น และ API ต้องไม่ให้ใครสมัครชื่อซ้ำ
* ตอนนี้ ใครมีบัญชี API ก็ login เข้า shell ได้ ถ้าไม่ต้องการ ต้องมีตัวกรองเพิ่ม (เช็ค role หรือรายชื่อที่อนุญาต)
* ทุกชื่อที่ผ่าน regex “มีตัวตน” ใครสแกน SSH ก็ทำให้ยิง API ได้ ควรเปิด fail2ban และ rate limit ที่ API
* API ล่ม/timeout 5 วินาที → API user login และ sudo ไม่ได้ (fail closed) ส่วน admin local ยังเข้าได้ด้วยรหัสเครื่องหรือ SSH key
* CLIENT_SECRET อยู่ใน script ต้องตั้งสิทธิ์ 700 เจ้าของ root
* /home/<user> ไม่ถูกลบเอง ควรมีงานเก็บกวาดตามระยะเวลา
* ส่ง log (journald/auditd) ออกนอกเครื่อง เพราะ user ที่มี sudo ลบ log ในเครื่องได้

10) ถอนระบบทั้งหมด (rollback)

sed -i '/pam_api_auth.sh/d;/pam_mkhomedir.so/d' /etc/pam.d/sshd
sed -i '/pam_api_auth.sh/d' /etc/pam.d/sudo
rm -f /etc/sudoers.d/90-api-sudo
systemctl disable --now io.local.apiuser.socket
rm -f /etc/systemd/system/io.local.apiuser.socket /etc/systemd/system/io.local.apiuser@.service
rm -f /usr/local/sbin/pam_api_auth.sh /usr/local/sbin/apiuser-userdb
rm -rf /var/lib/apiusers
systemctl daemon-reload
visudo -c

