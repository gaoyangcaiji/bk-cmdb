#!/bin/bash
# invalid in skip-login mode
ip=127.0.0.1
port=8090

cd /data/sidecar && ./initialize.sh

if [ $? != 0 ]
then
	echo "start db fail."
fi

cd /data/cmdb
python init.py --discovery 127.0.0.1:2181 --database cmdb --redis_ip 127.0.0.1 --redis_port 6379 --redis_pass cc --mongo_ip 127.0.0.1 --mongo_port 27017 --mongo_user cc --mongo_pass cc --blueking_cmdb_url http://localhost:9527 --blueking_paas_url http://localhost:9527 --listen_port 9527 --user_info admin:admin --auth_enabled false --auth_login_version ldap

# skip-login mode
cd /data/cmdb/cmdb_adminserver/configures/

# sed -i 's/opensource/skip-login/g' common.conf
# sed -i 's/opensource/skip-login/g' common.yaml

# start cmdb
cd /data/cmdb
./start.sh

# init data
cd cmdb_adminserver && ./init_db.sh

# hold on
tail -f /dev/null