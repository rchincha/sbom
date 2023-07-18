if [ -z "$ZOT" ]; then
  export TOPDIR="$(git rev-parse --show-toplevel)"
  export PATH="${TOPDIR}/hack/tools/bin:$PATH"
fi

function run_git {
    git "$@"
}

function common_setup {
  # set up temporary directories for installs
  export TMPD=$(mktemp -d "${PWD}/batstest-XXXXX")
  export BOMD=$(mktemp -d "${PWD}/batstest-XXXXX")
}

function zot_setup {
	export ZOT_HOST=127.0.0.1
	export ZOT_PORT=5000
	cat > $TMPD/zot-config.json << EOF
{
  "distSpecVersion": "1.0.1-dev",
  "storage": {
    "rootDirectory": "$TMPD/zot",
    "gc": false
  },
  "http": {
    "address": "$ZOT_HOST",
    "port": "$ZOT_PORT"
  },
  "log": {
    "level": "error"
  }
}
EOF
	# start as a background task
	zot serve $TMPD/zot-config.json &
	pid=$!
	# wait until service is up
	count=5
	up=0
	while [[ $count -gt 0 ]]; do
		if [ ! -d /proc/$pid ]; then
			echo "zot failed to start or died"
			exit 1
		fi
		up=1
		curl -f http://$ZOT_HOST:$ZOT_PORT/v2/ || up=0
		if [ $up -eq 1 ]; then break; fi
		sleep 1
		count=$((count - 1))
	done
	if [ $up -eq 0 ]; then
		echo "Timed out waiting for zot"
		exit 1
	fi
  # setup a OCI client
  regctl registry set --tls=disabled $ZOT_HOST:$ZOT_PORT
}

function common_teardown {
	echo "Deleting $TMPD"
  rm -rf "$TMPD"
	echo "Deleting $BOMD"
  rm -rf "$BOMD"
}

function zot_teardown {
  killall zot
  rm -f $TMPD/zot-config.json
}
