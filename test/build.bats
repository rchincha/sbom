load helpers

function setup() {
  common_setup
}

function teardown() {
  common_teardown
}

@test "build workflow" {
  # create folders and files
  mkdir -p $BATS_TEST_TMPDIR/dir1/
  truncate -s 1k $BATS_TEST_TMPDIR/dir1/file1
  truncate -s 1k $BATS_TEST_TMPDIR/dir1/file2

  # directory scan
  ${TOPDIR}/bin/stacker-bom-linux-amd64 build --name dir1 --pkgname pkg1 --pkgversion 1.0.0 --license MIT --path $BATS_TEST_TMPDIR/dir1 -o $BATS_TEST_TMPDIR/dir1.json
  [ -f $BATS_TEST_TMPDIR/dir1.json ]
  cat $BATS_TEST_TMPDIR/dir1.json | jq .
  rm $BATS_TEST_TMPDIR/dir1.json

  # directory scan with glob
  ${TOPDIR}/bin/stacker-bom-linux-amd64 build --name dir1 --pkgname pkg1 --pkgversion 1.0.0 --license MIT --path $BATS_TEST_TMPDIR/dir1/.* -o $BATS_TEST_TMPDIR/dir1.json
  [ -f $BATS_TEST_TMPDIR/dir1.json ]
  cat $BATS_TEST_TMPDIR/dir1.json | jq .
  rm $BATS_TEST_TMPDIR/dir1.json

  # file scan with glob
  ${TOPDIR}/bin/stacker-bom-linux-amd64 build --name dir1 --pkgname pkg1 --pkgversion 1.0.0 --license MIT --path "$BATS_TEST_TMPDIR/dir1/file*" -o $BATS_TEST_TMPDIR/dir1.json
  [ -f $BATS_TEST_TMPDIR/dir1.json ]
  cat $BATS_TEST_TMPDIR/dir1.json | jq .
  rm $BATS_TEST_TMPDIR/dir1.json
}
