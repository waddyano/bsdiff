#!/bin/sh

#!/bin/sh

. "$COMMON/platform.sh"

set -e

echo hello > hello
echo world > world

zstd -q hello world

println >&2 "Tests cases where progress information should not be printed"

for args in \
	"" \
	"--fake-stderr-is-console -q" \
	"--fake-stderr-is-console -qq --progress" \
	"--no-progress --fake-stderr-is-console" \
	"--no-progress --fake-stderr-is-console -v"
do
	println >&2 "args = $args"
	println >&2 "compress file to file"
	zstd $args -f hello
	println >&2 "compress pipe to pipe"
	zstd $args < hello > $INTOVOID
	println >&2 "compress pipe to file"
	zstd $args < hello -fo hello.zst
	println >&2 "compress file to pipe"
	zstd $args hello -c > $INTOVOID
	println >&2 "compress 2 files"
	zstd $args -f hello world

	println >&2 "decompress file to file"
	zstd $args -d -f hello.zst
	println >&2 "decompress pipe to pipe"
	zstd $args -d < hello.zst > $INTOVOID
	println >&2 "decompress pipe to file"
	zstd $args -d < hello.zst -fo hello
	println >&2 "decompress file to pipe"
	zstd $args -d hello.zst -c > $INTOVOID
	println >&2 "decompress 2 files"
	zstd $args -d -f hello.zst world.zst
	println >&2 ""
done
