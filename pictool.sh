#!/bin/sh

# conv is not mandatory, the device should support Palette Type and Win2000 BMP formats

usageexit() {
	echo "usage: $0 conv <src.bmp> | check <img.bmp> | modcopy"
	exit 0
}
trace() { echo "# $*"; "$@"; }

[ $# -lt 1 ] && usageexit
action="$1"; shift

case $action in
modcopy)
	for b in work/mods/*.bmp; do
		trace cp $b work/Res.work/$(basename $b .bmp)
	done
	;;
conv)
	[ $# -lt 1 ] && usageexit
	src="$1"
	dst="$src.conv"
	trace convert $src -alpha set -define bmp:format=bmp3 -define bmp3:alpha=true -transparent black -background "rgba(0,0,0,0)" -alpha Background $dst
	ls -l $src
	ls -l $dst
	echo "created $dst"
	;;
check)
	[ $# -lt 1 ] && usageexit
	img="$1"
	identify -verbose $img |head -n15
	;;
*)
	usageexit
	;;
esac


