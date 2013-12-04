#!/bin/sh

# Compare HFS files using the metadata in their AppleDouble representations.

# Version 0.1

# Copyright (c) 2013 Finn Thain
# fthain@telegraphics.com.au

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


set -e -u

o1=/tmp/1.out
o2=/tmp/2.out
md=/tmp/1-2.mac.diff
dd=/tmp/1-2.data.diff

appledouble_decode () {
  if test -d "$1" ; then
    pushd "$1" > /dev/null || return 1
    top=./
  else
    d=$( dirname "$1" )
    b=$( basename "$1" )
    pushd "$d" > /dev/null || return 1
    top="$b"
  fi
  find.pl -0se '
    if (-d $_) {
      if ($depth == 1) {
        prune() if $base eq q(.Trashes) or
                   $base eq q(Trash) or
                   $base eq q(.Spotlight-V100) or
                   $base eq q(.TemporaryItems) or
                   $base eq q(TheVolumeSettingsFolder)
      }
      0
    } elsif (-f $_) {
      $base ne q(.DS_Store)
    }
  ' "$top" | applesingle -0wo posix_name,appledouble,quash_atime | applesingle -v
  popd > /dev/null
}

if false ; then
  # Do the I/O sequentially when the two paths share the same spindle.
  appledouble_decode "$1" > "$o1" || exit 1
  appledouble_decode "$2" > "$o2" || exit 2
else
  # Otherwise do the I/O in parallel and save a lot of time.
  appledouble_decode "$1" > "$o1" &
  appledouble_decode "$2" > "$o2" &
  wait %1 || exit 1
  wait %2 || exit 2
fi

perl -i -ne '
  chop;
  # Different HFS volumes munge the same long filenames in different ways...
  s/#[0-9A-F]{5}(?=[.]|$)/######/;
  print qq($_\n)
' "$o1" "$o2"

status=0
if ! diff -u -U 19 "$o1" "$o2" > "$md" 2>&1 ; then
  status=3
  egrep -B1 '^([-+]| [.]/)' < "$md" > "$md"x
  mv "$md"x "$md"
  echo "*** Resource fork and/or Mac info difference(s)"
  cat "$md"
fi
if ! diff --brief -r "$1" "$2" > "$dd" 2>&1 ; then
  status=3$status
  echo "*** Data fork difference(s)"
  cat "$dd"
fi
exit $status
