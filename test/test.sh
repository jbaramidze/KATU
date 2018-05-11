#!/bin/bash
export LD_LIBRARY_PATH=`pwd`/../third_party/lp_solve_5.5/

echo "Testing vulnerable cases"
for filename in testcases/vuln*.cpp; do
  echo -n "Testing ${filename}.......  "
  executable=${filename::-4}
  cmd="~/Thesis/installer/dynamorio/build/bin64/drrun -c /home/zhani/Thesis/project/build/bin/libnashromi.so \
          -- \"/home/zhani/Thesis/project/test/build/${executable}\" 2>&1 | grep --silent \"\!\!\!WARNING\!\!\!\""


   ~/Thesis/installer/dynamorio/build/bin64/drrun -c /home/zhani/Thesis/project/build/bin/libnashromi.so \
          -- "/home/zhani/Thesis/project/test/build/${executable}" 2>&1 | grep --silent "\!\!\!WARNING\!\!\!"


  if [ "$?" -ne "0" ]; then
    echo "FAIL!"
    echo "Command: ${cmd}"
    exit
  else
    echo "Success."
  fi
done

echo "Testing correct cases"
for filename in testcases/correct*.cpp; do
  echo -n "Testing ${filename}.......  "
  executable=${filename::-4}
  cmd="~/Thesis/installer/dynamorio/build/bin64/drrun -c /home/zhani/Thesis/project/build/bin/libnashromi.so \
          -- \"/home/zhani/Thesis/project/test/build/${executable}\" 2>&1 | grep --silent \"\!\!\!WARNING\!\!\!\""


   ~/Thesis/installer/dynamorio/build/bin64/drrun -c /home/zhani/Thesis/project/build/bin/libnashromi.so \
          -- "/home/zhani/Thesis/project/test/build/${executable}" 2>&1 | grep --silent "\!\!\!WARNING\!\!\!"


  if [ "$?" -ne "1" ]; then
    echo "FAIL!"
    echo "Command: ${cmd}"
    exit
  else
    echo "Success."
  fi
done
