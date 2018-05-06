#!/bin/bash
for filename in testcases/vuln*.cpp; do
    echo -n "Testing ${filename}......."

  ~/Thesis/installer/dynamorio/build/bin64/drrun -c /home/zhani/Thesis/project/build/bin/libnashromi.so \
          -- /home/zhani/Thesis/project/test/build/annotation 2>&1 | grep --silent "\!\!\!WARNING\!\!\!"


  if [ "$?" -ne "0" ]; then
    echo "FAIL!"
  else
    echo "Success."
  fi 


done
