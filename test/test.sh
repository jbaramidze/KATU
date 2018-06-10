#!/bin/bash
export LD_LIBRARY_PATH=`pwd`/../third_party/lp_solve_5.5/
export LD_BIND_NOW=1

logpath=/home/zhani/Thesis/project/build/nshr.log

echo "Testing vulnerable cases"
for filename in testcases/vuln*.cpp; do
  echo -n "Testing ${filename}.......  "
  executable=${filename::-4}
  cmd="   ~/Thesis/installer/dynamorio/build/bin64/drrun -c /home/zhani/Thesis/project/build/bin/libnashromi.so \
          -- \"/home/zhani/Thesis/project/test/build/${executable}\" > /dev/null 2>&1 &&  grep --silent \"\!\!\!VULNERABILITY\!\!\!\" ${logpath}"


   ~/Thesis/installer/dynamorio/build/bin64/drrun -c /home/zhani/Thesis/project/build/bin/libnashromi.so \
          -- "/home/zhani/Thesis/project/test/build/${executable}" > /dev/null 2>&1 &&  grep --silent "\!\!\!VULNERABILITY\!\!\!" ${logpath}


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
  cmd="   ~/Thesis/installer/dynamorio/build/bin64/drrun -c /home/zhani/Thesis/project/build/bin/libnashromi.so \
          -- \"/home/zhani/Thesis/project/test/build/${executable}\" > /dev/null 2>&1 &&  grep --silent \"\!\!\!VULNERABILITY\!\!\!\" ${logpath}"


   ~/Thesis/installer/dynamorio/build/bin64/drrun -c /home/zhani/Thesis/project/build/bin/libnashromi.so \
          -- "/home/zhani/Thesis/project/test/build/${executable}" > /dev/null 2>&1 &&  grep --silent "\!\!\!VULNERABILITY\!\!\!" ${logpath}


  if [ "$?" -ne "1" ]; then
    echo "FAIL!"
    echo "Command: ${cmd}"
    exit
  else
    echo "Success."
  fi
done

echo ""

echo -n "Testing scanf_vuln working case.......  "

echo "121" | ~/Thesis/installer/dynamorio/build/bin64/drrun -c /home/zhani/Thesis/project/build/bin/libnashromi.so \
        -- "/home/zhani/Thesis/project/test/build/testcases/scanf_vuln" > /dev/null 2>&1 &&  grep --silent "\!\!\!VULNERABILITY\!\!\!" ${logpath}


  if [ "$?" -ne "1" ]; then
    echo "FAIL!"
    exit
  else
    echo "Success."
  fi


  echo -n "Testing scanf_vuln vulnerable case.......  "

echo "121212" | ~/Thesis/installer/dynamorio/build/bin64/drrun -c /home/zhani/Thesis/project/build/bin/libnashromi.so \
        -- "/home/zhani/Thesis/project/test/build/testcases/scanf_vuln" > /dev/null 2>&1 &&  grep --silent "\!\!\!VULNERABILITY\!\!\!" ${logpath}


  if [ "$?" -ne "0" ]; then
    echo "FAIL!"
    exit
  else
    echo "Success."
  fi


echo -n "Testing commandline args....... "

     ~/Thesis/installer/dynamorio/build/bin64/drrun -c /home/zhani/Thesis/project/build/bin/libnashromi.so \
        -- "/home/zhani/Thesis/project/test/build/testcases/cmdline_vuln1" "21" > /dev/null 2>&1 &&  grep --silent "\!\!\!VULNERABILITY\!\!\!" ${logpath}


  if [ "$?" -ne "0" ]; then
    echo "FAIL!"
    exit
  else
    echo "Success."
  fi

