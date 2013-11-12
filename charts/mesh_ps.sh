#!/bin/bash

function hex2d
{
	echo $((0x$1))
}

function add_box
{
    local obj_ct=$1
    local sta=$2
    local yoff=$3
    local lt=$4
    local start=$5
    local end=$6

    box_bl=$(echo $yoff-0.01 | bc)
    box_tr=$(echo $yoff+0.01 | bc)

    echo "set object $obj_ct rect from $start,$box_bl to $end,$box_tr fc lt $lt lw 0" >> ${plotfile}
}

sta0="72-b5"
sta1="fe-01"
stas="$sta0 $sta1"
plotfile=plot_psp.gpi
capfile=$1

rm -f *.dat
./mesh_ps.py $capfile
rm ${plotfile}

i=1
obj_ct=1
for sta in $stas; do
    # draw lines for dtim beacons
	cat mesh-sta-$sta.dat | grep '1 1$' | awk '{print $1}' | \
        sed -e "s/\(.*\)/set arrow from \1,(1.0$i-.02) to \1,(1.0$i+.02) nohead lc $i /g" >> ${plotfile}

    # add an awake window box for each beacon
	while read line; do
        awake_start=$(echo $line | awk '{print $1;}')
        awake_end=$(echo $line | awk '{print $2;}')
        add_box $obj_ct $sta 1.0$i $i $awake_start $awake_end
	    let $((obj_ct++))
    done < mesh-window-$sta.dat

	let $((i++))
done

cat<<EOM >> ${plotfile}
set pointsize 0.2
set yrange [0:5]
plot 'mesh-sta-$sta0.dat' using 1:(1.01) with points, \
     'mesh-sta-$sta1.dat' using 1:(1.02) with points
EOM
gnuplot -p ${plotfile}
