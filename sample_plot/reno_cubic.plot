set terminal postscript eps color size 13,8
set output "plot_reno_cubic.eps"
set multiplot layout 2,1 title "TCP cwnd_send development"

set xtics nomirror
set ytics nomirror

set key right bottom

set grid linecolor rgb "black"

#set style line 1 lt 1 lw 2 pt 7 
#set style line 2 lt 1 lw 2 pt 9

#show timestamp
set xlabel "time in sec"
set ylabel "snd_cwnd in segments"

# Congestion control send window
set title "CUBIC on 1Mbit/1Mbit/350ms/350ms"
plot "data/bic.dat" using 1:7 title "cwnd" with linespoints, \
  "data/bic.dat" using 1:($8>=2147483647 ? 0 : $8) title "ssthresh" with linespoints

set xrange [0:165]
set yrange [0:160]
set title "Reno on 1Mbit/1Mbit/50ms/50ms"
plot "data/reno.dat" using 1:7 title "cwnd" with linespoints, \
  "data/reno.dat" using 1:($8>=2147483647 ? 0 : $8) title "ssthresh" with linespoints
