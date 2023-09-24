
out_csv="runtime_mono_app.csv"
err_csv="runtime_mono_err.csv"
#p="/data/disk01/yujyet/projects/letterbomb_v1.5/letterbomb/workspace/phenomenon/eval/apks-full"
#p="/data/disk01/yiruih/AndroidProject/subjectApks/librarian_apks"
#p="/data/disk01/jessy-scrape100/results/APPLICATION"
#p="/data/disk03/yujyet/apks/apks-full"
p="/Users/yujyet/projects/apks/librarian_vuln_libs"

cmd="python3 monotone.py"

touch $out_csv
touch $err_csv
touch error.mono

for so in `ls $p`
do 

# ====== begin ==========
echo "so: ${so}" >> error.mono
begin=`date +%s`

${cmd} $p/$so 2>> error.mono
#if timeout 3600s ${cmd} $p/$so; then 
#    end=`date +%s`
#    runtime=$( echo "$end - $begin" | bc -l ) 
#    echo "$so, $runtime" >> "$out_csv"
#else
#    end=`date +%s`
#    runtime=$( echo "$end - $begin" | bc -l ) 
#    echo "$so, $runtime" >> "$err_csv"
#fi

# ====== end ==========

done
