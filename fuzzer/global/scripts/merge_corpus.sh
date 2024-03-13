set -ex

mv corpus/ old_corpus/
mkdir corpus/

./fuzzer -merge=1 corpus/ old_corpus/

rm -rf old_corpus/
