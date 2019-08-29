# @TEST-EXEC: zeek -NN Demo::Rot13 |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
