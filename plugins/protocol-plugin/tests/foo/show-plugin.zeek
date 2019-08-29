# @TEST-EXEC: zeek -NN Demo::Foo |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
