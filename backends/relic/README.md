## Fix flaky infinite `DEADLYSIGNAL` loop for address sanitizer

See this [stackoverflow](https://stackoverflow.com/questions/77672217/gcc-fsanitize-address-results-in-an-endless-loop-on-program-that-does-nothing) question.

```
sudo sysctl -w vm.mmap_rnd_bits=28
```
