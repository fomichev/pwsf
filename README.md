Implements [V3](http://github.com/pwsafe/pwsafe/blob/master/docs/formatV3.txt)
format of the https://pwsafe.org.

# Installation

```
go get github.com/fomichev/pwsf
```

# Usage example

```
$ echo bogus12345 | pwsf -S -p ./simple.psafe3 list

$ echo bogus12345 | pwsf -S -p ./simple.psafe3 show "(Four|Five)"

$ pwsf -p ./simple.psafe3 copy "(Four|Five)"
```
