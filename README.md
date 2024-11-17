# gp2

## Command

```bash
$ docker build -t ebpf-for-mac .
$ docker run -it --rm --privileged -v /lib/modules:/lib/modules:ro -v /etc/localtime:/etc/localtime:ro --pid=host ebpf-for-mac
```
