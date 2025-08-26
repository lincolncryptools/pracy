# pracy

## Setup and Installation (with Docker)
To get things up and running, we recommend to use [Docker](https://www.docker.com/).
After installation, you can build an image for `pracy` with

```
$ docker build -t pracy -f Dockerfile .
```
This may take a while when run for the first time, but future invocations make use of caches.

Once the image has been built you can start a container with
```
$ docker run -it pracy
```
This drops you into a completely setup environment. You can exit it with `exit` or `Ctrl-D`.

## Playing around with `pracy`
We have provided shell scripts which faciliate the invocation of all the different tools and backends. You can invoke them simply with

```
$ ./commands/compile_scheme.sh
$ ./commands/test_relic_backend.sh
$ ./commands/test_charm_backend.sh
```

Checkout the scripts themselves to see possible settings.
