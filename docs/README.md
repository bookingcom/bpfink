bpfink Documentation
===================

Logs
----

bpfink is pushing logs to Kafka and the logging pipeline as a JSON blob. 
In order to make detection easier, all the FIM related logs are pushed at the
warn level.

__Structure of the logs:__

As bpfink is trying to be smart during parsing, we are able to log a difference
of state for dedicated structures. For the moment there's only __3 types of structures/logs__:

- users
- access
- generic

For each of those the internal structure is bit different, but the way it is logged 
is the same. Basically, when detecting a change bpfink will logs __3 different information__:

- what has been added, under the `add` JSON key
- what has been deleted, under the `del` JSON key
- what is the current state, which as a different key depending on the consumer: 
`users`, `generic`, `access`.

In order to avoid complex logging logic, if an internal part of a structure has
changed, this structure is logged both as `add` and `del`, the difference can
be inferred by running a JSON diff on both entries, i.e:

```json
{
	"message": "user entries",
	"level": "warn",
	"add": [{
		"user": "root",
		"passwd": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXbar",
		"keys": []
	}],
	"del": [{
		"user": "root",
		"passwd": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXfoo",
		"keys": []
	}],
	"users": [{
		"user": "root",
		"passwd": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXbar",
		"keys": []
	}, {
		"user": "ncircle",
		"passwd": "",
		"keys": [
			"AAAAB3Nz.../Xyb7Bw== ncircle@scanning_device"
		]
	}]
}
```
In this example, the same user is logged both as a `del` and as an `add`, if
we run a diff, we can see that the password has changed. In addition we also have
the current state in order to validate that everything is fine.

``` json
{
	"message":"access entries",
	"level":"warn",
	"access":{
		"grant":["john"],
		"deny":["root","ALL"]
	},
	"add":{
		"grant":[],
		"deny":[]
	},
	"del":{
		"grant":["nobody"],
		"deny":[]
	},
	"processName":"sed"
}

```
In this example, the user `nobody` was removed from granted access. The current state of access is that user `John` has been granted.
while `root` and `ALL` were 

``` json
{
	"message":"generic file created",
	"level":"warn",
	"generic":{
		"current":"","next":"1a25723c4bbfb4ae20b83cbdcfc039e1a4d5f878e0c4b9f58db30478d6f8b6252403ba19d45ade5ea8e3bf65140a8a9b4995674626034f60cc7f405b"
	},
	"path":"dynamicPathFile",
	"processName":"touch",
}
```

In this example the file dynamicPathFile was created. 
