# zap-repl

Lets you run a Python REPL _inside_ another process.  No GDB required.  Works
across versions.

Usage:

```
# To run, then attach
python -m zap_repl /path/to/python foo.py

# To attach to an already-running interpreter
python -m zap_repl -p <pid>

Python ... on ...
>>> import os
>>> print(os.getpid())
<pid>
```

You can even have multiple attached concurrently, and they share their vars, as
well as share vars with an interactive interpreter if there happens to be one.

Doesn't require planning ahead and loading anything in the target process, just
a normal Python 3.8+ interpreter with stdlib.


# Version Compat

This library is compatile with Python 3.10+, but should be linted under the
newest stable version.

# Versioning

This library follows [meanver](https://meanver.org/) which basically means
[semver](https://semver.org/) along with a promise to rename when the major
version changes.

# License

zap-repl is copyright [Tim Hatch](https://timhatch.com/), and licensed under
the MIT license.  See the `LICENSE` file for details.
