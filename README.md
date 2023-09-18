# JWT Auth Builder (Work in Progress)

IMPORTANT NOTICE: This is a work in progress - it is *NOT A SUPPORTED PRODUCT*. 
You are free to try and experiment and provide feedback.

The jwt-auth-builder library is an opinionated wrapper on the NATS JWT library.
It provides an API for building entities (JWTs) that is self-documenting.
The configurations (JWTs) and secrets (nkeys) are persisted using an AuthProvider.

The AuthProvider is an interface for loading and storing configurations.

The `NscAuth` provider, is a provided implementation that uses a
[nsc](github.com/nats-io/nsc) data directory to load/store entities.
Note that the `NscAuth` provider is not thread-safe, so it should only be used
from a single thread and pointed to directories that the library manages.

## Usage

Here's an example usage, more examples as this gets further along. For additional
insight check the godoc and look at the tests.

```go
auth, err := NewAuth(NewNscAuth(storeDirPath, keysDirPath))
// create an operator
o, _ := auth.Operators().Add("O")
// create an account for system purposes
sys, _ := o.AddAccount("SYS")
o.SetSystemAccount(sys)
sys.Users().Add("sys")
// generate the creds for the sys user, save the data to a file
// this is only valid for a day
data, _ := sys.Creds(time.Hour * 24)
// create an account for users
a, _ := o.Accounts().Add("A")
// add a user
u, _ := a.Users().Add("U")
// generate the creds for the user, save the data to a file
u.PubPermissions().Allow("q", "foo", "bar")
u.SubPermissions().Allow("_inbox.foo.>")
u.RespPermissions().SetMaxMessages(1)
// store the changes in the store dir/key dir
auth.Commit()
```

